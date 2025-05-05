import os, json, base64, time, asyncio, oracledb
from datetime import datetime, timezone
from dotenv import load_dotenv

from fastapi import ( FastAPI, Request, Form, UploadFile, File, WebSocket, WebSocketDisconnect, HTTPException, Response, Depends)

from fastapi.responses import JSONResponse, RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from sqlalchemy import ( create_engine, Column, Integer, String, Text, inspect, DateTime, text)
from sqlalchemy.orm import sessionmaker, declarative_base, Session

from passlib.context import CryptContext
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from urllib.parse import quote_plus



# ─── Configuration & Environment ──────────────────────────────────────────────
load_dotenv()

SECRET_KEY    = os.getenv("SECRET_KEY", "fallback-secret")
UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", "uploads")
ORACLE_USER = os.getenv("ORACLE_USER")
ORACLE_PWD  = os.getenv("ORACLE_PWD")
ORACLE_DSN  = os.getenv("ORACLE_DSN")
TNS = os.getenv("TNS_ADMIN", "/app/Wallet_securechatDB")

# Ensure upload & logs & db dirs exist
os.environ["TNS_ADMIN"] = TNS
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs("logs", exist_ok=True)

if not (ORACLE_USER and ORACLE_PWD and ORACLE_DSN):
    raise RuntimeError("Missing one of ORACLE_USER, ORACLE_PWD, ORACLE_DSN")
# ─── Database Setup ────────────────────────────────────────────────────────────
PWD_Q = quote_plus(ORACLE_PWD)

engine = create_engine(
    f"oracle+oracledb://",
    connect_args={
    "user": ORACLE_USER,
    "password": ORACLE_PWD,
    "dsn": ORACLE_DSN, 
    "ssl_server_dn_match": True,
    },
    pool_size=10,
    max_overflow=20,
    pool_timeout=30,
    pool_recycle=1800,
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id           = Column(Integer, primary_key=True)
    username     = Column(String(50), unique=True, index=True, nullable=False)
    password_hash= Column(String(128), nullable=False)
    public_key   = Column(Text, nullable=True)

class Message(Base):
    __tablename__ = "messages"
    id         = Column(Integer, primary_key=True)
    chat_id    = Column(String(255), index=True, nullable=False)
    sender     = Column(String(50), nullable=False)
    ciphertext = Column(Text, nullable=False)
    iv         = Column(String(32))
    timestamp  = Column(DateTime, default=datetime.now(timezone.utc))

class Log(Base):
    __tablename__ = "logs"
    id        = Column(Integer, primary_key=True)
    chat_id   = Column(String(255), index=True)
    entry     = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.now(timezone.utc))

# Create tables if missing
if not inspect(engine).has_table("user"):
    Base.metadata.create_all(engine)

# ─── Password Utilities ────────────────────────────────────────────────────────
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
def hash_password(pw: str) -> str:
    return pwd_context.hash(pw)
def verify_password(pw: str, h: str) -> bool:
    return pwd_context.verify(pw, h)

# ─── FastAPI Setup ──────────────────────────────────────────────────
app = FastAPI()


app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

# Serve your existing front-end
app.mount("/static", StaticFiles(directory="client/static"), name="static")
templates = Jinja2Templates(directory="client")

# ─── Global State for WebSocket ───────────────────────────────────────────────
CONNECTED_CLIENTS     = {}  # username -> WebSocket
CLIENTS_STATUS       = {}  # username -> "online"/"offline"
UNDISPATCHED_MESSAGES= {}  # username -> [message_dict,...]
GROUP_CHATS          = {}  # chat_id -> [user1,user2...]
USER_FILE_KEYS       = {}  # filename -> hex(key)
LOG_FILE_TRACKER     = {}  # chat_id -> log_filepath
USER_MESSAGE_TIMESTAMPS = {}  # username -> [timestamps]
MUTED_USERS          = {}  # username -> unmute_timestamp

MESSAGE_RATE_LIMIT = 5    # msgs
TIME_FRAME         = 10   # seconds
MUTE_DURATION      = 10   # seconds

AES_KEY                = None

HEARTBEAT_INTERVAL     = 10   # seconds
HEARTBEAT_TIMEOUT      = 5    # seconds

FAILED_LOGINS      = {}        # ip -> [timestamps]
BRUTE_FORCE_LIMIT  = 5         # attempts
BRUTE_FORCE_WINDOW = 5 * 60    # 5 minutes in seconds

# ─── Logging & DB Helpers ──────────────────────────────────────────────────────────
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def generate_timestamp() -> str:
    return datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")

def generate_session_filename(chat_id: str) -> str:
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    return f"logs/chat_{chat_id}_session_{ts}.txt"

def log_message(chat_id: str, sender: str, message: str, iv: str):
    # Determine filename
    if chat_id not in LOG_FILE_TRACKER:
        LOG_FILE_TRACKER[chat_id] = generate_session_filename(chat_id)
    path = LOG_FILE_TRACKER[chat_id]

    # Build log line
    if iv and iv != "No IV":
        payload = json.dumps({"ciphertext":message,"iv":iv})
    else:
        payload = message
    line = f"{sender}: {payload} - {generate_timestamp()}\n"

    # Append
    with open(path, "a", encoding="utf-8") as f:
        f.write(line)

    
# ─── Encryption Helpers ────────────────────────────────────────────────────────
def encrypt_file(input_path: str, output_path: str, key: bytes):
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce
    plaintext = open(input_path, "rb").read()
    ct, tag = cipher.encrypt_and_digest(plaintext)
    open(output_path, "wb").write(nonce + tag + ct)

def decrypt_file(input_path: str, output_path: str, key: bytes):
    data = open(input_path, "rb").read()
    nonce, tag, ct = data[:16], data[16:32], data[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    pt = cipher.decrypt_and_verify(ct, tag)
    open(output_path, "wb").write(pt)

# ─── HTTP ROUTES ───────────────────────────────────────────────────────────────

@app.get("/users/{user_id}")
def read_user(user_id: int, db=Depends(get_db)):
    # using text() + bind params to avoid SQL injection
    result = db.execute(text("SELECT id, username FROM users WHERE id = :uid"), {"uid": user_id})
    row = result.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="User not found")
    return {"id": row.id, "username": row.username}

@app.get("/")
def root():
    return RedirectResponse("/home")

@app.get("/home")
def home_get(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/home")
def home_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    action:   str = Form(...)
):
    client_ip = request.client.host
    now = time.time()
    # prune old failures
    attempts = [t for t in FAILED_LOGINS.get(client_ip, []) if now - t < BRUTE_FORCE_WINDOW]
    FAILED_LOGINS[client_ip] = attempts

    # --- LOGIN branch ---
    if action.lower() == "login":
        # throttle failed attempts
        if len(attempts) >= BRUTE_FORCE_LIMIT:
            return JSONResponse(
                {"message": "Too many login attempts. Try again later."},
                status_code=429
            )

        db = SessionLocal()
        user = db.query(User).filter_by(username=username).first()
        db.close()

        if not user or not verify_password(password, user.password_hash):
            # **record** this failure
            FAILED_LOGINS.setdefault(client_ip, []).append(now)
            return JSONResponse(
                {"message": "Invalid username and/or password."},
                status_code=401
            )

        # success! clear failures and set session
        FAILED_LOGINS[client_ip] = []
        request.session["username"] = username
        return JSONResponse({"redirect": "/chat"})

    # --- SIGNUP branch (unlimited) ---
    if action.lower() == "signup":
        db = SessionLocal()
        if db.query(User).filter_by(username=username).first():
            db.close()
            return JSONResponse({"message": "Username exists"}, status_code=400)
        user = User(username=username, password_hash=hash_password(password))
        db.add(user); db.commit(); db.close()

        request.session["username"] = username
        return JSONResponse({"message": "Signup successful! You may now login" ,"redirect": "/chat"}, status_code=201)

    # Fallback 
    return JSONResponse({"message": "Unknown action"}, status_code=400)
@app.get("/chat")
def chat_page(request: Request):
    if not request.session.get("username"):
        return RedirectResponse("/home")
    return templates.TemplateResponse("chat.html", {
        "request": request, 
        "username": request.session["username"]
    })

@app.get("/chat/{chat_id}")
def get_chat_history(chat_id: str):
    path = LOG_FILE_TRACKER.get(chat_id)
    if path and os.path.exists(path):
        lines = open(path, "r", encoding="utf-8").read().splitlines()
        return {"chat_logs": lines}
    return {"chat_logs": []}

@app.post("/create_group")
def create_group(data: dict):
    name    = data.get("group_name")
    members = data.get("members")
    if not name or not members:
        raise HTTPException(400, "Name & members required")
    chat_id = f"group_{name}"
    GROUP_CHATS[chat_id] = members
    return {"chat_id": chat_id, "members": members}

@app.get("/leave")
def leave(request: Request):
    request.session.pop("username", None)
    return RedirectResponse("/home")


@app.post("/register_public_key")
def register_public_key(data: dict):
    db: Session = SessionLocal()
    user = db.query(User).filter_by(username=data.get("username")).first()
    if not user:
        db.close()
        raise HTTPException(404, "User not found")
    user.public_key = data.get("public_key")
    db.commit(); db.close()
    return {"message":"Public key registered"}

@app.get("/get_public_key/{username}")
def get_public_key(username: str):
    db: Session = SessionLocal()
    user = db.query(User).filter_by(username=username).first()
    db.close()
    if not user or not user.public_key:
        raise HTTPException(404, "Key not found")
    return {"public_key": user.public_key}

@app.get("/get_aes_key")
def get_aes_key():
    global AES_KEY
    if AES_KEY is None:
        AES_KEY = get_random_bytes(32)
    return {"aes_key": base64.b64encode(AES_KEY).decode()}

@app.post("/upload")
def upload_file(
    file: UploadFile = File(...),
    username: str     = Form(None)
):
    path = os.path.join(UPLOAD_FOLDER, file.filename)
    open(path, "wb").write(file.file.read())
    enc_path = path + ".enc"
    key = get_random_bytes(32)
    encrypt_file(path, enc_path, key)
    os.remove(path)
    if username:
        USER_FILE_KEYS[file.filename] = key.hex()
    return {"filename": file.filename, "key": key.hex()}

@app.get("/download/{filename}")
def download_file(filename: str, key: str):
    enc = os.path.join(UPLOAD_FOLDER, filename + ".enc")
    if not os.path.exists(enc):
        raise HTTPException(404, "Not found")
    dec = os.path.join(UPLOAD_FOLDER, filename)
    decrypt_file(enc, dec, bytes.fromhex(key))
    return FileResponse(dec, filename=filename)




# ─── Rate-limit & Muting Helpers ────────────────────────────────────────────────
async def is_user_muted(user: str, now: float) -> bool:
    expiry = MUTED_USERS.get(user)
    if expiry and now < expiry:
        return True
    MUTED_USERS.pop(user, None)
    return False

async def check_rate_limit(user: str, now: float) -> bool:
    lst = USER_MESSAGE_TIMESTAMPS.setdefault(user, [])
    # drop old
    USER_MESSAGE_TIMESTAMPS[user] = [t for t in lst if now - t < TIME_FRAME]
    return len(USER_MESSAGE_TIMESTAMPS[user]) >= MESSAGE_RATE_LIMIT

async def warn_and_mute(user: str, now: float):
    MUTED_USERS[user] = now + MUTE_DURATION
    await CONNECTED_CLIENTS[user].send_text(json.dumps({
        "error": f"RATE LIMIT EXCEEDED. WAIT {MUTE_DURATION}s",
        "timestamp": generate_timestamp()
    }))

# ─── File Upload/Download Over WebSocket ──────────────────────────────────────
async def handle_file_upload(ws: WebSocket, user: str, data: dict):
    fn = data.get("filename")
    raw= base64.b64decode(data.get("file_data",""))
    if not fn or not raw:
        await ws.send_text(json.dumps({"error":"Invalid file data"}))
        return
    path,enc = os.path.join(UPLOAD_FOLDER, fn), os.path.join(UPLOAD_FOLDER, fn+".enc")
    open(path,"wb").write(raw)
    key = get_random_bytes(32)
    encrypt_file(path, enc, key); os.remove(path)
    USER_FILE_KEYS[fn] = key.hex()
    ts = generate_timestamp()
    # broadcast
    for c in CONNECTED_CLIENTS.values():
        await c.send_text(json.dumps({
            "type":"file_upload_response",
            "filename": fn,
            "key": key.hex(),
            "sender": user,
            "timestamp": ts
        }))

async def handle_file_download(ws: WebSocket, user: str, data: dict):
    fn  = data.get("filename")
    key = USER_FILE_KEYS.get(fn)
    enc = os.path.join(UPLOAD_FOLDER, fn+".enc")
    if not (fn and key and os.path.exists(enc)):
        await ws.send_text(json.dumps({"error":"File/download missing"}))
        return
    raw = base64.b64encode(open(enc,"rb").read()).decode()
    await ws.send_text(json.dumps({
        "type":"file_download_response",
        "filename":fn,
        "file_data": raw,
        "key": key,
        "sender": user
    }))

async def heartbeat(ws: WebSocket):
    try:
        while True:
            await ws.send_text(json.dumps({"type":"ping"}))
            await asyncio.sleep(HEARTBEAT_INTERVAL)
    except:
        pass


# ─── Typing Indicator, Broadcasts, Undelivered & Group Logic ────────────────
@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    user = None

    try:
        # ─── Handshake ──────────────────────────────
        init = json.loads(await ws.receive_text())
        user = init.get("username")
        db = SessionLocal()
        exists = db.query(User).filter_by(username=user).first() is not None
        db.close()
        if not exists:
            await ws.send_text(json.dumps({"error":"Unauthorized"}))
            await ws.close()
            return

        # ─── Register & flush undelivered ───────────
        CONNECTED_CLIENTS[user] = ws
        CLIENTS_STATUS[user]   = "online"
        await notify_user_list()
        for msg in UNDISPATCHED_MESSAGES.pop(user, []):
            await ws.send_text(json.dumps(msg))

        # ─── Main loop ──────────────────────────────
        while True:
            raw = await ws.receive_text()
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                data = {
                    "type":    "message",
                    "message": raw,
                    "iv":      None
                }

            typ = data.get("type", "message")

            # 2) Handle typing indicator immediately
            if typ == "typing":
                cid      = data.get("chat_id")
                isTyping = data.get("isTyping")
                if cid:
                    targets = (GROUP_CHATS.get(cid)
                               if cid.startswith("group_")
                               else [u for u in CONNECTED_CLIENTS if u != user])
                    for u in targets:
                        ws2 = CONNECTED_CLIENTS.get(u)
                        if ws2:
                            await ws2.send_text(json.dumps({
                                "type":     "typing",
                                "sender":   user,
                                "isTyping": isTyping,
                                "chat_id":  cid
                            }))
                continue  # 

            # 3) Rate-limit
            now = time.time()
            if await is_user_muted(user, now):
                continue
            if await check_rate_limit(user, now):
                await warn_and_mute(user, now)
                continue
            USER_MESSAGE_TIMESTAMPS.setdefault(user, []).append(now)

            # 4) File ops
            if typ == "file_upload":
                await handle_file_upload(ws, user, data)
            elif typ == "file_download":
                await handle_file_download(ws, user, data)

            # 5) Text message
            else:
                cid = data.get("chat_id", "general_chat")
                msg = data["message"]
                iv  = data.get("iv", "No IV")

                # Log will now correctly record ciphertext + IV
                log_message(cid, user, msg, iv)

                if cid == "general_chat":
                    recipients = list(CONNECTED_CLIENTS.keys())
                elif cid.startswith("group_"):
                    recipients = GROUP_CHATS.get(cid, [])
                else:
                    recipients = cid.split("_")

                envelope = {
                    "chat_id":   cid,
                    "sender":    user,
                    "message":   msg,
                    "timestamp": generate_timestamp()
                }
                for u in recipients:
                    ws2 = CONNECTED_CLIENTS.get(u)
                    if ws2:
                        await ws2.send_text(json.dumps(envelope))
                    else:
                        UNDISPATCHED_MESSAGES.setdefault(u, []).append(envelope)

    except WebSocketDisconnect:
        # client disconnected
        pass

    finally:
        # cleanup
        if user:
            CONNECTED_CLIENTS.pop(user, None)
            CLIENTS_STATUS[user] = "offline"
            await notify_user_list()

# ─── Utility ──────────────────────────────────────────────────────────────────
async def notify_user_list():
    lst = [{"username":u,"status":CLIENTS_STATUS.get(u,"offline")} 
           for u in CLIENTS_STATUS]
    msg = json.dumps({"type":"user_list_status_update","users":lst})
    for ws in CONNECTED_CLIENTS.values():
        await ws.send_text(msg)


@app.get("/healthz")
def healthz():
    """
    Health check for external monitors.
    Returns HTTP 200 + JSON.
    """
    return {"status": "ok"}

@app.head("/")               
def head_root() -> Response:
    return Response(status_code=200)

@app.head("/healthz")        
def head_healthz() -> Response:
    return Response(status_code=200)