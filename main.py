import os, json, time, asyncio, httpx, firebase_admin
from datetime import datetime, timezone
from dotenv import load_dotenv

from firebase_admin import credentials, auth

from fastapi import ( FastAPI, Request, Form, UploadFile, File, WebSocket, WebSocketDisconnect, HTTPException, Response, Depends)

from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from sqlalchemy import ( create_engine, Column, Integer, String, Text, inspect, DateTime)
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from sqlalchemy.dialects.postgresql.base import PGDialect

from passlib.context import CryptContext


from json import JSONDecoder



# ─── Configuration & Environment ──────────────────────────────────────────────
load_dotenv()

DATABASE_URL  = os.getenv("DATABASE_URL", "sqlite:///users.db")
SECRET_KEY    = os.getenv("SECRET_KEY", "fallback-secret")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY") # VirusTotal API key for malware scan

# Firebase admin sdk for token
raw = os.environ.get("FIREBASE_CREDENTIALS", "")
if not raw:
    raise RuntimeError("FIREBASE_CREDENTIALS not set")
cred_data = JSONDecoder(strict=False).decode(raw)
cred = credentials.Certificate(cred_data)
firebase_admin.initialize_app(cred)

# Ensure logs dirs exist
os.makedirs("logs", exist_ok=True)

# ─── Database Setup ────────────────────────────────────────────────────────────


# forces SQLAlchemy to treat CockroachDB as if it were PostgreSQL 13.0
PGDialect._get_server_version_info = lambda self, connection: (13, 0)



engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "user"
    id           = Column(Integer, primary_key=True, index=True)
    username     = Column(String(50), unique=True, nullable=False)
    password_hash= Column(String(128), nullable=False)
    public_key   = Column(Text, nullable=True)
class Message(Base):
    __tablename__ = "message"
    id        = Column(Integer, primary_key=True, index=True)
    chat_id   = Column(String(50), index=True, nullable=False)
    sender    = Column(String(50), nullable=False)
    recipient = Column(String(100), nullable=False)
    content   = Column(Text, nullable=False)
    iv        = Column(String(256), nullable=False)
    timestamp = Column(DateTime(timezone=True),
                       default=lambda: datetime.now(timezone.utc))

class Log(Base):
    __tablename__ = "log"
    id        = Column(Integer, primary_key=True, index=True)
    chat_id   = Column(String(50), index=True, nullable=False)
    user      = Column(String(50), nullable=False)
    action    = Column(String(100), nullable=False)
    details   = Column(Text, nullable=True)
    timestamp = Column(DateTime(timezone=True),
                       default=lambda: datetime.now(timezone.utc))

# Creates any missing tables
Base.metadata.create_all(engine)
#---- DB HELper dependency----
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ─── Password Utilities ────────────────────────────────────────────────────────
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
def hash_password(pw: str) -> str:
    return pwd_context.hash(pw)
def verify_password(pw: str, h: str) -> bool:
    return pwd_context.verify(pw, h)

# ─── FastAPI Setup ──────────────────────────────────────────────────
app = FastAPI()


app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

# Serves existing front-end
app.mount("/static", StaticFiles(directory="client/static"), name="static")
templates = Jinja2Templates(directory="client")

# ─── Global State for WebSocket ───────────────────────────────────────────────
CONNECTED_CLIENTS     = {}  # username -> WebSocket
CLIENTS_STATUS       = {}  # username -> "online"/"offline"
UNDISPATCHED_MESSAGES= {}  # username -> [message_dict,...]
GROUP_CHATS          = {}  # chat_id -> [user1,user2...]
CHAT_FILES = {}            # chat_id -> list of { filename, file_data, iv, sender }
LOG_FILE_TRACKER     = {}  # chat_id -> log_filepath
USER_MESSAGE_TIMESTAMPS = {}  # username -> [timestamps]
MUTED_USERS          = {}  # username -> unmute_timestamp

MESSAGE_RATE_LIMIT = 5    # msgs
TIME_FRAME         = 10   # seconds
MUTE_DURATION      = 10   # seconds

HEARTBEAT_INTERVAL     = 10   # seconds
HEARTBEAT_TIMEOUT      = 5    # seconds

FAILED_LOGINS      = {}        # ip -> [timestamps]
BRUTE_FORCE_LIMIT  = 5         # attempts
BRUTE_FORCE_WINDOW = 5 * 60    # 5 minutes in seconds

# ─── Logging Helpers ──────────────────────────────────────────────────────────
def generate_timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

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

# ─── HTTP ROUTES ───────────────────────────────────────────────────────────────

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

@app.get("/get_firebase_token")
def get_firebase_token(request: Request):
    if not request.session.get("username"):
        return RedirectResponse("/home")
    user_id = request.session.get("username")
    custom_token = auth.create_custom_token(user_id)
    return JSONResponse({'firebase_token': custom_token.decode('utf-8')})

@app.get("/chat/{chat_id}")
def get_chat_history(chat_id: str):
    path = LOG_FILE_TRACKER.get(chat_id)
    lines = []
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()

    # Get file list for this chat, return filenames only
    chat_files = CHAT_FILES.get(chat_id, [])
    file_list = [f["filename"] for f in chat_files]

    return {
        "chat_logs": lines,
        "files": file_list
    }

@app.post("/create_group")
def create_group(data: dict):
    name    = data.get("group_name")
    members = data.get("members")
    encrypted_keys = data.get("encrypted_keys")
    if not name or not members:
        raise HTTPException(400, "Name & members required")
    chat_id = f"group_{name}"
    GROUP_CHATS[chat_id] = {
        "members": members,
        "encrypted_keys": encrypted_keys
    }
    return {"chat_id": chat_id, "members": members}

# Send requestor's encrypted group key
@app.get("/group_key/{chat_id}")
async def get_group_key(chat_id: str, request: Request):
    username = request.session.get("username")
    if not username:
        raise HTTPException(status_code=401, detail="Not authenticated")

    chat = GROUP_CHATS.get(chat_id)
    if not chat or username not in chat["members"]:
        raise HTTPException(status_code=403, detail="Access denied")

    encrypted_key = chat["encrypted_keys"].get(username)
    if not encrypted_key:
        raise HTTPException(status_code=404, detail="Encrypted key not found for user")

    return {
        "group_key": encrypted_key["groupKey"],
        "group_key_iv": encrypted_key["groupKeyiv"]
    }


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

#VirusTotal scan
@app.post("/scan")
async def scan_file(file: UploadFile = File(...)):
    if not VIRUSTOTAL_API_KEY:
        raise HTTPException(status_code=500, detail="VirusTotal API key not configured")

    async with httpx.AsyncClient(timeout=60.0) as client:
        # Upload file to VirusTotal & send analysis id to client
        files = {'file': (file.filename, await file.read())}
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        vt_response = await client.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files)

        if vt_response.status_code != 200:
            raise HTTPException(status_code=vt_response.status_code, detail=vt_response.text)

        vt_data = vt_response.json()
        analysis_id = vt_data["data"]["id"]
        return {"status": "submitted", "analysis_id": analysis_id}

@app.get("/scan-result/{analysis_id}")
async def get_scan_result(analysis_id: str):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    async with httpx.AsyncClient() as client:
        response = await client.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)

    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.text)

    result = response.json()
    return {
        "status": result["data"]["attributes"]["status"],
        "stats": result["data"]["attributes"].get("stats", {})
    }

# API logging and history
@app.post("/api/logs/{chat_id}")
def add_log(chat_id: str, action: str = Form(...), details: str = Form(None),
            db: Session = Depends(get_db)):
    entry = Log(chat_id=chat_id, user="external", action=action, details=details)
    db.add(entry)
    db.commit()
    return {"status":"ok"}



@app.get("/api/history/{chat_id}")
def get_history(chat_id: str, db: Session = Depends(get_db)):
    msgs = (
        db.query(Message)
          .filter(
             Message.chat_id == chat_id,
             Message.timestamp != None
          )
          .order_by(Message.timestamp.desc())
          .limit(100)
          .all()
    )
    out = []
    for m in reversed(msgs):
        out.append({
            "sender":    m.sender,
            "recipient": m.recipient,
            "content":   m.content,
            "iv":        m.iv,
            "timestamp": m.timestamp.isoformat() if m.timestamp else ""
        })
    return out



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
    chat_id = data.get("chat_id")
    if not chat_id:
        return

    file_record = {
        "filename": fn,
        "firebase_url": data["firebase_url"],
        "iv": data["iv"],
        "sender": data["username"]
    }

    if chat_id not in CHAT_FILES:
        CHAT_FILES[chat_id] = []
    CHAT_FILES[chat_id].append(file_record)

    ts = generate_timestamp()

    targets = get_chat_recipients(chat_id)

    for u in targets:
        ws2 = CONNECTED_CLIENTS.get(u)
        if ws2:
            await ws2.send_text(json.dumps({
                "type":"file_upload_response",
                "filename": fn,
                # "key": key.hex(),
                "sender": user,
                "timestamp": ts,
                "chat_id": chat_id
            }))

async def handle_file_download(ws: WebSocket, user: str, data: dict):
    fn  = data.get("filename")
    chat_id = data.get("chat_id")
    username = data["username"]

    if chat_id not in CHAT_FILES:
        return

    targets = get_chat_recipients(chat_id)

    if username not in targets:
        await ws.send_json({"type": "error", "message": "Unauthorized access"})
        return

    file_entry = next((f for f in CHAT_FILES[chat_id] if f["filename"] == fn), None)
    
    if file_entry:
        await ws.send_text(json.dumps({
            "type":"file_download_response",
            "filename":fn,
            "firebase_url": file_entry["firebase_url"],
            "iv": file_entry["iv"]
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
                # If raw ciphertext string, preserve as ciphertext
                data = {
                    "type":    "message",
                    "message": raw,
                    "iv":      None
                }

            typ = data.get("type", "message")

            # Handles ...istyping indicator
            if typ == "typing":
                cid      = data.get("chat_id")
                isTyping = data.get("isTyping")
                if cid:

                    targets = get_chat_recipients(cid)

                    for u in targets:
                        if u != user:
                            ws2 = CONNECTED_CLIENTS.get(u)
                            if ws2:
                                await ws2.send_text(json.dumps({
                                    "type":     "typing",
                                    "sender":   user,
                                    "isTyping": isTyping,
                                    "chat_id":  cid
                                }))
                continue

            # Rate-limiting
            now = time.time()
            if await is_user_muted(user, now):
                continue
            if await check_rate_limit(user, now):
                await warn_and_mute(user, now)
                continue
            USER_MESSAGE_TIMESTAMPS.setdefault(user, []).append(now)

            # File ops
            if typ == "file_upload":
                await handle_file_upload(ws, user, data)
            elif typ == "file_download":
                await handle_file_download(ws, user, data)

            # Text message
            else:
                #logs message to cockroachDB
                cid = data.get("chat_id", "general_chat")
                msg = data["message"]
                iv  = data.get("iv", "No IV")

                db: Session = SessionLocal()
                db.add(
                    Message(
                    chat_id   = cid,
                    sender    = user,
                    recipient = ",".join(get_chat_recipients(cid)),
                    content   = msg,
                    iv        = iv or "",
                    timestamp = datetime.now(timezone.utc)    
                    )
                )
                db.commit()
                db.close()


                log_message(cid, user, msg, iv)


                recipients = get_chat_recipients(cid)
                is_group = cid.startswith("group_") and cid in GROUP_CHATS

                envelope = {
                    "chat_id":   cid,
                    "sender":    user,
                    "message":   msg,
                    "timestamp": generate_timestamp(),
                    "iv": iv,
                    "encrypted": data["encrypted"]
                }

                for u in recipients:
                    #if its a group chat send the encrypted group key to the specific recipient
                    if is_group:
                        encrypted_key = GROUP_CHATS[cid]["encrypted_keys"].get(u)
                        if encrypted_key:
                            envelope["group_key"] = encrypted_key["groupKey"]
                            envelope["group_key_iv"] = encrypted_key["groupKeyiv"]

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


def get_chat_recipients(chat_id):
    # Returns a list of usernames based on the chat type
    if chat_id.startswith("group_") and chat_id in GROUP_CHATS:
        targets = GROUP_CHATS[chat_id]["members"]
    elif chat_id == "general_chat":
        targets = list(CONNECTED_CLIENTS.keys())
    else:
        targets = chat_id .split("_")

    return targets

# ───  24/7 Uptime robot + head request handler ───────────────────
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