from flask import Flask, render_template, request, redirect, session, url_for, jsonify
import asyncio, websockets, threading, os, time, sys, ssl, json 
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt


CONNECTED_CLIENTS = {} # Active WebSocket connections
HEARTBEAT_INTERVAL = 10  #seconds
HEARTBEAT_TIMEOUT = 5  #seconds
USER_MESSAGE_TIMESTAMPS = {} 
MUTED_USERS = {}  # Store muted users and when they can send again
MESSAGE_RATE_LIMIT = 5  # of msgs
TIME_FRAME = 10  #seconds
MUTE_DURATION = 10  # Mute user for 10 seconds after exceeding limit
GROUP_CHATS = {}  # Group chat mapping

#Loading environment variables from .env file
load_dotenv()


app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "fallback@secret!")

# Configuring the database
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# Password hashing
bcrypt = Bcrypt(app)


# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)


# Ensure database is created before running
def create_database():
    with app.app_context():
        db.create_all()

create_database()

# ssl cert implementation 

SSL_CERT_PATH = os.getenv("SSL_CERT_PATH", "your_cert.pem") 
SSL_KEY_PATH = os.getenv("SSL_KEY_PATH", "your_key.pem")     

if not os.path.exists(SSL_CERT_PATH) or not os.path.exists(SSL_KEY_PATH):
    print("SSL Certificate and Key not found. ")
    print("Please use the instructions in README.md to create SSL cert before running the server.\n")
    sys.exit(1) 

SSL_CONTEXT = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
SSL_CONTEXT.load_cert_chain(certfile=SSL_CERT_PATH, keyfile=SSL_KEY_PATH)


#Logging each chat session
chat_logs_dir = "logs"
os.makedirs(chat_logs_dir, exist_ok=True)

# Logs messages to a file per chat
def log_message(chat_id, sender, message):
    with open(f"{chat_logs_dir}/chat_{chat_id}.txt", "a") as f:
        f.write(f"{sender}: {message}\n")


# auto redirects url to /home 
@app.route("/")
def index():
    return redirect(url_for("home"))


@app.route("/home", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        action = request.form.get("action")  # signing up OR logging in 

    

        if action == "signup":
            if User.query.filter_by(username=username).first():
                return jsonify({"message": "Username already exists."}), 400

            hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            

            return jsonify({"message": "Signup successful. You may now log in."}), 201

        elif action == "login":
            user = User.query.filter_by(username=username).first()
            if user and bcrypt.check_password_hash(user.password, password):
                session["username"] = username  
                return jsonify({"redirect": url_for('chat')}), 200

            return jsonify({"message": "Invalid username and/or password."}), 401

    return render_template("index.html")


@app.route("/chat")
def chat():
    ## Temp start
    username = session.get("username")

    if username is None:
        return redirect(url_for("home"))
    ##  Temp end

    return render_template("chat.html", username=username)


#Get chat history based on chat_id
@app.route("/chat/<chat_id>", methods=["GET"])
def get_chat(chat_id):
    chat_file = f"{chat_logs_dir}/chat_{chat_id}.txt"
    if os.path.exists(chat_file):
        with open(chat_file, "r") as f:
            chat_logs = f.readlines()
        return jsonify({"chat_logs": chat_logs})
    return jsonify({"chat_logs": []})

#Creating a new group
@app.route("/create_group", methods=["POST"])
def create_group():
    data = request.json
    group_name = data.get("group_name")
    members = data.get("members")

    if not group_name or not members:
        return jsonify({"error": "Group name and members required"}), 400

    chat_id = f"group_{group_name}"
    GROUP_CHATS[chat_id] = members

    return jsonify({"chat_id": chat_id, "members": members})


@app.route("/leave")
def leave_room():
    session.pop("username", None) #Remove username from session
    return redirect(url_for("home"))


#Broadcast messages to all connected users
async def broadcast_message(sender, message, chat_id):
    print("Inside broadcast_message")

    current_time = time.time()

    #Check if user is muted
    if sender in MUTED_USERS and current_time < MUTED_USERS[sender]:
        print(f"{sender} is muted, message ignored.")
        return  #Ignore muted user's message
    
    #Check if user is muted
    if sender in MUTED_USERS:
        mute_expiry = MUTED_USERS[sender]
        if current_time < mute_expiry:
            return  #Ignore muted user's message
        else:
            del MUTED_USERS[sender]  #Unmute the user after MUTE_DURATION
    
    #Initialize user history
    if sender not in USER_MESSAGE_TIMESTAMPS:
        USER_MESSAGE_TIMESTAMPS[sender] = []
    
    #Remove timestamps outside the TIME_FRAME
    USER_MESSAGE_TIMESTAMPS[sender] = [
        ts for ts in USER_MESSAGE_TIMESTAMPS[sender] if current_time - ts < TIME_FRAME
    ]

    #rate limit 
    if len(USER_MESSAGE_TIMESTAMPS[sender]) >= MESSAGE_RATE_LIMIT:
        if sender not in MUTED_USERS:  #Add to MUTED_USERS & send warning msg
            print(f"Rate limit exceeded for {sender}. Warning sent. Muting for {MUTE_DURATION} seconds.")
            await CONNECTED_CLIENTS[sender].send(json.dumps({"error": "RATE LIMIT EXCEEDED. PLEASE WAIT FOR 10 SECONDS."}))
            MUTED_USERS[sender] = current_time + MUTE_DURATION  # Mute user for 10 sec
            return  #Ignore message
    
    # Adds a timestamp and send message
    USER_MESSAGE_TIMESTAMPS[sender].append(current_time)

    log_message(chat_id, sender, message)

    # Broadcast the message to all chat members
    if chat_id.startswith("group"):
        for user in GROUP_CHATS[chat_id]:
            try:
                if user in CONNECTED_CLIENTS:
                    await CONNECTED_CLIENTS[user].send(json.dumps({"chat_id": chat_id, "sender": sender, "message": message}))
            
            except websockets.exceptions.ConnectionClosed:
                continue  #Ignore disconnected WebSocket
    else:   
        for user in chat_id.split("_"):
            try:
                if user in CONNECTED_CLIENTS:
                    await CONNECTED_CLIENTS[user].send(json.dumps({"chat_id": chat_id, "sender": sender, "message": message}))
            
            except websockets.exceptions.ConnectionClosed:
                continue  #Ignore disconnected WebSocket


# Notify all clients about the updated user list
async def notify_user_list():
    users = list(CONNECTED_CLIENTS.keys())
    for ws in CONNECTED_CLIENTS.values():
        await ws.send(json.dumps({"user_list": users}))


#Handler for websocket connections & message listening
async def websocket_server(websocket):
    username = None
    try:
        #Expecting the first message to be the username
        print("Inside websocket_server")
        data = await websocket.recv()
        user_data = json.loads(data)
        username = user_data.get("username")

        # Run database queries inside app context
        with app.app_context():
            registered_users = [user.username for user in User.query.all()]

        ## ensures users must be registered/logged in before accessing chat
        if username not in registered_users:
            await websocket.send(json.dumps({"error": "Unauthorized access. Disconnecting..."}))
            return
        
        
        CONNECTED_CLIENTS[username] = websocket
        await notify_user_list()

        async for message in websocket:
            message_data = json.loads(message)
            sender = message_data["sender"]
            chat_id = message_data["chat_id"]
            msg_text = message_data["message"]
            await broadcast_message(sender,msg_text,chat_id)

    except websockets.exceptions.ConnectionClosed:
        print(f"Connection closed for {username}")

    finally:
        #Remove user on disconnect
        if username in CONNECTED_CLIENTS:
            print(f"{username} User diconnected")
            del CONNECTED_CLIENTS[username]
            await notify_user_list()


#Starting the websocket server inside the event loop
async def start_websocket_server():
    async with websockets.serve(
        websocket_server, 
        "0.0.0.0", 
        8765, 
        ssl = SSL_CONTEXT, 
        ping_interval = HEARTBEAT_INTERVAL, 
        ping_timeout = HEARTBEAT_TIMEOUT):
        print("Secure WebSocket server started with (wss://)")
        await asyncio.Future() #Keeps the server running indefinitely


if __name__ == '__main__':
    #Starting Flask in main thread with SSL
    flask_thread = threading.Thread(
        target=lambda: app.run(host= "0.0.0.0", port=5000, ssl_context=(SSL_CERT_PATH, SSL_KEY_PATH), use_reloader=False),daemon=True)
    flask_thread.start()

    #Running WebSocket server in the main event loop
    asyncio.run(start_websocket_server())