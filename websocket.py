from flask import Flask, render_template, request, redirect, session, url_for, jsonify
import asyncio, websockets, threading, os, time, sys, ssl 
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt


CONNECTED_CLIENTS = {}
HEARTBEAT_INTERVAL = 10
HEARTBEAT_TIMEOUT = 5

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


SSL_CERT_PATH = os.getenv("SSL_CERT_PATH", "your_cert.pem") 
SSL_KEY_PATH = os.getenv("SSL_KEY_PATH", "your_key.pem")     

if not os.path.exists(SSL_CERT_PATH) or not os.path.exists(SSL_KEY_PATH):
    print("\n SSL Certificate and Key not found. ")
    print("Please use the instructions in README.md to create SSL cert before running the server.\n")
    sys.exit(1) 

SSL_CONTEXT = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
SSL_CONTEXT.load_cert_chain(certfile=SSL_CERT_PATH, keyfile=SSL_KEY_PATH)

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
                session["username"] = username  # Store username in session
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


@app.route("/leave")
def leave_room():
    session.pop("username", None) #Remove username from session
    return redirect(url_for("home"))

USER_MESSAGE_TIMESTAMPS = {} 
MESSAGE_RATE_LIMIT = 5  # of msgs
TIME_FRAME = 10  #seconds

#Broadcast messages to all connected users except the sender.
async def broadcast_message(sender, message):
    print("Inside broadcast_message")

    current_time = time.time()
    if sender not in USER_MESSAGE_TIMESTAMPS:
        USER_MESSAGE_TIMESTAMPS[sender] = []
    
    # Remove old messages beyond TIME_FRAME
    USER_MESSAGE_TIMESTAMPS[sender] = [
        ts for ts in USER_MESSAGE_TIMESTAMPS[sender] if current_time - ts < TIME_FRAME
    ]
    #rate limit 
    if len(USER_MESSAGE_TIMESTAMPS[sender]) >= MESSAGE_RATE_LIMIT:
        print(f"Rate limit exceeded for {sender}")
        await CONNECTED_CLIENTS[sender].send("Rate limit exceeded. Please wait before sending more messages.")
        return
    
    # Adds a timestamp and send message
    USER_MESSAGE_TIMESTAMPS[sender].append(current_time)
    
    for connection in CONNECTED_CLIENTS.values():
        try:
            print("Sending message to broadcast_message")
            await connection.send(f"{sender}: {message}")

        except websockets.exceptions.ConnectionClosed:
            continue  #Continue when sending a message to a disconnected WebSocket


#Handler for websocket connections & message listening
async def websocket_server(websocket):
    try:
        #Expecting the first message to be the username
        print("Inside websocket_server")
        username = await websocket.recv()
        
         # Run database queries inside app context
        with app.app_context():
            registered_users = [user.username for user in User.query.all()]

            ## ensures users must be registered/logged in before accessing chat
        if username not in registered_users:
            await websocket.send("Unauthorized access. Disconnecting...")
            return
        
        
        CONNECTED_CLIENTS[username] = websocket
        print("Connected Clients :", CONNECTED_CLIENTS.keys())
        join_msg = f"{username} has joined the chat!"
        await broadcast_message(username,join_msg)

        async for message in websocket:
            await broadcast_message(username,message)

    except websockets.exceptions.ConnectionClosed:
        print(f"Connection closed for {username}")

    finally:
        #Remove user on disconnect
        if username in CONNECTED_CLIENTS:
            print(f"{username} User diconnected")
            del CONNECTED_CLIENTS[username]
            left_msg = f"{username} has left the chat!"
            await broadcast_message(username,left_msg)

#Starting the websocket server inside the event loop
async def start_websocket_server():
    async with websockets.serve(
        websocket_server, 
        "localhost", 
        8765, 
        ssl = SSL_CONTEXT, 
        ping_interval = HEARTBEAT_INTERVAL, 
        ping_timeout = HEARTBEAT_TIMEOUT):
        print("Secure WebSocket server started with (wss://)")
        await asyncio.Future() #Keeps the server running indefinitely


def run_flask():
    # Running Flask in a separate thread with SSL
    app.run(debug=True, port=5000, ssl_context=(SSL_CERT_PATH, SSL_KEY_PATH))



if __name__ == '__main__':
    #Starting Flask in main thread with SSL
    flask_thread = threading.Thread(
        target=lambda: app.run(port=5000, ssl_context=(SSL_CERT_PATH, SSL_KEY_PATH), use_reloader=False),daemon=True)
    flask_thread.start()

    #Running WebSocket server in the main event loop
    asyncio.run(start_websocket_server())