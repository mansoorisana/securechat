from flask import Flask, render_template, request, redirect, session, url_for
import asyncio, websockets, threading, os
from dotenv import load_dotenv

CONNECTED_CLIENTS = {}
HEARTBEAT_INTERVAL = 10
HEARTBEAT_TIMEOUT = 5

#Loading environment variables from .env file
load_dotenv()

#Initializing flask app
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "fallback@secret!")


@app.route("/home", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        username = request.form.get("name")
        chat = request.form.get("join", False)
        if chat!= False:
            session["username"] = username
            return redirect(url_for("chat"))

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


#Broadcast messages to all connected users except the sender.
async def broadcast_message(sender, message):
    print("Inside broadcast_message")
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
    async with websockets.serve(websocket_server, "localhost", 8765, ping_interval=HEARTBEAT_INTERVAL, ping_timeout=HEARTBEAT_TIMEOUT):
        print("WebSocket server started")
        await asyncio.Future() #Keeps the server running indefinitely


def run_flask():
    #Running Flask in a separate thread
    app.run(debug=True, port=5000, use_reloader=False)


if __name__ == '__main__':
    #Starting Flask in a separate thread
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()

    #Running WebSocket server in the main event loop
    asyncio.run(start_websocket_server())