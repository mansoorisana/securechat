# SecureChat  

SecureChat is a real-time chat application built using **FastAPI** and **WebSockets**.  
It enables multiple users to connect, send messages, files instantly, and handle connections securely.  

---

## 📌 Technologies Used  

- **FastAPI** – Handles the web interface and user session management.  
- **WebSockets** – Enables real-time communication between users.
- **HTML/CSS/Javascript** - Acts as the websocket client.
- **Flask-SQLAlchemy** – Manages user database and authentication.
- **Flask-Bcrypt** – Securely hashes user passwords.
- **SSL/TLS Encryption** – Secures WebSocket communication.
- **SQLite** – Lightweight database for user authentication.
- **Quill Editor & Emoji Picker** - Provides rich text formatting and emoji support.

- **Render** - Hosting FastAPI, templates and Websocket server.
- **PostgreSQL** - Database storage service offered on Render.
- **UptimeRobot** - Uptime monitoring service.
- **VirusTotal** - Scanning file uplaod for malware.
- **Firebase** - Hosting uploaded files for each chat.


---

## 📌 Installation  

### **1️⃣ Install Python (if not already installed)**  
Ensure you have Python **3.8 or later** installed. If not, download it from:  
🔗 [Python Official Website](https://www.python.org/downloads/)  

### **2️⃣ Install Required Dependencies**  
Run the following command in the project directory:  
```bash
pip install -r requirements.txt
```

### **3️⃣ Create the .env File**
In the same folder as websocket.py, create a new file named .env and add:
```bash
SECRET_KEY=your-secure-random-key
```
Replace 'your-secure-random-key' with a randomly generated secure key.

### **4️⃣ Generate SSL Certificates (Self-Signed)**
SecureChat requires an SSL certificate to enable **encrypted WebSocket (wss://) communication**.

Running the following command will create an SSL certificate and key with default filenames:

```bash
openssl req -x509 -newkey rsa:4096 -keyout your_key.pem -out your_cert.pem -days 365 -nodes
```

### **⚠️Custom SSL Certificate Names(Only if neccessary)**
If you used different filenames for your cetificate and private key, add them to an .env file:

```bash
SSL_CERT_PATH=your_custom_cert.pem
SSL_KEY_PATH=your_custom_key.pem
```
Replace your_custom_cert.pem and your_custom_key.pem with your actual variable names.


### **5️⃣ Run the Application**
Start the Flask and WebSocket server with:
```bash
python websocket.py
```

The application will be available at:
🔗 https://localhost:5000/home

### **NOTE: SERVER DEPLOYMENT ON CLOUD**
The server was hosted on cloud using Amazon EC2 and was available at below IP. 
The application was available at: 🔗 https://3.148.186.254:5000/home 
The WebSocket server ran at: 🔗 wss://3.148.186.254:8765/ 

This is demonstrated in video recordings. The instance is now deleted due to uncertainty regarding duration of hosting the server & costs of using the cloud service. Refer below screenshot for server setup:

![EC2 instance log](images/ssh.png?raw=true)

![Server Files](images/ftp.png?raw=true)

---

## 📌 Features

### **1️⃣ User Authentication** 
- Users must **sign up** before logging in.  
- Passwords are securely hashed with **Flask-Bcrypt**.  
- Only authenticated users can participate in the chat.
- Equipped with brute-force protection 

### **2️⃣ Secure Communication & Real-Time Messaging**  
- **SSL/TLS Encryption** ensures all WebSocket messages are protected.  
- Uses **wss://**  for secure communication.
- Messages are broadcast to all connected users in real-time. 

### **3️⃣ Connection Handling**
- New users can create/join **private** & **group chats** upon connecting.
- Enable chat with all connected users with a default **general chat** room.
- Users can leave the app.
- Users are reconnected in case of interruptions.
- Heartbeat mechanism to maintain persistent connections.

### **4️⃣ Server & Database Deployment**  


### **5️⃣ Rate Limiting & 24/7 Uptime Strategy**  
- Prevents spamming by **limiting messages per user** & **login** requests.  
- **UptimeRobot** is used to ping backend and ensure it's online

### **6️⃣ User Friendly GUI & Online/Offline Presence Management**  
- Provides list of online users to select from for **private** and **group** chat.
- Users can view and select their **active chats**.
- Seamlessly **switch** between conversations without leaving the application with session chat history.
- User lists shows green and red dot for each user to indicate **online** and **offline** presence.
- Current open chat shows **typing** indicators for the user who is typing in the chat.

### **7️⃣ Secure File Sharing (Cloud Friendly)**
- All chats have file **upload/download** options.
- File uploads are first scanned with **VirusTotal** APIs for **malware** before transmission at client-side 
- Files are **encrypted** before upload to cloud storage & decrypted upon download.
- Uploaded files are hosted on **Firebase** per chat id.
- Custom Auth token is issued to the authenticated user upon login to the server for Firebase Authentication. The user is signed out from Firebase after logging out from the chat page. 
- Firebase bucket rule allows read & write only from authenticated users.

### **8️⃣ Emoji & Rich Media Support**  
- Send **emojis** in chat with the Unicode emoji picker.
- Text formatting features such as **bold, italics, underline, strikethrough, headings, superscript/subscript, bullets/numbering list, change font color & text highlight**.

### **9️⃣ Session Based Logging**  
-  Each session of user conversation is logged with timestamp in txt format in logs folder of the root directory. Example **chat_general_chat_session_2025-03-20_07-44-57**.
- Blobs stored on the server are encrypted. The server cannot decrypt messages.

### **🔟 End-to-end encryption**  
- Chat messages are end-to-end encrypted.
- ECDH (Elliptic Curve Diffie-Hellman) is used for key exchange and AES-GCM for message encryption
- **Private chats:** Each user generates an ECDH key pair. The sender and receiver exchange public keys to derive a shared symmetric key, which is used to encrypt and decrypt messages.
- **Group Chats:** A group symmetric key is encrypted with each recipient's public key and shared with the group. Each recipient then uses their private key to decrypt the group key and can encrypt/decrypt messages using it.
- **File Encryption:** Files are encrypted before being uploaded to Firebase using AES-GCM and are only accessible by the intended recipient(s) after decryption.
---

## 📌 Project Structure
```bash
/SecureChat
│── main.py                     # Main Python server file
│── requirements.txt            # Dependency list
│── .env.example                # Example .env file (without actual secrets)
│── .gitignore                  # Ensures sensitive files are not pushed to Git
│── /client                  # HTML templates
│   ├── index.html              # Signup/Login page
│   ├── chat.html               # Chat interface
│   ├── base.html               # Base html file
│   ├──/static/css              # CSS files
│      ├── style.css               # Styling for UI
│── README.md                   # Instructions for running the project
│── Dockerfile                  # For docker image
│── render.yaml                 # Render deployment file
│── User Guide - Group 23.pdf   # User Guide for setup & running the project
```