# SecureChat  

SecureChat is a real-time chat application built using **Flask** and **WebSockets**.  
It enables multiple users to connect, send messages instantly, and handle connections securely.  

---

## 📌 Technologies Used  

- **Flask** – Handles the web interface and user session management.  
- **WebSockets** – Enables real-time communication between users.
- **HTML/CSS/Javascript** - Acts as the websocket client.
- **Flask-SQLAlchemy** – Manages user database and authentication.
- **Flask-Bcrypt** – Securely hashes user passwords.
- **SSL/TLS Encryption** – Secures WebSocket communication.
- **SQLite** – Lightweight database for user authentication.
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

### **2️⃣ Real-Time Messaging**  
- Uses **WebSockets** for instant communication.  
- Messages are broadcast to all connected users in real-time. 

### **3️⃣ Connection Handling**
- New users can create/join **private** & **group chats** upon connecting.
- Enable chat with all connected users with a default **general chat** room.
- Users can leave the app.
- Users are reconnected in case of interruptions & messages are redelivered when the user was offline.

### **4️⃣ Secure Communication**  
- **SSL/TLS Encryption** ensures all WebSocket messages are protected.  
- Uses **wss://**  for secure communication.  

### **5️⃣ Rate Limiting**  
- Prevents spamming by **limiting messages per user**.  

### **6️⃣ User Friendly GUI**  
- Provides list of online users to select from for **private** and **group** chat.
- Users can view and select their **active chats**.
- Seamlessly **switch** between conversations without leaving the application with session chat history.

### **7️⃣ File Sharing**  
- Securely transfer text files with encryption.  

### **8️⃣ Emoji & Rich Media Support**  
- Send **emojis** in chat with the Unicode emoji picker.
- Text formatting features such as **bold, italics, underline, strikethrough, headings, superscript/subscript, bullets/numbering list, change font color & text highlight**.

### **9️⃣ Session Based Logging**  
-  Each session of user conversation is logged with timestamp in txt format in logs folder of the root directory. Example **chat_general_chat_session_2025-03-20_07-44-57**.

### **🔟 End-to-end message encryption**  
- Chat messages are end-to-end encrypted.

---

## 📌 Project Structure
```bash
/SecureChat
│── websocket.py                # Main Python server file
│── requirements.txt            # Dependency list
│── .env.example                # Example .env file (without actual secrets)
│── .gitignore                  # Ensures sensitive files are not pushed to Git
│── /templates                  # HTML templates
│   ├── index.html              # Signup/Login page
│   ├── chat.html               # Chat interface
│── /static/css                 # CSS files
│   ├── style.css               # Styling for UI
│── README.md                   # Instructions for running the project
│── User Guide - Group 23.pdf   # User Guide for setup & running the project
```