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
- **Flask-Limiter** – Prevents spamming with rate limiting.
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

---

## 📌 Features

### **1️⃣ User Authentication  
- Users must **sign up** before logging in.  
- Passwords are securely hashed with **Flask-Bcrypt**.  
- Only authenticated users can participate in the chat. 

### **2️⃣ Real-Time Messaging  
- Uses **WebSockets** for instant communication.  
- Messages are broadcast to all connected users in real-time. 

### **2️⃣ Connection Handling**  
- New users can Join the chat room & receive a "joined the chat" message upon connecting.
- Users can leave the room & trigger a "left the chat" message.
- Users are reconnected in case of interruptions.

### **4️⃣ Secure Communication  
- **SSL/TLS Encryption** ensures all WebSocket messages are protected.  
- Uses **wss://**  for secure communication.  

### **5️⃣ Rate Limiting  
- Prevents spamming by **limiting messages per user**.  
- Uses **Flask-Limiter** to restrict **max messages per minute**.  
---

## 📌 Project Structure
```bash
/SecureChat
│── websocket.py       # Main Python server file
│── requirements.txt   # Dependency list
│── .env.example       # Example .env file (without actual secrets)
│── .gitignore         # Ensures sensitive files are not pushed to Git
│── /templates         # HTML templates
│   ├── index.html     # Signup/Login page
│   ├── chat.html      # Chat interface
│── /static/css        # CSS files
│   ├── style.css      # Styling for UI
│── README.md          # Instructions for running the project
```


