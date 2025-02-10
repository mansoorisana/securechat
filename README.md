# SecureChat  

SecureChat is a real-time chat application built using **Flask** and **WebSockets**.  
It enables multiple users to connect, send messages instantly, and handle connections securely.  

---

## 📌 Technologies Used  

- **Flask** – Handles the web interface and user session management.  
- **WebSockets** – Enables real-time communication between users.
- **HTML/CSS/Javascript** - Acts as the websocket client.

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
Replace 'your-secure-random-key' with a random secret key

### **4️⃣ Run the Application**
Start the Flask and WebSocket server with:
```bash
python websocket.py
```

The application will be available at:
🔗 http://localhost:5000/home

---

## 📌 Features

### **1️⃣ Real-Time Messaging**
Uses WebSockets for instant communication.
Messages are broadcast to all connected users in real time.

### **2️⃣ Connection Handling**  
New users can Join chat room & receive a "joined the chat" message upon connecting.
Users can leave the room & trigger a "left the chat" message.
Users are reconnected in case of interruptions.
Only authenticated users can participate in the chat.

---

## 📌 Project Structure
```bash
/SecureChat
│── websocket.py  # Main Python server file
│── requirements.txt  # Dependency list
│── .env.example  # Example .env file (without actual secrets)
│── /templates  # HTML files
│   ├── index.html
│   ├── chat.html
│── /static/css  # CSS files
│   ├── style.css
│── README.md  # Instructions for running the project