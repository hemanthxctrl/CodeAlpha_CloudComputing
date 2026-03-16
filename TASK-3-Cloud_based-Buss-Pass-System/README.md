# ☁️ Cloud-Based Buss-Pass-System 🚌


A fully cloud-hosted online bus ticket and pass booking system built with Python Flask, MongoDB, and deployed on AWS EC2. Prevents ticket loss and theft using QR code-based digital passes, with dynamic server provisioning to handle high traffic.


# Features📸 

🔐 Secure Authentication — JWT-based login/register with bcrypt password hashing
🎫 Pass Booking — Daily, Weekly, Monthly, Yearly passes with instant pricing
📱 QR Code Generation — Every pass gets a unique scannable QR code
📋 Pass Management — View all passes with active/expired status
☁️ Cloud Hosted — Deployed on AWS EC2 with Auto Scaling for high traffic
🛡️ Security — Input validation, JWT protection, AWS Security Groups


 # Architecture
 Users (Browser)
      │
      ▼ HTTPS
AWS EC2 — Flask App (Python)
  ├── Auth Module  (JWT + bcrypt)
  ├── Booking API  (Pass + QR Code)
  ├── Validation   (Pricing + Routes)
      │
      ▼ PyMongo
MongoDB Database
  ├── users
  ├── bookings
  ├── routes
      │
      ▼
AWS Services
  ├── EC2 Auto Scaling
  ├── S3 (Static Assets)
  └── Security Groups / IAM


# Tech Stack🛠️ 

LayerTechnologyBackendPython 3.11, Flask 3.0FrontendHTML5, CSS3, JavaScript (Vanilla)DatabaseMongoDB 7.xAuthenticationFlask-JWT-Extended, bcryptQR Codesqrcode + PillowCloudAWS EC2 (t2.micro), S3Version ControlGit + GitHub

# Project Structure📁 


```
├── 📁 Cloud-Buss-Pass
│   └── 📁 app
│       ├── 📁 models
│       │   ├── 🐍 booking.py
│       │   └── 🐍 user.py
│       ├── 📁 routes
│       │   └── 🐍 auth.py
│       ├── 📁 static
│       │   └── 📁 images
│       │       └── 📁 qr_codes
│       ├── 📁 templates
│       │   ├── 🌐 book_pass.html
│       │   ├── 🌐 dashboard.html
│       │   ├── 🌐 login.html
│       │   ├── 🌐 register.html
│       │   └── 🌐 view_pass.html
│       ├── 🐍 __init__.py
│       └── 🐍 config.py
├── 📝 README.md
├── 📄 requirements.txt
└── 🐍 run.py
```


# Developed by:

- Hemanth Sreenivas
- CodeAlpha Virtual Internship
- Cloud Computing
- Task 3 —Cloud-Based Buss-Pass-System 

---

*Built and deployed on AWS as part of CodeAlpha Cloud Computing Virtual Internship*
