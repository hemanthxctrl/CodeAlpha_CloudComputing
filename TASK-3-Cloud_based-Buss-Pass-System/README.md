# ☁️ Cloud-Based Buss-Pass-System 🚌


A fully cloud-hosted online bus ticket and pass booking system built with Python Flask, MongoDB, and deployed on AWS EC2. Prevents ticket loss and theft using QR code-based digital passes, with dynamic server provisioning to handle high traffic.


# Features📸 

🔐 Secure Authentication — JWT-based login/register with bcrypt password hashing

🎫 Pass Booking — Daily, Weekly, Monthly, Yearly passes with instant pricing

📱 QR Code Generation — Every pass gets a unique scannable QR code

📋 Pass Management — View all passes with active/expired status

☁️ Cloud Hosted — Deployed on AWS EC2 with Auto Scaling for high traffic

🛡️ Security — Input validation, JWT protection, AWS Security Groups


 # System Architecture


```
                +------------------+
                |      Users       |
                |     (Browser)    |
                +---------+--------+
                          |
                          | HTTPS Requests
                          ▼
                +----------------------+
                |      AWS EC2         |
                |   Flask Application  |
                +----------+-----------+
                           |
        +------------------+------------------+
        |                  |                  |
        ▼                  ▼                  ▼
+---------------+   +---------------+   +---------------+
| Auth Module   |   | Booking API   |   | Validation    |
| JWT + bcrypt  |   | Pass + QRCode |   | Routes/Pricing|
+---------------+   +---------------+   +---------------+
                           |
                           ▼
                   +---------------+
                   |    PyMongo    |
                   +-------+-------+
                           |
                           ▼
                   +---------------+
                   |   MongoDB     |
                   +---------------+
                   | users         |
                   | bookings      |
                   | routes        |
                   +---------------+
                           |
                           ▼
                   +---------------+
                   |  AWS Services |
                   +---------------+
                   | EC2 AutoScale |
                   | S3 Storage    |
                   | IAM / SG      |
                   +---------------+
```



## 🛠️ Tech Stack

| Layer | Technology |
|------|-------------|
| **Backend** | Python 3.11, Flask 3.0 |
| **Frontend** | HTML5, CSS3, JavaScript (Vanilla) |
| **Database** | MongoDB 7.x |
| **Authentication** | Flask-JWT-Extended, bcrypt |
| **QR Code Generation** | qrcode + Pillow |
| **Cloud Infrastructure** | AWS EC2 (t2.micro), AWS S3 |
| **Version Control** | Git + GitHub |



# Project Structure📁 


```
├── 📁 Cloud-Buss-Pass
│   └── 📁 app
│       ├── 📁 models
│       │   ├── 🐍 booking.py          # Booking logic + QR generation
│       │   └── 🐍 user.py             # User CRUD + password hashing
|       |
│       ├── 📁 routes
│       │   └── 🐍 auth.py             # /api/auth/register, /api/auth/login
|       |   └── 🐍 bookings.py         # /api/booking/book, /api/booking/my-passes
|       |
│       ├── 📁 static
│       │   └── 📁 images
│       │       └── 📁 qr_codes        # Generated QR code images
|       |
│       ├── 📁 templates
│       │   ├── 🌐 book_pass.html
│       │   ├── 🌐 dashboard.html
│       │   ├── 🌐 login.html
│       │   ├── 🌐 register.html
│       │   └── 🌐 view_pass.html
│       ├── 🐍 __init__.py              # App factory, DB init, blueprints
│       └── 🐍 config.py                # Configuration (env vars)
|
├── 🐍 run.py                           # App entry point
├── 📄 requirements.txt
└── 📝 README.md
``` 


# Developed by:

- Hemanth Sreenivas
- CodeAlpha Virtual Internship
- Cloud Computing
- Task 3 —Cloud-Based Buss-Pass-System 

---

*Built and deployed on AWS as part of CodeAlpha Cloud Computing Virtual Internship*
