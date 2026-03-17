# ☁️ Cloud-Based Buss-Pass-System 🚌

A cloud-hosted online bus ticket and pass booking system built using Python Flask, MongoDB, and AWS EC2.


The system prevents ticket loss and theft using QR code–based digital passes and supports scalable cloud infrastructure to handle high traffic.


# Features📸 

🔐 Secure Authentication — JWT-based login/register with bcrypt password hashing

🎫 Pass Booking — Daily, Weekly, Monthly, Yearly passes with instant pricing

📱 QR Code Generation — Every pass gets a unique scannable QR code

📋 Pass Management — View all passes with active/expired status

☁️ Cloud Hosted — Deployed on AWS EC2 with Auto Scaling for high traffic

🛡️ Security — Input validation, JWT protection, AWS Security Groups

## 📸 Screenshots

### Login Page
![Login](/TASK-3-Cloud_based-Buss-Pass-System/Cloud-Buss-Pass/app/static/images/login_page.png)

### Register
![user](/TASK-3-Cloud_based-Buss-Pass-System/Cloud-Buss-Pass/app/static/images/register.png)

### Dashboard
![Dashboard](/TASK-3-Cloud_based-Buss-Pass-System/Cloud-Buss-Pass/app/static/images/dashboard.png)

### Book Pass
![Book Pass](/TASK-3-Cloud_based-Buss-Pass-System/Cloud-Buss-Pass/app/static/images/booking_success.png)

### View Pass with QR Code
![View Pass](/TASK-3-Cloud_based-Buss-Pass-System/Cloud-Buss-Pass/app/static/images/view_pass_qr.png)

### AWS DynamoDB Tables
![DynamoDB](/TASK-3-Cloud_based-Buss-Pass-System/Cloud-Buss-Pass/app/static/images/dynamo_data.png)

### Dynamo db data
![Dynamo db](/TASK-3-Cloud_based-Buss-Pass-System/Cloud-Buss-Pass/app/static/images/dynamo_data.png)




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


# Quick start (Local Setup)


1️⃣ Clone the Repository

git clone https://github.com/hemanthxctrl/CodeAlpha_CloudComputing.git
cd CodeAlpha_CloudComputing

2️⃣ Install Dependencies

pip install -r requirements.txt

3️⃣ Create Environment Variables

Create a .env file:

MONGO_URI=mongodb://localhost:27017/buspassdb
JWT_SECRET_KEY=your-super-secret-key
SECRET_KEY=another-secret-key
FLASK_ENV=development

4️⃣ Start MongoDB

Windows
net start MongoDB
Linux / Mac
sudo systemctl start mongod

5️⃣ Run the Application

python run.py

Visit:

http://localhost:5000


# API Endpoints


Method	Endpoint	Description	Auth

POST	/api/auth/register	Register new user	❌

POST	/api/auth/login	Login user	❌

POST	/api/booking/book	Book a pass	✅

GET	/api/booking/my-passes	Get user passes	✅

GET	/api/booking/prices	Get pass pricing	❌


## Example: Book a Pass 📌 

curl -X POST http://localhost:5000/api/booking/book \
-H "Authorization: Bearer <your_token>" \
-H "Content-Type: application/json" \
-d '{"passenger_name":"John","pass_type":"monthly","route":"Route 1: City Center - Airport"}'


## Pass Pricing 💰 

Pass Type	Duration	Price
Daily	1 Day	₹30
Weekly	7 Days	₹150
Monthly	30 Days	₹500
Yearly	365 Days	₹5000


#  AWS EC2 Deployment☁️

## Instance Setup

AMI: Ubuntu 22.04 LTS

Instance Type: t2.micro (Free Tier)

## Security Group:

Port 22 (SSH)

Port 80 (HTTP)

Port 5000 (Flask)

## Deploy on EC2

sudo apt update
sudo apt install -y python3-pip python3-venv git

git clone https://github.com/hemanthxctrl/CodeAlpha_CloudComputing.git
cd CodeAlpha_CloudComputing

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
Install MongoDB
sudo apt install -y mongodb
sudo systemctl start mongod
sudo systemctl enable mongod
Run with Gunicorn
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 run:app


# 🔒 Security Features

Passwords hashed using bcrypt

JWT authentication with expiration

Input validation for all APIs

.env secrets excluded from Git

AWS Security Groups restrict access

CORS protection enabled


#   Testing🧪

Register User
curl -X POST http://localhost:5000/api/auth/register \
-H "Content-Type: application/json" \
-d '{"name":"Test User","email":"test@test.com","password":"test123","phone":"9999999999"}'
Login
curl -X POST http://localhost:5000/api/auth/login \
-H "Content-Type: application/json" \
-d '{"email":"test@test.com","password":"test123"}'


#  Scalability Design📊

Challenge	Solution
High Traffic	AWS EC2 Auto Scaling
Ticket Loss	Digital QR Codes
Theft Prevention	JWT Authentication + Unique Pass IDs
Incorrect Pricing	Server-side price validation
Reliability	Cloud hosting infrastructure


#  Future Improvements🚀

Mobile app integration

Payment gateway integration

Real-time bus tracking

Admin dashboard

SMS/Email notifications



# Developed by:

- Hemanth Sreenivas
- GitHub: @hemanthxctrl

---

*Built and deployed on AWS as part of CodeAlpha Cloud Computing Virtual Internship*
