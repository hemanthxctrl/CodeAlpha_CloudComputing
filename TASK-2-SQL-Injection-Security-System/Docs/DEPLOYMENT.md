# 🚀 Deployment Guide — Step by Step AWS Setup

This guide walks you through the complete AWS deployment.
Estimated time: 30–45 minutes.

---

## PHASE 1: AWS RDS (Database Setup)

### Step 1.1 — Create RDS Instance
1. Go to **AWS Console → RDS → Create Database**
2. Select:
   - Engine: **MySQL**
   - Template: **Free tier**
   - DB instance identifier: `sqli-detector-db`
   - Master username: `admin`
   - Master password: (create a strong password, save it!)
   - DB instance class: `db.t3.micro` (free tier)
   - Storage: 20 GB GP2
3. Under **Connectivity**:
   - VPC: Default
   - Public access: **Yes** (for now — restrict to EC2 later)
   - Security group: Create new → name it `sqli-db-sg`
4. Click **Create Database** → wait 5–10 minutes

### Step 1.2 — Configure RDS Security Group
1. Find your new RDS instance → click its **Security group**
2. Edit **Inbound rules** → Add rule:
   - Type: MySQL/Aurora
   - Port: 3306
   - Source: Your EC2 security group (add after creating EC2)
   - For testing: `0.0.0.0/0` temporarily

### Step 1.3 — Note Your RDS Endpoint
- In RDS console, find your instance
- Copy the **Endpoint** (looks like: `sqli-detector-db.xxxx.us-east-1.rds.amazonaws.com`)
- You'll need this in your `.env` file

---

## PHASE 2: AWS EC2 (Server Setup)

### Step 2.1 — Launch EC2 Instance
1. Go to **AWS Console → EC2 → Launch Instance**
2. Configure:
   - Name: `sqli-detector-server`
   - AMI: **Ubuntu Server 22.04 LTS** (Free tier eligible)
   - Instance type: `t2.micro` (free tier)
   - Key pair: Create new → download `.pem` file → **KEEP THIS SAFE**
   - Security group → Add rules:
     - SSH: Port 22 → My IP
     - HTTP: Port 80 → Anywhere (0.0.0.0/0)
     - Custom TCP: Port 5000 → Anywhere (for testing)
3. Click **Launch Instance**

### Step 2.2 — Connect to EC2
```bash
# On your local machine (Mac/Linux):
chmod 400 your-key.pem
ssh -i your-key.pem ubuntu@YOUR_EC2_PUBLIC_IP

# On Windows: Use PuTTY or Windows Terminal with .pem
```

### Step 2.3 — Upload Your Project to EC2
```bash
# From your local machine (different terminal):
scp -i your-key.pem -r sql-injection-detector/ ubuntu@YOUR_EC2_IP:/opt/sqlidetector/
```

OR clone from GitHub (after you push):
```bash
# On EC2:
sudo git clone https://github.com/YOUR_USERNAME/sql-injection-detector /opt/sqlidetector
```

---

## PHASE 3: Configure the App on EC2

### Step 3.1 — Run Setup Script
```bash
# On EC2:
cd /opt/sqlidetector
sudo chmod +x infrastructure/setup_aws.sh
sudo ./infrastructure/setup_aws.sh
```

### Step 3.2 — Edit Environment Variables
```bash
sudo nano /opt/sqlidetector/.env
```
Fill in:
```
FLASK_ENV=production
FLASK_SECRET=generate-with-python-secrets.token_hex(32)
SECRET_KEY=another-long-random-string
CAPABILITY_SECRET=yet-another-secret
DB_HOST=YOUR_RDS_ENDPOINT_FROM_PHASE_1
DB_PORT=3306
DB_NAME=security_db
DB_USER=admin
DB_PASSWORD=YOUR_RDS_PASSWORD
PORT=5000
```

### Step 3.3 — Initialize the Database
```bash
# On EC2 (install MySQL client first):
sudo apt-get install -y mysql-client

# Run schema:
mysql -h YOUR_RDS_ENDPOINT -u admin -p security_db < /opt/sqlidetector/database/schema.sql
# Enter your RDS password when prompted
```

### Step 3.4 — Create Admin User
```bash
cd /opt/sqlidetector/backend
source ../venv/bin/activate
python3 -c "
from encryption import hash_password, AESCipher
c = AESCipher()
print('Password hash:', hash_password('Admin@1234'))
print('Encrypted email:', c.encrypt('admin@yoursite.com'))
"
```
Copy the outputs and update the seed in `database/schema.sql`, then re-run the schema.

### Step 3.5 — Start the Application
```bash
sudo systemctl start sqlidetector
sudo systemctl status sqlidetector
# Should show: Active (running)
```

---

## PHASE 4: Test Your Deployment

### Step 4.1 — Visit Your Site
Open browser: `http://YOUR_EC2_PUBLIC_IP`

You should see the SecureAuth login page!

### Step 4.2 — Test SQL Injection Detection
1. In the login form, type: `' OR '1'='1` in username
2. Click Login
3. You should see: **🚫 SQL Injection Detected!**

### Step 4.3 — View Attack Logs
```bash
# On EC2:
tail -f /opt/sqlidetector/backend/attack.log
```

### Step 4.4 — Check Application Logs
```bash
sudo journalctl -u sqlidetector -f
```

---

## PHASE 5: Push to GitHub

### Step 5.1 — Initialize Git Repository
```bash
# On your LOCAL machine (not EC2):
cd sql-injection-detector
git init
git add .
git commit -m "Initial commit: SQL Injection Detection System - CodeAlpha Task 2"
```

### Step 5.2 — Create GitHub Repository
1. Go to github.com → New Repository
2. Name: `sql-injection-detector`
3. Description: `CodeAlpha Cloud Computing Internship - Task 2: SQL Injection Detection with AES-256 encryption on AWS`
4. Public repository
5. Don't initialize with README (we have one)

### Step 5.3 — Push Code
```bash
git remote add origin https://github.com/YOUR_USERNAME/sql-injection-detector.git
git branch -M main
git push -u origin main
```

### Step 5.4 — Add Screenshots
1. Take screenshots following `docs/SCREENSHOTS_GUIDE.md`
2. Add to `docs/screenshots/` folder
3. Commit and push:
```bash
git add docs/screenshots/
git commit -m "Add deployment screenshots"
git push
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| App won't start | `journalctl -u sqlidetector -n 50` to see errors |
| Can't connect to RDS | Check RDS security group inbound rules |
| Port 80 not accessible | Check EC2 security group — allow HTTP |
| Import errors | Run `pip install -r requirements.txt` in venv |
| DB connection refused | Verify `DB_HOST` in `.env` matches RDS endpoint |

---

## ✅ Deployment Checklist

- [ ] RDS instance created and running
- [ ] EC2 instance launched (t2.micro, Ubuntu 22.04)
- [ ] Project uploaded to EC2
- [ ] Setup script ran successfully
- [ ] `.env` file configured with real credentials
- [ ] Database schema applied
- [ ] Admin user created
- [ ] App running (`systemctl status sqlidetector`)
- [ ] Login page visible at EC2 public IP
- [ ] SQL injection detection tested and working
- [ ] Attack logs visible in dashboard
- [ ] Screenshots taken
- [ ] Code pushed to GitHub