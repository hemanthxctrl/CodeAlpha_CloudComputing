#!/bin/bash
# =============================================================
# setup_aws.sh — One-Script AWS EC2 Setup
# Run this on a fresh Ubuntu 22.04 EC2 instance
#
# WHAT THIS DOES:
# 1. Updates system packages
# 2. Installs Python 3, pip, Nginx
# 3. Installs your app dependencies
# 4. Sets up Gunicorn (production WSGI server)
# 5. Configures Nginx as reverse proxy
# 6. Creates systemd service for auto-restart
#
# HOW TO RUN:
# chmod +x setup_aws.sh
# sudo ./setup_aws.sh
# =============================================================

set -e  # Exit immediately if any command fails

echo "=============================================="
echo "  SQL Injection Detection System - AWS Setup"
echo "=============================================="

# ---- 1. System Updates ----
echo "[1/7] Updating system packages..."
apt-get update -y
apt-get upgrade -y

# ---- 2. Install Dependencies ----
echo "[2/7] Installing Python, Nginx, Git..."
apt-get install -y python3 python3-pip python3-venv nginx git curl

# ---- 3. Clone/Copy Project ----
echo "[3/7] Setting up project directory..."
mkdir -p /opt/sqlidetector
cd /opt/sqlidetector

# If you've already uploaded via SCP, skip clone
# If using GitHub:
# git clone https://github.com/YOUR_USERNAME/sql-injection-detector .

# ---- 4. Python Virtual Environment ----
echo "[4/7] Creating Python virtual environment..."
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r backend/requirements.txt

# ---- 5. Environment Variables ----
echo "[5/7] Creating .env file (EDIT THIS WITH YOUR VALUES)..."
cat > /opt/sqlidetector/.env << 'EOF'
FLASK_ENV=production
FLASK_SECRET=CHANGE_THIS_TO_RANDOM_STRING_64_CHARS
SECRET_KEY=CHANGE_THIS_AES_KEY_VERY_LONG_STRING
CAPABILITY_SECRET=CHANGE_THIS_CAPABILITY_SECRET
DB_HOST=YOUR_RDS_ENDPOINT.rds.amazonaws.com
DB_PORT=3306
DB_NAME=security_db
DB_USER=admin
DB_PASSWORD=YOUR_RDS_PASSWORD
PORT=5000
EOF

echo "⚠️  IMPORTANT: Edit /opt/sqlidetector/.env with your actual values!"

# ---- 6. Systemd Service (auto-start on reboot) ----
echo "[6/7] Creating systemd service..."
cat > /etc/systemd/system/sqlidetector.service << 'EOF'
[Unit]
Description=SQL Injection Detection System
After=network.target

[Service]
User=ubuntu
WorkingDirectory=/opt/sqlidetector/backend
Environment="PATH=/opt/sqlidetector/venv/bin"
EnvironmentFile=/opt/sqlidetector/.env
ExecStart=/opt/sqlidetector/venv/bin/gunicorn --workers 2 --bind 0.0.0.0:5000 app:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable sqlidetector

# ---- 7. Nginx Configuration ----
echo "[7/7] Configuring Nginx reverse proxy..."
cat > /etc/nginx/sites-available/sqlidetector << 'EOF'
server {
    listen 80;
    server_name _;  # Replace with your domain or EC2 public IP

    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Limit request size (prevent large payload attacks)
    client_max_body_size 1M;
}
EOF

ln -sf /etc/nginx/sites-available/sqlidetector /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl restart nginx

echo ""
echo "=============================================="
echo "  ✅ Setup Complete!"
echo "=============================================="
echo ""
echo "Next steps:"
echo "1. Edit /opt/sqlidetector/.env with your RDS credentials"
echo "2. Run: mysql -h YOUR_RDS_HOST -u admin -p security_db < database/schema.sql"
echo "3. Start app: systemctl start sqlidetector"
echo "4. Check logs: journalctl -u sqlidetector -f"
echo "5. Visit: http://YOUR_EC2_PUBLIC_IP"
echo ""