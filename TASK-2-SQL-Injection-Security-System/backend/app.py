"""
app.py — Main Flask Application

This is the entry point for the web server.
It wires together:
1. SQL injection detection middleware (Layer 1)
2. Route handlers (auth, admin, API)
3. Rate limiting (prevent brute force)
4. CORS headers (for API access)
"""

from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
import json
from datetime import datetime

from sql_detector import scan_all_inputs, get_attack_stats
from encryption import AESCipher, hash_password, verify_password, generate_capability_code, verify_capability_code
from database import UserRepository, AttackLogRepository

# ============================================================
# APP INITIALIZATION
# ============================================================
app = Flask(__name__, template_folder="../frontend", static_folder="../frontend/assets")
app.secret_key = os.environ.get("FLASK_SECRET", "change-this-in-production-please")

# Rate limiter — prevents brute force attacks
# WHY? Even with SQLi protection, attackers can try thousands of passwords
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

cipher = AESCipher()


# ============================================================
# SECURITY MIDDLEWARE — runs before EVERY request
# ============================================================
@app.before_request
def security_middleware():
    """
    This function runs BEFORE every single route handler.
    WHY? We want to catch SQL injection in ALL inputs — forms, URL params, JSON body.
    """
    # Collect all input data from the request
    inputs_to_check = {}
    
    # Check URL query parameters: ?username=...&password=...
    inputs_to_check.update(dict(request.args))
    
    # Check form data (POST forms)
    if request.form:
        inputs_to_check.update(dict(request.form))
    
    # Check JSON body (API requests)
    if request.is_json and request.json:
        inputs_to_check.update(request.json)
    
    if not inputs_to_check:
        return None  # No input to check — continue
    
    # Flatten any list values (some fields can have multiple values)
    flat_inputs = {}
    for key, value in inputs_to_check.items():
        flat_inputs[key] = value[0] if isinstance(value, list) else str(value)
    
    # Run Layer 1 detection
    result = scan_all_inputs(flat_inputs, ip=request.remote_addr)
    
    if not result["all_safe"]:
        # Log attack to database
        for threat in result["threats"]:
            payload = flat_inputs.get(threat["field"], "")
            AttackLogRepository.log_attack(
                ip=request.remote_addr,
                field=threat["field"],
                payload=payload,
                threat_level=threat["threat_level"],
                endpoint=request.endpoint or "unknown"
            )
        
        # Block the request
        return jsonify({
            "error": "Request blocked by security system",
            "code": "SQL_INJECTION_DETECTED",
            "message": "Your request contained potentially malicious content and has been blocked and logged."
        }), 403  # 403 = Forbidden


# ============================================================
# ROUTES — PAGES
# ============================================================

@app.route("/")
def index():
    """Home page — login/register form"""
    return render_template("index.html")


@app.route("/dashboard")
def dashboard():
    """Security monitoring dashboard"""
    if "user_id" not in session:
        return redirect(url_for("index"))
    return render_template("dashboard.html")


@app.route("/admin")
def admin():
    """Admin panel — requires capability code"""
    if "user_id" not in session or not session.get("is_admin"):
        return redirect(url_for("index"))
    return render_template("admin.html")


# ============================================================
# ROUTES — AUTH API
# ============================================================

@app.route("/api/register", methods=["POST"])
@limiter.limit("5 per hour")  # Max 5 registrations per IP per hour
def register():
    """Register a new user with encrypted credentials"""
    data = request.get_json()
    
    if not data or not data.get("username") or not data.get("password") or not data.get("email"):
        return jsonify({"error": "Username, password, and email are required"}), 400
    
    username = data["username"].strip()
    password = data["password"]
    email = data["email"].strip()
    
    # Check if username already exists
    existing = UserRepository.find_by_username(username)
    if existing:
        return jsonify({"error": "Username already taken"}), 409
    
    # Hash password (one-way — can't be reversed)
    hashed_pw = hash_password(password)
    
    # Encrypt email with AES-256 (reversible for display)
    encrypted_email = cipher.encrypt(email)
    
    # Store in database
    user_id = UserRepository.create_user(username, hashed_pw, encrypted_email)
    
    return jsonify({
        "success": True,
        "message": "Account created successfully",
        "user_id": user_id
    }), 201


@app.route("/api/login", methods=["POST"])
@limiter.limit("10 per minute")  # Max 10 login attempts per minute
def login():
    """Authenticate a user. Returns capability code on success."""
    data = request.get_json()
    
    if not data or not data.get("username") or not data.get("password"):
        return jsonify({"error": "Username and password required"}), 400
    
    username = data["username"].strip()
    password = data["password"]
    
    # Find user (parameterized query — injection-proof)
    user = UserRepository.find_by_username(username)
    
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401
    
    # Verify password against stored hash
    if not verify_password(password, user["password_hash"]):
        return jsonify({"error": "Invalid credentials"}), 401
    
    # Login successful — create session
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["is_admin"] = user.get("is_admin", False)
    
    # Update last login
    UserRepository.update_last_login(user["id"])
    
    # Generate capability code for this session
    cap_code = generate_capability_code(str(user["id"]), "session")
    
    return jsonify({
        "success": True,
        "message": "Login successful",
        "username": user["username"],
        "capability_code": cap_code,  # Client must include this in sensitive requests
        "is_admin": user.get("is_admin", False)
    })


@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"success": True, "message": "Logged out"})


# ============================================================
# ROUTES — ADMIN/SECURITY API
# ============================================================

@app.route("/api/attacks", methods=["GET"])
def get_attacks():
    """Return recent attack logs — requires valid session + capability code"""
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    # Verify capability code
    cap_code = request.headers.get("X-Capability-Code", "")
    if not verify_capability_code(str(session["user_id"]), "session", cap_code):
        return jsonify({"error": "Invalid or expired capability code"}), 403
    
    attacks = AttackLogRepository.get_recent_attacks(limit=50)
    
    # Convert datetime objects to strings for JSON
    for attack in attacks:
        if attack.get("detected_at"):
            attack["detected_at"] = str(attack["detected_at"])
    
    return jsonify({
        "attacks": attacks,
        "total": len(attacks)
    })


@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Return attack statistics for the dashboard charts"""
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    summary = AttackLogRepository.get_attack_summary()
    file_stats = get_attack_stats()
    
    return jsonify({
        "db_summary": summary,
        "file_stats": file_stats,
        "timestamp": datetime.now().isoformat()
    })


@app.route("/api/blocked-ips", methods=["GET"])
def get_blocked_ips():
    """Get IPs with multiple attack attempts"""
    if "user_id" not in session or not session.get("is_admin"):
        return jsonify({"error": "Admin access required"}), 403
    
    ips = AttackLogRepository.get_blocked_ips()
    return jsonify({"blocked_ips": ips})


@app.route("/api/test-injection", methods=["POST"])
def test_injection():
    """
    Safe endpoint to test SQL injection detection.
    EDUCATIONAL PURPOSE: Shows what gets blocked and why.
    """
    data = request.get_json()
    payload = data.get("payload", "")
    
    from sql_detector import detect_sql_injection
    result = detect_sql_injection(payload, "test_field", request.remote_addr)
    
    return jsonify({
        "payload": payload,
        "is_safe": result["is_safe"],
        "threat_level": result["threat_level"],
        "message": result["message"]
    })


@app.route("/api/capability-code", methods=["GET"])
def get_capability_code():
    """Generate a new capability code for the logged-in user"""
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    action = request.args.get("action", "general")
    code = generate_capability_code(str(session["user_id"]), action)
    
    return jsonify({
        "capability_code": code,
        "expires_in": "5 minutes",
        "action": action
    })


@app.route("/health")
def health():
    """Health check endpoint for AWS load balancer"""
    return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(429)
def rate_limit_exceeded(e):
    return jsonify({
        "error": "Too many requests",
        "message": "Rate limit exceeded. Please slow down."
    }), 429

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error"}), 500


# ============================================================
# MAIN ENTRY POINT
# ============================================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("DEBUG", "false").lower() == "true"
    
    print(f"""
    ╔══════════════════════════════════════════╗
    ║  SQL Injection Detection System          ║
    ║  CodeAlpha Cloud Computing - Task 2      ║
    ╠══════════════════════════════════════════╣
    ║  Running on: http://0.0.0.0:{port}          ║
    ║  Debug mode: {debug}                   ║
    ║  Security: Double-layer active ✓         ║
    ╚══════════════════════════════════════════╝
    """)
    
    app.run(host="0.0.0.0", port=port, debug=debug)