from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
from datetime import datetime

from sql_detector import scan_all_inputs, get_attack_stats
from encryption import AESCipher, hash_password, verify_password, generate_capability_code, verify_capability_code
from database import UserRepository, AttackLogRepository

app = Flask(__name__, template_folder="../frontend", static_folder="../frontend")
app.secret_key = os.environ.get("FLASK_SECRET", "change-this-in-production")

limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])
cipher = AESCipher()

@app.before_request
def security_middleware():
    inputs_to_check = {}
    inputs_to_check.update(dict(request.args))
    if request.form:
        inputs_to_check.update(dict(request.form))
    if request.is_json and request.json:
        inputs_to_check.update(request.json)
    if not inputs_to_check:
        return None
    flat_inputs = {k: v[0] if isinstance(v, list) else str(v) for k, v in inputs_to_check.items()}
    result = scan_all_inputs(flat_inputs, ip=request.remote_addr)
    if not result["all_safe"]:
        for threat in result["threats"]:
            payload = flat_inputs.get(threat["field"], "")
            AttackLogRepository.log_attack(
                ip=request.remote_addr, field=threat["field"],
                payload=payload, threat_level=threat["threat_level"],
                endpoint=request.endpoint or "unknown"
            )
        return jsonify({"error": "Request blocked", "code": "SQL_INJECTION_DETECTED",
                        "message": "Malicious content detected and blocked."}), 403

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("index"))
    return render_template("dashboard.html")

@app.route("/api/register", methods=["POST"])
@limiter.limit("5 per hour")
def register():
    data = request.get_json()
    if not data or not data.get("username") or not data.get("password") or not data.get("email"):
        return jsonify({"error": "All fields required"}), 400
    existing = UserRepository.find_by_username(data["username"].strip())
    if existing:
        return jsonify({"error": "Username already taken"}), 409
    hashed_pw = hash_password(data["password"])
    encrypted_email = cipher.encrypt(data["email"].strip())
    user_id = UserRepository.create_user(data["username"].strip(), hashed_pw, encrypted_email)
    return jsonify({"success": True, "message": "Account created", "user_id": user_id}), 201

@app.route("/api/login", methods=["POST"])
@limiter.limit("10 per minute")
def login():
    data = request.get_json()
    if not data or not data.get("username") or not data.get("password"):
        return jsonify({"error": "Username and password required"}), 400
    user = UserRepository.find_by_username(data["username"].strip())
    if not user or not verify_password(data["password"], user["password_hash"]):
        return jsonify({"error": "Invalid credentials"}), 401
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["is_admin"] = user.get("is_admin", False)
    UserRepository.update_last_login(user["id"])
    cap_code = generate_capability_code(str(user["id"]), "session")
    return jsonify({"success": True, "username": user["username"], "capability_code": cap_code})

@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"success": True})

@app.route("/api/attacks", methods=["GET"])
def get_attacks():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    cap_code = request.headers.get("X-Capability-Code", "")
    if not verify_capability_code(str(session["user_id"]), "session", cap_code):
        return jsonify({"error": "Invalid capability code"}), 403
    attacks = AttackLogRepository.get_recent_attacks(limit=50)
    for a in attacks:
        if a.get("detected_at"):
            a["detected_at"] = str(a["detected_at"])
    return jsonify({"attacks": attacks})

@app.route("/api/stats", methods=["GET"])
def get_stats():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"file_stats": get_attack_stats(), "timestamp": datetime.now().isoformat()})

@app.route("/api/test-injection", methods=["POST"])
def test_injection():
    data = request.get_json()
    payload = data.get("payload", "")
    from sql_detector import detect_sql_injection
    result = detect_sql_injection(payload, "test_field", request.remote_addr)
    return jsonify({"payload": payload, "is_safe": result["is_safe"],
                    "threat_level": result["threat_level"], "message": result["message"]})

@app.route("/api/capability-code", methods=["GET"])
def get_capability_code():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    code = generate_capability_code(str(session["user_id"]), "general")
    return jsonify({"capability_code": code, "expires_in": "5 minutes"})

@app.route("/health")
def health():
    return jsonify({"status": "healthy"})

@app.errorhandler(429)
def rate_limit_exceeded(e):
    return jsonify({"error": "Too many requests"}), 429

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print("Starting SQL Injection Detection System...")
    app.run(host="0.0.0.0", port=port, debug=False)