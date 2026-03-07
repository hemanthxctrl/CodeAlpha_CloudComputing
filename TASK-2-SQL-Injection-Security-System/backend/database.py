"""
database.py — Layer 2 Security: Database Connection + Parameterized Queries

WHY PARAMETERIZED QUERIES?
Regular query (VULNERABLE):
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    
    If username = "' OR '1'='1", the full query becomes:
    SELECT * FROM users WHERE username = '' OR '1'='1'
    → Returns ALL users! Authentication bypassed!

Parameterized query (SAFE):
    query = "SELECT * FROM users WHERE username = %s"
    cursor.execute(query, (username,))
    
    The database driver treats username as pure DATA, never as SQL code.
    Even "' OR '1'='1" is treated literally — no injection possible!

This is Layer 2 of our double-layer security.
Even if our Layer 1 (SQLi detector) is somehow bypassed, this layer 
makes injection structurally impossible at the database driver level.
"""

import os
import mysql.connector
from mysql.connector import Error
import logging

logger = logging.getLogger(__name__)


def get_db_connection():
    """
    Create and return a MySQL database connection using environment variables.
    
    WHY ENV VARIABLES? Never hardcode DB credentials in code.
    If code is on GitHub, credentials could be exposed.
    """
    try:
        connection = mysql.connector.connect(
            host=os.environ.get("DB_HOST", "localhost"),
            port=int(os.environ.get("DB_PORT", "3306")),
            database=os.environ.get("DB_NAME", "security_db"),
            user=os.environ.get("DB_USER", "admin"),
            password=os.environ.get("DB_PASSWORD", ""),
            ssl_ca=os.environ.get("DB_SSL_CA", None),  # For AWS RDS SSL
            ssl_disabled=os.environ.get("DB_SSL_DISABLED", "false").lower() == "true"
        )
        return connection
    except Error as e:
        logger.error(f"Database connection failed: {e}")
        raise


class UserRepository:
    """
    All database operations for the users table.
    EVERY query here uses parameterized format — NO string concatenation.
    """

    @staticmethod
    def create_user(username: str, hashed_password: str, encrypted_email: str) -> int:
        """
        Insert a new user. Returns the new user's ID.
        
        WHY %s PLACEHOLDERS?
        MySQL connector replaces %s with properly escaped values.
        Special characters are automatically neutralized.
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            # ✅ SAFE: parameterized query
            query = """
                INSERT INTO users (username, password_hash, email_encrypted, created_at)
                VALUES (%s, %s, %s, NOW())
            """
            cursor.execute(query, (username, hashed_password, encrypted_email))
            conn.commit()
            return cursor.lastrowid
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def find_by_username(username: str) -> dict | None:
        """
        Look up a user by username.
        
        VULNERABLE version (DO NOT USE):
            query = f"SELECT * FROM users WHERE username = '{username}'"
        
        SAFE version (parameterized):
            query = "SELECT * FROM users WHERE username = %s"
            cursor.execute(query, (username,))
        """
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            # ✅ SAFE: parameterized
            query = "SELECT * FROM users WHERE username = %s LIMIT 1"
            cursor.execute(query, (username,))
            return cursor.fetchone()
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def update_last_login(user_id: int) -> None:
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            query = "UPDATE users SET last_login = NOW() WHERE id = %s"
            cursor.execute(query, (user_id,))
            conn.commit()
        finally:
            cursor.close()
            conn.close()


class AttackLogRepository:
    """
    All database operations for the attack_logs table.
    Stores every detected SQL injection attempt.
    """

    @staticmethod
    def log_attack(ip: str, field: str, payload: str, threat_level: str, endpoint: str) -> None:
        """
        Save an attack attempt to the database.
        Useful for analysis, reporting, and blocking repeat offenders.
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            query = """
                INSERT INTO attack_logs 
                (attacker_ip, targeted_field, payload, threat_level, endpoint, detected_at)
                VALUES (%s, %s, %s, %s, %s, NOW())
            """
            # Truncate payload to 500 chars for DB storage
            cursor.execute(query, (ip, field, payload[:500], threat_level, endpoint))
            conn.commit()
        except Exception as e:
            logger.error(f"Failed to log attack: {e}")
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_recent_attacks(limit: int = 20) -> list:
        """
        Retrieve recent attacks for the admin dashboard.
        """
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            query = """
                SELECT attacker_ip, targeted_field, payload, threat_level, endpoint, detected_at
                FROM attack_logs
                ORDER BY detected_at DESC
                LIMIT %s
            """
            cursor.execute(query, (limit,))
            return cursor.fetchall()
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_attack_summary() -> dict:
        """
        Get counts by threat level for dashboard charts.
        """
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            query = """
                SELECT 
                    threat_level,
                    COUNT(*) as count,
                    MAX(detected_at) as last_seen
                FROM attack_logs
                GROUP BY threat_level
            """
            cursor.execute(query)
            rows = cursor.fetchall()
            return {row["threat_level"]: {"count": row["count"], "last_seen": str(row["last_seen"])} for row in rows}
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_blocked_ips() -> list:
        """
        Get IPs with more than 5 attack attempts — candidates for blocking.
        """
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            query = """
                SELECT attacker_ip, COUNT(*) as attempts
                FROM attack_logs
                GROUP BY attacker_ip
                HAVING COUNT(*) > 5
                ORDER BY attempts DESC
            """
            cursor.execute(query)
            return cursor.fetchall()
        finally:
            cursor.close()
            conn.close()