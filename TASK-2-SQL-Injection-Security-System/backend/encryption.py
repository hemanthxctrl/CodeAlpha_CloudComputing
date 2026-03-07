"""
encryption.py — AES-256 Encryption Module

WHY AES-256?
- AES = Advanced Encryption Standard
- 256 = key length in bits (2^256 possible keys — more than atoms in the universe)
- Used by US government, banks, and militaries worldwide
- Even if your database is stolen, data appears as random bytes

HOW IT WORKS (CBC Mode):
1. Generate a random 16-byte IV (Initialization Vector) — makes each encryption unique
2. Pad the plaintext to be a multiple of 16 bytes (AES block size)
3. Encrypt using the 32-byte (256-bit) secret key + IV
4. Store: base64(IV + ciphertext) — IV is needed for decryption but is NOT secret

WHAT WE ENCRYPT:
- User passwords (before storing in DB)
- Sensitive fields: email, phone, SSN, API keys
- Session tokens
"""

import os
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


# ============================================================
# THE MASTER ENCRYPTION KEY
# In production: load from AWS Secrets Manager or .env file
# NEVER hardcode this in real code — this is for education only
# ============================================================
def get_encryption_key() -> bytes:
    """
    Retrieve the 32-byte (256-bit) AES encryption key.
    
    WHY 32 BYTES? AES-256 requires exactly a 256-bit key.
    We take the SECRET_KEY env variable and hash it to always
    get exactly 32 bytes, regardless of the input length.
    """
    secret = os.environ.get("SECRET_KEY", "codealpha-default-key-change-in-production!")
    # SHA-256 always produces exactly 32 bytes — perfect for AES-256
    return hashlib.sha256(secret.encode()).digest()


class AESCipher:
    """
    AES-256-CBC Encryption/Decryption class.
    
    Usage:
        cipher = AESCipher()
        encrypted = cipher.encrypt("mysecretpassword")
        original  = cipher.decrypt(encrypted)
    """
    
    def __init__(self):
        self.key = get_encryption_key()
        self.block_size = AES.block_size  # 16 bytes

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt a string using AES-256-CBC.
        
        Returns: base64-encoded string of (IV + ciphertext)
        The IV is NOT secret — it's stored alongside ciphertext.
        """
        if not plaintext:
            return ""
        
        # Step 1: Generate a fresh random IV for each encryption
        # WHY? Same plaintext encrypted twice gives different ciphertext
        # This prevents pattern analysis attacks
        iv = get_random_bytes(self.block_size)  # 16 random bytes
        
        # Step 2: Create AES cipher object (CBC mode)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        
        # Step 3: Pad plaintext to multiple of 16 bytes (PKCS7 padding)
        padded = pad(plaintext.encode('utf-8'), self.block_size)
        
        # Step 4: Encrypt
        ciphertext = cipher.encrypt(padded)
        
        # Step 5: Prepend IV to ciphertext, then base64 encode
        # Format stored in DB: base64(IV[16 bytes] + ciphertext)
        encrypted = base64.b64encode(iv + ciphertext).decode('utf-8')
        
        return encrypted

    def decrypt(self, encrypted_text: str) -> str:
        """
        Decrypt an AES-256-CBC encrypted string.
        
        Args: base64-encoded string (IV + ciphertext)
        Returns: original plaintext string
        """
        if not encrypted_text:
            return ""
        
        try:
            # Step 1: Decode base64 to get raw bytes
            raw = base64.b64decode(encrypted_text.encode('utf-8'))
            
            # Step 2: Extract IV (first 16 bytes) and ciphertext (rest)
            iv = raw[:self.block_size]
            ciphertext = raw[self.block_size:]
            
            # Step 3: Recreate cipher with same key and IV
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            
            # Step 4: Decrypt and remove padding
            plaintext = unpad(cipher.decrypt(ciphertext), self.block_size)
            
            return plaintext.decode('utf-8')
            
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")

    def encrypt_dict(self, data: dict, fields_to_encrypt: list) -> dict:
        """
        Encrypt specific fields in a dictionary.
        
        Args:
            data: The full data dict
            fields_to_encrypt: List of field names to encrypt
        
        Returns: dict with specified fields encrypted
        
        Example:
            user = {"name": "Alice", "password": "secret123", "email": "a@b.com"}
            encrypted_user = cipher.encrypt_dict(user, ["password", "email"])
        """
        result = data.copy()
        for field in fields_to_encrypt:
            if field in result and result[field]:
                result[field] = self.encrypt(str(result[field]))
        return result


# ============================================================
# PASSWORD HASHING (separate from encryption)
# WHY? Passwords should never be decryptable — use one-way hash
# For passwords: hash with salt using bcrypt-like approach
# For other sensitive data: use reversible AES-256 above
# ============================================================

import hashlib
import secrets

def hash_password(password: str) -> str:
    """
    Create a secure one-way hash of a password.
    
    WHY NOT JUST AES? Passwords should be one-way.
    If your DB is stolen, hashed passwords can't be reversed.
    
    Uses: SHA-256 + random salt (in production, use bcrypt)
    """
    salt = secrets.token_hex(32)  # 64-char random salt
    salted = salt + password
    hashed = hashlib.sha256(salted.encode()).hexdigest()
    return f"{salt}:{hashed}"  # Store both salt and hash

def verify_password(password: str, stored_hash: str) -> bool:
    """
    Verify a password against its stored hash.
    """
    try:
        salt, original_hash = stored_hash.split(":", 1)
        salted = salt + password
        check_hash = hashlib.sha256(salted.encode()).hexdigest()
        return check_hash == original_hash
    except:
        return False


# ============================================================
# CAPABILITY CODE MECHANISM
# WHY? An extra access token required for admin/server actions
# Like a 2FA code — even with username+password, you need this
# ============================================================

import hmac
import time

def generate_capability_code(user_id: str, action: str, secret: str = None) -> str:
    """
    Generate a time-based capability code for server access control.
    
    WHY? Prevents CSRF attacks and unauthorized server-side actions.
    A capability code is a short-lived token tied to:
    - The specific user
    - The specific action they're trying to perform
    - The current time window (expires every 5 minutes)
    
    Returns: 8-character hex capability code
    """
    if not secret:
        secret = os.environ.get("CAPABILITY_SECRET", "capability-secret-key")
    
    # Time window: code changes every 5 minutes
    time_window = str(int(time.time()) // 300)
    
    # Create HMAC using user_id + action + time_window
    message = f"{user_id}:{action}:{time_window}"
    code = hmac.new(
        secret.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()[:8].upper()  # First 8 chars, uppercase
    
    return code

def verify_capability_code(user_id: str, action: str, provided_code: str, secret: str = None) -> bool:
    """
    Verify a capability code. Checks current AND previous time window
    to handle edge cases where the window just changed.
    """
    # Check current window
    expected = generate_capability_code(user_id, action, secret)
    if hmac.compare_digest(expected, provided_code.upper()):
        return True
    
    # Check previous window (within last 5 min)
    if not secret:
        secret = os.environ.get("CAPABILITY_SECRET", "capability-secret-key")
    
    prev_window = str(int(time.time()) // 300 - 1)
    message = f"{user_id}:{action}:{prev_window}"
    prev_code = hmac.new(
        secret.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()[:8].upper()
    
    return hmac.compare_digest(prev_code, provided_code.upper())