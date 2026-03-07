-- =============================================================
-- schema.sql — Database Schema for SQL Injection Detection System
-- Run this on your AWS RDS MySQL instance to set up the DB
-- =============================================================

-- Create the database
CREATE DATABASE IF NOT EXISTS security_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE security_db;

-- =============================================================
-- USERS TABLE
-- WHY STORE ENCRYPTED EMAIL?
-- If DB is breached, emails (PII) can't be read without the AES key
-- Passwords are hashed (one-way) — never stored in plain text
-- =============================================================
CREATE TABLE IF NOT EXISTS users (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    username        VARCHAR(50) UNIQUE NOT NULL,
    password_hash   VARCHAR(200) NOT NULL,       -- SHA-256 hash with salt
    email_encrypted TEXT,                         -- AES-256 encrypted email
    is_admin        BOOLEAN DEFAULT FALSE,
    created_at      DATETIME DEFAULT NOW(),
    last_login      DATETIME
);

-- Index for fast username lookups
CREATE INDEX idx_username ON users(username);

-- =============================================================
-- ATTACK LOGS TABLE
-- Stores every detected SQL injection attempt
-- Used for the security dashboard and incident reporting
-- =============================================================
CREATE TABLE IF NOT EXISTS attack_logs (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    attacker_ip     VARCHAR(45) NOT NULL,          -- IPv4 or IPv6
    targeted_field  VARCHAR(100),                  -- Which form field was attacked
    payload         TEXT,                          -- The malicious input (truncated to 500 chars)
    threat_level    ENUM('medium','high','critical') DEFAULT 'medium',
    endpoint        VARCHAR(200),                  -- Which URL endpoint was targeted
    detected_at     DATETIME DEFAULT NOW(),
    
    INDEX idx_ip (attacker_ip),
    INDEX idx_level (threat_level),
    INDEX idx_time (detected_at)
);

-- =============================================================
-- CAPABILITY CODES TABLE (optional — if you want DB-backed codes)
-- Stores server access capability codes per user/action
-- =============================================================
CREATE TABLE IF NOT EXISTS capability_codes (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    user_id     INT NOT NULL,
    action      VARCHAR(100) NOT NULL,
    code_hash   VARCHAR(200) NOT NULL,
    expires_at  DATETIME NOT NULL,
    used        BOOLEAN DEFAULT FALSE,
    created_at  DATETIME DEFAULT NOW(),
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_action (user_id, action)
);

-- =============================================================
-- SEED: Create a default admin user
-- Password: Admin@1234  (CHANGE THIS!)
-- The hash below is SHA-256("salt:Admin@1234") — for demo only
-- =============================================================
INSERT IGNORE INTO users (username, password_hash, email_encrypted, is_admin)
VALUES (
    'admin',
    -- This is hash_password("Admin@1234") output — replace with real hash from Python
    'changeme:changeme_run_create_admin_script',
    -- Encrypted version of admin@example.com — replace after running encryption
    'PLACEHOLDER_ENCRYPTED_EMAIL',
    TRUE
);

SHOW TABLES;
SELECT 'Database setup complete!' AS status;