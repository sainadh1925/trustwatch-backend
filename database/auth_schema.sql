-- Add users table for authentication
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    is_verified BOOLEAN DEFAULT 0,
    verification_code TEXT,
    subscription_plan TEXT DEFAULT 'free', -- 'free' or 'premium'
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME
);

-- Add user_settings table
CREATE TABLE IF NOT EXISTS user_settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    sms_protection BOOLEAN DEFAULT 0,
    email_protection BOOLEAN DEFAULT 0,
    notifications BOOLEAN DEFAULT 1,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Add sessions table
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    session_token TEXT NOT NULL UNIQUE,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Update scans table to include user_id
ALTER TABLE scans ADD COLUMN user_id INTEGER;
