-- TrustWatch Database Schema

-- Scans table: stores all scan history
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_type TEXT NOT NULL, -- 'url', 'text', 'sms'
    content TEXT NOT NULL,
    threat_score REAL NOT NULL,
    risk_level TEXT NOT NULL, -- 'Low', 'Medium', 'High', 'Critical'
    is_phishing BOOLEAN NOT NULL,
    detected_patterns TEXT, -- JSON array of detected patterns
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Threats table: known malicious entities
CREATE TABLE IF NOT EXISTS threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_type TEXT NOT NULL, -- 'domain', 'url', 'keyword'
    value TEXT NOT NULL UNIQUE,
    severity TEXT NOT NULL, -- 'Low', 'Medium', 'High', 'Critical'
    description TEXT,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Blacklist table: known phishing domains and URLs
CREATE TABLE IF NOT EXISTS blacklist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE,
    category TEXT, -- 'phishing', 'malware', 'scam'
    source TEXT, -- 'manual', 'threat_feed', 'ml_detection'
    added_date DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Statistics table: system performance metrics
CREATE TABLE IF NOT EXISTS statistics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    total_scans INTEGER DEFAULT 0,
    phishing_detected INTEGER DEFAULT 0,
    false_positives INTEGER DEFAULT 0,
    avg_response_time REAL DEFAULT 0.0,
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Insert initial statistics row
INSERT INTO statistics (total_scans, phishing_detected, false_positives, avg_response_time)
VALUES (0, 0, 0, 0.0);

-- Insert sample blacklist entries
INSERT OR IGNORE INTO blacklist (domain, category, source) VALUES
('phishing-example.com', 'phishing', 'manual'),
('malicious-bank.com', 'phishing', 'threat_feed'),
('fake-login.net', 'phishing', 'manual'),
('scam-alert.org', 'scam', 'ml_detection');
