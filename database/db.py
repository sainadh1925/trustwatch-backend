"""
Database connection and utility functions
"""
import sqlite3
import os
import json
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), 'trustwatch.db')

def get_connection():
    """Get database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_database():
    """Initialize database with schema"""
    conn = get_connection()
    
    # Read and execute main schema
    schema_path = os.path.join(os.path.dirname(__file__), 'schema.sql')
    with open(schema_path, 'r') as f:
        schema = f.read()
    
    conn.executescript(schema)
    
    # Read and execute auth schema
    auth_schema_path = os.path.join(os.path.dirname(__file__), 'auth_schema.sql')
    if os.path.exists(auth_schema_path):
        with open(auth_schema_path, 'r') as f:
            auth_schema = f.read()
        
        try:
            conn.executescript(auth_schema)
        except Exception as e:
            print(f"Auth schema already applied or error: {e}")
    
    conn.commit()
    conn.close()
    print("Database initialized successfully")


def save_scan(scan_type, content, threat_score, risk_level, is_phishing, detected_patterns):
    """Save scan result to database"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO scans (scan_type, content, threat_score, risk_level, is_phishing, detected_patterns)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (scan_type, content, threat_score, risk_level, is_phishing, json.dumps(detected_patterns)))
    
    conn.commit()
    scan_id = cursor.lastrowid
    conn.close()
    
    return scan_id

def get_recent_scans(limit=10):
    """Get recent scan history"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT * FROM scans 
        ORDER BY timestamp DESC 
        LIMIT ?
    """, (limit,))
    
    scans = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return scans

def check_blacklist(domain):
    """Check if domain is in blacklist"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM blacklist WHERE domain = ?", (domain,))
    result = cursor.fetchone()
    conn.close()
    
    return dict(result) if result else None

def get_statistics():
    """Get system statistics"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM statistics ORDER BY id DESC LIMIT 1")
    stats = dict(cursor.fetchone())
    conn.close()
    
    return stats

def update_statistics(total_scans=None, phishing_detected=None, avg_response_time=None):
    """Update system statistics"""
    conn = get_connection()
    cursor = conn.cursor()
    
    updates = []
    params = []
    
    if total_scans is not None:
        updates.append("total_scans = total_scans + ?")
        params.append(total_scans)
    
    if phishing_detected is not None:
        updates.append("phishing_detected = phishing_detected + ?")
        params.append(phishing_detected)
    
    if avg_response_time is not None:
        updates.append("avg_response_time = ?")
        params.append(avg_response_time)
    
    updates.append("last_updated = ?")
    params.append(datetime.now().isoformat())
    
    query = f"UPDATE statistics SET {', '.join(updates)} WHERE id = 1"
    cursor.execute(query, params)
    
    conn.commit()
    conn.close()
