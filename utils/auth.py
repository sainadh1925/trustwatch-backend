"""
Authentication utilities for user management
"""
import hashlib
import secrets
import random
from datetime import datetime, timedelta
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from database.db import get_connection
from utils.email_service import send_otp_email, send_welcome_email

def hash_password(password):
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, password_hash):
    """Verify password against hash"""
    return hash_password(password) == password_hash

def generate_verification_code():
    """Generate 6-digit verification code"""
    return str(random.randint(100000, 999999))

def generate_session_token():
    """Generate secure session token"""
    return secrets.token_urlsafe(32)

def create_user(full_name, email, password):
    """Create new user account"""
    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        # Check if email already exists
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        if cursor.fetchone():
            return {'success': False, 'error': 'Email already registered'}
        
        # Hash password
        password_hash = hash_password(password)
        
        # Generate verification code
        verification_code = generate_verification_code()
        
        # Insert user
        cursor.execute("""
            INSERT INTO users (full_name, email, password_hash, verification_code)
            VALUES (?, ?, ?, ?)
        """, (full_name, email, password_hash, verification_code))
        
        user_id = cursor.lastrowid
        
        # Create default settings
        cursor.execute("""
            INSERT INTO user_settings (user_id, sms_protection, email_protection, notifications)
            VALUES (?, 0, 0, 1)
        """, (user_id,))
        
        conn.commit()
        
        # Send OTP email
        email_result = send_otp_email(email, full_name, verification_code)
        
        # Build response based on email delivery status
        response = {
            'success': True,
            'user_id': user_id,
            'email_sent': email_result.get('success', False)
        }
        
        # Only include verification code if email failed (for fallback)
        if not email_result.get('success', False):
            response['verification_code'] = verification_code
        
        return response
    
    except Exception as e:
        conn.rollback()
        return {'success': False, 'error': str(e)}
    
    finally:
        conn.close()

def verify_user(email, verification_code):
    """Verify user email with code"""
    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT id, verification_code FROM users 
            WHERE email = ? AND is_verified = 0
        """, (email,))
        
        user = cursor.fetchone()
        
        if not user:
            return {'success': False, 'error': 'User not found or already verified'}
        
        if user['verification_code'] != verification_code:
            return {'success': False, 'error': 'Invalid verification code'}
        
        # Get user details for welcome email
        cursor.execute("SELECT full_name FROM users WHERE id = ?", (user['id'],))
        user_data = cursor.fetchone()
        
        # Mark as verified
        cursor.execute("""
            UPDATE users SET is_verified = 1, verification_code = NULL
            WHERE id = ?
        """, (user['id'],))
        
        conn.commit()
        
        # Send welcome email
        if user_data:
            send_welcome_email(email, user_data['full_name'])
        
        return {'success': True}
    
    except Exception as e:
        conn.rollback()
        return {'success': False, 'error': str(e)}
    
    finally:
        conn.close()

def login_user(email, password):
    """Login user and create session"""
    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT id, full_name, password_hash, is_verified, subscription_plan
            FROM users WHERE email = ?
        """, (email,))
        
        user = cursor.fetchone()
        
        if not user:
            return {'success': False, 'error': 'Invalid email or password'}
        
        if not verify_password(password, user['password_hash']):
            return {'success': False, 'error': 'Invalid email or password'}
        
        if not user['is_verified']:
            return {'success': False, 'error': 'Please verify your email first'}
        
        # Create session
        session_token = generate_session_token()
        expires_at = datetime.now() + timedelta(days=7)
        
        cursor.execute("""
            INSERT INTO sessions (user_id, session_token, expires_at)
            VALUES (?, ?, ?)
        """, (user['id'], session_token, expires_at))
        
        # Update last login
        cursor.execute("""
            UPDATE users SET last_login = ? WHERE id = ?
        """, (datetime.now(), user['id']))
        
        conn.commit()
        
        return {
            'success': True,
            'session_token': session_token,
            'user': {
                'id': user['id'],
                'full_name': user['full_name'],
                'email': email,
                'subscription_plan': user['subscription_plan']
            }
        }
    
    except Exception as e:
        conn.rollback()
        return {'success': False, 'error': str(e)}
    
    finally:
        conn.close()

def verify_session(session_token):
    """Verify session token and return user"""
    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT s.user_id, u.full_name, u.email, u.subscription_plan, s.expires_at
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.session_token = ?
        """, (session_token,))
        
        session = cursor.fetchone()
        
        if not session:
            return None
        
        # Check if expired
        expires_at = datetime.fromisoformat(session['expires_at'])
        if expires_at < datetime.now():
            return None
        
        return {
            'id': session['user_id'],
            'full_name': session['full_name'],
            'email': session['email'],
            'subscription_plan': session['subscription_plan']
        }
    
    finally:
        conn.close()

def logout_user(session_token):
    """Logout user by deleting session"""
    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("DELETE FROM sessions WHERE session_token = ?", (session_token,))
        conn.commit()
        return {'success': True}
    
    except Exception as e:
        return {'success': False, 'error': str(e)}
    
    finally:
        conn.close()

def get_user_settings(user_id):
    """Get user protection settings"""
    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT sms_protection, email_protection, notifications
            FROM user_settings WHERE user_id = ?
        """, (user_id,))
        
        settings = cursor.fetchone()
        return dict(settings) if settings else None
    
    finally:
        conn.close()

def update_user_settings(user_id, sms_protection=None, email_protection=None, notifications=None):
    """Update user protection settings"""
    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        updates = []
        params = []
        
        if sms_protection is not None:
            updates.append("sms_protection = ?")
            params.append(sms_protection)
        
        if email_protection is not None:
            updates.append("email_protection = ?")
            params.append(email_protection)
        
        if notifications is not None:
            updates.append("notifications = ?")
            params.append(notifications)
        
        if updates:
            params.append(user_id)
            query = f"UPDATE user_settings SET {', '.join(updates)} WHERE user_id = ?"
            cursor.execute(query, params)
            conn.commit()
        
        return {'success': True}
    
    except Exception as e:
        conn.rollback()
        return {'success': False, 'error': str(e)}
    
    finally:
        conn.close()

def update_subscription(user_id, plan):
    """Update user subscription plan"""
    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            UPDATE users SET subscription_plan = ? WHERE id = ?
        """, (plan, user_id))
        
        conn.commit()
        return {'success': True}
    
    except Exception as e:
        conn.rollback()
        return {'success': False, 'error': str(e)}
    
    finally:
        conn.close()
