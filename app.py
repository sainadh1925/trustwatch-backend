"""
TrustWatch - Real-Time Phishing Detection API
Main Flask application with REST endpoints
"""
from flask import Flask, request, jsonify
from flask_cors import CORS
import time
from datetime import datetime

# Import models
from models.ml_detector import MLDetector
from models.threat_intel import ThreatIntelligence

# Import database functions
from database.db import init_database, save_scan, get_recent_scans, get_statistics, update_statistics

# Import utilities
from utils.validators import validate_url, validate_text
from utils.logger import get_logger
from utils.auth import (create_user, verify_user, login_user, verify_session, 
                        logout_user, get_user_settings, update_user_settings, 
                        update_subscription)

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for frontend

# Initialize logger
logger = get_logger('api')

# Initialize ML detector and threat intelligence
ml_detector = MLDetector()
threat_intel = ThreatIntelligence()

# Initialize database on startup
try:
    init_database()
    logger.info("Database initialized successfully")
except Exception as e:
    logger.error(f"Database initialization failed: {e}")

@app.route('/')
def home():
    """API home endpoint"""
    return jsonify({
        'name': 'TrustWatch API',
        'version': '1.0.0',
        'description': 'Real-Time AI/ML-Based Phishing Detection System',
        'endpoints': {
            'scan_url': '/api/scan/url',
            'scan_text': '/api/scan/text',
            'scan_sms': '/api/scan/sms',
            'statistics': '/api/stats',
            'recent_scans': '/api/scans/recent'
        }
    })

@app.route('/api/scan/url', methods=['POST'])
def scan_url():
    """
    Scan URL for phishing
    Request body: { "url": "http://example.com" }
    """
    start_time = time.time()
    
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        
        # Validate URL
        is_valid, validated_url = validate_url(url)
        if not is_valid:
            return jsonify({'error': validated_url}), 400
        
        # Check threat intelligence
        threat_info = threat_intel.check_threat(validated_url)
        
        # Perform ML detection
        result = ml_detector.detect_url(validated_url)
        
        # Add threat intelligence info if found
        if threat_info and threat_info.get('found'):
            result['threat_intelligence'] = threat_info
            # Boost score if in threat database
            threat_score_boost = threat_intel.get_threat_score(threat_info)
            result['threat_score'] = min(result['threat_score'] + threat_score_boost, 100)
            result['risk_level'] = ml_detector._calculate_risk_level(result['threat_score'])
            result['is_phishing'] = result['threat_score'] >= 50
        
        # Calculate response time
        response_time = (time.time() - start_time) * 1000  # Convert to ms
        result['response_time_ms'] = round(response_time, 2)
        
        # Save to database
        save_scan(
            scan_type='url',
            content=validated_url,
            threat_score=result['threat_score'],
            risk_level=result['risk_level'],
            is_phishing=result['is_phishing'],
            detected_patterns=result['indicators']
        )
        
        # Update statistics
        update_statistics(
            total_scans=1,
            phishing_detected=1 if result['is_phishing'] else 0,
            avg_response_time=response_time
        )
        
        logger.info(f"URL scan completed: {validated_url} - Risk: {result['risk_level']}")
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Error scanning URL: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/text', methods=['POST'])
def scan_text():
    """
    Scan text/email content for phishing
    Request body: { "text": "...", "language": "english" }
    """
    start_time = time.time()
    
    try:
        data = request.get_json()
        text = data.get('text', '').strip()
        language = data.get('language', 'english')
        
        # Validate text
        is_valid, validated_text = validate_text(text)
        if not is_valid:
            return jsonify({'error': validated_text}), 400
        
        # Perform ML detection
        result = ml_detector.detect_text(validated_text, language)
        
        # Calculate response time
        response_time = (time.time() - start_time) * 1000
        result['response_time_ms'] = round(response_time, 2)
        
        # Save to database
        save_scan(
            scan_type='text',
            content=validated_text[:200],  # Store first 200 chars
            threat_score=result['threat_score'],
            risk_level=result['risk_level'],
            is_phishing=result['is_phishing'],
            detected_patterns=result['indicators']
        )
        
        # Update statistics
        update_statistics(
            total_scans=1,
            phishing_detected=1 if result['is_phishing'] else 0,
            avg_response_time=response_time
        )
        
        logger.info(f"Text scan completed - Risk: {result['risk_level']}")
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Error scanning text: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/sms', methods=['POST'])
def scan_sms():
    """
    Scan SMS message for phishing
    Request body: { "text": "...", "language": "english" }
    """
    start_time = time.time()
    
    try:
        data = request.get_json()
        text = data.get('text', '').strip()
        language = data.get('language', 'english')
        
        # Validate text
        is_valid, validated_text = validate_text(text)
        if not is_valid:
            return jsonify({'error': validated_text}), 400
        
        # Perform ML detection
        result = ml_detector.detect_sms(validated_text, language)
        
        # Calculate response time
        response_time = (time.time() - start_time) * 1000
        result['response_time_ms'] = round(response_time, 2)
        
        # Save to database
        save_scan(
            scan_type='sms',
            content=validated_text,
            threat_score=result['threat_score'],
            risk_level=result['risk_level'],
            is_phishing=result['is_phishing'],
            detected_patterns=result['indicators']
        )
        
        # Update statistics
        update_statistics(
            total_scans=1,
            phishing_detected=1 if result['is_phishing'] else 0,
            avg_response_time=response_time
        )
        
        logger.info(f"SMS scan completed - Risk: {result['risk_level']}")
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Error scanning SMS: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get system statistics"""
    try:
        stats = get_statistics()
        
        # Calculate detection rate
        if stats['total_scans'] > 0:
            stats['detection_rate'] = round((stats['phishing_detected'] / stats['total_scans']) * 100, 2)
        else:
            stats['detection_rate'] = 0
        
        return jsonify(stats)
    
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scans/recent', methods=['GET'])
def get_recent():
    """Get recent scan history"""
    try:
        limit = request.args.get('limit', 10, type=int)
        scans = get_recent_scans(limit)
        
        return jsonify({
            'count': len(scans),
            'scans': scans
        })
    
    except Exception as e:
        logger.error(f"Error getting recent scans: {e}")
        return jsonify({'error': str(e)}), 500


# Authentication Endpoints

@app.route('/api/auth/signup', methods=['POST'])
def signup():
    """
    User registration
    Request body: { "full_name": "...", "email": "...", "password": "..." }
    """
    try:
        data = request.get_json()
        full_name = data.get('full_name', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        if not full_name or not email or not password:
            return jsonify({'error': 'All fields are required'}), 400
        
        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400
        
        result = create_user(full_name, email, password)
        
        if result['success']:
            # Return the result as-is - it already has email_sent flag
            # and verification_code only if email failed
            response = {
                'success': True,
                'message': 'Account created successfully',
                'email_sent': result.get('email_sent', False)
            }
            # Only include verification_code if it exists (email failed)
            if 'verification_code' in result:
                response['verification_code'] = result['verification_code']
            return jsonify(response)
        else:
            return jsonify({'error': result['error']}), 400
    
    except Exception as e:
        logger.error(f"Error in signup: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/verify', methods=['POST'])
def verify():
    """
    Verify email with code
    Request body: { "email": "...", "code": "..." }
    """
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        code = data.get('code', '').strip()
        
        result = verify_user(email, code)
        
        if result['success']:
            return jsonify({'success': True, 'message': 'Email verified successfully'})
        else:
            return jsonify({'error': result['error']}), 400
    
    except Exception as e:
        logger.error(f"Error in verification: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    """
    User login
    Request body: { "email": "...", "password": "..." }
    """
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        result = login_user(email, password)
        
        if result['success']:
            return jsonify({
                'success': True,
                'session_token': result['session_token'],
                'user': result['user']
            })
        else:
            return jsonify({'error': result['error']}), 401
    
    except Exception as e:
        logger.error(f"Error in login: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    """
    User logout
    Request body: { "session_token": "..." }
    """
    try:
        data = request.get_json()
        session_token = data.get('session_token', '')
        
        result = logout_user(session_token)
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Error in logout: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/me', methods=['GET'])
def get_current_user():
    """
    Get current user from session token
    Header: Authorization: Bearer <session_token>
    """
    try:
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Invalid authorization header'}), 401
        
        session_token = auth_header.replace('Bearer ', '')
        user = verify_session(session_token)
        
        if user:
            return jsonify({'user': user})
        else:
            return jsonify({'error': 'Invalid or expired session'}), 401
    
    except Exception as e:
        logger.error(f"Error getting current user: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/settings', methods=['GET', 'POST'])
def user_settings():
    """
    Get or update user settings
    """
    try:
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Invalid authorization header'}), 401
        
        session_token = auth_header.replace('Bearer ', '')
        user = verify_session(session_token)
        
        if not user:
            return jsonify({'error': 'Invalid or expired session'}), 401
        
        if request.method == 'GET':
            settings = get_user_settings(user['id'])
            return jsonify(settings)
        
        else:  # POST
            data = request.get_json()
            result = update_user_settings(
                user['id'],
                sms_protection=data.get('sms_protection'),
                email_protection=data.get('email_protection'),
                notifications=data.get('notifications')
            )
            return jsonify(result)
    
    except Exception as e:
        logger.error(f"Error with user settings: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/subscription', methods=['POST'])
def upgrade_subscription():
    """
    Upgrade user subscription
    Request body: { "plan": "premium" }
    """
    try:
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Invalid authorization header'}), 401
        
        session_token = auth_header.replace('Bearer ', '')
        user = verify_session(session_token)
        
        if not user:
            return jsonify({'error': 'Invalid or expired session'}), 401
        
        data = request.get_json()
        plan = data.get('plan', 'free')
        
        result = update_subscription(user['id'], plan)
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Error upgrading subscription: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat()
    })

if __name__ == '__main__':
    print("=" * 60)
    print("TrustWatch - Real-Time Phishing Detection System")
    print("Backend API Server")
    print("=" * 60)
    print("Server starting on http://localhost:5000")
    print("API Documentation: http://localhost:5000")
    print("=" * 60)
    
    app.run(debug=True, host='0.0.0.0', port=5000)
