"""
Email service using SendGrid for sending OTP and notifications
"""
import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Email, To, Content
from dotenv import load_dotenv
from utils.logger import get_logger

# Load environment variables
load_dotenv()

logger = get_logger('email_service')

# SendGrid configuration
SENDGRID_API_KEY = os.getenv('SENDGRID_API_KEY', '')
SENDGRID_FROM_EMAIL = os.getenv('SENDGRID_FROM_EMAIL', 'noreply@trustwatch.com')
SENDGRID_FROM_NAME = os.getenv('SENDGRID_FROM_NAME', 'TrustWatch Security')
APP_NAME = os.getenv('APP_NAME', 'TrustWatch')
APP_URL = os.getenv('APP_URL', 'http://localhost:3000')


def send_otp_email(to_email, full_name, otp_code):
    """
    Send OTP verification email to user
    
    Args:
        to_email: Recipient email address
        full_name: User's full name
        otp_code: 6-digit OTP code
    
    Returns:
        dict: {'success': bool, 'error': str (if failed)}
    """
    try:
        # Check if API key is configured
        if not SENDGRID_API_KEY or SENDGRID_API_KEY == 'your_sendgrid_api_key_here':
            logger.warning("SendGrid API key not configured, skipping email send")
            return {
                'success': False, 
                'error': 'Email service not configured. Please set SENDGRID_API_KEY in .env file'
            }
        
        # Create email content
        subject = f"Your {APP_NAME} Verification Code"
        
        # HTML email template
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Helvetica', sans-serif;
                    line-height: 1.6;
                    color: #1D1D1F;
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                .container {{
                    background: #FFFFFF;
                    border-radius: 12px;
                    padding: 40px;
                    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
                }}
                .header {{
                    text-align: center;
                    margin-bottom: 30px;
                }}
                .logo {{
                    font-size: 32px;
                    font-weight: 700;
                    color: #007AFF;
                }}
                .otp-code {{
                    background: #F5F5F7;
                    border: 2px solid #007AFF;
                    border-radius: 8px;
                    padding: 20px;
                    text-align: center;
                    margin: 30px 0;
                }}
                .otp-code h2 {{
                    font-size: 36px;
                    letter-spacing: 8px;
                    color: #007AFF;
                    margin: 0;
                }}
                .footer {{
                    text-align: center;
                    margin-top: 30px;
                    padding-top: 20px;
                    border-top: 1px solid #E8E8ED;
                    color: #86868B;
                    font-size: 14px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <div class="logo">🛡️ {APP_NAME}</div>
                    <h1>Email Verification</h1>
                </div>
                
                <p>Hi {full_name},</p>
                
                <p>Thank you for signing up for {APP_NAME}! To complete your registration, please verify your email address using the code below:</p>
                
                <div class="otp-code">
                    <h2>{otp_code}</h2>
                </div>
                
                <p>This verification code will expire in 15 minutes for security purposes.</p>
                
                <p>If you didn't create an account with {APP_NAME}, you can safely ignore this email.</p>
                
                <div class="footer">
                    <p>© 2025 {APP_NAME}. Real-Time AI/ML-Based Phishing Detection System.</p>
                    <p>This is an automated message, please do not reply to this email.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Plain text version
        text_content = f"""
        Hi {full_name},
        
        Thank you for signing up for {APP_NAME}!
        
        Your verification code is: {otp_code}
        
        This code will expire in 15 minutes.
        
        If you didn't create an account, you can safely ignore this email.
        
        © 2025 {APP_NAME}
        """
        
        # Create SendGrid message
        message = Mail(
            from_email=Email(SENDGRID_FROM_EMAIL, SENDGRID_FROM_NAME),
            to_emails=To(to_email),
            subject=subject,
            plain_text_content=Content("text/plain", text_content),
            html_content=Content("text/html", html_content)
        )
        
        # Send email
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)
        
        logger.info(f"OTP email sent to {to_email}, status code: {response.status_code}")
        
        return {'success': True}
    
    except Exception as e:
        logger.error(f"Failed to send OTP email to {to_email}: {str(e)}")
        return {'success': False, 'error': str(e)}


def send_welcome_email(to_email, full_name):
    """
    Send welcome email after successful verification
    
    Args:
        to_email: Recipient email address
        full_name: User's full name
    
    Returns:
        dict: {'success': bool, 'error': str (if failed)}
    """
    try:
        if not SENDGRID_API_KEY or SENDGRID_API_KEY == 'your_sendgrid_api_key_here':
            logger.warning("SendGrid API key not configured, skipping welcome email")
            return {'success': False, 'error': 'Email service not configured'}
        
        subject = f"Welcome to {APP_NAME}!"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Helvetica', sans-serif;
                    line-height: 1.6;
                    color: #1D1D1F;
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                .container {{
                    background: #FFFFFF;
                    border-radius: 12px;
                    padding: 40px;
                    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
                }}
                .header {{
                    text-align: center;
                    margin-bottom: 30px;
                }}
                .logo {{
                    font-size: 32px;
                    font-weight: 700;
                    color: #007AFF;
                }}
                .btn {{
                    display: inline-block;
                    background: #007AFF;
                    color: white;
                    padding: 12px 24px;
                    border-radius: 8px;
                    text-decoration: none;
                    margin: 20px 0;
                }}
                .features {{
                    margin: 30px 0;
                }}
                .feature {{
                    margin: 15px 0;
                    padding-left: 30px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <div class="logo">🛡️ {APP_NAME}</div>
                    <h1>Welcome Aboard!</h1>
                </div>
                
                <p>Hi {full_name},</p>
                
                <p>Your email has been verified successfully! You're now part of the {APP_NAME} community.</p>
                
                <div class="features">
                    <h3>What you can do now:</h3>
                    <div class="feature">🔗 Scan URLs for phishing threats</div>
                    <div class="feature">📧 Analyze suspicious emails</div>
                    <div class="feature">📱 Check SMS messages for scams</div>
                    <div class="feature">📊 View your scan history and statistics</div>
                </div>
                
                <center>
                    <a href="{APP_URL}/scan.html" class="btn">Start Scanning Now</a>
                </center>
                
                <p>Stay safe online!</p>
                
                <div style="text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #E8E8ED; color: #86868B; font-size: 14px;">
                    <p>© 2025 {APP_NAME}. Real-Time AI/ML-Based Phishing Detection System.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        message = Mail(
            from_email=Email(SENDGRID_FROM_EMAIL, SENDGRID_FROM_NAME),
            to_emails=To(to_email),
            subject=subject,
            html_content=Content("text/html", html_content)
        )
        
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)
        
        logger.info(f"Welcome email sent to {to_email}, status code: {response.status_code}")
        
        return {'success': True}
    
    except Exception as e:
        logger.error(f"Failed to send welcome email to {to_email}: {str(e)}")
        return {'success': False, 'error': str(e)}


# Test function
if __name__ == '__main__':
    print("Testing SendGrid Email Service...")
    print(f"API Key configured: {bool(SENDGRID_API_KEY and SENDGRID_API_KEY != 'your_sendgrid_api_key_here')}")
    print(f"From Email: {SENDGRID_FROM_EMAIL}")
    
    # Test OTP email (replace with your email for testing)
    test_email = input("Enter your email to test OTP delivery (or press Enter to skip): ").strip()
    if test_email:
        result = send_otp_email(test_email, "Test User", "123456")
        print(f"Result: {result}")
