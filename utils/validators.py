"""
Input validation utilities
"""
import re
import validators

def validate_url(url):
    """Validate URL format"""
    if not url:
        return False, "URL cannot be empty"
    
    # Add http:// if no protocol specified
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    if validators.url(url):
        return True, url
    else:
        return False, "Invalid URL format"

def validate_text(text):
    """Validate text content"""
    if not text or len(text.strip()) == 0:
        return False, "Text cannot be empty"
    
    if len(text) > 10000:
        return False, "Text too long (max 10000 characters)"
    
    return True, text.strip()

def extract_domain(url):
    """Extract domain from URL"""
    try:
        # Remove protocol
        domain = re.sub(r'^https?://', '', url)
        # Remove path
        domain = domain.split('/')[0]
        # Remove port
        domain = domain.split(':')[0]
        # Remove www
        domain = re.sub(r'^www\.', '', domain)
        return domain.lower()
    except:
        return None

def extract_urls_from_text(text):
    """Extract all URLs from text"""
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls = re.findall(url_pattern, text)
    return urls
