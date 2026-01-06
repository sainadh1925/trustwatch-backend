"""
Threat Intelligence Module
Manages threat feeds and blacklist checking
"""
from datetime import datetime
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from database.db import check_blacklist

class ThreatIntelligence:
    def __init__(self):
        # Known phishing patterns
        self.known_patterns = [
            'verify-account',
            'secure-login',
            'update-payment',
            'confirm-identity',
            'suspended-account'
        ]
        
        # Known malicious domains (sample)
        self.malicious_domains = [
            'phishing-example.com',
            'malicious-bank.com',
            'fake-login.net',
            'scam-alert.org'
        ]
    
    def check_threat(self, url_or_domain):
        """
        Check if URL/domain is in threat database
        Returns: threat info if found, None otherwise
        """
        # Extract domain from URL if needed
        domain = self._extract_domain(url_or_domain)
        
        # Check database blacklist
        db_result = check_blacklist(domain)
        if db_result:
            return {
                'found': True,
                'source': 'database',
                'category': db_result.get('category'),
                'severity': 'Critical',
                'description': f'Domain {domain} is in blacklist'
            }
        
        # Check in-memory malicious domains
        if domain in self.malicious_domains:
            return {
                'found': True,
                'source': 'threat_feed',
                'category': 'phishing',
                'severity': 'Critical',
                'description': f'Domain {domain} is known malicious'
            }
        
        # Check for known patterns
        for pattern in self.known_patterns:
            if pattern in url_or_domain.lower():
                return {
                    'found': True,
                    'source': 'pattern_matching',
                    'category': 'suspicious_pattern',
                    'severity': 'High',
                    'description': f'Contains known phishing pattern: {pattern}'
                }
        
        return None
    
    def get_threat_score(self, threat_info):
        """
        Calculate threat score from threat intelligence
        Returns: score (0-50)
        """
        if not threat_info or not threat_info.get('found'):
            return 0
        
        severity_scores = {
            'Critical': 50,
            'High': 35,
            'Medium': 20,
            'Low': 10
        }
        
        return severity_scores.get(threat_info.get('severity'), 0)
    
    def _extract_domain(self, url):
        """Extract domain from URL"""
        import re
        # Remove protocol
        domain = re.sub(r'^https?://', '', url)
        # Remove path
        domain = domain.split('/')[0]
        # Remove port
        domain = domain.split(':')[0]
        # Remove www
        domain = re.sub(r'^www\.', '', domain)
        return domain.lower()
