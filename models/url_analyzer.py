"""
URL Analysis Module
Analyzes URLs for phishing indicators
"""
import re
import requests
from urllib.parse import urlparse
from datetime import datetime
import socket

class URLAnalyzer:
    def __init__(self):
        # Suspicious keywords commonly found in phishing URLs
        self.suspicious_keywords = [
            'login', 'signin', 'account', 'verify', 'secure', 'update',
            'banking', 'paypal', 'amazon', 'microsoft', 'apple',
            'suspended', 'locked', 'confirm', 'urgent', 'alert'
        ]
        
        # Suspicious TLDs
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
        
    def analyze(self, url):
        """
        Main analysis function
        Returns: dict with analysis results
        """
        results = {
            'url': url,
            'indicators': [],
            'score': 0,
            'details': {}
        }
        
        # Parse URL
        try:
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path.split('/')[0]
            results['domain'] = domain
        except:
            results['indicators'].append('Invalid URL format')
            results['score'] += 30
            return results
        
        # Check URL length (phishing URLs are often long)
        if len(url) > 75:
            results['indicators'].append('Unusually long URL')
            results['score'] += 15
        
        # Check for IP address instead of domain
        if self._is_ip_address(domain):
            results['indicators'].append('Uses IP address instead of domain')
            results['score'] += 25
        
        # Check for suspicious keywords
        keyword_count = sum(1 for keyword in self.suspicious_keywords if keyword in url.lower())
        if keyword_count >= 2:
            results['indicators'].append(f'Contains {keyword_count} suspicious keywords')
            results['score'] += keyword_count * 10
        
        # Check for suspicious TLD
        for tld in self.suspicious_tlds:
            if url.lower().endswith(tld) or tld in url.lower():
                results['indicators'].append(f'Suspicious TLD: {tld}')
                results['score'] += 20
                break
        
        # Check for excessive subdomains
        subdomain_count = domain.count('.')
        if subdomain_count > 3:
            results['indicators'].append(f'Excessive subdomains ({subdomain_count})')
            results['score'] += 15
        
        # Check for @ symbol (URL obfuscation)
        if '@' in url:
            results['indicators'].append('Contains @ symbol (URL obfuscation)')
            results['score'] += 25
        
        # Check for double slashes in path
        if url.count('//') > 1:
            results['indicators'].append('Multiple // in URL')
            results['score'] += 10
        
        # Check for homoglyph attacks (similar looking characters)
        if self._check_homoglyphs(domain):
            results['indicators'].append('Possible homoglyph attack detected')
            results['score'] += 30
        
        # Check for HTTPS
        if not url.startswith('https://'):
            results['indicators'].append('No HTTPS encryption')
            results['score'] += 20
        
        # Check URL shorteners
        shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly']
        if any(shortener in domain.lower() for shortener in shorteners):
            results['indicators'].append('URL shortener detected')
            results['score'] += 15
        
        # Check for excessive hyphens
        if domain.count('-') > 3:
            results['indicators'].append('Excessive hyphens in domain')
            results['score'] += 10
        
        results['details']['domain'] = domain
        results['details']['protocol'] = parsed.scheme
        results['details']['path'] = parsed.path
        
        return results
    
    def _is_ip_address(self, domain):
        """Check if domain is an IP address"""
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        return bool(re.match(ip_pattern, domain))
    
    def _check_homoglyphs(self, domain):
        """Check for common homoglyph attacks"""
        # Common brand names to check
        brands = ['google', 'facebook', 'amazon', 'microsoft', 'apple', 'paypal']
        
        # Common homoglyphs
        homoglyphs = {
            'o': ['0', 'ο', 'о'],  # o, zero, greek omicron, cyrillic o
            'a': ['а', 'α'],        # a, cyrillic a, greek alpha
            'e': ['е', 'ε'],        # e, cyrillic e, greek epsilon
            'i': ['і', 'ι', '1'],   # i, cyrillic i, greek iota, one
            'l': ['1', 'ӏ'],        # l, one, cyrillic palochka
        }
        
        domain_lower = domain.lower()
        
        for brand in brands:
            if brand in domain_lower and brand != domain_lower:
                # Check if it's a slight variation
                for char, variants in homoglyphs.items():
                    for variant in variants:
                        if variant in domain_lower:
                            return True
        
        return False
