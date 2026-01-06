"""
Text Analysis Module
Analyzes text content (emails, SMS) for phishing indicators
"""
import re
from collections import Counter

class TextAnalyzer:
    def __init__(self):
        # Phishing keywords in multiple languages
        self.phishing_keywords = {
            'english': [
                'urgent', 'verify', 'suspended', 'locked', 'confirm', 'update',
                'click here', 'act now', 'limited time', 'expire', 'account',
                'password', 'credit card', 'bank', 'security', 'alert',
                'winner', 'prize', 'congratulations', 'claim', 'free',
                'refund', 'tax', 'payment', 'invoice', 'billing'
            ],
            'hindi': [
                'तुरंत', 'सत्यापित', 'निलंबित', 'लॉक', 'पुष्टि', 'अपडेट',
                'यहाँ क्लिक करें', 'अभी कार्य करें', 'खाता', 'पासवर्ड',
                'बैंक', 'सुरक्षा', 'चेतावनी', 'विजेता', 'पुरस्कार'
            ],
            'tamil': [
                'அவசரம்', 'சரிபார்', 'இடைநிறுத்தப்பட்டது', 'பூட்டப்பட்டது',
                'உறுதிப்படுத்து', 'புதுப்பிப்பு', 'கணக்கு', 'கடவுச்சொல்'
            ],
            'telugu': [
                'అత్యవసరం', 'ధృవీకరించు', 'నిలిపివేయబడింది', 'లాక్',
                'నిర్ధారించు', 'నవీకరణ', 'ఖాతా', 'పాస్వర్డ్'
            ]
        }
        
        # Urgency indicators
        self.urgency_words = [
            'urgent', 'immediately', 'now', 'asap', 'hurry', 'quick',
            'expire', 'deadline', 'limited', 'act now', 'last chance'
        ]
        
        # Financial keywords
        self.financial_words = [
            'bank', 'credit card', 'payment', 'money', 'transfer',
            'account', 'refund', 'tax', 'invoice', 'billing', 'paypal'
        ]
        
    def analyze(self, text, language='english'):
        """
        Main text analysis function
        Returns: dict with analysis results
        """
        results = {
            'text_length': len(text),
            'indicators': [],
            'score': 0,
            'details': {},
            'language': language
        }
        
        text_lower = text.lower()
        
        # Check for phishing keywords
        keyword_matches = []
        for lang, keywords in self.phishing_keywords.items():
            for keyword in keywords:
                if keyword in text_lower or keyword in text:
                    keyword_matches.append(keyword)
        
        if keyword_matches:
            results['indicators'].append(f'Found {len(keyword_matches)} phishing keywords')
            results['score'] += len(keyword_matches) * 5
            results['details']['keywords'] = keyword_matches[:5]  # Top 5
        
        # Check for urgency
        urgency_count = sum(1 for word in self.urgency_words if word in text_lower)
        if urgency_count > 0:
            results['indicators'].append(f'Contains {urgency_count} urgency indicators')
            results['score'] += urgency_count * 10
        
        # Check for financial keywords
        financial_count = sum(1 for word in self.financial_words if word in text_lower)
        if financial_count >= 2:
            results['indicators'].append(f'Contains {financial_count} financial keywords')
            results['score'] += financial_count * 8
        
        # Check for URLs in text
        urls = self._extract_urls(text)
        if urls:
            results['indicators'].append(f'Contains {len(urls)} URL(s)')
            results['score'] += len(urls) * 10
            results['details']['urls'] = urls
        
        # Check for excessive capitalization
        if text.isupper() and len(text) > 20:
            results['indicators'].append('Excessive capitalization (ALL CAPS)')
            results['score'] += 15
        
        # Check for excessive exclamation marks
        exclamation_count = text.count('!')
        if exclamation_count > 2:
            results['indicators'].append(f'Excessive exclamation marks ({exclamation_count})')
            results['score'] += 10
        
        # Check for suspicious patterns
        if re.search(r'\b(click here|click now|verify now|update now)\b', text_lower):
            results['indicators'].append('Suspicious call-to-action detected')
            results['score'] += 20
        
        # Check for credential requests
        credential_patterns = [
            r'(enter|provide|verify|confirm).*(password|pin|otp|code)',
            r'(username|user id).*(password|pin)',
            r'(credit card|card number|cvv|expiry)'
        ]
        
        for pattern in credential_patterns:
            if re.search(pattern, text_lower):
                results['indicators'].append('Requests sensitive credentials')
                results['score'] += 30
                break
        
        # Check for poor grammar/spelling (simplified check)
        if self._check_poor_grammar(text):
            results['indicators'].append('Possible poor grammar detected')
            results['score'] += 10
        
        # Check for brand impersonation
        brands = ['google', 'facebook', 'amazon', 'microsoft', 'apple', 'paypal', 'bank']
        brand_mentions = [brand for brand in brands if brand in text_lower]
        if brand_mentions:
            results['details']['mentioned_brands'] = brand_mentions
            # If brand mentioned with urgency, higher score
            if urgency_count > 0:
                results['indicators'].append('Brand impersonation with urgency')
                results['score'] += 25
        
        return results
    
    def _extract_urls(self, text):
        """Extract URLs from text"""
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        return re.findall(url_pattern, text)
    
    def _check_poor_grammar(self, text):
        """Simple grammar check (looks for common mistakes)"""
        # Check for multiple spaces
        if '  ' in text:
            return True
        
        # Check for missing spaces after punctuation
        if re.search(r'[.,!?][a-zA-Z]', text):
            return True
        
        return False
