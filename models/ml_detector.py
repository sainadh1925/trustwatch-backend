"""
ML Detection Engine
Combines URL and text analysis to provide final threat assessment
"""
from .url_analyzer import URLAnalyzer
from .text_analyzer import TextAnalyzer

class MLDetector:
    def __init__(self):
        self.url_analyzer = URLAnalyzer()
        self.text_analyzer = TextAnalyzer()
        
        # Threat score thresholds
        self.thresholds = {
            'low': 25,
            'medium': 50,
            'high': 75,
            'critical': 100
        }
    
    def detect_url(self, url):
        """
        Detect phishing in URL
        Returns: comprehensive threat assessment
        """
        # Analyze URL
        url_results = self.url_analyzer.analyze(url)
        
        # Calculate final score
        threat_score = min(url_results['score'], 100)
        
        # Determine risk level
        risk_level = self._calculate_risk_level(threat_score)
        
        # Determine if phishing
        is_phishing = threat_score >= self.thresholds['medium']
        
        return {
            'type': 'url',
            'content': url,
            'threat_score': threat_score,
            'risk_level': risk_level,
            'is_phishing': is_phishing,
            'confidence': self._calculate_confidence(threat_score),
            'indicators': url_results['indicators'],
            'details': url_results['details'],
            'recommendation': self._get_recommendation(risk_level)
        }
    
    def detect_text(self, text, language='english'):
        """
        Detect phishing in text content
        Returns: comprehensive threat assessment
        """
        # Analyze text
        text_results = self.text_analyzer.analyze(text, language)
        
        # Check if text contains URLs
        if 'urls' in text_results.get('details', {}):
            # Analyze embedded URLs
            url_scores = []
            for url in text_results['details']['urls']:
                url_result = self.url_analyzer.analyze(url)
                url_scores.append(url_result['score'])
            
            # Add average URL score to text score
            if url_scores:
                avg_url_score = sum(url_scores) / len(url_scores)
                text_results['score'] += avg_url_score * 0.5
        
        # Calculate final score
        threat_score = min(text_results['score'], 100)
        
        # Determine risk level
        risk_level = self._calculate_risk_level(threat_score)
        
        # Determine if phishing
        is_phishing = threat_score >= self.thresholds['medium']
        
        return {
            'type': 'text',
            'content': text[:100] + '...' if len(text) > 100 else text,
            'threat_score': threat_score,
            'risk_level': risk_level,
            'is_phishing': is_phishing,
            'confidence': self._calculate_confidence(threat_score),
            'indicators': text_results['indicators'],
            'details': text_results['details'],
            'language': language,
            'recommendation': self._get_recommendation(risk_level)
        }
    
    def detect_sms(self, sms_text, language='english'):
        """
        Detect phishing in SMS
        Returns: comprehensive threat assessment
        """
        # SMS analysis is similar to text analysis but with stricter rules
        result = self.detect_text(sms_text, language)
        result['type'] = 'sms'
        
        # SMS phishing often has shorter messages with URLs
        if len(sms_text) < 100 and 'urls' in result.get('details', {}):
            result['threat_score'] += 15
            result['indicators'].append('Short message with URL (common in SMS phishing)')
        
        # Recalculate risk level
        result['threat_score'] = min(result['threat_score'], 100)
        result['risk_level'] = self._calculate_risk_level(result['threat_score'])
        result['is_phishing'] = result['threat_score'] >= self.thresholds['medium']
        result['confidence'] = self._calculate_confidence(result['threat_score'])
        result['recommendation'] = self._get_recommendation(result['risk_level'])
        
        return result
    
    def _calculate_risk_level(self, score):
        """Calculate risk level from threat score"""
        if score >= self.thresholds['critical']:
            return 'Critical'
        elif score >= self.thresholds['high']:
            return 'High'
        elif score >= self.thresholds['medium']:
            return 'Medium'
        else:
            return 'Low'
    
    def _calculate_confidence(self, score):
        """Calculate confidence percentage"""
        # Confidence increases with score
        if score >= 75:
            return 95
        elif score >= 50:
            return 85
        elif score >= 25:
            return 70
        else:
            return 60
    
    def _get_recommendation(self, risk_level):
        """Get user recommendation based on risk level"""
        recommendations = {
            'Critical': 'DO NOT INTERACT! This is highly likely a phishing attempt. Block and report immediately.',
            'High': 'AVOID! Strong indicators of phishing. Do not click any links or provide information.',
            'Medium': 'CAUTION! Suspicious content detected. Verify sender authenticity before proceeding.',
            'Low': 'Appears safe, but always verify sender and be cautious with sensitive information.'
        }
        return recommendations.get(risk_level, 'Unable to determine')
