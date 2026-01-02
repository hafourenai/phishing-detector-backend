"""Content detector using BS4."""
import requests
from bs4 import BeautifulSoup
from typing import Dict, Any, List

from app.config import config
from app.detectors.base import BaseDetector
from app.models import DetectionResult
from app.utils.logger import get_logger

logger = get_logger(__name__)

PHISHING_KEYWORDS = {
    "high_risk": ["login", "verify", "secure", "update", "confirm", "password", "account", "banking", 
                  "authentication", "validation", "authorize", "credential", "signin", "signon"],
    "medium_risk": ["free", "bonus", "gift", "prize", "winner", "claim", "urgent", "suspended",
                   "limited", "offer", "discount", "exclusive", "alert", "warning"],
    "low_risk": ["click", "update", "renew", "access", "service", "support", "help", "notification"]
}

class ContentDetector(BaseDetector):
    """Detector analyzing page content for phishing indicators."""
    
    def __init__(self):
        super().__init__(name="content")
        self.timeout = config.request_timeout
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        }
        
    async def detect(self, url: str, **kwargs) -> DetectionResult:
        """Perform content analysis based on server.py logic."""
        try:
            response = requests.get(url, timeout=self.timeout, headers=self.headers, allow_redirects=True)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            score = 0.0
            issues = []
            features = {
                'has_login_form': False,
                'has_password_field': False,
                'has_credit_card_field': False,
                'has_hidden_elements': False,
                'external_scripts': 0,
                'iframe_count': 0,
                'redirect_count': len(response.history),
                'final_url': response.url
            }
            
            # Form Analysis
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '').lower()
                if any(k in action for k in ['login', 'signin', 'auth', 'authenticate']):
                    features['has_login_form'] = True
                    score += 20
                
                if form.find('input', {'type': 'password'}):
                    features['has_password_field'] = True
                    score += 15
                
                if form.find('input', {'name': ['card', 'credit', 'cvv', 'expiry']}):
                    features['has_credit_card_field'] = True
                    score += 25
            
            # Iframe Analysis
            iframes = soup.find_all('iframe')
            features['iframe_count'] = len(iframes)
            for iframe in iframes:
                style = iframe.get('style', '').lower()
                if 'display:none' in style or 'visibility:hidden' in style:
                    features['has_hidden_elements'] = True
                    score += 30
                    if "Ditemukan hidden iframe (teknik phishing umum)" not in issues:
                        issues.append("Hidden iframe detected (common phishing technique).")
            
            # Script Analysis
            scripts = soup.find_all('script', src=True)
            features['external_scripts'] = len(scripts)
            for script in scripts:
                src = script.get('src', '').lower()
                if 'telegram' in src or 't.me' in src:
                    score += 15
                    if "Script mengandung referensi Telegram yang mencurigakan" not in issues:
                        issues.append("Suspicious Telegram script references found.")
            
            # Keyword Analysis
            text_content = soup.get_text().lower()
            found_keywords = []
            for category, keywords in PHISHING_KEYWORDS.items():
                for kw in keywords:
                    if kw in text_content:
                        found_keywords.append(kw)
            
            if found_keywords:
                score += len(set(found_keywords)) * 2
                issues.append(f"Phishing keywords found: {', '.join(list(set(found_keywords))[:5])}")
            
            if features['redirect_count'] > 2:
                score += 10
                issues.append(f"Excessive redirects detected ({features['redirect_count']}).")
                
            return self._create_result(
                score=min(score, 100.0),
                issues=issues,
                details=features
            )
            
        except Exception as e:
            return self._create_result(
                score=0.0,
                success=False,
                issues=["Could not analyze page content."]
            )
