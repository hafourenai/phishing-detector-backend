"""Heuristic detector."""
import re
import tldextract
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any, List

from app.detectors.base import BaseDetector
from app.models import DetectionResult

PHISHING_KEYWORDS = {
    "high_risk": ["login", "verify", "secure", "update", "confirm", "password", "account", "banking", 
                  "authentication", "validation", "authorize", "credential", "signin", "signon"],
    "medium_risk": ["free", "bonus", "gift", "prize", "winner", "claim", "urgent", "suspended",
                   "limited", "offer", "discount", "exclusive", "alert", "warning"],
    "low_risk": ["click", "update", "renew", "access", "service", "support", "help", "notification"]
}

KNOWN_PHISHING_DOMAINS = [
    "appleid-apple.com", "facebook-login.com", "google-verify.com", "paypal-secure.com",
    "whatsapp-update.com", "instagram-confirm.com", "twitter-account.com", "amazon-verify.com"
]

SHORTENERS = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'is.gd', 'buff.ly', 'shorturl.at']
SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.info', '.biz']
POPULAR_DOMAINS = ['google', 'facebook', 'paypal', 'apple', 'amazon', 'microsoft', 'twitter', 'instagram']

class HeuristicDetector(BaseDetector):
    """Detector for URL heuristics and patterns."""
    
    def __init__(self):
        super().__init__(name="heuristic")
        
    async def detect(self, url: str, **kwargs) -> DetectionResult:
        """Perform heuristic analysis based on server.py logic."""
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        score = 0.0
        issues = []
        
        # 1. URL/Domain Length
        if len(domain) > 50:
            score += 20
            issues.append(f"Domain name is unusually long ({len(domain)} chars).")
            
        # 2. Subdomain count
        try:
            ext = tldextract.extract(domain)
            subdomain_count = len(ext.subdomain.split('.')) if ext.subdomain else 0
            if subdomain_count >= 3:
                score += 15
                issues.append(f"Excessive number of subdomains ({subdomain_count}).")
        except:
            subdomain_count = 0
            
        # 3. Special characters
        special_chars = sum(1 for c in domain if not c.isalnum() and c not in '.-')
        if special_chars >= 3:
            score += 10
            issues.append("High number of special characters in domain.")
            
        # 4. Suspicious TLD
        if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
            score += 25
            issues.append(f"Suspicious TLD detected: {ext.suffix if 'ext' in locals() else 'unknown'}")
            
        # 5. Keywords in domain
        for risk, keywords in PHISHING_KEYWORDS.items():
            weight = {'high_risk': 10, 'medium_risk': 5, 'low_risk': 2}[risk]
            for kw in keywords:
                if kw in domain:
                    score += weight
                    issues.append(f"Suspicious keyword '{kw}' found in domain.")
                    break
                    
        # 6. Typosquatting
        for target in POPULAR_DOMAINS:
            if target in domain and domain != f"{target}.com" and domain != f"www.{target}.com":
                if len(domain) - len(target) <= 5:
                    score += 30
                    issues.append(f"Possible typosquatting targeting {target}.")
                    break
                    
        # 7. IP Address usage
        import ipaddress
        try:
            ip_part = domain.split(':')[0]
            ipaddress.ip_address(ip_part)
            score += 40
            issues.append("URL uses numeric IP address instead of domain name.")
        except:
            pass
            
        # 8. Shorteners
        if any(s in domain for s in SHORTENERS):
            score += 20
            issues.append("URL shortener service used (may obscure destination).")
            
        # 9. Sensitive parameters
        params = parse_qs(parsed.query)
        sensitive = ['password', 'token', 'auth', 'key', 'secret', 'credit', 'card', 'cvv']
        found_params = [p for p in sensitive if p in params]
        if found_params:
            score += 25
            issues.append(f"Sensitive parameters found in URL: {', '.join(found_params)}")
            
        # 10. Known Phishing Database
        for d in KNOWN_PHISHING_DOMAINS:
            if d in domain:
                score += 50
                issues.append("Domain matches known phishing patterns.")
                break
                
        return self._create_result(
            score=min(score, 100.0),
            issues=issues,
            details={
                "domain": domain,
                "subdomain_count": subdomain_count,
                "special_chars": special_chars
            }
        )
