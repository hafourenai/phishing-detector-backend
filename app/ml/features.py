"""Feature extraction for ML model."""
import re
import tldextract
import ipaddress
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any

from app.utils.logger import get_logger

logger = get_logger(__name__)


class FeatureExtractor:
    """Extract features from URL for ML model."""
    
    @staticmethod
    def extract(url: str) -> Dict[str, Any]:
        """
        Extract all features from URL according to UCI dataset format (30 features).
        Values are typically 1 (legitimate), 0 (suspicious), -1 (phishing).
        """
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        
        try:
            extracted = tldextract.extract(domain)
        except:
            extracted = None

        # Helper to check if IP
        is_ip = 1 if FeatureExtractor._has_ip(domain) else -1
        
        # URL Length
        url_len = len(url)
        url_feature = 1 if url_len < 54 else (0 if 54 <= url_len <= 75 else -1)
        
        # Short URL (TinyURL etc)
        short_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                        r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                        r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snip\.li|fig\.sh|loopt\.us|" \
                        r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                        r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                        r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                        r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                        r"tr\.im|link\.zip\.net"
        is_short = -1 if re.search(short_services, url) else 1

        # Features
        features = {
            'UsingIP': is_ip,
            'LongURL': url_feature,
            'ShortURL': is_short,
            'Symbol@': -1 if "@" in url else 1,
            'Redirecting//': -1 if url.rfind("//") > 7 else 1,
            'PrefixSuffix-': -1 if "-" in domain else 1,
            'SubDomains': FeatureExtractor._subdomain_feature(extracted),
            'HTTPS': 1 if url.startswith('https') else -1,
            'DomainRegLen': 1,  # Default safe
            'Favicon': 1,       # Default safe
            'NonStdPort': -1 if parsed.port and parsed.port not in [80, 443] else 1,
            'HTTPSDomainURL': -1 if "https" in domain else 1,
            'RequestURL': 1,    # Placeholder
            'AnchorURL': 1,     # Placeholder
            'LinksInScriptTags': 1, # Placeholder
            'ServerFormHandler': 1, # Placeholder
            'InfoEmail': -1 if "mailto:" in url or "mail()" in url else 1,
            'AbnormalURL': 1 if domain in url else -1,
            'WebsiteForwarding': -1 if url.count("//") > 1 else 1,
            'StatusBarCust': 1,   # Default safe
            'DisableRightClick': 1, # Default safe
            'UsingPopupWindow': 1,  # Default safe
            'IframeRedirection': 1, # Default safe
            'AgeofDomain': 1,      # Default safe
            'DNSRecording': 1,     # Default safe
            'WebsiteTraffic': 0,   # Default suspicious/neutral
            'PageRank': 0,         # Default neutral
            'GoogleIndex': 1,      # Default safe
            'LinksPointingToPage': 0, # Default neutral
            'StatsReport': 1       # Default safe
        }
        
        return features

    @staticmethod
    def _has_ip(domain: str) -> bool:
        """Check if domain is an IP address."""
        try:
            ip_part = domain.split(':')[0]
            ipaddress.ip_address(ip_part)
            return True
        except:
            return False

    @staticmethod
    def _subdomain_feature(extracted) -> int:
        if not extracted: return -1
        s = extracted.subdomain
        if not s: return 1
        dots = s.count('.')
        if dots == 0: return 0 # suspicious
        return -1 # phishing (2+ subdomains)
