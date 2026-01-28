"""
Feature extraction for ML model - 48 Features.

Matches training feature order from feature_columns.joblib
"""
import re
import tldextract
import ipaddress
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any
from app.utils.logger import get_logger

logger = get_logger(__name__)


class FeatureExtractor:
    """Extract 48 features from URL for ML model (trained offline)."""
    
    # Sensitive words commonly used in phishing
    SENSITIVE_WORDS = [
        'login', 'signin', 'account', 'update', 'confirm', 'verify',
        'secure', 'banking', 'password', 'paypal', 'ebay', 'amazon'
    ]
    
    # Brand names often spoofed
    BRAND_NAMES = [
        'paypal', 'amazon', 'ebay', 'apple', 'microsoft', 'google',
        'facebook', 'instagram', 'netflix', 'bank', 'wells', 'chase'
    ]
    
    @staticmethod
    def extract(url: str) -> Dict[str, Any]:
        """
        Extract all 48 features from URL.
        
        Note: Some features require HTML content analysis which is not done
        for performance reasons. These features use safe default values.
        
        Returns:
            Dictionary with 48 features in exact training order
        """
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        query = parsed.query
        
        try:
            extracted = tldextract.extract(url)
        except Exception:
            extracted = None
        
        # Feature extraction
        features = {}
        
        # 1. NumDots - Number of dots in URL
        features['NumDots'] = url.count('.')
        
        # 2. SubdomainLevel - Number of subdomains
        if extracted:
            subdomain = extracted.subdomain
            features['SubdomainLevel'] = subdomain.count('.') + 1 if subdomain else 0
        else:
            features['SubdomainLevel'] = 0
        
        # 3. PathLevel - Number of path components
        path_parts = [p for p in path.split('/') if p]
        features['PathLevel'] = len(path_parts)
        
        # 4. UrlLength - Total URL length
        features['UrlLength'] = len(url)
        
        # 5. NumDash - Number of dashes in URL
        features['NumDash'] = url.count('-')
        
        # 6. NumDashInHostname - Number of dashes in hostname
        features['NumDashInHostname'] = domain.count('-')
        
        # 7. AtSymbol - Has @ symbol (suspicious)
        features['AtSymbol'] = 1 if '@' in url else 0
        
        # 8. TildeSymbol - Has ~ symbol
        features['TildeSymbol'] = 1 if '~' in url else 0
        
        # 9. NumUnderscore - Number of underscores
        features['NumUnderscore'] = url.count('_')
        
        # 10. NumPercent - Number of % symbols
        features['NumPercent'] = url.count('%')
        
        # 11. NumQueryComponents - Number of query parameters
        query_params = parse_qs(query)
        features['NumQueryComponents'] = len(query_params)
        
        # 12. NumAmpersand - Number of & symbols
        features['NumAmpersand'] = url.count('&')
        
        # 13. NumHash - Number of # symbols
        features['NumHash'] = url.count('#')
        
        # 14. NumNumericChars - Number of digits in URL
        features['NumNumericChars'] = sum(c.isdigit() for c in url)
        
        # 15. NoHttps - Not using HTTPS (1 = no HTTPS)
        features['NoHttps'] = 0 if url.startswith('https') else 1
        
        # 16. RandomString - Has random-looking string (heuristic)
        # Check for long alphanumeric strings
        random_pattern = r'[a-zA-Z0-9]{20,}'
        features['RandomString'] = 1 if re.search(random_pattern, url) else 0
        
        # 17. IpAddress - Using IP address instead of domain
        features['IpAddress'] = 1 if FeatureExtractor._is_ip(domain) else 0
        
        # 18. DomainInSubdomains - Domain name appears in subdomain
        if extracted and extracted.domain:
            features['DomainInSubdomains'] = 1 if extracted.domain in (extracted.subdomain or '') else 0
        else:
            features['DomainInSubdomains'] = 0
        
        # 19. DomainInPaths - Domain name appears in path
        if extracted and extracted.domain:
            features['DomainInPaths'] = 1 if extracted.domain in path else 0
        else:
            features['DomainInPaths'] = 0
        
        # 20. HttpsInHostname - "https" appears in hostname (suspicious)
        features['HttpsInHostname'] = 1 if 'https' in domain.lower() else 0
        
        # 21. HostnameLength - Length of hostname
        features['HostnameLength'] = len(domain)
        
        # 22. PathLength - Length of path
        features['PathLength'] = len(path)
        
        # 23. QueryLength - Length of query string
        features['QueryLength'] = len(query)
        
        # 24. DoubleSlashInPath - Has // in path (not protocol)
        features['DoubleSlashInPath'] = 1 if '//' in path else 0
        
        # 25. NumSensitiveWords - Count of sensitive keywords
        url_lower = url.lower()
        features['NumSensitiveWords'] = sum(1 for word in FeatureExtractor.SENSITIVE_WORDS if word in url_lower)
        
        # 26. EmbeddedBrandName - Contains brand name (potential spoofing)
        features['EmbeddedBrandName'] = 1 if any(brand in url_lower for brand in FeatureExtractor.BRAND_NAMES) else 0
        
        # === HTML-based features (require page content - using safe defaults for URL-only analysis) ===
        # For production with actual HTML scraping, these would be extracted from page content
        
        # 27. PctExtHyperlinks - % of external hyperlinks (default: 0 = safe)
        features['PctExtHyperlinks'] = 0.0
        
        # 28. PctExtResourceUrls - % of external resources (default: 0 = safe)
        features['PctExtResourceUrls'] = 0.0
        
        # 29. ExtFavicon - External favicon (default: 0 = safe)
        features['ExtFavicon'] = 0
        
        # 30. InsecureForms - Has insecure forms (default: 0 = safe)
        features['InsecureForms'] = 0
        
        # 31. RelativeFormAction - Has relative form action (default: 0 = safe)
        features['RelativeFormAction'] = 0
        
        # 32. ExtFormAction - Has external form action (default: 0 = safe)
        features['ExtFormAction'] = 0
        
        # 33. AbnormalFormAction - Has abnormal form action (default: 0 = safe)
        features['AbnormalFormAction'] = 0
        
        # 34. PctNullSelfRedirectHyperlinks - % of null/self-redirect links (default: 0 = safe)
        features['PctNullSelfRedirectHyperlinks'] = 0.0
        
        # 35. FrequentDomainNameMismatch - Frequent domain mismatches (default: 0 = safe)
        features['FrequentDomainNameMismatch'] = 0
        
        # 36. FakeLinkInStatusBar - Fake links in status bar (default: 0 = safe)
        features['FakeLinkInStatusBar'] = 0
        
        # 37. RightClickDisabled - Right click disabled (default: 0 = safe)
        features['RightClickDisabled'] = 0
        
        # 38. PopUpWindow - Has pop-up windows (default: 0 = safe)
        features['PopUpWindow'] = 0
        
        # 39. SubmitInfoToEmail - Submits to email (default: 0 = safe)
        features['SubmitInfoToEmail'] = 0
        
        # 40. IframeOrFrame - Contains iframe/frame (default: 0 = safe)
        features['IframeOrFrame'] = 0
        
        # 41. MissingTitle - Missing page title (default: 0 = safe)
        features['MissingTitle'] = 0
        
        # 42. ImagesOnlyInForm - Images only in forms (default: 0 = safe)
        features['ImagesOnlyInForm'] = 0
        
        # 43. SubdomainLevelRT - Subdomain level (risk threshold) - same as SubdomainLevel
        features['SubdomainLevelRT'] = features['SubdomainLevel']
        
        # 44. UrlLengthRT - URL length (risk threshold)
        # 1 if very long (> 75 chars), 0 otherwise
        features['UrlLengthRT'] = 1 if features['UrlLength'] > 75 else 0
        
        # 45. PctExtResourceUrlsRT - Same as PctExtResourceUrls
        features['PctExtResourceUrlsRT'] = features['PctExtResourceUrls']
        
        # 46. AbnormalExtFormActionR - Same as AbnormalFormAction
        features['AbnormalExtFormActionR'] = features['AbnormalFormAction']
        
        # 47. ExtMetaScriptLinkRT - External meta/script/link tags (default: 0 = safe)
        features['ExtMetaScriptLinkRT'] = 0
        
        # 48. PctExtNullSelfRedirectHyperlinksRT - Same as PctNullSelfRedirectHyperlinks
        features['PctExtNullSelfRedirectHyperlinksRT'] = features['PctNullSelfRedirectHyperlinks']
        
        return features
    
    @staticmethod
    def _is_ip(domain: str) -> bool:
        """Check if domain is an IP address."""
        try:
            # Remove port if present
            ip_part = domain.split(':')[0]
            ipaddress.ip_address(ip_part)
            return True
        except ValueError:
            return False
