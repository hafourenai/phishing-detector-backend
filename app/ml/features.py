import re
import tldextract
import ipaddress
import itertools
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any
from app.utils.logger import get_logger

logger = get_logger(__name__)


class FeatureExtractor:

    SENSITIVE_WORDS = [
        'login', 'signin', 'account', 'update', 'confirm', 'verify',
        'secure', 'banking', 'password', 'paypal', 'ebay', 'amazon'
    ]

    BRAND_NAMES = [
        'paypal', 'amazon', 'ebay', 'apple', 'microsoft', 'google',
        'facebook', 'instagram', 'netflix', 'bank', 'wells', 'chase'
    ]

    LEGITIMATE_TLDS = {
        'com', 'org', 'net', 'edu', 'gov', 'co', 'io', 'uk', 'us',
        'ca', 'au', 'de', 'fr', 'jp', 'br', 'in', 'it', 'es', 'nl'
    }

    @staticmethod
    def extract(url: str) -> Dict[str, Any]:
        """Return a unified feature dict covering all three dataset schemas."""
        features: Dict[str, Any] = {}
        features.update(FeatureExtractor._extract_dataset_b(url))
        features.update(FeatureExtractor._extract_dataset_a(url))
        features.update(FeatureExtractor._extract_dataset_c(url))
        return features


    @staticmethod
    def _extract_dataset_a(url: str) -> Dict[str, Any]:
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path

        try:
            extracted = tldextract.extract(url)
        except Exception:
            extracted = None

        f: Dict[str, Any] = {}

        # 1. UsingIP
        f['UsingIP'] = 1 if FeatureExtractor._is_ip(domain) else 0

        # 2. LongURL  (> 75 chars)
        f['LongURL'] = 1 if len(url) > 75 else 0

        # 3. ShortURL  (< 20 chars – possible URL shortener)
        f['ShortURL'] = 1 if len(url) < 20 else 0

        # 4. Symbol@
        f['Symbol@'] = 1 if '@' in url else 0

        # 5. Redirecting//  – double-slash in path
        f['Redirecting//'] = 1 if '//' in path else 0

        # 6. PrefixSuffix-  – dash in domain
        f['PrefixSuffix-'] = 1 if '-' in domain else 0

        # 7. SubDomains  – more than one subdomain level
        if extracted:
            sub = extracted.subdomain or ''
            sub_count = sub.count('.') + 1 if sub else 0
        else:
            sub_count = 0
        f['SubDomains'] = 1 if sub_count > 1 else 0

        # 8. HTTPS
        f['HTTPS'] = 1 if url.startswith('https') else 0

        # 9. DomainRegLen  – proxy: short domain ≈ newly registered
        f['DomainRegLen'] = 0 if len(domain) <= 6 else 1

        # 10. Favicon  – can't check without HTML fetch
        f['Favicon'] = 0

        # 11. NonStdPort
        port = parsed.port
        f['NonStdPort'] = 1 if (port and port not in (80, 443)) else 0

        # 12. HTTPSDomainURL  – "https" text inside the domain part
        f['HTTPSDomainURL'] = 1 if 'https' in domain.lower() else 0

        # 13. RequestURL  – many query params → external requests heuristic
        f['RequestURL'] = 1 if len(parse_qs(parsed.query)) > 3 else 0

        # 14. AnchorURL
        f['AnchorURL'] = 1 if '#' in url else 0

        # 15–16. HTML-only signals
        f['LinksInScriptTags'] = 0
        f['ServerFormHandler'] = 0

        # 17. InfoEmail
        f['InfoEmail'] = 1 if 'mailto:' in url.lower() else 0

        # 18. AbnormalURL  – IP used as hostname
        f['AbnormalURL'] = 1 if FeatureExtractor._is_ip(domain) else 0

        # 19. WebsiteForwarding  – multiple // occurrences
        f['WebsiteForwarding'] = 1 if url.count('//') > 1 else 0

        # 20–23. JS / HTML-only signals
        f['StatusBarCust'] = 0
        f['DisableRightClick'] = 0
        f['UsingPopupWindow'] = 0
        f['IframeRedirection'] = 0

        # 24. AgeofDomain  – proxy: very short first label ≈ new domain
        first_label = domain.split('.')[0] if domain else ''
        f['AgeofDomain'] = 0 if len(first_label) <= 4 else 1

        # 25–30. Live-lookup signals (can't check at runtime without external APIs)
        f['DNSRecording'] = 1       # assume valid DNS
        f['WebsiteTraffic'] = 0
        f['PageRank'] = 0
        f['GoogleIndex'] = 1        # assume indexed
        f['LinksPointingToPage'] = 0
        f['StatsReport'] = 0

        return f


    @staticmethod
    def _extract_dataset_b(url: str) -> Dict[str, Any]:
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        query = parsed.query

        try:
            extracted = tldextract.extract(url)
        except Exception:
            extracted = None

        f: Dict[str, Any] = {}
        url_lower = url.lower()

        f['NumDots'] = url.count('.')

        if extracted:
            subdomain = extracted.subdomain
            f['SubdomainLevel'] = subdomain.count('.') + 1 if subdomain else 0
        else:
            f['SubdomainLevel'] = 0

        path_parts = [p for p in path.split('/') if p]
        f['PathLevel'] = len(path_parts)
        f['UrlLength'] = len(url)
        f['NumDash'] = url.count('-')
        f['NumDashInHostname'] = domain.count('-')
        f['AtSymbol'] = 1 if '@' in url else 0
        f['TildeSymbol'] = 1 if '~' in url else 0
        f['NumUnderscore'] = url.count('_')
        f['NumPercent'] = url.count('%')

        query_params = parse_qs(query)
        f['NumQueryComponents'] = len(query_params)
        f['NumAmpersand'] = url.count('&')
        f['NumHash'] = url.count('#')
        f['NumNumericChars'] = sum(c.isdigit() for c in url)
        f['NoHttps'] = 0 if url.startswith('https') else 1

        random_pattern = r'[a-zA-Z0-9]{20,}'
        f['RandomString'] = 1 if re.search(random_pattern, url) else 0
        f['IpAddress'] = 1 if FeatureExtractor._is_ip(domain) else 0

        if extracted and extracted.domain:
            f['DomainInSubdomains'] = 1 if extracted.domain in (extracted.subdomain or '') else 0
            f['DomainInPaths'] = 1 if extracted.domain in path else 0
        else:
            f['DomainInSubdomains'] = 0
            f['DomainInPaths'] = 0

        f['HttpsInHostname'] = 1 if 'https' in domain.lower() else 0
        f['HostnameLength'] = len(domain)
        f['PathLength'] = len(path)
        f['QueryLength'] = len(query)
        f['DoubleSlashInPath'] = 1 if '//' in path else 0
        f['NumSensitiveWords'] = sum(1 for w in FeatureExtractor.SENSITIVE_WORDS if w in url_lower)
        f['EmbeddedBrandName'] = 1 if any(b in url_lower for b in FeatureExtractor.BRAND_NAMES) else 0

        # HTML-derived – safe defaults
        f['PctExtHyperlinks'] = 0.0
        f['PctExtResourceUrls'] = 0.0
        f['ExtFavicon'] = 0
        f['InsecureForms'] = 0
        f['RelativeFormAction'] = 0
        f['ExtFormAction'] = 0
        f['AbnormalFormAction'] = 0
        f['PctNullSelfRedirectHyperlinks'] = 0.0
        f['FrequentDomainNameMismatch'] = 0
        f['FakeLinkInStatusBar'] = 0
        f['RightClickDisabled'] = 0
        f['PopUpWindow'] = 0
        f['SubmitInfoToEmail'] = 0
        f['IframeOrFrame'] = 0
        f['MissingTitle'] = 0
        f['ImagesOnlyInForm'] = 0

        # Risk-threshold variants
        f['SubdomainLevelRT'] = f['SubdomainLevel']
        f['UrlLengthRT'] = 1 if f['UrlLength'] > 75 else 0
        f['PctExtResourceUrlsRT'] = f['PctExtResourceUrls']
        f['AbnormalExtFormActionR'] = f['AbnormalFormAction']
        f['ExtMetaScriptLinkRT'] = 0
        f['PctExtNullSelfRedirectHyperlinksRT'] = f['PctNullSelfRedirectHyperlinks']

        return f

    @staticmethod
    def _extract_dataset_c(url: str) -> Dict[str, Any]:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path
        query = parsed.query

        try:
            extracted = tldextract.extract(url)
        except Exception:
            extracted = None

        f: Dict[str, Any] = {}
        url_lower = url.lower()

        # --- URL structure ---
        f['URLLength'] = len(url)

        domain_only = domain.split(':')[0]
        f['DomainLength'] = len(domain_only)

        f['IsDomainIP'] = 1 if FeatureExtractor._is_ip(domain) else 0

        brand_hits = sum(1 for b in FeatureExtractor.BRAND_NAMES if b in url_lower)
        f['URLSimilarityIndex'] = round(brand_hits / len(FeatureExtractor.BRAND_NAMES), 4)

        # Longest run of identical consecutive characters / URL length
        max_run = max(
            (len(list(g)) for _, g in itertools.groupby(url)),
            default=1
        )
        f['CharContinuationRate'] = round(max_run / max(len(url), 1), 4)

        tld = (extracted.suffix if extracted else '').lower().lstrip('.')
        f['TLDLegitimateProb'] = 1 if tld in FeatureExtractor.LEGITIMATE_TLDS else 0

        alnum = sum(c.isalnum() for c in url)
        f['URLCharProb'] = round(alnum / max(len(url), 1), 4)

        f['TLDLength'] = len(tld)

        if extracted:
            sub = extracted.subdomain or ''
            f['NoOfSubDomain'] = sub.count('.') + 1 if sub else 0
        else:
            f['NoOfSubDomain'] = 0

        # Obfuscation (percent-encoding)
        f['HasObfuscation'] = 1 if '%' in url else 0
        f['NoOfObfuscatedChar'] = url.count('%')
        f['ObfuscationRatio'] = round(url.count('%') / max(len(url), 1), 4)

        # Character composition
        letters = sum(c.isalpha() for c in url)
        digits = sum(c.isdigit() for c in url)
        f['NoOfLettersInURL'] = letters
        f['LetterRatioInURL'] = round(letters / max(len(url), 1), 4)
        f['NoOfDegitsInURL'] = digits
        f['DegitRatioInURL'] = round(digits / max(len(url), 1), 4)

        f['NoOfEqualsInURL'] = url.count('=')
        f['NoOfQMarkInURL'] = url.count('?')
        f['NoOfAmpersandInURL'] = url.count('&')
        other_special = sum(
            1 for c in url if not c.isalnum() and c not in r'/:.-_?=&#%@~+'
        )
        f['NoOfOtherSpecialCharsInURL'] = other_special
        special_total = sum(1 for c in url if not c.isalnum())
        f['SpacialCharRatioInURL'] = round(special_total / max(len(url), 1), 4)

        f['IsHTTPS'] = 1 if url.startswith('https') else 0

        # HTML-derived signals – safe defaults (require page fetch)
        f['LineOfCode'] = 0
        f['LargestLineLength'] = 0
        f['HasTitle'] = 0
        f['DomainTitleMatchScore'] = 0
        f['URLTitleMatchScore'] = 0
        f['HasFavicon'] = 0
        f['Robots'] = 0
        f['IsResponsive'] = 0
        f['NoOfURLRedirect'] = 0
        f['NoOfSelfRedirect'] = 0
        f['HasDescription'] = 0
        f['NoOfPopup'] = 0
        f['NoOfiFrame'] = 0
        f['HasExternalFormSubmit'] = 0
        f['HasSocialNet'] = 0
        f['HasSubmitButton'] = 0
        f['HasHiddenFields'] = 0
        f['HasPasswordField'] = 0

        # Keyword flags (URL-only)
        f['Bank'] = 1 if 'bank' in url_lower else 0
        f['Pay'] = 1 if 'pay' in url_lower else 0
        f['Crypto'] = 1 if any(
            w in url_lower for w in ('crypto', 'bitcoin', 'btc', 'eth', 'wallet')
        ) else 0
        f['HasCopyrightInfo'] = 0

        f['NoOfImage'] = 0
        f['NoOfCSS'] = 0
        f['NoOfJS'] = 0
        f['NoOfSelfRef'] = 0
        f['NoOfEmptyRef'] = 0
        f['NoOfExternalRef'] = 0

        return f


    @staticmethod
    def _is_ip(domain: str) -> bool:
        """Return True if *domain* is an IPv4 or IPv6 address."""
        try:
            ipaddress.ip_address(domain.split(':')[0])
            return True
        except ValueError:
            return False