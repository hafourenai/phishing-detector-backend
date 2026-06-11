import re
import tldextract
import ipaddress
import itertools
from urllib.parse import urlparse, parse_qs, urljoin
from typing import Dict, Any, Optional
from bs4 import BeautifulSoup
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
    def extract(
        url: str,
        soup: Optional[BeautifulSoup] = None,
        response=None,
        domain_age_days: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Return a unified feature dict covering all three dataset schemas.

        Args:
            url: The URL to analyze.
            soup: Optional BeautifulSoup object from fetched page content.
                  When provided, HTML-dependent features are extracted from it.
            response: Optional requests.Response object. Used for redirect tracking.
            domain_age_days: Optional domain age in days from WHOIS lookup.

        Returns:
            Dictionary of extracted features.
        """
        features: Dict[str, Any] = {}
        features.update(FeatureExtractor._extract_dataset_b(url))
        features.update(FeatureExtractor._extract_dataset_a(url, domain_age_days=domain_age_days))
        features.update(FeatureExtractor._extract_dataset_c(url))

        if soup is not None:
            html_features = FeatureExtractor._extract_html_features(url, soup, response)
            features.update(html_features)

        return features


    @staticmethod
    def _extract_dataset_a(url: str, domain_age_days: Optional[int] = None) -> Dict[str, Any]:
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

        # 9. DomainRegLen  – domain registration length
        #    If WHOIS data available, use actual domain age.
        #    Otherwise proxy: registered domain length ≤ 6 chars ≈ new domain.
        if domain_age_days is not None:
            f['DomainRegLen'] = 0 if domain_age_days >= 365 else 1
        else:
            registered_domain = extracted.domain if extracted and extracted.domain else domain.split('.')[0] if domain else ''
            f['DomainRegLen'] = 0 if len(registered_domain) <= 6 else 1

        # 10. Favicon  – filled by HTML extraction when available
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

        # 15–16. HTML-only signals – filled by HTML extraction when available
        f['LinksInScriptTags'] = 0
        f['ServerFormHandler'] = 0

        # 17. InfoEmail
        f['InfoEmail'] = 1 if 'mailto:' in url.lower() else 0

        # 18. AbnormalURL  – IP used as hostname
        f['AbnormalURL'] = 1 if FeatureExtractor._is_ip(domain) else 0

        # 19. WebsiteForwarding  – multiple // occurrences
        f['WebsiteForwarding'] = 1 if url.count('//') > 1 else 0

        # 20–23. JS / HTML-only signals – filled by HTML extraction when available
        f['StatusBarCust'] = 0
        f['DisableRightClick'] = 0
        f['UsingPopupWindow'] = 0
        f['IframeRedirection'] = 0

        # 24. AgeofDomain  – domain age in years
        #     If WHOIS data available, use actual age.
        #     Otherwise proxy: registered domain label ≤ 4 chars ≈ new domain.
        if domain_age_days is not None:
            f['AgeofDomain'] = 0 if domain_age_days >= 365 else 1
        else:
            registered_label = extracted.domain if extracted and extracted.domain else ''
            f['AgeofDomain'] = 0 if len(registered_label) <= 4 else 1

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
    def _extract_html_features(url: str, soup: BeautifulSoup, response=None) -> Dict[str, Any]:
        """Extract HTML-dependent features from a BeautifulSoup object.

        Fills in features that are otherwise defaulted to 0 across all
        three dataset schemas.
        """
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        f: Dict[str, Any] = {}

        # Helper: is a URL external to the main domain?
        def _is_external(href: str) -> bool:
            if not href:
                return False
            try:
                h_parsed = urlparse(urljoin(url, href))
                return bool(h_parsed.netloc) and h_parsed.netloc.lower() != domain
            except Exception:
                return False

        # --- Dataset A HTML features ---
        # Favicon
        icon_link = soup.find('link', rel=lambda v: v and 'icon' in v.lower()) if hasattr(soup, 'find') else None
        f['Favicon'] = 1 if icon_link is not None else 0

        # LinksInScriptTags
        script_tags = soup.find_all('script', src=True) if hasattr(soup, 'find_all') else []
        f['LinksInScriptTags'] = len(script_tags)

        # ServerFormHandler
        forms = soup.find_all('form') if hasattr(soup, 'find_all') else []
        f['ServerFormHandler'] = 0
        for form in forms:
            action = form.get('action', '')
            if action and _is_external(action):
                f['ServerFormHandler'] = 1
                break

        # StatusBarCust / FakeLinkInStatusBar
        has_onmouseover = False
        for tag in soup.find_all(attrs={'onmouseover': True}) if hasattr(soup, 'find_all') else []:
            has_onmouseover = True
            break
        f['StatusBarCust'] = 1 if has_onmouseover else 0
        f['FakeLinkInStatusBar'] = f['StatusBarCust']

        # DisableRightClick / RightClickDisabled
        has_contextmenu = False
        for tag in soup.find_all(attrs={'oncontextmenu': True}) if hasattr(soup, 'find_all') else []:
            has_contextmenu = True
            break
        f['DisableRightClick'] = 1 if has_contextmenu else 0
        f['RightClickDisabled'] = f['DisableRightClick']

        # UsingPopupWindow / PopUpWindow
        text_lower = soup.get_text().lower() if hasattr(soup, 'get_text') else ''
        has_popup = 'window.open' in text_lower or 'showmodal' in text_lower
        f['UsingPopupWindow'] = 1 if has_popup else 0
        f['PopUpWindow'] = f['UsingPopupWindow']

        # IframeRedirection / IframeOrFrame / NoOfiFrame
        iframes = soup.find_all(['iframe', 'frame']) if hasattr(soup, 'find_all') else []
        f['IframeRedirection'] = 1 if len(iframes) > 0 else 0
        f['IframeOrFrame'] = f['IframeRedirection']
        f['NoOfiFrame'] = len(iframes)

        # --- Dataset A metadata-only features (use URL heuristics + HTML) ---
        # WebsiteTraffic - unavailable without external API, keep 0
        f['WebsiteTraffic'] = 0
        # PageRank - unavailable, keep 0
        f['PageRank'] = 0
        # GoogleIndex - assume indexed (can't verify without API)
        f['GoogleIndex'] = 1
        # LinksPointingToPage - unavailable, keep 0
        f['LinksPointingToPage'] = 0
        # StatsReport - unavailable, keep 0
        f['StatsReport'] = 0
        # DNSRecording - assume valid DNS
        f['DNSRecording'] = 1

        # --- Dataset B HTML features ---
        # PctExtHyperlinks
        all_links = soup.find_all('a', href=True) if hasattr(soup, 'find_all') else []
        total_links = len(all_links)
        ext_links = sum(1 for a in all_links if _is_external(a['href'])) if total_links > 0 else 0
        f['PctExtHyperlinks'] = round(ext_links / total_links, 4) if total_links > 0 else 0.0

        # PctExtResourceUrls
        resource_tags = []
        for tag in soup.find_all(['link', 'script', 'img'], href=True) if hasattr(soup, 'find_all') else []:
            resource_tags.append(tag['href'])
        for tag in soup.find_all(['script', 'img'], src=True) if hasattr(soup, 'find_all') else []:
            resource_tags.append(tag['src'])
        total_resources = len(resource_tags)
        ext_resources = sum(1 for r in resource_tags if _is_external(r)) if total_resources > 0 else 0
        f['PctExtResourceUrls'] = round(ext_resources / total_resources, 4) if total_resources > 0 else 0.0

        # ExtFavicon
        f['ExtFavicon'] = 1 if (icon_link and _is_external(icon_link.get('href', ''))) else 0

        # InsecureForms
        f['InsecureForms'] = 0
        for form in forms:
            action = form.get('action', '').lower()
            if action.startswith('http://'):
                f['InsecureForms'] = 1
                break

        # RelativeFormAction
        f['RelativeFormAction'] = 0
        for form in forms:
            action = form.get('action', '')
            if action and not action.startswith('http') and not action.startswith('//'):
                f['RelativeFormAction'] = 1
                break

        # ExtFormAction
        f['ExtFormAction'] = f['ServerFormHandler']

        # AbnormalFormAction / AbnormalExtFormActionR
        f['AbnormalFormAction'] = 0
        for form in forms:
            action = form.get('action', '')
            if action and ('<script' in action.lower() or 'javascript:' in action.lower() or action == '#'):
                f['AbnormalFormAction'] = 1
                break
        f['AbnormalExtFormActionR'] = f['AbnormalFormAction']

        # PctNullSelfRedirectHyperlinks & RT variant
        null_self = 0
        for a in all_links:
            href = a['href'].lower().strip()
            if not href or href == '#' or href.startswith('javascript:') or href == domain or href == '/' or href == '':
                null_self += 1
        f['PctNullSelfRedirectHyperlinks'] = round(null_self / total_links, 4) if total_links > 0 else 0.0
        f['PctExtNullSelfRedirectHyperlinksRT'] = f['PctNullSelfRedirectHyperlinks']

        # FrequentDomainNameMismatch
        f['FrequentDomainNameMismatch'] = 0
        for a in all_links:
            href = a.get('href', '')
            if href and _is_external(href) and not href.startswith('mailto:'):
                f['FrequentDomainNameMismatch'] = 1
                break

        # SubmitInfoToEmail
        f['SubmitInfoToEmail'] = 0
        for form in forms:
            action = form.get('action', '').lower()
            if 'mailto:' in action:
                f['SubmitInfoToEmail'] = 1
                break

        # MissingTitle
        title_tag = soup.find('title') if hasattr(soup, 'find') else None
        f['MissingTitle'] = 0 if (title_tag and title_tag.get_text(strip=True)) else 1

        # ImagesOnlyInForm
        f['ImagesOnlyInForm'] = 0
        for form in forms:
            inputs = form.find_all('input')
            images = form.find_all('img')
            if inputs and all(inp.get('type') == 'image' for inp in inputs) and len(images) > 0:
                f['ImagesOnlyInForm'] = 1
                break

        # ExtMetaScriptLinkRT
        meta_scripts = soup.find_all('meta', attrs={'http-equiv': True}) if hasattr(soup, 'find_all') else []
        ext_meta = sum(1 for m in meta_scripts if _is_external(m.get('content', '')))
        f['ExtMetaScriptLinkRT'] = 1 if ext_meta > 0 else 0

        # --- Dataset C HTML features ---
        # LineOfCode
        html_str = str(soup)
        f['LineOfCode'] = html_str.count('\n') + 1

        # LargestLineLength
        lines = html_str.split('\n')
        f['LargestLineLength'] = max(len(l) for l in lines) if lines else 0

        # HasTitle
        f['HasTitle'] = 1 if title_tag and title_tag.get_text(strip=True) else 0

        # DomainTitleMatchScore
        title_text = title_tag.get_text(strip=True).lower() if title_tag else ''
        domain_parts = domain.replace('www.', '').split('.')
        main_domain = domain_parts[0] if domain_parts else ''
        if title_text and main_domain:
            f['DomainTitleMatchScore'] = 1 if main_domain in title_text else 0
        else:
            f['DomainTitleMatchScore'] = 0

        # URLTitleMatchScore
        url_lower = url.lower()
        if title_text:
            f['URLTitleMatchScore'] = 1 if any(word in url_lower for word in title_text.split()) else 0
        else:
            f['URLTitleMatchScore'] = 0

        # HasFavicon
        f['HasFavicon'] = f['Favicon']

        # Robots
        robots_link = soup.find('link', rel='search', href=True) if hasattr(soup, 'find') else None
        if not robots_link:
            robots_link = soup.find('a', href=lambda v: v and 'robots.txt' in v.lower())
        f['Robots'] = 1 if robots_link else 0

        # IsResponsive
        has_viewport = soup.find('meta', attrs={'name': 'viewport'}) if hasattr(soup, 'find') else None
        f['IsResponsive'] = 1 if has_viewport else 0

        # NoOfURLRedirect
        f['NoOfURLRedirect'] = len(response.history) if response and hasattr(response, 'history') else 0

        # NoOfSelfRedirect
        self_redirects = 0
        if response and hasattr(response, 'history'):
            for resp in response.history:
                if resp.url and domain in resp.url.lower():
                    self_redirects += 1
        f['NoOfSelfRedirect'] = self_redirects

        # HasDescription
        meta_desc = soup.find('meta', attrs={'name': 'description'}) if hasattr(soup, 'find') else None
        f['HasDescription'] = 1 if (meta_desc and meta_desc.get('content', '').strip()) else 0

        # NoOfPopup
        popup_count = 0
        for script in script_tags:
            script_text = script.string or ''
            if 'window.open' in script_text or 'showModalDialog' in script_text:
                popup_count += 1
        f['NoOfPopup'] = popup_count

        # HasExternalFormSubmit
        f['HasExternalFormSubmit'] = f['ServerFormHandler']

        # HasSocialNet
        social_domains = ('facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com', 'youtube.com')
        f['HasSocialNet'] = 0
        for a in all_links:
            href = a.get('href', '').lower()
            if any(sd in href for sd in social_domains):
                f['HasSocialNet'] = 1
                break

        # HasSubmitButton
        submit_btn = soup.find('input', {'type': 'submit'}) if hasattr(soup, 'find') else None
        if not submit_btn:
            submit_btn = soup.find('button', {'type': 'submit'}) if hasattr(soup, 'find') else None
        f['HasSubmitButton'] = 1 if submit_btn else 0

        # HasHiddenFields
        hidden_inputs = soup.find_all('input', {'type': 'hidden'}) if hasattr(soup, 'find_all') else []
        f['HasHiddenFields'] = 1 if len(hidden_inputs) > 0 else 0

        # HasPasswordField
        password_input = soup.find('input', {'type': 'password'}) if hasattr(soup, 'find') else None
        f['HasPasswordField'] = 1 if password_input else 0

        # HasCopyrightInfo
        f['HasCopyrightInfo'] = 1 if 'copyright' in text_lower or '©' in text_lower else 0

        # NoOfImage
        images = soup.find_all('img') if hasattr(soup, 'find_all') else []
        f['NoOfImage'] = len(images)

        # NoOfCSS
        css_links = soup.find_all('link', rel='stylesheet') if hasattr(soup, 'find_all') else []
        f['NoOfCSS'] = len(css_links)

        # NoOfJS
        f['NoOfJS'] = len(script_tags)

        # NoOfSelfRef
        self_refs = 0
        for a in all_links:
            href = a.get('href', '')
            if href and (domain in href.lower() or href.startswith('/') or href.startswith('#')):
                self_refs += 1
        f['NoOfSelfRef'] = self_refs

        # NoOfEmptyRef
        empty_refs = sum(1 for a in all_links if not a.get('href', '').strip() or a['href'] == '#')
        f['NoOfEmptyRef'] = empty_refs

        # NoOfExternalRef
        f['NoOfExternalRef'] = ext_links

        return f

    @staticmethod
    def _is_ip(domain: str) -> bool:
        """Return True if *domain* is an IPv4 or IPv6 address."""
        try:
            ipaddress.ip_address(domain.split(':')[0])
            return True
        except ValueError:
            return False