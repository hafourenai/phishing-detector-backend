"""Visual detector using Playwright headless Chromium browser."""
import asyncio
import os
from typing import List
from urllib.parse import urlparse

from app.config import config
from app.detectors.base import BaseDetector
from app.models import DetectionResult
from app.utils.logger import get_logger

logger = get_logger(__name__)

# Ensure Playwright can find the installed browser in Docker
os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", "/app/.playwright-browsers")

# Popular brands to check for impersonation.
# Key = brand identifier, Value = list of keywords to match in page title.
POPULAR_BRANDS = {
    "google": ["google", "gmail", "youtube"],
    "facebook": ["facebook", "fb"],
    "instagram": ["instagram"],
    "whatsapp": ["whatsapp"],
    "apple": ["apple", "icloud", "itunes"],
    "microsoft": ["microsoft", "outlook", "office365", "hotmail"],
    "paypal": ["paypal"],
    "amazon": ["amazon"],
    "netflix": ["netflix"],
    # Indonesian banks & e-wallets — high-value targets
    "bca": ["bca", "bank central asia", "klikbca"],
    "mandiri": ["bank mandiri", "mandiri", "livin"],
    "bri": ["bank rakyat", "bri", "brimo"],
    "bni": ["bank negara", "bni"],
    "cimb": ["cimb", "octo mobile"],
    "gopay": ["gopay", "gojek"],
    "ovo": ["ovo"],
    "dana": ["dana"],
    "shopee": ["shopee", "shopeepay"],
    "tokopedia": ["tokopedia"],
    "bukalapak": ["bukalapak"],
}

# Inline JS patterns that are commonly abused in phishing pages
SUSPICIOUS_JS_PATTERNS = [
    "window.location.replace(",
    "window.location.href =",
    "document.write(",
    "eval(",
    "atob(",
    "String.fromCharCode(",
]

# Chromium launch args tuned for memory-constrained free-tier environments
CHROMIUM_ARGS = [
    "--no-sandbox",
    "--disable-dev-shm-usage",   # Use /tmp instead of /dev/shm (important in Docker)
    "--disable-gpu",
    "--disable-extensions",
    "--disable-background-networking",
    "--disable-default-apps",
    "--disable-sync",
    "--no-first-run",
    "--mute-audio",
    "--disable-notifications",
    "--disable-popup-blocking",
]


class VisualDetector(BaseDetector):
    """
    Detector that uses a real Playwright Chromium browser to analyze URLs.

    Unlike ContentDetector (which parses raw HTML), this detector:
    - Executes JavaScript (catches JS-rendered content)
    - Follows redirects and captures the final URL
    - Detects brand impersonation via page title
    - Identifies suspicious JS behavior in inline scripts

    Only activated when the caller passes deep_scan=True.
    """

    def __init__(self):
        super().__init__(name="visual")
        # Timeout in milliseconds for Playwright page.goto()
        self._timeout_ms = config.visual_analysis_timeout * 1000

    async def detect(self, url: str, **kwargs) -> DetectionResult:
        """
        Perform visual analysis using headless Chromium.

        Args:
            url: URL to analyze
            **kwargs: Unused, kept for interface compatibility

        Returns:
            DetectionResult with visual analysis findings
        """
        if not config.visual_analysis_enabled:
            return self._create_result(
                score=0.0,
                success=False,
                issues=[],
                details={"skipped": True, "reason": "VISUAL_ANALYSIS_ENABLED is False"},
            )

        # Graceful fallback if Playwright is not installed
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            logger.warning("Playwright not installed. Skipping visual analysis.")
            return self._create_result(
                score=0.0,
                success=False,
                issues=[],
                details={"error": "playwright_not_installed"},
            )

        score = 0.0
        issues: List[str] = []
        details = {
            "final_url": url,
            "redirected": False,
            "page_title": None,
            "brand_impersonation": None,
            "has_password_field": False,
            "favicon_mismatch": False,
            "suspicious_js": False,
            "suspicious_js_patterns": [],
            "hidden_elements_count": 0,
        }

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,
                    args=CHROMIUM_ARGS,
                )
                context = await browser.new_context(
                    user_agent=(
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/120.0.0.0 Safari/537.36"
                    ),
                    ignore_https_errors=True,  # SSL is checked by SSLDetector
                    viewport={"width": 1280, "height": 720},
                )
                page = await context.new_page()

                try:
                    await page.goto(
                        url,
                        wait_until="domcontentloaded",
                        timeout=self._timeout_ms,
                    )

                    original_domain = urlparse(url).netloc.lower()

                    # --- Check 1: Redirect Chain ---
                    final_url = page.url
                    details["final_url"] = final_url
                    final_domain = urlparse(final_url).netloc.lower()

                    if final_domain and original_domain != final_domain:
                        details["redirected"] = True
                        score += 30
                        issues.append(
                            f"URL dialihkan ke domain berbeda: {final_domain}"
                        )

                    # Use final_domain as reference for subsequent checks
                    active_domain = final_domain or original_domain

                    # --- Check 2: Brand Impersonation via Page Title ---
                    title = await page.title()
                    details["page_title"] = title
                    title_lower = title.lower()

                    for brand, keywords in POPULAR_BRANDS.items():
                        brand_in_title = any(kw in title_lower for kw in keywords)
                        brand_in_domain = any(kw in active_domain for kw in keywords)

                        if brand_in_title and not brand_in_domain:
                            details["brand_impersonation"] = brand
                            score += 40
                            issues.append(
                                f"Peniruan brand '{brand.upper()}' terdeteksi: "
                                f"judul halaman mengklaim sebagai '{brand}' "
                                f"namun domain '{active_domain}' tidak cocok."
                            )
                            break  # One impersonation finding is enough

                    # --- Check 3: JS-Rendered Password Field ---
                    password_fields = await page.query_selector_all(
                        'input[type="password"]'
                    )
                    if password_fields:
                        details["has_password_field"] = True
                        score += 20
                        issues.append(
                            "Form login dengan field password terdeteksi "
                            "(hasil render JavaScript, lebih akurat dari analisis HTML statis)."
                        )

                    # --- Check 4: Favicon Domain Mismatch ---
                    favicon_href = await page.evaluate("""() => {
                        const selectors = [
                            'link[rel="icon"]',
                            'link[rel="shortcut icon"]',
                            'link[rel*="icon"]'
                        ];
                        for (const sel of selectors) {
                            const el = document.querySelector(sel);
                            if (el && el.href) return el.href;
                        }
                        return null;
                    }""")

                    if favicon_href:
                        favicon_domain = urlparse(favicon_href).netloc.lower()
                        if favicon_domain and favicon_domain != active_domain:
                            details["favicon_mismatch"] = True
                            score += 15
                            issues.append(
                                f"Favicon berasal dari domain berbeda ({favicon_domain}), "
                                "teknik umum dalam halaman phishing."
                            )

                    # --- Check 5: Suspicious Inline JavaScript Patterns ---
                    inline_js = await page.evaluate("""() => {
                        return Array.from(
                            document.querySelectorAll('script:not([src])')
                        ).map(s => s.textContent).join(' ');
                    }""")

                    found_patterns = [
                        pat for pat in SUSPICIOUS_JS_PATTERNS if pat in inline_js
                    ]
                    if found_patterns:
                        details["suspicious_js"] = True
                        details["suspicious_js_patterns"] = found_patterns
                        score += 15
                        issues.append(
                            f"Pola JavaScript mencurigakan ditemukan: "
                            f"{', '.join(found_patterns[:3])}"
                        )

                    # --- Check 6: Excessive Hidden Elements ---
                    hidden_count: int = await page.evaluate("""() => {
                        return document.querySelectorAll(
                            '[style*="display:none"],[style*="display: none"],' +
                            '[style*="visibility:hidden"],[style*="visibility: hidden"],' +
                            '[hidden]'
                        ).length;
                    }""")
                    details["hidden_elements_count"] = hidden_count
                    if hidden_count > 10:
                        score += 10
                        issues.append(
                            f"Jumlah elemen tersembunyi berlebihan ({hidden_count} elemen), "
                            "teknik umum untuk menyembunyikan konten phishing."
                        )

                finally:
                    # Always release browser resources, even if an error occurred
                    await page.close()
                    await context.close()
                    await browser.close()

        except asyncio.TimeoutError:
            logger.warning(f"Visual analysis timed out for {url[:60]}")
            # Timeout itself is slightly suspicious (bot-blocking behavior)
            return self._create_result(
                score=10.0,
                success=False,
                issues=[
                    "Situs tidak merespons dalam batas waktu analisis visual. "
                    "Kemungkinan memblokir akses bot/scanner."
                ],
                details=details,
            )

        except Exception as e:
            logger.error(f"Visual detection error for {url[:60]}: {str(e)}")
            return self._create_result(
                score=0.0,
                success=False,
                issues=[],
                details={**details, "error": str(e)[:200]},
            )

        return self._create_result(
            score=min(score, 100.0),
            issues=issues,
            details=details,
        )
