import asyncio
import requests
import tldextract
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from app.config import config
from app.detectors.base import BaseDetector
from app.models import DetectionResult
from app.utils.logger import get_logger

logger = get_logger(__name__)

_RDAP_URL = "https://rdap.org/domain/{domain}"
_API_NINJAS_URL = "https://api.api-ninjas.com/v1/whois"
_RDAP_TIMEOUT = 10 

def _parse_iso_date(raw: str) -> Optional[datetime]:
    """Parse an ISO-8601 date string returned by RDAP."""
    if not raw:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(raw[:19], fmt[:len(fmt)])
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _parse_creation_date(raw) -> Optional[datetime]:
    """
    Parse creation_date from API-Ninjas WHOIS response.
    The API returns a Unix timestamp (int) or ISO string.
    """
    if raw is None:
        return None

    # Unix timestamp (int or float)
    if isinstance(raw, (int, float)):
        try:
            return datetime.fromtimestamp(raw, tz=timezone.utc)
        except (OSError, OverflowError, ValueError):
            return None

    # ISO-format string fallback
    if isinstance(raw, str):
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(raw, fmt)
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue

    return None


def _extract_rdap_data(data: dict) -> dict:
    """
    Extract registration date, expiration date, registrar, and status
    from an RDAP JSON response.
    """
    registration_date: Optional[str] = None
    expiration_date: Optional[str] = None

    for event in data.get("events", []):
        action = event.get("eventAction", "")
        date = event.get("eventDate", "")
        if action == "registration" and not registration_date:
            registration_date = date
        elif action == "expiration" and not expiration_date:
            expiration_date = date

    registrar: Optional[str] = None
    for entity in data.get("entities", []):
        vcard = entity.get("vcardArray")
        if vcard and isinstance(vcard, list) and len(vcard) > 1:
            for prop in vcard[1]:
                if isinstance(prop, list) and prop[0] == "fn":
                    registrar = prop[3]
                    break
        if not registrar:
            registrar = entity.get("handle")
        if registrar:
            break

    status = data.get("status", [])
    if isinstance(status, str):
        status = [status]

    return {
        "registration_date": registration_date,
        "expiration_date": expiration_date,
        "registrar": registrar,
        "status": status,
    }


async def _fetch_rdap(domain: str) -> dict:
    """Call the RDAP endpoint in a thread pool to keep it non-blocking."""
    loop = asyncio.get_event_loop()
    url = _RDAP_URL.format(domain=domain)

    def _call():
        return requests.get(url, timeout=_RDAP_TIMEOUT)

    return await asyncio.wait_for(
        loop.run_in_executor(None, _call),
        timeout=_RDAP_TIMEOUT + 2,
    )


async def _fetch_whois_ninjas(domain: str, api_key: str, timeout: float = 10.0) -> dict:
    """
    Call the API-Ninjas WHOIS endpoint in a thread to keep it non-blocking.
    """
    loop = asyncio.get_event_loop()

    def _call():
        return requests.get(
            _API_NINJAS_URL,
            params={"domain": domain},
            headers={"X-Api-Key": api_key},
            timeout=timeout,
        )

    return await asyncio.wait_for(
        loop.run_in_executor(None, _call),
        timeout=timeout + 2,
    )


def _score_from_creation_date(
    creation_date: datetime,
    domain: str,
    registrar: Optional[str],
    extra_details: Optional[dict] = None,
) -> DetectionResult:
    """Build a DetectionResult based on how old the domain is."""
    now = datetime.now(timezone.utc)
    age_days = (now - creation_date).days
    age_years = round(age_days / 365.25, 2)

    issues = []
    score = 0.0

    if age_days < 14:
        issues.append(f"Domain sangat baru (±{age_days} hari).")
        score = 90.0
    elif age_days < 90:
        issues.append(f"Domain relatif baru ({age_days} hari).")
        score = 60.0
    elif age_days < 365:
        issues.append(f"Domain berusia kurang dari 1 tahun ({age_days} hari).")
        score = 30.0

    details = {
        "domain": domain,
        "age_days": age_days,
        "age_years": age_years,
        "creation_date": creation_date.isoformat(),
        "registrar": registrar,
    }
    if extra_details:
        details.update(extra_details)

    return {"score": score, "issues": issues, "details": details}

class WhoisDetector(BaseDetector):
    """Domain age and WHOIS information detector."""

    def __init__(self):
        super().__init__("whois_detector")
        self.api_key = config.apis.whois
        self.timeout = config.request_timeout

    async def detect(self, url: str, **kwargs) -> DetectionResult:
        parsed = urlparse(url)
        domain = parsed.netloc.split(":")[0]

        if not domain:
            return self._create_result(
                score=0.0,
                success=False,
                issues=["Domain tidak valid."],
                details={},
            )

        extracted = tldextract.extract(domain)
        tld_suffix = extracted.suffix  

        rdap_ok = False
        creation_date: Optional[datetime] = None
        registrar: Optional[str] = None
        extra_rdap: dict = {}

        try:
            response = await _fetch_rdap(domain)

            if response.status_code == 200:
                data = response.json()
                rdap_info = _extract_rdap_data(data)

                creation_date = _parse_iso_date(rdap_info["registration_date"])
                registrar = rdap_info["registrar"]
                extra_rdap = {
                    "expiration_date": rdap_info["expiration_date"],
                    "status": rdap_info["status"],
                    "source": "rdap",
                }
                rdap_ok = True
                logger.info(f"RDAP lookup succeeded for {domain}")
            else:
                logger.warning(
                    f"RDAP returned {response.status_code} for {domain}: {response.text[:200]}"
                )

        except asyncio.TimeoutError:
            logger.warning(f"RDAP timeout for {domain}")
        except Exception as exc:
            logger.warning(f"RDAP lookup failed for {domain}: {exc}")

        if rdap_ok:
            if not creation_date:
                return self._create_result(
                    score=40.0,
                    success=True,
                    issues=["Tanggal pembuatan domain tidak tersedia."],
                    details={"domain": domain, "source": "rdap", **extra_rdap},
                )

            scored = _score_from_creation_date(creation_date, domain, registrar, extra_rdap)
            return self._create_result(
                score=scored["score"],
                success=True,
                issues=scored["issues"],
                details=scored["details"],
            )

        if tld_suffix != "com":
            logger.info(
                f"Skipping API Ninjas fallback for {domain} (TLD '.{tld_suffix}' "
                f"not supported on free tier)."
            )
            return self._create_result(
                score=0.0,
                success=False,
                issues=["WHOIS lookup gagal."],
                details={"reason": "WHOIS lookup failed", "domain": domain},
            )

        if not self.api_key:
            return self._create_result(
                score=0.0,
                success=False,
                issues=["WHOIS API key tidak dikonfigurasi."],
                details={"domain": domain},
            )

        try:
            resp = await _fetch_whois_ninjas(domain, self.api_key, timeout=self.timeout)

            if resp.status_code != 200:
                if resp.status_code == 400:
                    logger.warning(
                        f"API Ninjas WHOIS returned 400 for {domain} – "
                        f"Response: {resp.text}"
                    )
                else:
                    logger.warning(
                        f"API Ninjas WHOIS returned {resp.status_code} for {domain}"
                    )
                return self._create_result(
                    score=0.0,
                    success=False,
                    issues=[f"WHOIS API mengembalikan status {resp.status_code}."],
                    details={"domain": domain},
                )

            data = resp.json()
            creation_date = _parse_creation_date(data.get("creation_date"))

            if not creation_date:
                return self._create_result(
                    score=40.0,
                    success=True,
                    issues=["Tanggal pembuatan domain tidak tersedia."],
                    details={"domain": domain, "source": "api_ninjas"},
                )

            scored = _score_from_creation_date(
                creation_date,
                domain,
                data.get("registrar"),
                {"source": "api_ninjas"},
            )
            return self._create_result(
                score=scored["score"],
                success=True,
                issues=scored["issues"],
                details=scored["details"],
            )

        except asyncio.TimeoutError:
            logger.warning(f"API Ninjas WHOIS timeout for {domain}")
            return self._create_result(
                score=0.0,
                success=False,
                issues=["WHOIS API timeout."],
                details={"domain": domain, "timeout": True},
            )

        except Exception as e:
            logger.error(f"WHOIS detection failed for {domain}: {str(e)}")
            return self._create_result(
                score=0.0,
                success=False,
                issues=["Pencarian WHOIS gagal."],
                details={"domain": domain, "error": str(e)},
            )
