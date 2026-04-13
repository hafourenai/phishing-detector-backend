"""
Domain age detector using WHOIS.
Cloud-safe version with hard timeout.
"""

import asyncio
import whois
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from app.detectors.base import BaseDetector
from app.models import DetectionResult
from app.utils.logger import get_logger

logger = get_logger(__name__)


def _normalize_datetime(dt) -> Optional[datetime]:
    """
    Normalize a datetime value to timezone-aware UTC.
    Handles list, naive datetime, aware datetime, and invalid values.
    """
    if isinstance(dt, list):
        for item in dt:
            normalized = _normalize_datetime(item)
            if normalized is not None:
                return normalized
        return None

    if not isinstance(dt, datetime):
        return None

    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)

    return dt.astimezone(timezone.utc)


async def _safe_whois_lookup(domain: str, timeout: float = 5.0):
    """
    Run blocking whois.whois() safely with a hard timeout.
    Prevents Gunicorn worker freeze in cloud environments.
    """
    loop = asyncio.get_event_loop()
    return await asyncio.wait_for(
        loop.run_in_executor(None, whois.whois, domain),
        timeout=timeout
    )


class WhoisDetector(BaseDetector):
    """Domain age and WHOIS information detector."""

    def __init__(self):
        super().__init__("whois_detector")

    async def detect(self, url: str, **kwargs) -> DetectionResult:
        parsed = urlparse(url)
        domain = parsed.netloc.split(":")[0]

        if not domain:
            return self._create_result(
                score=0.0,
                success=False,
                issues=["Domain tidak valid."],
                details={}
            )

        try:
            w = await _safe_whois_lookup(domain)

            creation_date = _normalize_datetime(w.creation_date)

            if not creation_date:
                return self._create_result(
                    score=40.0,
                    success=True,
                    issues=["Tanggal pembuatan domain tidak tersedia."],
                    details={"domain": domain}
                )

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

            return self._create_result(
                score=score,
                success=True,
                issues=issues,
                details={
                    "domain": domain,
                    "age_days": age_days,
                    "age_years": age_years,
                    "creation_date": creation_date.isoformat(),
                    "registrar": getattr(w, "registrar", None),
                }
            )

        except asyncio.TimeoutError:
            logger.warning(f"WHOIS lookup timeout for {domain}")
            return self._create_result(
                score=0.0,
                success=False,
                issues=["WHOIS lookup timeout (dibatasi cloud)."],
                details={"domain": domain, "timeout": True}
            )

        except Exception as e:
            logger.error(f"WHOIS detection failed for {domain}: {str(e)}")
            return self._create_result(
                score=0.0,
                success=False,
                issues=["Pencarian WHOIS gagal."],
                details={"domain": domain, "error": str(e)}
            )
