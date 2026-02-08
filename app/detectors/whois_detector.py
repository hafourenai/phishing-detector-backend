"""Domain age detector using WHOIS."""
import whois
from datetime import datetime, timezone
from typing import List, Union, Optional
from urllib.parse import urlparse

from app.detectors.base import BaseDetector
from app.models import DetectionResult
from app.utils.logger import get_logger

logger = get_logger(__name__)


def _normalize_datetime(dt) -> Optional[datetime]:
    """
    Normalize a datetime value to timezone-aware UTC.
    
    Handles:
    - Lists (extracts first valid element)
    - Timezone-naive datetimes (attaches UTC)
    - Timezone-aware datetimes (converts to UTC)
    - None/invalid values (returns None)
    """
    # Handle list - extract first valid datetime
    if isinstance(dt, list):
        for item in dt:
            normalized = _normalize_datetime(item)
            if normalized is not None:
                return normalized
        return None
    
    # Handle non-datetime values
    if not isinstance(dt, datetime):
        return None
    
    # Handle timezone-naive datetime - attach UTC
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    
    # Handle timezone-aware datetime - convert to UTC
    return dt.astimezone(timezone.utc)


class WhoisDetector(BaseDetector):
    """Domain age and WHOIS information detector."""
    
    def __init__(self):
        super().__init__("whois_detector")
    
    async def detect(self, url: str, **kwargs) -> DetectionResult:
        """
        Check domain age using WHOIS data.
        """
        parsed = urlparse(url)
        domain = parsed.netloc.split(':')[0]
        
        try:
            # whois.whois is a blocking call, but for simplicity we'll keep it as is
            # or wrap it if performance is a major concern
            w = whois.whois(domain)
            
            # Normalize creation_date to timezone-aware UTC
            creation_date = _normalize_datetime(w.creation_date)
            
            if not creation_date:
                return self._create_result(
                    score=50.0,
                    success=True,
                    issues=["Tidak dapat menentukan tanggal pembuatan domain."],
                    details={"domain": domain}
                )
            
            # Use timezone-aware now() for safe arithmetic
            age_days = (datetime.now(timezone.utc) - creation_date).days
            age_years = age_days / 365.25
            
            issues = []
            score = 0.0
            
            if age_days < 14: # Less than 2 weeks
                issues.append(f"Domain sangat baru (hanya berusia {age_days} hari).")
                score = 90.0
            elif age_days < 90: # Less than 3 months
                issues.append(f"Domain relatif baru ({age_days} hari).")
                score = 60.0
            elif age_days < 365: # Less than 1 year
                issues.append(f"Domain berusia kurang dari satu tahun ({age_days} hari).")
                score = 30.0
                
            return self._create_result(
                score=score,
                success=True,
                issues=issues,
                details={
                    "domain": domain,
                    "age_days": age_days,
                    "age_years": round(age_years, 2),
                    "creation_date": creation_date.isoformat() if creation_date else None,
                    "registrar": w.registrar
                }
            )
            
        except Exception as e:
            logger.error(f"WHOIS detection failed for {domain}: {str(e)}")
            return self._create_result(
                score=0.0,
                success=False,
                issues=[f"Pencarian WHOIS gagal: {str(e)}"],
                details={"error": str(e), "domain": domain}
            )

#love u N
