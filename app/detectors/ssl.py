"""SSL certificate expiration detector."""
import ssl
import socket
from datetime import datetime
from typing import Dict, Any
from urllib.parse import urlparse

from app.detectors.base import BaseDetector
from app.models import DetectionResult
from app.utils.logger import get_logger

logger = get_logger(__name__)


class SSLDetector(BaseDetector):
    """SSL certificate verification detector."""
    
    def __init__(self):
        super().__init__("ssl_detector")
    
    async def detect(self, url: str, **kwargs) -> DetectionResult:
        """
        Check SSL certificate expiration.
        """
        parsed = urlparse(url)
        hostname = parsed.netloc.split(':')[0]
        port = parsed.port or 443
        
        if not url.startswith('https://'):
            return self._create_result(
                score=100.0,
                success=True,
                issues=["Website is not using HTTPS."],
                details={"has_ssl": False}
            )
            
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
            if not cert:
                return self._create_result(
                    score=80.0,
                    success=True,
                    issues=["Could not retrieve SSL certificate."],
                    details={"has_ssl": False}
                )
                
            # Parse dates
            not_after_str = cert.get('notAfter')
            # Example format: 'Oct 31 23:59:59 2023 GMT'
            expiry_date = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
            days_remaining = (expiry_date - datetime.utcnow()).days
            
            issues = []
            score = 0.0
            
            if days_remaining < 0:
                issues.append("SSL certificate has expired.")
                score = 100.0
            elif days_remaining < 7:
                issues.append(f"SSL certificate expires in {days_remaining} days.")
                score = 80.0
            elif days_remaining < 30:
                issues.append(f"SSL certificate expires soon ({days_remaining} days).")
                score = 40.0
            
            return self._create_result(
                score=score,
                success=True,
                issues=issues,
                details={
                    "has_ssl": True,
                    "days_remaining": days_remaining,
                    "expiry_date": expiry_date.isoformat(),
                    "issuer": dict(x[0] for x in cert.get('issuer', []))
                }
            )
            
        except Exception as e:
            logger.error(f"SSL detection failed for {hostname}: {str(e)}")
            return self._create_result(
                score=50.0,
                success=False,
                issues=[f"SSL certificate error: {str(e)}"],
                details={"error": str(e), "has_ssl": False}
            )
