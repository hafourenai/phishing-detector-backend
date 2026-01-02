"""Google Safe Browsing detector."""
import requests
from typing import Dict, Any, List

from app.config import config
from app.detectors.base import BaseDetector
from app.models import DetectionResult
from app.utils.logger import get_logger

logger = get_logger(__name__)


class SafeBrowsingDetector(BaseDetector):
    """Detector using Google Safe Browsing API."""
    
    def __init__(self):
        super().__init__(name="safe_browsing")
        self.api_key = config.apis.safe_browsing
        self.timeout = config.request_timeout
        
    async def detect(self, url: str, **kwargs) -> DetectionResult:
        """Check URL against Google Safe Browsing."""
        if not self.api_key:
            return self._create_result(
                score=0.0,
                success=False,
                issues=["Google Safe Browsing API key not configured"]
            )
            
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.api_key}"
        payload = {
            "client": {
                "clientId": "phishing-detector",
                "clientVersion": config.model_version
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION", "THREAT_TYPE_UNSPECIFIED"
                ],
                "platformTypes": ["ANY_PLATFORM", "WINDOWS", "LINUX", "ANDROID", "IOS", "CHROME", "ALL_PLATFORMS"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        
        try:
            # Safe Browsing lookup is synchronous in server.py, keeping it simple
            # but using safe_detect (async) wrapper
            response = requests.post(endpoint, json=payload, timeout=self.timeout)
            data = response.json()
            
            if "matches" in data and len(data["matches"]) > 0:
                threats = []
                for match in data["matches"]:
                    threats.append({
                        'type': match.get('threatType', 'UNKNOWN'),
                        'platform': match.get('platformType', 'ANY_PLATFORM'),
                        'url': match.get('threat', {}).get('url', url)
                    })
                
                threat_types = ', '.join([t['type'] for t in threats])
                return self._create_result(
                    score=100.0,
                    issues=[f"Google Safe Browsing: Dangerous threat detected ({threat_types})"],
                    details={"threats": threats}
                )
            
            return self._create_result(
                score=0.0,
                issues=[],
                details={"status": "No threats found"}
            )
            
        except Exception as e:
            logger.error(f"Safe Browsing detection error: {str(e)}")
            return self._create_result(
                score=0.0,
                success=False,
                issues=[f"Safe Browsing API error: {str(e)}"]
            )
