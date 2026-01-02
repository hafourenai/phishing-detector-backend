"""VirusTotal detector."""
import requests
import hashlib
from typing import Dict, Any

from app.config import config
from app.detectors.base import BaseDetector
from app.models import DetectionResult
from app.utils.logger import get_logger

logger = get_logger(__name__)


class VirusTotalDetector(BaseDetector):
    """Detector using VirusTotal API v3."""
    
    def __init__(self):
        super().__init__(name="virustotal")
        self.api_key = config.apis.virustotal
        self.timeout = config.request_timeout
        
    async def detect(self, url: str, **kwargs) -> DetectionResult:
        """Check URL against VirusTotal."""
        if not self.api_key:
            return self._create_result(
                score=0.0,
                success=False,
                issues=["VirusTotal API key not configured"]
            )
            
        try:
            # Hash URL for analysis as per server.py logic
            url_hash = hashlib.sha256(url.encode()).hexdigest()
            
            headers = {
                'x-apikey': self.api_key,
                'Content-Type': 'application/json'
            }
            
            response = requests.get(
                f'https://www.virustotal.com/api/v3/urls/{url_hash}',
                headers=headers,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                total_engines = sum(stats.values())
                
                score = (malicious / max(total_engines, 1)) * 100
                issues = []
                if malicious > 0:
                    issues.append(f"VirusTotal: {malicious} engines detected this URL as malicious.")
                
                return self._create_result(
                    score=score,
                    issues=issues,
                    details={
                        "stats": stats,
                        "reputation": data.get('data', {}).get('attributes', {}).get('reputation', 0)
                    }
                )
            elif response.status_code == 404:
                return self._create_result(
                    score=0.0,
                    issues=[],
                    details={"status": "URL not found in VirusTotal database"}
                )
            else:
                return self._create_result(
                    score=0.0,
                    success=False,
                    issues=[f"VirusTotal API returned status {response.status_code}"]
                )
                
        except Exception as e:
            logger.error(f"VirusTotal detection error: {str(e)}")
            return self._create_result(
                score=0.0,
                success=False,
                issues=[f"VirusTotal API error: {str(e)}"]
            )
