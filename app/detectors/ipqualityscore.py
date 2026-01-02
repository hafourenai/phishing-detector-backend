"""IPQualityScore detector."""
import requests
from typing import Dict, Any

from app.config import config
from app.detectors.base import BaseDetector
from app.models import DetectionResult
from app.utils.logger import get_logger

logger = get_logger(__name__)


class IPQualityScoreDetector(BaseDetector):
    """Detector using IPQualityScore API."""
    
    def __init__(self):
        super().__init__(name="ipqualityscore")
        self.api_key = config.apis.ipqualityscore
        self.timeout = config.request_timeout
        
    async def detect(self, url: str, **kwargs) -> DetectionResult:
        """Check URL against IPQualityScore."""
        if not self.api_key:
            return self._create_result(
                score=0.0,
                success=False,
                issues=["IPQualityScore API key not configured"]
            )
            
        try:
            encoded_url = requests.utils.quote(url)
            endpoint = f'https://www.ipqualityscore.com/api/json/url/{self.api_key}/{encoded_url}'
            
            response = requests.get(endpoint, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                risk_score = data.get('risk_score', 0)
                
                issues = []
                if data.get('phishing'):
                    issues.append("IPQualityScore: Identified as phishing.")
                if data.get('malware'):
                    issues.append("IPQualityScore: Identified as malware.")
                if data.get('suspicious'):
                    issues.append("IPQualityScore: Identified as suspicious.")
                
                return self._create_result(
                    score=float(risk_score), # Assuming it's already 0-100 based on server.py usage
                    issues=issues,
                    details=data
                )
            else:
                return self._create_result(
                    score=0.0,
                    success=False,
                    issues=[f"IPQualityScore API returned status {response.status_code}"]
                )
                
        except Exception as e:
            logger.error(f"IPQualityScore detection error: {str(e)}")
            return self._create_result(
                score=0.0,
                success=False,
                issues=[f"IPQualityScore API error: {str(e)}"]
            )
