"""Main analysis orchestrator."""
import time
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

from app.config import config
from app.models import (
    URLAnalysisResult, 
    DetectionResult, 
    ThreatLevel,
    URLAnalysisRequest
)
from app.core.validator import URLValidator
from app.ml.model import PhishingMLModel
from app.ml.features import FeatureExtractor
from app.detectors.ssl import SSLDetector
from app.detectors.whois_detector import WhoisDetector
from app.utils.logger import get_logger

logger = get_logger(__name__)


class URLAnalyzer:
    """Main orchestrator for URL analysis."""
    
    def __init__(self):
        """Initialize analyzer."""
        self.ml_model = PhishingMLModel()
        self.validator = URLValidator()
        self.extractor = FeatureExtractor()
        self.ssl_detector = SSLDetector()
        self.whois_detector = WhoisDetector()
    
    async def analyze(self, url: str, force_refresh: bool = False) -> URLAnalysisResult:
        """
        Perform complete URL analysis.
        
        Args:
            url: URL to analyze
            force_refresh: Whether to bypass cache
            
        Returns:
            URLAnalysisResult
        """
        start_time = time.time()
        
        # 1. Process and validate URL
        sanitized_url = self.validator.process(url)
        parsed = urlparse(sanitized_url)
        hostname = parsed.netloc
        
        detections: List[DetectionResult] = []
        
        # 2. Parallel Detection
        # Use asyncio.gather for better performance
        import asyncio
        
        ml_task = self._run_in_executor(self._analyze_ml, sanitized_url)
        ssl_task = self.ssl_detector.safe_detect(sanitized_url)
        whois_task = self.whois_detector.safe_detect(sanitized_url)
        
        ml_result, ssl_result, whois_result = await asyncio.gather(
            ml_task, ssl_task, whois_task
        )
        
        detections.extend([ml_result, ssl_result, whois_result])
        
        # 3. Calculate final score with heuristic adjustments
        ml_score = ml_result.score
        ssl_score = ssl_result.score
        whois_score = whois_result.score
        
        is_phishing = ml_result.details.get('is_phishing', False)
        
        # Combined Risk Score (Weighted)
        # ML is powerful but heuristics are definitive for certain cases
        final_score = (ml_score * 0.5) + (ssl_score * 0.3) + (whois_score * 0.2)
        
        # Force high score if definitive threats found
        if ssl_score >= 80 or whois_score >= 90:
            final_score = max(final_score, 85.0)
            is_phishing = True
            
        final_score = min(final_score, 100.0)
        
        threat_level = self._calculate_threat_level(final_score, is_phishing)
        recommendation = self._get_recommendation(threat_level)
        
        # 4. Aggregate issues
        total_issues = []
        for d in detections:
            if d.success:
                total_issues.extend(d.issues)
        
        # Extract confidence from ML result if available
        confidence = ml_result.details.get('confidence', 0.8) if ml_result.success else 0.5
        
        result = URLAnalysisResult(
            url=sanitized_url,
            hostname=hostname,
            final_score=final_score,
            threat_level=threat_level,
            is_phishing=is_phishing,
            confidence=confidence,
            recommendation=recommendation,
            detections=detections,
            total_issues=total_issues,
            score_breakdown={
                "ml_score": final_score
            },
            execution_time=time.time() - start_time,
            cached=False
        )
        
        return result
    
    def _analyze_ml(self, url: str) -> DetectionResult:
        """Perform ML-based analysis."""
        start_time = time.time()
        
        try:
            if not self.ml_model.is_loaded():
                return DetectionResult(
                    name="ml_detector",
                    score=0.0,
                    success=False,
                    issues=["ML model not loaded"],
                    execution_time=time.time() - start_time
                )
            
            features = self.extractor.extract(url)
            prediction = self.ml_model.predict(features)
            
            issues = []
            if prediction['is_phishing']:
                issues.append("ML model identified suspicious patterns consistent with phishing.")
            
            return DetectionResult(
                name="ml_detector",
                score=prediction['probability'] * 100,
                success=True,
                issues=issues,
                details=prediction,
                execution_time=time.time() - start_time
            )
            
        except Exception as e:
            logger.error(f"ML analysis failed: {str(e)}")
            return DetectionResult(
                name="ml_detector",
                score=0.0,
                success=False,
                issues=[f"ML analysis error: {str(e)}"],
                execution_time=time.time() - start_time
            )
    
    def _calculate_threat_level(self, score: float, is_phishing: bool) -> ThreatLevel:
        """Calculate threat level based on score and prediction."""
        if score >= 80 or (is_phishing and score >= 60):
            return ThreatLevel.DANGER
        elif score >= 50 or is_phishing:
            return ThreatLevel.WARNING
        elif score >= 20:
            return ThreatLevel.CAUTION
        return ThreatLevel.SAFE
    
    def _get_recommendation(self, threat_level: ThreatLevel) -> str:
        """Get user recommendation based on threat level."""
        if threat_level == ThreatLevel.DANGER:
            return "Do not visit this website. It is highly likely to be a phishing site."
        elif threat_level == ThreatLevel.WARNING:
            return "Be extremely cautious. This website shows suspicious characteristics."
        elif threat_level == ThreatLevel.CAUTION:
            return "Use caution when interacting with this website."
        return "This website appears to be safe."

    async def _run_in_executor(self, func, *args):
        """Run blocking function in executor."""
        import asyncio
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, func, *args)
