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
from app.detectors.safe_browsing import SafeBrowsingDetector
from app.detectors.virustotal import VirusTotalDetector
from app.detectors.ipqualityscore import IPQualityScoreDetector
from app.detectors.telegram import TelegramDetector
from app.detectors.content import ContentDetector
from app.detectors.heuristic_detector import HeuristicDetector
from app.ml.prediction_cache import PredictionCache
from app.utils.logger import get_logger

logger = get_logger(__name__)


class URLAnalyzer:
    """Main orchestrator for URL analysis."""
    
    def __init__(self):
        """Initialize analyzer."""
        self.ml_model = PhishingMLModel()
        self.validator = URLValidator()
        self.extractor = FeatureExtractor()
        
        # Initialize prediction cache
        from app.config import config
        self.cache = PredictionCache(
            max_size=config.prediction_cache_max_size,
            ttl=config.prediction_cache_ttl
        ) if config.prediction_cache_enabled else None
        
        # Initialize detectors
        self.ssl_detector = SSLDetector()
        self.whois_detector = WhoisDetector()
        self.safe_browsing = SafeBrowsingDetector()
        self.virustotal = VirusTotalDetector()
        self.ipqualityscore = IPQualityScoreDetector()
        self.telegram = TelegramDetector()
        self.content = ContentDetector()
        self.heuristic = HeuristicDetector()
    
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
        
        # 2. Parallel Detection
        # Use asyncio.gather for better performance
        import asyncio
        
        ml_task = self._run_in_executor(self._analyze_ml, sanitized_url)
        ssl_task = self.ssl_detector.safe_detect(sanitized_url)
        whois_task = self.whois_detector.safe_detect(sanitized_url)
        sb_task = self.safe_browsing.safe_detect(sanitized_url)
        vt_task = self.virustotal.safe_detect(sanitized_url)
        ipq_task = self.ipqualityscore.safe_detect(sanitized_url)
        tg_task = self.telegram.safe_detect(sanitized_url)
        cnt_task = self.content.safe_detect(sanitized_url)
        heu_task = self.heuristic.safe_detect(sanitized_url)
        
        # Gather all results
        (
            ml_res, ssl_res, whois_res, sb_res, 
            vt_res, ipq_res, tg_res, cnt_res, heu_res
        ) = await asyncio.gather(
            ml_task, ssl_task, whois_task, sb_task,
            vt_task, ipq_task, tg_task, cnt_task, heu_task
        )
        
        detections = [
            ml_res, ssl_res, whois_res, sb_res, 
            vt_res, ipq_res, tg_res, cnt_res, heu_res
        ]
        
        # 3. Calculate final score with weighted adjustments (Ported from server.py)
        weights = {
            'heuristic': 0.25,
            'safe_browsing': 0.20,
            'virustotal': 0.15,
            'ipqualityscore': 0.15,
            'ml_detector': 0.10, # Replaced rapidapi_phishing with ML for weight
            'content': 0.10,
            'ssl': 0.05
        }
        
        total_weighted_score = 0.0
        score_breakdown = {}
        
        # Heuristic (25%)
        if heu_res.success:
            total_weighted_score += heu_res.score * weights['heuristic']
            score_breakdown['heuristic'] = heu_res.score
            
        # Safe Browsing (20%)
        if sb_res.success:
            total_weighted_score += sb_res.score * weights['safe_browsing']
            score_breakdown['safe_browsing'] = sb_res.score
            
        # VirusTotal (15%)
        if vt_res.success:
            total_weighted_score += vt_res.score * weights['virustotal']
            score_breakdown['virustotal'] = vt_res.score
            
        # IPQualityScore (15%)
        if ipq_res.success:
            total_weighted_score += ipq_res.score * weights['ipqualityscore']
            score_breakdown['ipqualityscore'] = ipq_res.score
            
        # ML Detector (10%)
        if ml_res.success:
            total_weighted_score += ml_res.score * weights['ml_detector']
            score_breakdown['ml_detector'] = ml_res.score
            
        # Content Analysis (10%)
        if cnt_res.success:
            total_weighted_score += cnt_res.score * weights['content']
            score_breakdown['content'] = cnt_res.score
            
        # SSL Check (5%)
        if ssl_res.success:
            total_weighted_score += ssl_res.score * weights['ssl']
            score_breakdown['ssl'] = ssl_res.score
            
        final_score = min(total_weighted_score, 100.0)
        
        # ML often provides strong phishing indication
        is_phishing = ml_res.details.get('is_phishing', False)
        if final_score >= 60:
            is_phishing = True
            
        threat_level = self._calculate_threat_level(final_score, is_phishing)
        recommendation = self._get_recommendation(threat_level)
        
        # 4. Aggregate issues
        total_issues = []
        for d in detections:
            if d.success:
                total_issues.extend(d.issues)
        
        # Remove duplicates while preserving order
        seen = set()
        total_issues = [x for x in total_issues if not (x in seen or seen.add(x))]
        
        # Confidence
        confidence = ml_res.details.get('confidence', 0.8) if ml_res.success else 0.5
        
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
            score_breakdown=score_breakdown,
            execution_time=time.time() - start_time,
            cached=False
        )
        
        return result
    
    def _analyze_ml(self, url: str) -> DetectionResult:
        """Perform ML-based analysis with caching."""
        start_time = time.time()
        
        try:
            # Check cache first
            if self.cache:
                cached_result = self.cache.get(url)
                if cached_result is not None:
                    logger.debug(f"Using cached ML prediction for {url[:50]}...")
                    # Return cached result as DetectionResult
                    return DetectionResult(
                        name="ml_detector",
                        score=cached_result['probability'] * 100,
                        success=True,
                        issues=["ML model identified suspicious patterns consistent with phishing."] if cached_result['is_phishing'] else [],
                        details=cached_result,
                        execution_time=time.time() - start_time
                    )
            
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
            
            # Cache the prediction result
            if self.cache:
                self.cache.set(url, prediction)
            
            issues = []
            if prediction['is_phishing']:
                issues.append("Model ML mengidentifikasi pola mencurigakan yang konsisten dengan phishing.")
            
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
        if score >= 75:
            return ThreatLevel.DANGER
        elif score >= 50 or is_phishing:
            return ThreatLevel.WARNING
        elif score >= 20:
            return ThreatLevel.CAUTION
        return ThreatLevel.SAFE
    
    def _get_recommendation(self, threat_level: ThreatLevel) -> str:
        """Get user recommendation based on threat level."""
        if threat_level == ThreatLevel.DANGER:
            return "Jangan kunjungi situs web ini. Sangat besar kemungkinan ini adalah situs phishing."
        elif threat_level == ThreatLevel.WARNING:
            return "Sangat berhati-hatilah. Situs web ini menunjukkan karakteristik yang mencurigakan."
        elif threat_level == ThreatLevel.CAUTION:
            return "Berhati-hatilah saat berinteraksi dengan situs web ini."
        return "Situs web ini tampak aman."

    async def _run_in_executor(self, func, *args):
        """Run blocking function in executor."""
        import asyncio
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, func, *args)
