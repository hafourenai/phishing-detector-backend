"""Data models and schemas."""
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class ThreatLevel(Enum):
    """Threat level enumeration."""
    SAFE = "safe"
    CAUTION = "caution"
    WARNING = "warning"
    DANGER = "danger"


@dataclass
class URLAnalysisRequest:
    """URL analysis request model."""
    url: str
    force_refresh: bool = False
    include_details: bool = True


@dataclass
class DetectionResult:
    """Detection result from a single detector."""
    name: str
    score: float
    success: bool
    issues: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)
    execution_time: float = 0.0


@dataclass
class URLAnalysisResult:
    """Complete URL analysis result."""
    url: str
    hostname: str
    final_score: float
    threat_level: ThreatLevel
    is_phishing: bool
    confidence: float
    recommendation: str
    
    # Detection results
    detections: List[DetectionResult] = field(default_factory=list)
    
    # Aggregated data
    total_issues: List[str] = field(default_factory=list)
    score_breakdown: Dict[str, float] = field(default_factory=dict)
    
    # Metadata
    analysis_timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    execution_time: float = 0.0
    cached: bool = False
    model_version: str = "1.0.0"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "url": self.url,
            "hostname": self.hostname,
            "score": self.final_score,
            "threat_level": self.threat_level.value,
            "is_phishing": self.is_phishing,
            "confidence": self.confidence,
            "recommendation": self.recommendation,
            "detections": [
                {
                    "name": d.name,
                    "score": d.score,
                    "success": d.success,
                    "issues": d.issues,
                    "details": d.details,
                    "execution_time": d.execution_time
                }
                for d in self.detections
            ],
            "total_issues": self.total_issues,
            "score_breakdown": self.score_breakdown,
            "analysis_timestamp": self.analysis_timestamp,
            "execution_time": self.execution_time,
            "cached": self.cached,
            "model_version": self.model_version
        }
