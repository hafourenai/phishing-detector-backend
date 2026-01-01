"""Base detector class."""
from abc import ABC, abstractmethod
from typing import Dict, Any
import time

from app.models import DetectionResult


class BaseDetector(ABC):
    """Base class for all detectors."""
    
    def __init__(self, name: str):
        """Initialize detector."""
        self.name = name
    
    @abstractmethod
    async def detect(self, url: str, **kwargs) -> DetectionResult:
        """
        Perform detection.
        
        Args:
            url: URL to analyze
            **kwargs: Additional arguments
            
        Returns:
            DetectionResult
        """
        pass
    
    def _create_result(
        self,
        score: float,
        success: bool = True,
        issues: list = None,
        details: dict = None,
        execution_time: float = 0.0
    ) -> DetectionResult:
        """Create detection result."""
        return DetectionResult(
            name=self.name,
            score=score,
            success=success,
            issues=issues or [],
            details=details or {},
            execution_time=execution_time
        )
    
    async def safe_detect(self, url: str, **kwargs) -> DetectionResult:
        """
        Safe detection with error handling.
        
        Args:
            url: URL to analyze
            **kwargs: Additional arguments
            
        Returns:
            DetectionResult (with error details if failed)
        """
        start_time = time.time()
        
        try:
            result = await self.detect(url, **kwargs)
            result.execution_time = time.time() - start_time
            return result
        except Exception as e:
            execution_time = time.time() - start_time
            return self._create_result(
                score=0.0,
                success=False,
                issues=[f"Detection failed: {str(e)}"],
                details={"error": str(e)},
                execution_time=execution_time
            )
