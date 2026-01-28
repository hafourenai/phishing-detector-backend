"""ML model wrapper."""
from typing import Dict, Any

from app.ml.model_manager import ModelManager
from app.exceptions import ModelError
from app.utils.logger import get_logger

logger = get_logger(__name__)


class PhishingMLModel:
    """
    Phishing detection ML model wrapper.
    
    Uses singleton ModelManager for efficient model loading.
    All .joblib files are loaded once at server startup.
    """
    
    def __init__(self):
        """Initialize model wrapper with singleton manager."""
        self.manager = ModelManager()
        
        if not self.manager.is_ready():
            logger.warning("ModelManager not ready - ML predictions will be unavailable")
    
    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Make prediction using Random Forest model.
        
        Args:
            features: Feature dictionary extracted from URL
            
        Returns:
            Prediction result with probability and confidence:
                - is_phishing: bool
                - probability: float (0-1, probability of phishing)
                - confidence: float (max probability)
                - scores: dict with legitimate and phishing probabilities
                
        Raises:
            ModelError: If model not loaded or prediction fails
        """
        if not self.is_loaded():
            raise ModelError("Model not loaded - cannot make predictions")
        
        try:
            # Delegate to ModelManager for end-to-end inference
            result = self.manager.predict(features)
            return result
            
        except Exception as e:
            logger.error(f"Prediction failed: {str(e)}")
            raise ModelError(f"Prediction failed: {str(e)}")
    
    def is_loaded(self) -> bool:
        """
        Check if model is loaded and ready.
        
        Returns:
            True if model ready for inference
        """
        return self.manager.is_ready()
    
    def get_metrics(self) -> Dict[str, Any]:
        """
        Get model information and metrics.
        
        Returns:
            Model metadata
        """
        return self.manager.get_info()
