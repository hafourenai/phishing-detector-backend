"""ML model wrapper."""
import pickle
import joblib
from pathlib import Path
from typing import Optional, Dict, Any
import numpy as np

from app.config import config
from app.exceptions import ModelError
from app.utils.logger import get_logger

logger = get_logger(__name__)


class PhishingMLModel:
    """Phishing detection ML model wrapper."""
    
    def __init__(self, model_path: Optional[str] = None):
        """Initialize model."""
        self.model_path = model_path or config.model_path
        self.model = None
        self.feature_names = None
        self.metadata = {}
        self._load_model()
    
    def _load_model(self):
        """Load trained model."""
        try:
            model_file = Path(self.model_path)
            
            if not model_file.exists():
                logger.warning(f"Model file not found: {self.model_path}")
                return
            
            # Load model
            # Support both joblib and pickle
            try:
                self.model = joblib.load(model_file)
                # If the saved object is the pipeline itself
                if hasattr(self.model, 'predict'):
                    # We might not have feature names or metadata in a simple dump
                    self.feature_names = getattr(self.model, 'feature_names_in_', [])
                    logger.info(f"Model loaded successfully from {self.model_path}")
                    return
            except:
                pass

            with open(model_file, 'rb') as f:
                model_data = pickle.load(f)
            
            if isinstance(model_data, dict):
                self.model = model_data.get('model')
                self.feature_names = model_data.get('feature_names', [])
                self.metadata = model_data.get('metadata', {})
            else:
                self.model = model_data
            
            logger.info(f"Model loaded successfully from {self.model_path}")
            
        except Exception as e:
            logger.error(f"Failed to load model: {str(e)}")
            raise ModelError(f"Model loading failed: {str(e)}")
    
    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Make prediction.
        
        Args:
            features: Feature dictionary
            
        Returns:
            Prediction result with probability and confidence
        """
        if self.model is None:
            raise ModelError("Model not loaded")
        
        try:
            # Convert features to array/DataFrame if needed
            # For simplicity, if feature_names is empty, we assume input matches model expectation
            if self.feature_names is not None and len(self.feature_names) > 0:
                import pandas as pd
                feature_array = pd.DataFrame([features])[self.feature_names]
            else:
                # Fallback to values in order
                feature_array = np.array(list(features.values())).reshape(1, -1)
            
            # Get prediction and probability
            prediction = self.model.predict(feature_array)[0]
            
            # Not all models support predict_proba
            try:
                probability = self.model.predict_proba(feature_array)[0]
                confidence = max(probability)
                prob_phishing = float(probability[1]) if len(probability) > 1 else float(probability[0])
            except:
                probability = [0.0, 1.0] if prediction == 1 else [1.0, 0.0]
                confidence = 1.0
                prob_phishing = 1.0 if prediction == 1 else 0.0
            
            return {
                'is_phishing': bool(prediction == 1 or prediction is True),
                'probability': prob_phishing,
                'confidence': float(confidence),
                'scores': {
                    'legitimate': float(probability[0]),
                    'phishing': prob_phishing
                }
            }
            
        except Exception as e:
            logger.error(f"Prediction failed: {str(e)}")
            raise ModelError(f"Prediction failed: {str(e)}")
    
    def is_loaded(self) -> bool:
        """Check if model is loaded."""
        return self.model is not None
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get model metrics."""
        return self.metadata.get('metrics', {})
