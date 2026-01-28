"""Singleton model manager for ML inference."""
import joblib
import threading
import numpy as np
from pathlib import Path
from typing import Optional, Dict, Any, List
from app.utils.logger import get_logger

logger = get_logger(__name__)


class ModelManager:
    """
    Singleton class to manage ML model artifacts.
    
    Loads model, scaler, and feature columns ONCE at initialization.
    Thread-safe and optimized for inference-only operations.
    """
    
    _instance = None
    _lock = threading.Lock()
    _initialized = False
    
    def __new__(cls):
        """Ensure singleton instance."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(ModelManager, cls).__new__(cls)
        return cls._instance
    
    def __init__(self):
        """Initialize model manager - loads artifacts only once."""
        if ModelManager._initialized:
            return
            
        with ModelManager._lock:
            if ModelManager._initialized:
                return
                
            self.model = None
            self.scaler = None
            self.feature_columns = None
            self._model_loaded = False
            
            # Load all artifacts
            self._load_artifacts()
            
            ModelManager._initialized = True
    
    def _load_artifacts(self):
        """Load model, scaler, and feature columns from .joblib files."""
        try:
            # Model files are in backend/models/ directory
            # Path from backend/app/ml/model_manager.py to backend/models/
            base_path = Path(__file__).parent.parent.parent / "models"
            
            model_path = base_path / "best_random_forest_model.joblib"
            scaler_path = base_path / "scaler.joblib"
            features_path = base_path / "feature_columns.joblib"
            
            logger.info("=" * 80)
            logger.info("  Loading ML Model Artifacts...")
            logger.info("=" * 80)
            
            # Load Random Forest model
            if model_path.exists():
                logger.info(f"Loading model from: {model_path}")
                self.model = joblib.load(model_path)
                logger.info(f"  Model loaded successfully: {type(self.model).__name__}")
            else:
                logger.warning(f"❌ Model file not found: {model_path}")
                return
            
            # Load scaler
            if scaler_path.exists():
                logger.info(f"Loading scaler from: {scaler_path}")
                self.scaler = joblib.load(scaler_path)
                logger.info(f"  Scaler loaded successfully: {type(self.scaler).__name__}")
            else:
                logger.warning(f"❌ Scaler file not found: {scaler_path}")
                return
            
            # Load feature columns (to maintain correct order)
            if features_path.exists():
                logger.info(f"Loading feature columns from: {features_path}")
                self.feature_columns = joblib.load(features_path)
                logger.info(f"  Feature columns loaded: {len(self.feature_columns)} features")
                logger.info(f"   Features: {self.feature_columns[:5]}... ({len(self.feature_columns)} total)")
            else:
                logger.warning(f"❌ Feature columns file not found: {features_path}")
                return
            
            self._model_loaded = True
            logger.info("=" * 80)
            logger.info("  All ML artifacts loaded successfully!")
            logger.info("=" * 80)
            
        except Exception as e:
            logger.error(f"❌ Failed to load ML artifacts: {str(e)}", exc_info=True)
            self._model_loaded = False
    
    def align_features(self, features_dict: Dict[str, Any]) -> np.ndarray:
        """
        Align features to training order and convert to numpy array.
        
        Args:
            features_dict: Dictionary of extracted features
            
        Returns:
            Numpy array with features in correct order
            
        Raises:
            ValueError: If feature columns not loaded or features missing
        """
        if self.feature_columns is None:
            raise ValueError("Feature columns not loaded")
        
        # Create ordered feature array
        feature_values = []
        missing_features = []
        
        for feature_name in self.feature_columns:
            if feature_name in features_dict:
                feature_values.append(features_dict[feature_name])
            else:
                missing_features.append(feature_name)
                feature_values.append(0)  # Default value for missing features
        
        if missing_features:
            logger.warning(f"Missing features (using default 0): {missing_features}")
        
        return np.array(feature_values).reshape(1, -1)
    
    def scale_features(self, features_array: np.ndarray) -> np.ndarray:
        """
        Apply scaling to features.
        
        Args:
            features_array: Raw feature array
            
        Returns:
            Scaled feature array
            
        Raises:
            ValueError: If scaler not loaded
        """
        if self.scaler is None:
            raise ValueError("Scaler not loaded")
        
        return self.scaler.transform(features_array)
    
    def predict(self, features_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform end-to-end prediction: align, scale, predict.
        
        Args:
            features_dict: Dictionary of extracted features
            
        Returns:
            Dictionary with prediction results:
                - is_phishing: bool
                - probability: float (0-1, probability of phishing)
                - confidence: float (max probability)
                - scores: dict with legitimate and phishing probabilities
                
        Raises:
            ValueError: If model not ready
            Exception: If prediction fails
        """
        if not self.is_ready():
            raise ValueError("Model not ready - artifacts not fully loaded")
        
        try:
            # 1. Align features to training order
            features_array = self.align_features(features_dict)
            
            # 2. Scale features
            scaled_features = self.scale_features(features_array)
            
            # 3. Predict
            prediction = self.model.predict(scaled_features)[0]
            
            # 4. Get probability scores
            if hasattr(self.model, 'predict_proba'):
                probabilities = self.model.predict_proba(scaled_features)[0]
                # Assuming binary classification: [legitimate, phishing]
                prob_legitimate = float(probabilities[0])
                prob_phishing = float(probabilities[1])
                confidence = max(probabilities)
            else:
                # Fallback if predict_proba not available
                prob_phishing = 1.0 if prediction == 1 else 0.0
                prob_legitimate = 1.0 - prob_phishing
                confidence = 1.0
            
            return {
                'is_phishing': bool(prediction == 1),
                'probability': prob_phishing,
                'confidence': float(confidence),
                'scores': {
                    'legitimate': prob_legitimate,
                    'phishing': prob_phishing
                }
            }
            
        except Exception as e:
            logger.error(f"Prediction failed: {str(e)}", exc_info=True)
            raise
    
    def is_ready(self) -> bool:
        """
        Check if model manager is ready for inference.
        
        Returns:
            True if all artifacts loaded successfully
        """
        return (
            self._model_loaded and 
            self.model is not None and 
            self.scaler is not None and 
            self.feature_columns is not None
        )
    
    def get_info(self) -> Dict[str, Any]:
        """
        Get model information.
        
        Returns:
            Dictionary with model metadata
        """
        return {
            'loaded': self.is_ready(),
            'model_type': type(self.model).__name__ if self.model else None,
            'scaler_type': type(self.scaler).__name__ if self.scaler else None,
            'num_features': len(self.feature_columns) if self.feature_columns else 0,
            'feature_names': list(self.feature_columns) if self.feature_columns else []
        }
