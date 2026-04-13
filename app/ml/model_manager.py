"""Singleton model manager for ML inference."""
import joblib
import threading
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Optional, Dict, Any, List
from app.utils.logger import get_logger

# Deep Learning model loader
try:
    from tensorflow.keras.models import load_model as keras_load_model
    _KERAS_AVAILABLE = True
except ImportError:
    _KERAS_AVAILABLE = False

logger = get_logger(__name__)


class ModelManager:
    """
    Singleton class to manage ML model artifacts.

    Loads model, scaler, and feature columns ONCE at initialization.
    Thread-safe and optimized for inference-only operations.

    Supports Dual Dataset Ensemble (6 models across Dataset A and Dataset B).
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

            # --- Legacy attributes (backward compatibility) ---
            self.model = None
            self.scaler = None
            self.feature_columns = None
            self._model_loaded = False

            # --- Dataset A models ---
            self.rf_A = None
            self.xgb_A = None
            self.dl_A = None
            self.scaler_A = None
            self.feature_columns_A = None

            # --- Dataset B models ---
            self.rf_B = None
            self.xgb_B = None
            self.dl_B = None
            self.scaler_B = None
            self.feature_columns_B = None

            # Load all artifacts
            self._load_artifacts()

            ModelManager._initialized = True

    def _load_artifacts(self):
        """Load all 6 ensemble models, 2 scalers, and 2 feature column lists."""
        try:
            base_path = Path(__file__).parent.parent.parent / "models"

            logger.info("=" * 80)
            logger.info("  Loading ML Model Artifacts (Dual Dataset Ensemble)...")
            logger.info("=" * 80)

            all_loaded = True

            # ── Dataset A ─────────────────────────────────────────────────
            path_A = base_path / "datasetA"

            # Random Forest A
            rf_A_path = path_A / "rf_model.joblib"
            if rf_A_path.exists():
                logger.info(f"Loading RF-A from: {rf_A_path}")
                self.rf_A = joblib.load(rf_A_path)
                logger.info(f"  RF-A loaded: {type(self.rf_A).__name__}")
            else:
                logger.warning(f"❌ RF-A not found: {rf_A_path}")
                all_loaded = False

            # XGBoost A
            xgb_A_path = path_A / "xgb_model.joblib"
            if xgb_A_path.exists():
                logger.info(f"Loading XGB-A from: {xgb_A_path}")
                self.xgb_A = joblib.load(xgb_A_path)
                logger.info(f"  XGB-A loaded: {type(self.xgb_A).__name__}")
            else:
                logger.warning(f"❌ XGB-A not found: {xgb_A_path}")
                all_loaded = False

            # Deep Learning A
            dl_A_path = path_A / "dl_model.keras"
            if dl_A_path.exists():
                if _KERAS_AVAILABLE:
                    logger.info(f"Loading DL-A from: {dl_A_path}")
                    self.dl_A = keras_load_model(str(dl_A_path))
                    logger.info("  DL-A loaded successfully")
                else:
                    logger.warning("❌ TensorFlow/Keras not available; cannot load DL-A")
                    all_loaded = False
            else:
                logger.warning(f"❌ DL-A not found: {dl_A_path}")
                all_loaded = False

            # Scaler A
            scaler_A_path = path_A / "scaler.joblib"
            if scaler_A_path.exists():
                logger.info(f"Loading Scaler-A from: {scaler_A_path}")
                self.scaler_A = joblib.load(scaler_A_path)
                logger.info(f"  Scaler-A loaded: {type(self.scaler_A).__name__}")
            else:
                logger.warning(f"❌ Scaler-A not found: {scaler_A_path}")
                all_loaded = False

            # Feature columns A
            fc_A_path = path_A / "feature_columns.joblib"
            if fc_A_path.exists():
                logger.info(f"Loading feature columns A from: {fc_A_path}")
                self.feature_columns_A = joblib.load(fc_A_path)
                logger.info(
                    f"  Feature columns A loaded: {len(self.feature_columns_A)} features"
                )
            else:
                logger.warning(f"❌ Feature columns A not found: {fc_A_path}")
                all_loaded = False

            # ── Dataset B ─────────────────────────────────────────────────
            path_B = base_path / "datasetB"

            # Random Forest B
            rf_B_path = path_B / "rf_model.joblib"
            if rf_B_path.exists():
                logger.info(f"Loading RF-B from: {rf_B_path}")
                self.rf_B = joblib.load(rf_B_path)
                logger.info(f"  RF-B loaded: {type(self.rf_B).__name__}")
            else:
                logger.warning(f"❌ RF-B not found: {rf_B_path}")
                all_loaded = False

            # XGBoost B
            xgb_B_path = path_B / "xgb_model.joblib"
            if xgb_B_path.exists():
                logger.info(f"Loading XGB-B from: {xgb_B_path}")
                self.xgb_B = joblib.load(xgb_B_path)
                logger.info(f"  XGB-B loaded: {type(self.xgb_B).__name__}")
            else:
                logger.warning(f"❌ XGB-B not found: {xgb_B_path}")
                all_loaded = False

            # Deep Learning B
            dl_B_path = path_B / "dl_model.keras"
            if dl_B_path.exists():
                if _KERAS_AVAILABLE:
                    logger.info(f"Loading DL-B from: {dl_B_path}")
                    self.dl_B = keras_load_model(str(dl_B_path))
                    logger.info("  DL-B loaded successfully")
                else:
                    logger.warning("❌ TensorFlow/Keras not available; cannot load DL-B")
                    all_loaded = False
            else:
                logger.warning(f"❌ DL-B not found: {dl_B_path}")
                all_loaded = False

            # Scaler B
            scaler_B_path = path_B / "scaler.joblib"
            if scaler_B_path.exists():
                logger.info(f"Loading Scaler-B from: {scaler_B_path}")
                self.scaler_B = joblib.load(scaler_B_path)
                logger.info(f"  Scaler-B loaded: {type(self.scaler_B).__name__}")
            else:
                logger.warning(f"❌ Scaler-B not found: {scaler_B_path}")
                all_loaded = False

            # Feature columns B
            fc_B_path = path_B / "feature_columns.joblib"
            if fc_B_path.exists():
                logger.info(f"Loading feature columns B from: {fc_B_path}")
                self.feature_columns_B = joblib.load(fc_B_path)
                logger.info(
                    f"  Feature columns B loaded: {len(self.feature_columns_B)} features"
                )
            else:
                logger.warning(f"❌ Feature columns B not found: {fc_B_path}")
                all_loaded = False

            # Backward-compat aliases 
            # / self.feature_columns continues to work.
            self.model = self.rf_B
            self.scaler = self.scaler_B
            self.feature_columns = self.feature_columns_B

            # Final status 
            self._model_loaded = all_loaded

            if self._model_loaded:
                logger.info("=" * 80)
                logger.info("  All 6 ML ensemble models loaded successfully!")
                logger.info("=" * 80)
            else:
                logger.warning("⚠️  One or more ensemble models failed to load.")

        except Exception as e:
            logger.error(f"❌ Failed to load ML artifacts: {str(e)}", exc_info=True)
            self._model_loaded = False

    #  Helper: extract phishing probability from a single model

    def _get_phishing_prob(self, model, scaled_df: pd.DataFrame) -> float:
        """Return the phishing class probability for *one* model.

        Handles sklearn-style (predict_proba), XGBoost DMatrix, and
        Keras models (predict returning a single float or array).
        """
        try:
            # Keras / tensorflow model
            if _KERAS_AVAILABLE and hasattr(model, "predict") and not hasattr(model, "predict_proba"):
                pred = model.predict(scaled_df.values, verbose=0)
                pred = np.asarray(pred).flatten()
                # Binary output: single sigmoid neuron → probability of class 1
                if len(pred) == 1:
                    return float(pred[0])
                # Softmax output: [prob_legit, prob_phishing]
                return float(pred[1]) if len(pred) >= 2 else float(pred[0])

            # Sklearn / XGBoost with predict_proba
            if hasattr(model, "predict_proba"):
                proba = model.predict_proba(scaled_df)[0]
                return float(proba[1])

            # Fallback: hard prediction
            pred = model.predict(scaled_df)[0]
            return 1.0 if int(pred) == 1 else 0.0

        except Exception as e:
            logger.warning(f"Could not get probability from {type(model).__name__}: {e}")
            return 0.5  # Neutral fallback

    #  Public API – signatures UNCHANGED from legacy version
    def align_features(
        self,
        features_dict: Dict[str, Any],
        feature_columns: Optional[List[str]] = None,
    ) -> pd.DataFrame:
        """
        Align features to training order and convert to pandas DataFrame.

        Args:
            features_dict: Dictionary of extracted features
            feature_columns: Optional explicit list of feature names.
                             Falls back to self.feature_columns when omitted.

        Returns:
            DataFrame with features in correct order and column names

        Raises:
            ValueError: If feature columns not loaded or features missing
        """
        cols = feature_columns if feature_columns is not None else self.feature_columns
        if cols is None:
            raise ValueError("Feature columns not loaded")

        feature_values = []
        missing_features = []

        for feature_name in cols:
            if feature_name in features_dict:
                feature_values.append(features_dict[feature_name])
            else:
                missing_features.append(feature_name)
                feature_values.append(0)  # Default value for missing features

        if missing_features:
            logger.warning(f"Missing features (using default 0): {missing_features}")

        # Return as DataFrame with column names to avoid sklearn warnings
        return pd.DataFrame([feature_values], columns=cols)

    def scale_features(
        self,
        features_df: pd.DataFrame,
        scaler=None,
    ) -> pd.DataFrame:
        """
        Apply scaling to features.

        Args:
            features_df: Raw feature DataFrame
            scaler: Optional explicit scaler instance.
                    Falls back to self.scaler when omitted.

        Returns:
            Scaled feature DataFrame

        Raises:
            ValueError: If scaler not loaded
        """
        sc = scaler if scaler is not None else self.scaler
        if sc is None:
            raise ValueError("Scaler not loaded")

        # Transform returns array, wrap back in DataFrame to preserve column names
        scaled_array = sc.transform(features_df)
        return pd.DataFrame(scaled_array, columns=features_df.columns)

    def predict(self, features_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform end-to-end prediction using the dual-dataset ensemble (soft voting).

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
            # Dataset A 
            features_A = self.align_features(features_dict, feature_columns=self.feature_columns_A)
            scaled_A = self.scale_features(features_A, scaler=self.scaler_A)

            prob_rf_A  = self._get_phishing_prob(self.rf_A,  scaled_A)
            prob_xgb_A = self._get_phishing_prob(self.xgb_A, scaled_A)
            prob_dl_A  = self._get_phishing_prob(self.dl_A,  scaled_A)
            avg_A = (prob_rf_A + prob_xgb_A + prob_dl_A) / 3.0

            # Dataset B 
            features_B = self.align_features(features_dict, feature_columns=self.feature_columns_B)
            scaled_B = self.scale_features(features_B, scaler=self.scaler_B)

            prob_rf_B  = self._get_phishing_prob(self.rf_B,  scaled_B)
            prob_xgb_B = self._get_phishing_prob(self.xgb_B, scaled_B)
            prob_dl_B  = self._get_phishing_prob(self.dl_B,  scaled_B)
            avg_B = (prob_rf_B + prob_xgb_B + prob_dl_B) / 3.0

            # Final ensemble probability
            final_prob  = (avg_A + avg_B) / 2.0
            is_phishing = final_prob >= 0.5
            confidence  = final_prob if is_phishing else (1.0 - final_prob)

            logger.debug(
                f"Ensemble probs — A:[rf={prob_rf_A:.3f}, xgb={prob_xgb_A:.3f}, "
                f"dl={prob_dl_A:.3f}] avg_A={avg_A:.3f} | "
                f"B:[rf={prob_rf_B:.3f}, xgb={prob_xgb_B:.3f}, "
                f"dl={prob_dl_B:.3f}] avg_B={avg_B:.3f} | "
                f"final={final_prob:.3f}"
            )

            return {
                'is_phishing': bool(is_phishing),
                'probability': float(final_prob),
                'confidence': float(confidence),
                'scores': {
                    'legitimate': float(1.0 - final_prob),
                    'phishing':   float(final_prob),
                }
            }

        except Exception as e:
            logger.error(f"Prediction failed: {str(e)}", exc_info=True)
            raise

    def is_ready(self) -> bool:
        """
        Check if model manager is ready for inference.

        Returns:
            True if ALL 6 ensemble models + 2 scalers + 2 feature column lists
            are loaded successfully.
        """
        return (
            self._model_loaded
            and self.rf_A is not None
            and self.xgb_A is not None
            and self.dl_A is not None
            and self.scaler_A is not None
            and self.feature_columns_A is not None
            and self.rf_B is not None
            and self.xgb_B is not None
            and self.dl_B is not None
            and self.scaler_B is not None
            and self.feature_columns_B is not None
        )

    def get_info(self) -> Dict[str, Any]:
        """
        Get model information.

        Returns:
            Dictionary with model metadata (legacy keys preserved + new keys).
        """
        # Legacy keys — preserved exactly
        info = {
            'loaded': self.is_ready(),
            'model_type': type(self.model).__name__ if self.model else None,
            'scaler_type': type(self.scaler).__name__ if self.scaler else None,
            'num_features': len(self.feature_columns) if self.feature_columns else 0,
            'feature_names': list(self.feature_columns) if self.feature_columns else [],
        }

        # New ensemble-specific keys
        info['ensemble_models'] = {
            'datasetA': {
                'rf':    type(self.rf_A).__name__  if self.rf_A  else None,
                'xgb':   type(self.xgb_A).__name__ if self.xgb_A else None,
                'dl':    type(self.dl_A).__name__  if self.dl_A  else None,
                'num_features': len(self.feature_columns_A) if self.feature_columns_A else 0,
            },
            'datasetB': {
                'rf':    type(self.rf_B).__name__  if self.rf_B  else None,
                'xgb':   type(self.xgb_B).__name__ if self.xgb_B else None,
                'dl':    type(self.dl_B).__name__  if self.dl_B  else None,
                'num_features': len(self.feature_columns_B) if self.feature_columns_B else 0,
            },
        }
        info['datasets'] = ['datasetA', 'datasetB']

        return info
