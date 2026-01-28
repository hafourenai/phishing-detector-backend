"""Application factory."""
from flask import Flask
from flask_cors import CORS

from app.config import config
from app.api.routes import api_bp, limiter
from app.utils.logger import get_logger

logger = get_logger(__name__)


def create_app() -> Flask:
    """
    Create and configure Flask application.
    
    Returns:
        Configured Flask app
    """
    app = Flask(__name__)
    
    # Configuration
    app.config['SECRET_KEY'] = config.secret_key
    
    # Extensions
    CORS(app, resources={r"/api/*": {"origins": config.allowed_origins}})
    limiter.init_app(app)
    
    # Blueprints
    app.register_blueprint(api_bp, url_prefix='/api')
    
    # Warmup ML model (load once at startup)
    with app.app_context():
        try:
            from app.ml.model_manager import ModelManager
            from app.ml.prediction_cache import PredictionCache
            
            # Initialize singleton instances
            manager = ModelManager()
            cache = PredictionCache(
                max_size=config.prediction_cache_max_size,
                ttl=config.prediction_cache_ttl
            )
            
            if manager.is_ready():
                logger.info("  ML Model warmup successful")
                info = manager.get_info()
                logger.info(f"   Model: {info['model_type']}")
                logger.info(f"   Features: {info['num_features']}")
            else:
                logger.warning("⚠️  ML Model warmup failed - predictions will be unavailable")
                
        except Exception as e:
            logger.error(f"❌ ML Model initialization error: {str(e)}")
    
    @app.route('/')
    def index():
        return {
            "message": "Phishing Detector API is running",
            "version": config.model_version,
            "docs": "/api/info"
        }
    
    return app
