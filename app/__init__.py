"""Application factory."""
from flask import Flask
from flask_cors import CORS

from app.config import config
from app.api.routes import api_bp, limiter


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
    
    @app.route('/')
    def index():
        return {
            "message": "Phishing Detector API is running",
            "version": config.model_version,
            "docs": "/api/info"
        }
    
    return app
