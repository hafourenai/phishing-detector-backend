"""API routes."""
from flask import Blueprint, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import asyncio

from app.config import config
from app.core.analyzer import URLAnalyzer
from app.exceptions import ValidationError, PhishingDetectorError
from app.utils.logger import get_logger

logger = get_logger(__name__)

# Create blueprint
api_bp = Blueprint('api', __name__)

# Initialize limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[
        f"{config.rate_limit_per_day} per day",
        f"{config.rate_limit_per_hour} per hour"
    ]
)

# Initialize analyzer
analyzer = URLAnalyzer()


@api_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'version': config.model_version,
        'environment': config.env
    })


@api_bp.route('/check', methods=['POST'])
@limiter.limit(f"{config.rate_limit_per_minute} per minute")
def check_url():
    """
    Check URL for phishing.
    
    Request body:
        {
            "url": "https://example.com",
            "force_refresh": false,
            "include_details": true
        }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Request body is required'}), 400
        
        url = data.get('url')
        force_refresh = data.get('force_refresh', False)
        include_details = data.get('include_details', True)
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        # Analyze URL - handle async
        # Flask is not async by default in old versions, but Blueprint.route can be in Flask 2.0+
        # If running in older flask or without async support, we might need a wrapper
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(analyzer.analyze(
            url=url,
            force_refresh=force_refresh
        ))
        loop.close()
        
        # Build response
        response = result.to_dict()
        
        if not include_details:
            # Remove detailed information
            response.pop('detections', None)
            response.pop('score_breakdown', None)
        
        return jsonify(response), 200
        
    except ValidationError as e:
        logger.warning(f"Validation error: {str(e)}")
        return jsonify({'error': str(e)}), 400
        
    except PhishingDetectorError as e:
        logger.error(f"Detector error: {str(e)}")
        return jsonify({'error': 'Analysis failed', 'message': str(e)}), 500
        
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500


@api_bp.route('/info', methods=['GET'])
def api_info():
    """Get API information."""
    return jsonify({
        'name': 'Phishing Detector API',
        'version': config.model_version,
        'endpoints': {
            'health': {
                'method': 'GET',
                'path': '/health',
                'description': 'Health check'
            },
            'check': {
                'method': 'POST',
                'path': '/check',
                'description': 'Check URL for phishing',
                'rate_limit': f'{config.rate_limit_per_minute} per minute'
            },
            'info': {
                'method': 'GET',
                'path': '/info',
                'description': 'API information'
            }
        }
    })
