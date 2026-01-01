"""Application entry point."""
import sys
from app import create_app
from app.config import config
from app.utils.logger import get_logger
from app.utils.cleaner import cleanup_pycache

logger = get_logger(__name__)


def main():
    """Run application."""
    try:
        # Automatic cleanup of __pycache__
        cleanup_pycache()
        
        app = create_app()
        
        logger.info("=" * 80)
        logger.info("🚀 PHISHING DETECTOR - PRODUCTION")
        logger.info("=" * 80)
        logger.info(f"Environment: {config.env}")
        logger.info(f"Host: {config.host}:{config.port}")
        logger.info(f"Debug: {config.debug}")
        logger.info(f"Model Version: {config.model_version}")
        logger.info("=" * 80)
        
        app.run(
            host=config.host,
            port=config.port,
            debug=config.debug,
            threaded=True
        )
    except Exception as e:
        logger.error(f"Failed to start application: {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()
