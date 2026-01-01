"""Logging configuration."""
import logging
import sys
from pathlib import Path
from typing import Optional

from app.config import config


def get_logger(name: str) -> logging.Logger:
    """
    Get a configured logger.
    
    Args:
        name: Logger name
        
    Returns:
        Configured logger
    """
    logger = logging.getLogger(name)
    
    if logger.handlers:
        return logger
    
    # Set level
    level = getattr(logging, config.log_level.upper(), logging.INFO)
    logger.setLevel(level)
    
    # Formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler
    if config.log_file:
        log_path = Path(config.log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(config.log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger
