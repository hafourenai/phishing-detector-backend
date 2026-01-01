import os
import shutil
from pathlib import Path
from app.utils.logger import get_logger

logger = get_logger(__name__)

def cleanup_pycache(root_dir: str = None):
    """
    Recursively delete all __pycache__ directories.
    """
    if root_dir is None:
        # Get the root of the backend
        root_dir = Path(__file__).parent.parent.parent
    else:
        root_dir = Path(root_dir)

    count = 0
    try:
        for pycache in root_dir.rglob("__pycache__"):
            if pycache.is_dir():
                shutil.rmtree(pycache)
                count += 1
        
        if count > 0:
            logger.info(f"Cleaned up {count} __pycache__ directories.")
    except Exception as e:
        logger.error(f"Failed to cleanup pycache: {str(e)}")
