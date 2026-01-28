"""Prediction result caching for ML inference."""
import hashlib
import time
import threading
from typing import Optional, Dict, Any
from collections import OrderedDict
from app.utils.logger import get_logger

logger = get_logger(__name__)


class PredictionCache:
    """
    Thread-safe LRU cache for ML prediction results.
    
    Caches predictions to avoid repeated inference for the same URLs.
    Uses SHA256 hashing for cache keys and implements TTL-based expiration.
    """
    
    _instance = None
    _lock = threading.Lock()
    _initialized = False
    
    def __new__(cls, max_size: int = 1000, ttl: int = 3600):
        """Ensure singleton instance."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(PredictionCache, cls).__new__(cls)
        return cls._instance
    
    def __init__(self, max_size: int = 1000, ttl: int = 3600):
        """
        Initialize cache.
        
        Args:
            max_size: Maximum number of entries (LRU eviction)
            ttl: Time-to-live in seconds (default 1 hour)
        """
        if PredictionCache._initialized:
            return
            
        with PredictionCache._lock:
            if PredictionCache._initialized:
                return
            
            self.max_size = max_size
            self.ttl = ttl
            self._cache: OrderedDict[str, Dict[str, Any]] = OrderedDict()
            self._access_lock = threading.Lock()
            
            # Stats
            self._hits = 0
            self._misses = 0
            
            PredictionCache._initialized = True
            logger.info(f"PredictionCache initialized: max_size={max_size}, ttl={ttl}s")
    
    def _hash_url(self, url: str) -> str:
        """
        Generate cache key from URL.
        
        Args:
            url: URL to hash
            
        Returns:
            SHA256 hash of URL
        """
        return hashlib.sha256(url.encode('utf-8')).hexdigest()
    
    def _is_expired(self, entry: Dict[str, Any]) -> bool:
        """
        Check if cache entry is expired.
        
        Args:
            entry: Cache entry with timestamp
            
        Returns:
            True if expired
        """
        if 'timestamp' not in entry:
            return True
        
        age = time.time() - entry['timestamp']
        return age > self.ttl
    
    def get(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Get cached prediction result.
        
        Args:
            url: URL to look up
            
        Returns:
            Cached prediction result or None if not found/expired
        """
        cache_key = self._hash_url(url)
        
        with self._access_lock:
            if cache_key in self._cache:
                entry = self._cache[cache_key]
                
                # Check expiration
                if self._is_expired(entry):
                    # Remove expired entry
                    del self._cache[cache_key]
                    self._misses += 1
                    logger.debug(f"Cache expired for URL: {url[:50]}...")
                    return None
                
                # Move to end (LRU)
                self._cache.move_to_end(cache_key)
                self._hits += 1
                logger.debug(f"Cache HIT for URL: {url[:50]}...")
                return entry['result']
            
            self._misses += 1
            logger.debug(f"Cache MISS for URL: {url[:50]}...")
            return None
    
    def set(self, url: str, result: Dict[str, Any]) -> None:
        """
        Store prediction result in cache.
        
        Args:
            url: URL key
            result: Prediction result to cache
        """
        cache_key = self._hash_url(url)
        
        with self._access_lock:
            # Check size limit (LRU eviction)
            if len(self._cache) >= self.max_size:
                # Remove oldest entry
                oldest_key = next(iter(self._cache))
                del self._cache[oldest_key]
                logger.debug(f"Cache full - evicted oldest entry")
            
            # Store with timestamp
            self._cache[cache_key] = {
                'result': result,
                'timestamp': time.time(),
                'url': url  # Store for debugging
            }
            
            logger.debug(f"Cache SET for URL: {url[:50]}...")
    
    def clear(self) -> None:
        """Clear all cache entries."""
        with self._access_lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0
            logger.info("Cache cleared")
    
    def stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.
        
        Returns:
            Dictionary with cache stats
        """
        with self._access_lock:
            total_requests = self._hits + self._misses
            hit_rate = (self._hits / total_requests * 100) if total_requests > 0 else 0
            
            return {
                'size': len(self._cache),
                'max_size': self.max_size,
                'ttl': self.ttl,
                'hits': self._hits,
                'misses': self._misses,
                'total_requests': total_requests,
                'hit_rate': round(hit_rate, 2)
            }
    
    def cleanup_expired(self) -> int:
        """
        Remove all expired entries.
        
        Returns:
            Number of entries removed
        """
        with self._access_lock:
            expired_keys = [
                key for key, entry in self._cache.items()
                if self._is_expired(entry)
            ]
            
            for key in expired_keys:
                del self._cache[key]
            
            if expired_keys:
                logger.info(f"Cleaned up {len(expired_keys)} expired cache entries")
            
            return len(expired_keys)
