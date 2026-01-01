"""Custom exceptions for the application."""


class PhishingDetectorError(Exception):
    """Base exception for phishing detector."""
    pass


class ValidationError(PhishingDetectorError):
    """Raised when validation fails."""
    pass


class APIError(PhishingDetectorError):
    """Raised when external API call fails."""
    pass


class ModelError(PhishingDetectorError):
    """Raised when ML model operation fails."""
    pass


class CacheError(PhishingDetectorError):
    """Raised when cache operation fails."""
    pass


class RateLimitError(PhishingDetectorError):
    """Raised when rate limit is exceeded."""
    pass
