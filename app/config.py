"""Application configuration management."""
import os
from typing import Optional
from dataclasses import dataclass, field
from dotenv import load_dotenv

load_dotenv()


@dataclass
class APIConfig:
    """API credentials configuration."""
    virustotal: Optional[str] = field(default_factory=lambda: os.getenv("VIRUSTOTAL_API_KEY"))
    safe_browsing: Optional[str] = field(default_factory=lambda: os.getenv("GOOGLE_SAFE_BROWSING_KEY"))
    ipqualityscore: Optional[str] = field(default_factory=lambda: os.getenv("IPQUALITYSCORE_API_KEY"))
    rapidapi: Optional[str] = field(default_factory=lambda: os.getenv("RAPIDAPI_KEY"))
    telegram: Optional[str] = field(default_factory=lambda: os.getenv("TELEGRAM_BOT_TOKEN"))


@dataclass
class AppConfig:
    """Application configuration."""
    # Environment
    env: str = field(default_factory=lambda: os.getenv("FLASK_ENV", "production"))
    debug: bool = field(default_factory=lambda: os.getenv("FLASK_DEBUG", "False").lower() == "true")
    
    # Server
    host: str = field(default_factory=lambda: os.getenv("HOST", "0.0.0.0"))
    port: int = field(default_factory=lambda: int(os.getenv("PORT", "5000")))
    
    # Security
    secret_key: str = field(default_factory=lambda: os.getenv("SECRET_KEY", "change-this-in-production"))
    allowed_origins: list = field(default_factory=lambda: os.getenv("ALLOWED_ORIGINS", "*").split(","))
    
    # Rate Limiting
    rate_limit_per_day: int = field(default_factory=lambda: int(os.getenv("RATE_LIMIT_DAY", "200")))
    rate_limit_per_hour: int = field(default_factory=lambda: int(os.getenv("RATE_LIMIT_HOUR", "50")))
    rate_limit_per_minute: int = field(default_factory=lambda: int(os.getenv("RATE_LIMIT_MINUTE", "10")))
    
    # Request Settings
    max_url_length: int = 2000
    request_timeout: int = 15
    max_workers: int = 5
    
    # Cache
    cache_enabled: bool = field(default_factory=lambda: os.getenv("CACHE_ENABLED", "True").lower() == "true")
    cache_ttl: int = field(default_factory=lambda: int(os.getenv("CACHE_TTL", "3600")))
    redis_url: Optional[str] = field(default_factory=lambda: os.getenv("REDIS_URL"))
    
    # ML Model
    model_path: str = field(default_factory=lambda: os.getenv("MODEL_PATH", "models/phishing_model_v1.pkl"))
    model_version: str = "1.0.0"
    
    # Logging
    log_level: str = field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))
    log_file: Optional[str] = field(default_factory=lambda: os.getenv("LOG_FILE"))
    
    # APIs
    apis: APIConfig = field(default_factory=APIConfig)
    
    @property
    def is_production(self) -> bool:
        """Check if running in production."""
        return self.env == "production"
    
    @property
    def is_development(self) -> bool:
        """Check if running in development."""
        return self.env == "development"


# Global config instance
config = AppConfig()
