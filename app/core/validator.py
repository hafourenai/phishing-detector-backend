"""URL validation and sanitization."""
import re
import ipaddress
from urllib.parse import urlparse, unquote
from typing import Tuple

from app.exceptions import ValidationError
from app.config import config


class URLValidator:
    """URL validation and sanitization."""
    
    @staticmethod
    def sanitize(url: str) -> str:
        """Sanitize URL."""
        url = url.strip()
        url = re.sub(r'[<>"\']', '', url)
        url = unquote(url)
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        return url
    
    @staticmethod
    def validate(url: str) -> Tuple[bool, str]:
        """
        Validate URL.
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not url:
            return False, "URL cannot be empty"
        
        if len(url) > config.max_url_length:
            return False, f"URL too long (max {config.max_url_length} characters)"
        
        try:
            result = urlparse(url)
            
            if result.scheme not in ['http', 'https']:
                return False, "Invalid URL scheme (must be http or https)"
            
            if not result.netloc:
                return False, "Invalid URL format (missing domain)"
            
            if re.search(r'[<>"\']', url):
                return False, "URL contains invalid characters"
            
            # Validate domain or IP
            try:
                domain = result.netloc.split(':')[0]
                ipaddress.ip_address(domain)
                return True, ""  # Valid IP
            except ValueError:
                # Not an IP, validate as domain
                if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', result.netloc):
                    return False, "Invalid domain format"
            
            return True, ""
            
        except Exception as e:
            return False, f"URL validation error: {str(e)}"
    
    @staticmethod
    def process(url: str) -> str:
        """
        Process URL: sanitize and validate.
        
        Raises:
            ValidationError: If URL is invalid
        """
        sanitized = URLValidator.sanitize(url)
        is_valid, error = URLValidator.validate(sanitized)
        
        if not is_valid:
            raise ValidationError(error)
        
        return sanitized
