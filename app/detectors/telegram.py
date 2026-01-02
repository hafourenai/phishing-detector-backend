"""Telegram detector."""
import requests
import re
from typing import Dict, Any, Tuple

from app.config import config
from app.detectors.base import BaseDetector
from app.models import DetectionResult
from app.utils.logger import get_logger

logger = get_logger(__name__)


class TelegramDetector(BaseDetector):
    """Detector for Telegram bots and phishing links."""
    
    def __init__(self):
        super().__init__(name="telegram")
        self.token = config.apis.telegram
        self.timeout = config.request_timeout
        
    async def detect(self, url: str, **kwargs) -> DetectionResult:
        """Check if URL contains suspicious Telegram bot references."""
        issues = []
        score = 0.0
        
        # Check if URL itself is a Telegram link
        is_tg_link = "t.me/" in url or "telegram.me/" in url
        
        if is_tg_link and self.token:
            username_match = re.findall(r"(?:t\.me|telegram\.me)/([A-Za-z0-9_]+)", url)
            if username_match:
                username = username_match[0]
                success, info = self._check_bot(username)
                
                if success:
                    if info.get('is_bot'):
                        issues.append(f"Telegram: Official bot identified (@{username})")
                        # Official bots are generally safer, but could be a tool for phishing
                        # We don't necessarily increase risk score just because it's a bot
                    else:
                        issues.append(f"Telegram: Regular account link ({info.get('status')})")
                else:
                    issues.append(f"Telegram: Account check failed: {info.get('status')}")
                    score += 20 # Suspicious if claim is a bot but not found
        
        return self._create_result(
            score=score,
            issues=issues,
            details={"is_telegram_link": is_tg_link}
        )

    def _check_bot(self, username: str) -> Tuple[bool, Dict[str, Any]]:
        """Ported logic from server.py check_telegram_bot."""
        url = f"https://api.telegram.org/bot{self.token}/getChat?chat_id=@{username}"
        try:
            response = requests.get(url, timeout=self.timeout).json()
            
            if response.get("ok"):
                chat = response.get("result", {})
                is_bot = chat.get("type") == "bot"
                
                return True, {
                    "is_official": True,
                    "is_bot": is_bot,
                    "first_name": chat.get("first_name", ""),
                    "status": "Bot found" if is_bot else "Regular account found"
                }
            else:
                return False, {"status": "Account not found"}
        except Exception as e:
            return False, {"status": str(e)}
