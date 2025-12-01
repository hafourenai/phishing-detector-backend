from flask import Flask, request, jsonify, redirect
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import requests
import re
import os
import socket
import ssl
from dotenv import load_dotenv
from urllib.parse import urlparse, parse_qs
from datetime import datetime
from bs4 import BeautifulSoup
import logging

load_dotenv()

app = Flask(__name__)

ALLOWED_ORIGINS = os.getenv('ALLOWED_ORIGINS', '*').split(',')
CORS(app, resources={
    r"/*": {
        "origins": ALLOWED_ORIGINS,
        "methods": ["GET", "POST"],
        "allow_headers": ["Content-Type"]
    }
})

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
    strategy="fixed-window"
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
GOOGLE_SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY")
API_KEY = os.getenv("API_KEY")

MAX_URL_LENGTH = 2000
REQUEST_TIMEOUT = 10


@app.before_request
def before_request():
    if not request.is_secure and os.getenv("FLASK_ENV") == "production":
        url = request.url.replace("http://", "https://", 1)
        return redirect(url, code=301)
    
    logger.info(f"Request: {request.method} {request.path} from {request.remote_addr}")


@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response


def is_valid_url(url):
    if not url or len(url) > MAX_URL_LENGTH:
        return False
    
    try:
        result = urlparse(url)
        return all([
            result.scheme in ['http', 'https'],
            result.netloc,
            not re.search(r'[<>"\']', url)
        ])
    except Exception:
        return False


def sanitize_url(url):
    url = url.strip()
    url = re.sub(r'[<>"\']', '', url)
    return url


def check_ssl_certificate(hostname):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(REQUEST_TIMEOUT)
            s.connect((hostname, 443))
            cert = s.getpeercert()
            
            issued_to = dict(x[0] for x in cert['subject']).get('commonName', 'Unknown')
            issuer = dict(x[0] for x in cert['issuer']).get('commonName', 'Unknown')
            
            valid_from = datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z")
            valid_until = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
            
            now = datetime.now()
            is_valid = valid_from <= now <= valid_until
            days_remaining = (valid_until - now).days
            
            return {
                'success': True,
                'issued_to': issued_to,
                'issuer': issuer,
                'valid_from': valid_from.strftime('%Y-%m-%d'),
                'valid_until': valid_until.strftime('%Y-%m-%d'),
                'is_valid': is_valid,
                'days_remaining': days_remaining
            }
    except ssl.SSLError as e:
        logger.warning(f"SSL Error for {hostname}: {str(e)}")
        return {
            'success': False,
            'error': f'SSL Error: {str(e)}',
            'message': 'Sertifikat SSL tidak valid atau bermasalah'
        }
    except socket.timeout:
        logger.warning(f"Timeout checking SSL for {hostname}")
        return {
            'success': False,
            'error': 'Timeout',
            'message': 'Koneksi timeout, server tidak merespons'
        }
    except Exception as e:
        logger.error(f"Error checking SSL for {hostname}: {str(e)}")
        return {
            'success': False,
            'error': str(e),
            'message': 'Tidak dapat mengecek sertifikat SSL'
        }


def heuristic_analysis(url):
    parsed = urlparse(url)
    score = 0
    issues = []
    
    suspicious_keywords = ["bonus", "login", "free", "airdrop", "verify", "gift", "bot", 
                          "account", "secure", "update", "confirm", "banking", "password",
                          "prize", "winner", "claim", "urgent", "suspended"]
    url_lower = url.lower()
    found_keywords = [kw for kw in suspicious_keywords if kw in url_lower]
    if found_keywords:
        score += 5
        issues.append(f"Kata mencurigakan dalam URL: {', '.join(found_keywords)}")
    
    if re.search(r"(t[.\-_,]me|te1egram|telegraam|telegrarn|paypa1|g00gle|faceb00k)", url_lower):
        if "t.me/" not in url_lower and "telegram.me/" not in url_lower:
            score += 30
            issues.append("Domain menyerupai brand terkenal (kemungkinan palsu)")
    
    if parsed.hostname and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", parsed.hostname):
        score += 50
        issues.append("URL menggunakan IP address langsung")
    
    if parsed.hostname and len(parsed.hostname) > 50:
        score += 20
        issues.append("Nama domain terlalu panjang")
    
    if parsed.hostname and parsed.hostname.count('-') >= 3:
        score += 15
        issues.append("Terlalu banyak tanda hubung di domain")
    
    if parsed.scheme != "https":
        score += 35
        issues.append("Tidak menggunakan HTTPS (koneksi tidak aman)")
    
    params = parse_qs(parsed.query)
    suspicious_params = ['start', 'ref', 'token', 'key', 'auth', 'password']
    found_params = [p for p in suspicious_params if p in params]
    if found_params:
        score += 10
        issues.append(f"Parameter mencurigakan: {', '.join(found_params)}")
    
    shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co']
    if any(short in url_lower for short in shorteners):
        score += 15
        issues.append("Menggunakan URL shortener (bisa menyembunyikan tujuan asli)")
    
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
    if any(parsed.hostname and parsed.hostname.endswith(tld) for tld in suspicious_tlds):
        score += 20
        issues.append("Menggunakan TLD yang sering dipakai untuk phishing")
    
    return score, issues


def check_telegram_bot(username):
    if not TELEGRAM_BOT_TOKEN:
        return None, "Token Telegram tidak tersedia"
    
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getChat?chat_id=@{username}"
    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT).json()
        if response.get("ok"):
            chat = response.get("result", {})
            if chat.get("type") == "bot":
                return True, "Bot resmi terdaftar di Telegram"
            else:
                return False, "Akun bukan bot resmi"
        else:
            return False, "Akun tidak ditemukan di Telegram"
    except requests.RequestException as e:
        logger.error(f"Error checking Telegram bot: {str(e)}")
        return False, f"Error saat cek Telegram: {e}"


def check_safe_browsing(url):
    api_key = GOOGLE_SAFE_BROWSING_KEY or API_KEY
    
    if not api_key:
        return False, "API Key Google Safe Browsing tidak tersedia", []
    
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {
            "clientId": "phishing-detector",
            "clientVersion": "2.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    
    try:
        response = requests.post(endpoint, json=payload, timeout=REQUEST_TIMEOUT).json()
        if "matches" in response and len(response["matches"]) > 0:
            threat_types = [match.get('threatType', 'UNKNOWN') for match in response['matches']]
            threat_info = ', '.join(threat_types)
            logger.warning(f"Threat detected for {url}: {threat_info}")
            return True, f"Terindikasi berbahaya: {threat_info}", threat_types
        else:
            return False, "Tidak ditemukan ancaman di Google Safe Browsing", []
    except requests.RequestException as e:
        logger.error(f"Error checking Safe Browsing: {str(e)}")
        return False, f"Error saat cek Safe Browsing: {e}", []


def analyze_content(url):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=headers)
        soup = BeautifulSoup(response.content, 'html.parser')
        score = 0
        issues = []
        
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action', '')
            if 't.me/' in action or 'telegram' in action.lower():
                score += 20
                issues.append("Form submit ke link Telegram, mencurigakan")
                break
        
        scripts = soup.find_all('script')
        for script in scripts:
            script_text = script.string or ''
            if 't.me/' in script_text or 'telegram' in script_text.lower():
                score += 15
                issues.append("Script mengandung referensi Telegram")
                break
        
        iframes = soup.find_all('iframe', style=lambda x: x and 'display:none' in x)
        if iframes:
            score += 25
            issues.append("Ditemukan hidden iframe (teknik phishing umum)")
        
        return score, issues
    except requests.RequestException:
        return 0, []
    except Exception:
        return 0, []


@app.route("/check", methods=["POST"])
@limiter.limit("10 per minute")
def check_link():
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({"error": "Request body kosong"}), 400
        
        url = data.get("url", "").strip()
        
        if not url:
            return jsonify({"error": "URL tidak boleh kosong"}), 400
        
        if len(url) > MAX_URL_LENGTH:
            return jsonify({"error": f"URL terlalu panjang (max {MAX_URL_LENGTH} karakter)"}), 400
        
        url = sanitize_url(url)
        
        if not is_valid_url(url):
            return jsonify({"error": "URL tidak valid (harus dimulai dengan http:// atau https://)"}), 400
        
        logger.info(f"Checking URL: {url} from IP: {request.remote_addr}")
        
        parsed = urlparse(url)
        hostname = parsed.hostname
        
        results = {
            "url": url,
            "hostname": hostname,
            "checks": {}
        }
        
        total_score = 0
        all_issues = []
        
        heur_score, heur_issues = heuristic_analysis(url)
        total_score += heur_score
        all_issues.extend(heur_issues)
        results["checks"]["heuristic"] = {
            "score": heur_score,
            "issues": heur_issues
        }
        
        ssl_info = None
        if parsed.scheme == 'https':
            ssl_info = check_ssl_certificate(hostname)
            if not ssl_info['success']:
                total_score += 25
                all_issues.append(ssl_info['message'])
            elif not ssl_info['is_valid']:
                total_score += 20
                all_issues.append("Sertifikat SSL sudah kadaluarsa atau belum valid")
            elif ssl_info['days_remaining'] < 30:
                total_score += 10
                all_issues.append(f"Sertifikat SSL akan kadaluarsa dalam {ssl_info['days_remaining']} hari")
            results["checks"]["ssl"] = ssl_info
        
        telegram_username = None
        telegram_status = None
        if "t.me/" in url or "telegram.me/" in url:
            username_match = re.findall(r"(?:t\.me|telegram\.me)/([A-Za-z0-9_]+)", url)
            if username_match:
                telegram_username = username_match[0]
                is_official, telegram_status = check_telegram_bot(telegram_username)
                
                if is_official is False:
                    total_score += 30
                    all_issues.append(f"Bot @{telegram_username} tidak resmi atau tidak ditemukan")
                elif is_official is True:
                    all_issues.append(f"Bot @{telegram_username} adalah bot resmi")
                
                results["checks"]["telegram"] = {
                    "username": telegram_username,
                    "is_official": is_official,
                    "status": telegram_status
                }
        
        gsb_flagged, gsb_status, gsb_threats = check_safe_browsing(url)
        if gsb_flagged:
            total_score += 50
            all_issues.append(f"Google Safe Browsing: {gsb_status}")
        results["checks"]["google_safe_browsing"] = {
            "flagged": gsb_flagged,
            "status": gsb_status,
            "threats": gsb_threats
        }
        
        content_score, content_issues = analyze_content(url)
        total_score += content_score
        all_issues.extend(content_issues)
        if content_score > 0:
            results["checks"]["content"] = {
                "score": content_score,
                "issues": content_issues
            }
        
        if total_score >= 70:
            final_status = "⚠️ SANGAT BERBAHAYA"
            status_class = "danger"
        elif total_score >= 40:
            final_status = "⚠️ WASPADA"
            status_class = "warning"
        else:
            final_status = "✅ AMAN"
            status_class = "safe"
        
        results["score"] = total_score
        results["status"] = final_status
        results["status_class"] = status_class
        results["issues"] = all_issues
        
        logger.info(f"Check completed for {url}: {final_status} (score: {total_score})")
        
        return jsonify(results)
        
    except Exception as e:
        logger.error(f"Unexpected error in check_link: {str(e)}")
        return jsonify({"error": "Terjadi kesalahan internal server"}), 500


@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "message": "🔒 API Deteksi Phishing & URL Safety Checker",
        "version": "2.0 (Secure)",
        "status": "active",
        "endpoints": {
            "check": {
                "method": "POST",
                "path": "/check",
                "description": "Cek keamanan URL",
                "body": {"url": "https://example.com"},
                "rate_limit": "10 requests per minute"
            },
            "health": {
                "method": "GET",
                "path": "/health",
                "description": "Health check server"
            }
        },
        "features": [
            "Analisis Heuristik Enhanced",
            "Cek SSL Certificate",
            "Verifikasi Telegram Bot",
            "Google Safe Browsing API",
            "Content Analysis",
            "Rate Limiting Protection",
            "CORS Protection",
            "Input Validation",
            "Security Headers"
        ],
        "security": {
            "rate_limiting": "200 per day, 50 per hour, 10 per minute",
            "https_only": True,
            "cors_enabled": True,
            "input_sanitization": True
        }
    })


@app.route("/health", methods=["GET"])
@limiter.exempt
def health():
    return jsonify({
        "status": "ok",
        "message": "Server berjalan dengan baik!",
        "timestamp": datetime.now().isoformat(),
        "environment": os.getenv("FLASK_ENV", "development"),
        "rate_limiting": "active",
        "security_headers": "active"
    })


@app.errorhandler(429)
def ratelimit_handler(e):
    logger.warning(f"Rate limit exceeded from IP: {request.remote_addr}")
    return jsonify({
        "error": "Rate limit exceeded",
        "message": "Terlalu banyak request. Silakan tunggu beberapa saat."
    }), 429


@app.errorhandler(404)
def not_found(e):
    return jsonify({
        "error": "Endpoint not found",
        "message": "Endpoint yang Anda cari tidak ditemukan"
    }), 404


@app.errorhandler(500)
def internal_error(e):
    logger.error(f"Internal server error: {str(e)}")
    return jsonify({
        "error": "Internal server error",
        "message": "Terjadi kesalahan pada server"
    }), 500


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug_mode = os.getenv("FLASK_ENV") != "production"
    
    if not debug_mode:
        print("=" * 70)
        print("🔒 URL SAFETY CHECKER & PHISHING DETECTOR (SECURE)")
        print("=" * 70)
        print(f"✅ Server running in PRODUCTION mode on port {port}")
        print("🛡️  Security features: ACTIVE")
        print("   - Rate Limiting: 10/min, 50/hour, 200/day")
        print("   - CORS Protection: ACTIVE")
        print("   - Input Validation: ACTIVE")
        print("   - Security Headers: ACTIVE")
        print("=" * 70)
    else:
        print("=" * 70)
        print("🔒 URL SAFETY CHECKER & PHISHING DETECTOR (SECURE)")
        print("=" * 70)
        print("✅ Server berjalan di: http://localhost:5000")
        print("📝 Endpoint utama: POST /check")
        print("💚 Health check: GET /health")
        print("🛡️  Security: DEVELOPMENT MODE")
        print("=" * 70)
        print("\n🔧 Konfigurasi:")
        print(f"   - Telegram Bot Token: {'✅ Tersedia' if TELEGRAM_BOT_TOKEN else '❌ Tidak tersedia'}")
        print(f"   - Google Safe Browsing: {'✅ Tersedia' if (GOOGLE_SAFE_BROWSING_KEY or API_KEY) else '❌ Tidak tersedia'}")
        print(f"   - Rate Limiting: ✅ Active")
        print(f"   - CORS Protection: ✅ Active")
        print("=" * 70)
        print("\n⏳ Menunggu request...\n")
    
    app.run(host="0.0.0.0", port=port, debug=debug_mode)