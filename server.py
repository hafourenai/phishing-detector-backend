from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import re
import os
import socket
import ssl
from dotenv import load_dotenv
from urllib.parse import urlparse, parse_qs
from datetime import datetime
from bs4 import BeautifulSoup

load_dotenv()

app = Flask(__name__)

# CORS Configuration - Allow specific origins in production
ALLOWED_ORIGINS = os.getenv('ALLOWED_ORIGINS', '*').split(',')
CORS(app, resources={r"/*": {"origins": ALLOWED_ORIGINS}})

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
GOOGLE_SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY")
API_KEY = os.getenv("API_KEY")



def is_valid_url(url):
    """Validasi format URL"""
    regex = re.compile(
        r'^(?:http|https)://'
        r'(?:\S+)'
    )
    return re.match(regex, url) is not None



def check_ssl_certificate(hostname):
    """Cek SSL Certificate dengan detail lengkap"""
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(10)
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
        return {
            'success': False,
            'error': f'SSL Error: {str(e)}',
            'message': 'Sertifikat SSL tidak valid atau bermasalah'
        }
    except socket.timeout:
        return {
            'success': False,
            'error': 'Timeout',
            'message': 'Koneksi timeout, server tidak merespons'
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'message': 'Tidak dapat mengecek sertifikat SSL'
        }



def heuristic_analysis(url):
    """Analisis heuristik untuk mendeteksi pola mencurigakan"""
    parsed = urlparse(url)
    score = 0
    issues = []
    
    suspicious_keywords = ["bonus", "login", "free", "airdrop", "verify", "gift", "bot", 
                          "account", "secure", "update", "confirm", "banking", "password"]
    url_lower = url.lower()
    found_keywords = [kw for kw in suspicious_keywords if kw in url_lower]
    if found_keywords:
        score += 5
        issues.append(f"Kata mencurigakan dalam URL: {', '.join(found_keywords)}")
    
    if re.search(r"(t[.\-_,]me|te1egram|telegraam|telegrarn)", url_lower):
        if "t.me/" not in url_lower and "telegram.me/" not in url_lower:
            score += 15
            issues.append("Domain menyerupai Telegram (kemungkinan palsu)")
    
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
        score += 20
        issues.append("Tidak menggunakan HTTPS (koneksi tidak aman)")
    
    params = parse_qs(parsed.query)
    if 'start' in params:
        score += 10
        issues.append("Parameter 'start' ditemukan di URL")
    
    return score, issues



def check_telegram_bot(username):
    """Cek apakah bot resmi terdaftar di Telegram"""
    if not TELEGRAM_BOT_TOKEN:
        return None, "Token Telegram tidak tersedia"
    
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getChat?chat_id=@{username}"
    try:
        response = requests.get(url, timeout=10).json()
        if response.get("ok"):
            chat = response.get("result", {})
            if chat.get("type") == "bot":
                return True, "Bot resmi terdaftar di Telegram"
            else:
                return False, "Akun bukan bot resmi"
        else:
            return False, "Akun tidak ditemukan di Telegram"
    except Exception as e:
        return False, f"Error saat cek Telegram: {e}"


def check_safe_browsing(url):
    """Cek dengan Google Safe Browsing API"""
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
        response = requests.post(endpoint, json=payload, timeout=10).json()
        if "matches" in response and len(response["matches"]) > 0:
            threat_types = [match.get('threatType', 'UNKNOWN') for match in response['matches']]
            threat_info = ', '.join(threat_types)
            return True, f"Terindikasi berbahaya: {threat_info}", threat_types
        else:
            return False, "Tidak ditemukan ancaman di Google Safe Browsing", []
    except Exception as e:
        return False, f"Error saat cek Safe Browsing: {e}", []


def analyze_content(url):
    """Analisis konten halaman untuk mendeteksi pola phishing"""
    try:
        response = requests.get(url, timeout=10)
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
        
        return score, issues
    except requests.RequestException as e:
        return 0, []
    except Exception:
        return 0, []


@app.route("/check", methods=["POST"])
def check_link():
    """Endpoint utama untuk mengecek URL"""
    data = request.get_json()
    url = data.get("url", "").strip()
    
    if not url:
        return jsonify({"error": "URL tidak boleh kosong"}), 400
    
    if not is_valid_url(url):
        return jsonify({"error": "URL tidak valid (harus dimulai dengan http:// atau https://)"}), 400
    
    parsed = urlparse(url)
    hostname = parsed.hostname
    
    results = {
        "url": url,
        "hostname": hostname,
        "checks": {}
    }
    
    total_score = 0
    all_issues = []
    
    # 1. Analisis Heuristik
    heur_score, heur_issues = heuristic_analysis(url)
    total_score += heur_score
    all_issues.extend(heur_issues)
    results["checks"]["heuristic"] = {
        "score": heur_score,
        "issues": heur_issues
    }
    
    # 2. Cek SSL Certificate 
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
    
    # 3. Cek Telegram Bot 
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
    
    # 4. Google Safe Browsing
    gsb_flagged, gsb_status, gsb_threats = check_safe_browsing(url)
    if gsb_flagged:
        total_score += 50
        all_issues.append(f"Google Safe Browsing: {gsb_status}")
    results["checks"]["google_safe_browsing"] = {
        "flagged": gsb_flagged,
        "status": gsb_status,
        "threats": gsb_threats
    }
    
    # 5. Content Analysis
    content_score, content_issues = analyze_content(url)
    total_score += content_score
    all_issues.extend(content_issues)
    if content_score > 0:
        results["checks"]["content"] = {
            "score": content_score,
            "issues": content_issues
        }
    
    # Tentukan status akhir
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
    
    return jsonify(results)


@app.route("/", methods=["GET"])
def index():
    """Root endpoint - informasi API"""
    return jsonify({
        "message": "🔒 API Deteksi Phishing & URL Safety Checker",
        "version": "2.0",
        "status": "active",
        "endpoints": {
            "check": {
                "method": "POST",
                "path": "/check",
                "description": "Cek keamanan URL",
                "body": {"url": "https://example.com"}
            },
            "health": {
                "method": "GET",
                "path": "/health",
                "description": "Health check server"
            }
        },
        "features": [
            "Analisis Heuristik",
            "Cek SSL Certificate",
            "Verifikasi Telegram Bot",
            "Google Safe Browsing API",
            "Content Analysis"
        ]
    })


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint"""
    return jsonify({
        "status": "ok",
        "message": "Server berjalan dengan baik!",
        "timestamp": datetime.now().isoformat()
    })


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug_mode = os.getenv("FLASK_ENV") != "production"
    
    if not debug_mode:
        print("=" * 70)
        print("🔒 URL SAFETY CHECKER & PHISHING DETECTOR")
        print("=" * 70)
        print(f"✅ Server running in PRODUCTION mode on port {port}")
        print("=" * 70)
    else:
        print("=" * 70)
        print("🔒 URL SAFETY CHECKER & PHISHING DETECTOR")
        print("=" * 70)
        print("✅ Server berjalan di: http://localhost:5000")
        print("📝 Endpoint utama: POST /check")
        print("💚 Health check: GET /health")
        print("=" * 70)
        print("\n🔧 Konfigurasi:")
        print(f"   - Telegram Bot Token: {'✅ Tersedia' if TELEGRAM_BOT_TOKEN else '❌ Tidak tersedia'}")
        print(f"   - Google Safe Browsing: {'✅ Tersedia' if (GOOGLE_SAFE_BROWSING_KEY or API_KEY) else '❌ Tidak tersedia'}")
        print("=" * 70)
        print("\n⏳ Menunggu request...\n")
    
    app.run(host="0.0.0.0", port=port, debug=debug_mode)