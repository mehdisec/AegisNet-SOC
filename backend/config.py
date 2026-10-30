import sys
import os
from pathlib import Path

# Base Paths (supports both source dev and PyInstaller frozen executable)
if getattr(sys, 'frozen', False):
    BUNDLE_DIR = Path(sys._MEIPASS)
    RUNTIME_DIR = Path(sys.executable).resolve().parent
else:
    BUNDLE_DIR = Path(__file__).resolve().parent.parent
    RUNTIME_DIR = BUNDLE_DIR

BASE_DIR = BUNDLE_DIR
DATA_DIR = RUNTIME_DIR / "data"
FRONTEND_DIR = BUNDLE_DIR / "frontend"

os.makedirs(DATA_DIR, exist_ok=True)

# Server Configuration
SERVER_HOST = os.getenv("AEGIS_HOST", "0.0.0.0")
SERVER_PORT = int(os.getenv("AEGIS_PORT", "8080"))
WS_BROADCAST_INTERVAL = float(os.getenv("AEGIS_WS_INTERVAL", "1.0"))  # Seconds

# GeoIP Configuration
MMDB_PATH = DATA_DIR / "GeoLite2-City.mmdb"
if not MMDB_PATH.exists() and (BUNDLE_DIR / "data" / "GeoLite2-City.mmdb").exists():
    MMDB_PATH = BUNDLE_DIR / "data" / "GeoLite2-City.mmdb"

GEOIP_CACHE_FILE = DATA_DIR / "geoip_cache.json"
BLOCKED_IPS_FILE = DATA_DIR / "blocked_ips.json"

# Limits & Filtering
MAX_STREAM_CONNECTIONS = 250
CONNECTION_HISTORY_LIMIT = 500

# Log & Audit Persistence
SECURITY_LOGS_FILE = DATA_DIR / "security_logs.json"
LOGIN_ATTEMPTS_FILE = DATA_DIR / "login_attempts.json"
MAX_LOG_EVENTS = 500
