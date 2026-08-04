import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.environ["DATABASE_URL"]
SESSION_SECRET_KEY = os.environ["SESSION_SECRET_KEY"]
SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true"

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
WINDOWS_EXE_PATH = Path(
    os.environ.get("WINDOWS_EXE_PATH", str(REPO_ROOT / "backend" / "static" / "WebizInventory_Windows.exe"))
)
PUBLIC_API_BASE_URL = os.environ.get("PUBLIC_API_BASE_URL", "https://api.example.com")
CHECKIN_API_URL_FOR_DOWNLOAD = f"{PUBLIC_API_BASE_URL}/api/v1/inventory/checkin"

SENDLY_API_KEY = os.environ.get("SENDLY_API_KEY", "")
NOTIFICATION_FROM_EMAIL = os.environ.get("NOTIFICATION_FROM_EMAIL", "noreply@assetly.ge")
OPS_ALERT_EMAIL = os.environ.get("OPS_ALERT_EMAIL", "")
