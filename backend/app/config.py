import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.environ["DATABASE_URL"]
SESSION_SECRET_KEY = os.environ["SESSION_SECRET_KEY"]
SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true"

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
WINDOWS_EXE_PATH = Path(
    os.environ.get("WINDOWS_EXE_PATH", str(REPO_ROOT / "backend" / "static" / "AssetlyAgent_Windows.exe"))
)
PUBLIC_API_BASE_URL = os.environ.get("PUBLIC_API_BASE_URL", "https://api.example.com")
CHECKIN_API_URL_FOR_DOWNLOAD = f"{PUBLIC_API_BASE_URL}/api/v1/inventory/checkin"

SENDLY_API_KEY = os.environ.get("SENDLY_API_KEY", "")
NOTIFICATION_FROM_EMAIL = os.environ.get("NOTIFICATION_FROM_EMAIL", "noreply@assetly.ge")
OPS_ALERT_EMAIL = os.environ.get("OPS_ALERT_EMAIL", "")

# Device staleness bands, in days. These track inventory_agent.py's
# INTERVAL_MONTHS = 6: should_show_form() refuses to display the check-in form
# if the last run was under that, so a healthy device reports twice a year.
# "online" therefore means "within its 6-month window", not "recently active".
# If INTERVAL_MONTHS changes, change these with it.
DEVICE_ONLINE_MAX_AGE_DAYS = int(os.environ.get("DEVICE_ONLINE_MAX_AGE_DAYS", "180"))
DEVICE_PENDING_MAX_AGE_DAYS = int(os.environ.get("DEVICE_PENDING_MAX_AGE_DAYS", "270"))
