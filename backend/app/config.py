import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.environ["DATABASE_URL"]
SESSION_SECRET_KEY = os.environ["SESSION_SECRET_KEY"]
SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true"

# asyncpg pool sizing. Under serverless, every warm instance holds its own pool,
# so what actually lands on Postgres is (instances x max_size), not max_size --
# concurrency has to come from more instances, not fatter pools, or a traffic
# spike exhausts the connection limit. Deliberately small; raise only on a
# long-lived single-process deployment (container/VM), where the opposite is
# true and a bigger pool is free.
DB_POOL_MAX_SIZE = int(os.environ.get("DB_POOL_MAX_SIZE", "2"))
# Caps how long one query can hold a slot. Without it a query blocked on a lock
# runs until the platform kills the whole invocation, which surfaces as an
# opaque function timeout rather than a database error anyone can act on.
DB_COMMAND_TIMEOUT = float(os.environ.get("DB_COMMAND_TIMEOUT", "10"))

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
WINDOWS_EXE_PATH = Path(
    os.environ.get("WINDOWS_EXE_PATH", str(REPO_ROOT / "backend" / "static" / "AssetlyAgent_Windows.exe"))
)

# Identity of the macOS installer package. The identifier is what macOS keys
# receipts on, so changing it turns every future install into a second, parallel
# product rather than an upgrade of this one -- treat it as permanent. The
# version is what `pkgutil --pkg-info` reports, and should be bumped whenever
# the installed agent changes.
MACOS_PKG_IDENTIFIER = os.environ.get("MACOS_PKG_IDENTIFIER", "com.assetly.inventory-agent")
MACOS_PKG_VERSION = os.environ.get("MACOS_PKG_VERSION", "2.0")
PUBLIC_API_BASE_URL = os.environ.get("PUBLIC_API_BASE_URL", "https://api.example.com")
CHECKIN_API_URL_FOR_DOWNLOAD = f"{PUBLIC_API_BASE_URL}/api/v1/inventory/checkin"

SENDLY_API_KEY = os.environ.get("SENDLY_API_KEY", "")
NOTIFICATION_FROM_EMAIL = os.environ.get("NOTIFICATION_FROM_EMAIL", "noreply@assetly.ge")
OPS_ALERT_EMAIL = os.environ.get("OPS_ALERT_EMAIL", "")

# Fallback interval for a company row that cannot be read, and the source of
# the historic 180-day band. Per-company values live on companies.
# checkin_interval_seconds (migration 010) and are what actually drive status.
DEFAULT_CHECKIN_INTERVAL_SECONDS = int(
    os.environ.get("DEFAULT_CHECKIN_INTERVAL_SECONDS", "15552000")
)
# How far past its own interval a device drifts before it stops being merely
# "pending" and is written off. 1.5 reproduces the previous fixed 270-day
# pending boundary at the default 180-day interval, which is what makes this
# change behaviour-preserving for every existing company.
PENDING_GRACE_MULTIPLIER = float(os.environ.get("PENDING_GRACE_MULTIPLIER", "1.5"))

# Enrollment tokens are reusable within a window rather than single-use:
# installers are bulk-pushed via GPO/MDM to whole sites, so a single-use token
# would enroll one machine and silently fail every other one.
ENROLLMENT_TOKEN_DAYS = int(os.environ.get("ENROLLMENT_TOKEN_DAYS", "90"))

# Agents deployed before enrollment existed authenticate with the company key.
# self_update() rewrites the agent on disk but the running process is old code,
# so a machine only migrates on its NEXT run -- up to INTERVAL_MONTHS (6) later.
# Refusing company-key check-ins immediately would take those machines dark for
# a season, silently. Flip to false only once the fleet has converted.
ALLOW_LEGACY_COMPANY_KEY_CHECKIN = (
    os.environ.get("ALLOW_LEGACY_COMPANY_KEY_CHECKIN", "true").lower() == "true"
)
