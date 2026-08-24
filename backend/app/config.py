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

# Where sign_release.py writes and the manifest endpoint reads.
#
# Deliberately under backend/app/static/, not backend/static/: app/main.py
# only ever mounts the former at /static (see StaticFiles(directory=...
# app/static)), so an artifact written anywhere else is signed, verified by
# the agent as up to date, and then 404s the moment it tries to download --
# the update channel would authenticate a release it can never actually
# serve. vercel.json's includeFiles already lists both `backend/app/static/**`
# and `backend/static/**`, so this location ships in the deployed bundle
# either way.
UPDATES_DIR = os.environ.get(
    "UPDATES_DIR", str(REPO_ROOT / "backend" / "app" / "static" / "updates")
)

# The agent-update signing PUBLIC key, base64 DER (SubjectPublicKeyInfo).
# Public by definition -- committing it is correct and is what lets an agent
# verify. The PRIVATE key lives offline on a release owner's machine and is
# never in this repository, in CI, or in an environment variable: that is the
# entire control. See backend/scripts/sign_release.py.
UPDATE_SIGNING_PUBLIC_KEY = os.environ.get("UPDATE_SIGNING_PUBLIC_KEY", "")
OPS_ALERT_EMAIL = os.environ.get("OPS_ALERT_EMAIL", "")

# Fallbacks used by resolve_schedule when a company row cannot be read, and the
# source of the historic 180-day band. Per-company values live on
# companies.checkin_interval_seconds / .cancel_retry_seconds (migration 010)
# and are what actually drive both status and the agents.
DEFAULT_CHECKIN_INTERVAL_SECONDS = int(
    os.environ.get("DEFAULT_CHECKIN_INTERVAL_SECONDS", "15552000")
)
DEFAULT_CANCEL_RETRY_SECONDS = int(
    os.environ.get("DEFAULT_CANCEL_RETRY_SECONDS", "86400")
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

# Installer-minted tokens get a much shorter life than the 90-day default.
# A token embedded in an installer is distributed by email, file share, GPO,
# and MDM -- channels with no protection -- so its value to an attacker should
# expire in days, not a season. 90 stays available as an explicit admin choice.
INSTALLER_TOKEN_DAYS = int(os.environ.get("INSTALLER_TOKEN_DAYS", "14"))
INSTALLER_TOKEN_DAY_CHOICES = (7, 14, 30, 90)

# Agents deployed before enrollment existed authenticate with the company key.
# self_update() rewrites the agent on disk but the running process is old code,
# so a machine only migrates on its NEXT run -- up to INTERVAL_MONTHS (6) later.
# Refusing company-key check-ins immediately would take those machines dark for
# a season, silently. Flip to false only once the fleet has converted.
ALLOW_LEGACY_COMPANY_KEY_CHECKIN = (
    os.environ.get("ALLOW_LEGACY_COMPANY_KEY_CHECKIN", "true").lower() == "true"
)

# An explicit admin session lifetime. Starlette's SessionMiddleware default is
# 14 days, which for a console that can mint enrollment tokens and rotate any
# company's API key is far too long. Eight hours is one working day.
SESSION_MAX_AGE_SECONDS = int(os.environ.get("SESSION_MAX_AGE_SECONDS", "28800"))

# Drives the startup assertion below. Anything other than "production" is
# treated as a developer machine, where plain HTTP is normal.
ENVIRONMENT = os.environ.get("ENVIRONMENT", "development")

# A security-relevant default that fails open silently is exactly the failure
# mode the pre-launch audit called out: left unset, the admin session cookie
# is transmittable over plaintext HTTP. Refuse to boot rather than serve
# insecurely.
if ENVIRONMENT == "production" and not SESSION_COOKIE_SECURE:
    raise RuntimeError(
        "SESSION_COOKIE_SECURE must be true when ENVIRONMENT=production"
    )

# Rate limits, as (limit, window_seconds). Deliberately generous: these exist
# to stop credential stuffing and cost amplification, not to shape legitimate
# traffic. A real fleet checks in on a six-month interval, so an agent that
# trips its limit is malfunctioning or malicious either way.
RATE_LIMIT_LOGIN = (int(os.environ.get("RATE_LIMIT_LOGIN", "10")), 900)
# Enrollment is keyed on the bearer token, not client_ip, because Task 12
# moved enrollment to install time: an MDM/GPO rollout pushes the installer
# to every seat in a site from one egress IP, so an IP-keyed limit punishes
# large sites for being large. The real per-token ceiling is max_devices on
# the token itself (enforced in enroll_device) -- this bucket only needs to
# stop pathological abuse of one token (a scripted retry storm, a bug loop),
# not size a legitimate rollout, so it is set well above any realistic site:
# 500/hour is >16x a 30-per-hour site push and still far below what a script
# hammering one token would produce in the same window.
RATE_LIMIT_ENROLL_TOKEN = (int(os.environ.get("RATE_LIMIT_ENROLL_TOKEN", "500")), 3600)
# Kept as a secondary, coarser guard so a flood of malformed/unknown-token
# requests from one address (which have no token to bucket on until they're
# rejected) can still be capped. Set high enough that several companies'
# installers rolling out from behind the same NAT/proxy in the same hour
# don't collide with it: 300/hour comfortably covers a multi-company site
# while still bounding a single misbehaving address.
RATE_LIMIT_ENROLL_IP = (int(os.environ.get("RATE_LIMIT_ENROLL_IP", "300")), 3600)
RATE_LIMIT_AGENT = (int(os.environ.get("RATE_LIMIT_AGENT", "60")), 3600)

# Auth-failure digesting. At most one digest per interval, with a hard daily
# cap so that even a pathological failure of the interval logic cannot turn
# this back into an amplifier.
AUTH_DIGEST_INTERVAL_SECONDS = int(os.environ.get("AUTH_DIGEST_INTERVAL_SECONDS", "3600"))
AUTH_DIGEST_DAILY_CAP = int(os.environ.get("AUTH_DIGEST_DAILY_CAP", "24"))
