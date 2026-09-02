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

# The Windows agent the portal HANDS OUT. This deliberately points at the
# SIGNED artifact under UPDATES_DIR, not at CI's build output in
# backend/static/.
#
# Why: those were two different files, and on 2026-08-24 they diverged and put
# a real endpoint into a permanent update loop. CI rebuilds
# backend/static/AssetlyAgent_Windows.exe on every change to the .ps1; the
# release owner signs a copy into UPDATES_DIR by hand. A freshly downloaded
# agent compared its own hash against the signed manifest, found a difference,
# "updated" to the signed build, restarted -- and the legacy GitHub-raw path in
# the older build pulled it straight back. Each step was correct in isolation;
# the two channels simply disagreed about which build was current.
#
# Serving the signed artifact collapses that to one source of truth: what the
# portal distributes is, by construction, exactly what the manifest signs, so a
# fresh install is immediately "already up to date". It also makes the failure
# mode safe -- change the .ps1 without signing a release and the portal keeps
# serving the last SIGNED build, so the mistake shows up as "my change did not
# ship" rather than as a fleet-wide loop. An unsigned build is never
# distributed. See .github/workflows/release-consistency.yml, which fails when
# CI's build and the signed manifest disagree.
WINDOWS_EXE_PATH = Path(
    os.environ.get("WINDOWS_EXE_PATH", str(Path(UPDATES_DIR) / "AssetlyAgent_Windows.exe"))
)

# The per-machine installer IT deploys through Intune, SCCM or GPO. Same
# directory and same reasoning as WINDOWS_EXE_PATH above: what the portal hands
# out is the artifact sign_release.py published, so it cannot drift from the
# manifest, and an unsigned build is never distributed. It is absent until a
# release has been signed -- the download route reports that as a 503 rather
# than a broken file, because an MSI is the artifact a fleet installs and a
# corrupt one is worse than a missing one.
WINDOWS_MSI_PATH = Path(
    os.environ.get("WINDOWS_MSI_PATH", str(Path(UPDATES_DIR) / "AssetlyAgent.msi"))
)

# Identity of the macOS installer package. The identifier is what macOS keys
# receipts on, so changing it turns every future install into a second, parallel
# product rather than an upgrade of this one -- treat it as permanent. The
# version is what `pkgutil --pkg-info` reports, and should be bumped whenever
# the installed agent changes.
MACOS_PKG_IDENTIFIER = os.environ.get("MACOS_PKG_IDENTIFIER", "com.assetly.inventory-agent")
# Stamped into the .pkg an end user installs, so it is what they read back out
# of "About This Mac -> Software" or `pkgutil --pkg-info`. Tracks AGENT_VERSION
# in inventory_agent.py: leaving it at 2.0 while the agent reported 2.2.0 would
# reproduce, one layer up, exactly the mismatch that bump was made to remove.
MACOS_PKG_VERSION = os.environ.get("MACOS_PKG_VERSION", "2.2.1")
PUBLIC_API_BASE_URL = os.environ.get("PUBLIC_API_BASE_URL", "https://api.example.com")
CHECKIN_API_URL_FOR_DOWNLOAD = f"{PUBLIC_API_BASE_URL}/api/v1/inventory/checkin"

SENDLY_API_KEY = os.environ.get("SENDLY_API_KEY", "")
NOTIFICATION_FROM_EMAIL = os.environ.get("NOTIFICATION_FROM_EMAIL", "noreply@assetly.ge")


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

# Optional override for the key that encrypts stored TOTP seeds. Left unset,
# the key is derived from SESSION_SECRET_KEY (see app/mfa.py) -- deliberately,
# so that shipping this feature does not add a REQUIRED environment variable
# whose absence would kill admin login on the deploy that forgets it. Set this
# only when rotating the MFA key independently of the session key.
MFA_SECRET_KEY = os.environ.get("MFA_SECRET_KEY", "")

# A 6-digit code is a far weaker secret than a password, and code verification
# is a new brute-forceable surface. Tighter than RATE_LIMIT_LOGIN accordingly.
# This is the per-ADMIN-ID bucket and it is the load-bearing control: it is
# keyed on something the caller cannot discard by starting a fresh login.
RATE_LIMIT_MFA = (int(os.environ.get("RATE_LIMIT_MFA", "5")), 900)

# The per-IP bucket, deliberately MUCH looser than RATE_LIMIT_MFA and tracked
# as its own constant rather than reusing it.
#
# Two reasons it must not be tight. First, it is not trustworthy defence: off
# Vercel, client_ip() falls through to the LAST x-forwarded-for entry, which
# only means anything when a real proxy appended it -- on a direct-connection
# deployment an attacker rotates that header freely, so this bucket cannot be
# counted as protection against a determined attacker. Second, and the reason
# the number matters: several admins behind one office NAT share an address,
# so at 5/900 they would lock each other out of their own second factor for
# 15 minutes of ordinary mistyping, and one attacker on that NAT could do it
# to everyone deliberately. This bucket exists only as a coarse guard against
# one address hammering MANY accounts.
RATE_LIMIT_MFA_IP = (int(os.environ.get("RATE_LIMIT_MFA_IP", "30")), 900)

# How long a password-verified-but-not-yet-MFA'd login may sit before it must
# be restarted. Checked server-side against a timestamp in the session, not
# left to the cookie's own lifetime.
PENDING_LOGIN_MAX_AGE_SECONDS = int(
    os.environ.get("PENDING_LOGIN_MAX_AGE_SECONDS", "300")
)
