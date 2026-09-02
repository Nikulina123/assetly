#!/usr/bin/env python3
"""
Assetly Inventory Agent v2.0
Cross-platform (macOS + Linux) — zero pip dependencies.
Config is loaded from  ~/.assetly_inventory/config.json  (written by the installer).
"""

import os, sys, json, platform, subprocess, datetime, hashlib, hmac, base64, socket, re, time, argparse
import urllib.request, urllib.error
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, font as tkfont
import logging

# ─── Paths ────────────────────────────────────────────────────────────────────
_sys = platform.system()
if _sys == "Darwin":
    STATE_DIR = Path.home() / "Library" / "Application Support" / "AssetlyInventory"
else:
    STATE_DIR = Path.home() / ".assetly_inventory"

CONFIG_FILE = STATE_DIR / "config.json"
STATE_FILE  = STATE_DIR / "state.json"
QUEUE_FILE  = STATE_DIR / "queue.json"
LOG_FILE    = STATE_DIR / "agent.log"

# ─── Logging ──────────────────────────────────────────────────────────────────
# Directory creation and file-backed logging are deliberately deferred to the
# __main__ guard below: importing this module (as the test suite does, via
# importlib, to exercise verify_signature) must not perform disk I/O or start
# a GUI as a side effect of import alone. A plain stream logger exists at
# import time so every function that logs still has something to call.
log = logging.getLogger("assetly")
log.setLevel(logging.INFO)
if not log.handlers:
    _stream_handler = logging.StreamHandler(sys.stdout)
    _stream_handler.setFormatter(logging.Formatter("%(asctime)s  %(levelname)-8s  %(message)s"))
    log.addHandler(_stream_handler)


def _init_file_logging():
    """Creates STATE_DIR and adds the file handler. Called only for a real run
    (under the __main__ guard), never on import."""
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    file_handler.setFormatter(logging.Formatter("%(asctime)s  %(levelname)-8s  %(message)s"))
    log.addHandler(file_handler)

# ─── Config ───────────────────────────────────────────────────────────────────
_cfg: dict = {}
if CONFIG_FILE.exists():
    try:
        _cfg = json.loads(CONFIG_FILE.read_text())
    except Exception:
        pass

CHECKIN_API_URL  = _cfg.get("checkin_api_url", "https://api.example.com/api/v1/inventory/checkin")
CONFIG_API_URL   = CHECKIN_API_URL.rsplit("/checkin", 1)[0] + "/config"
ENROLL_API_URL   = CHECKIN_API_URL.rsplit("/inventory/checkin", 1)[0] + "/enroll"

# github_raw_url is deliberately NOT read, even when present in an existing
# config file. Honouring it was the second half of the fleet-RCE finding:
# any local user or process able to write this file could point the agent
# at a host they control and gain persistent code execution, re-established
# on every run. The update host is now derived from CHECKIN_API_URL, and the
# signature is what actually authorises an update -- so a redirected agent
# simply fails verification instead of installing an attacker's payload.

# ─── Update signing ───────────────────────────────────────────────────────────
# The release signing PUBLIC key, base64 DER. Compiled in on purpose: this is
# what the agent trusts, instead of trusting a URL. An attacker who can rewrite
# this agent's config file -- or who controls the network, or DNS, or the host
# the artifact is fetched from -- still cannot produce a manifest that verifies
# against this key, so none of those positions yields code execution any more.
#
# Replace with the real key at release time. An empty value disables updating
# entirely rather than falling back to anything.
UPDATE_SIGNING_PUBLIC_KEY = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEArlnAJm/gZa+426zuPIHjloYQVS1G0jb8SqZGbsLmjdzPvfT09DcUa+TKsphntNLAgxE8rDjbOTM9aVKol0LhMI9e/2XZe66EJBS881x8oh5hQKU5PkQV+lQHixCTz1YXExmRh2XltxeiaLgW5leK9djA5SauM2koR8LMu2GWEYzGFl6IpeOXiwv2OL2MJm9LjDBZrLecPu4MtbDLBjCTv3RieKxuUAkxiTXd/WYzMxt+E3FAzMPA1Ujy18UurRBDArX+r1+jbBU2QMbV4rClQ5bipFOIL2ylbuzFSNf4N2aqjCBsD8B0qi3tuMzRy9YDnQcaQGC9mU2uAINbrMc9EivYEqr2XYS0gxuZ317VBU8mOYKs/pjP0ynVLbjVGBteU1GoZ+qOLBtRwrhPj4NS5vJApkm/heyUbSRC8jJY1RtTnF6wOuTf5HIgocaxVSX1uUqMCUkVEbD1TnAWoZzcnbHeDhgynNGi7e+ZOxsHxKTJGecds0jSlUjOGrCa3BG0Nwm/SRO+wkB3VfjIp4lssh0BaNg9bZkMcBFj2shX7XOyK6HoO3hAlhajTSxslUKxfRZ9B49HEaV3DGKNJJlQX4LH5EMM/o9KvwGPUeSStBLKaS/rPs9ed/JbfPRf5JkiqiqjcY4hLbQiffDYlGEEpOL7Ee+LKPyBJRqO8t0Rmt0CAwEAAQ=="

_SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


def _parse_public_key_der(der: bytes) -> tuple:
    """(modulus, exponent) from a SubjectPublicKeyInfo DER blob. Hand-rolled
    because this agent runs on whatever system Python the endpoint has and
    cannot take a dependency. Mirrors backend/app/update_manifest.py exactly --
    if the two diverge, agents silently stop updating."""
    def read_tlv(data, offset):
        tag = data[offset]
        length = data[offset + 1]
        offset += 2
        if length & 0x80:
            n = length & 0x7F
            length = int.from_bytes(data[offset:offset + n], "big")
            offset += n
        return tag, data[offset:offset + length], offset + length

    _, spki, _ = read_tlv(der, 0)
    _, _algorithm, next_offset = read_tlv(spki, 0)
    _, bitstring, _ = read_tlv(spki, next_offset)
    rsa_der = bitstring[1:]
    _, rsa_seq, _ = read_tlv(rsa_der, 0)
    _, modulus, after_modulus = read_tlv(rsa_seq, 0)
    _, exponent, _ = read_tlv(rsa_seq, after_modulus)
    return int.from_bytes(modulus, "big"), int.from_bytes(exponent, "big")


def verify_signature(manifest_bytes: bytes, signature_b64: str, public_key_der_b64: str) -> bool:
    """RSA PKCS#1 v1.5 SHA-256 verification, stdlib only. Never raises:
    malformed input is a failed verification, and a failed verification means
    the agent changes nothing on disk."""
    try:
        signature = base64.b64decode(signature_b64)
        modulus, exponent = _parse_public_key_der(base64.b64decode(public_key_der_b64))
        key_size = (modulus.bit_length() + 7) // 8
        if len(signature) != key_size:
            return False
        recovered = pow(int.from_bytes(signature, "big"), exponent, modulus)
        encoded = recovered.to_bytes(key_size, "big")
        digest = hashlib.sha256(manifest_bytes).digest()
        suffix = _SHA256_DIGEST_INFO + digest
        expected = b"\x00\x01" + b"\xff" * (key_size - 3 - len(suffix)) + b"\x00" + suffix
        return hmac.compare_digest(encoded, expected)
    except Exception:
        return False

# Resolved lazily by resolve_credential() before the first authenticated call --
# never read at import time, because enrollment may need to run first and write
# a new value back to config.json. (No type hint: this file targets Python 3.9,
# which predates the `str | None` union syntax used elsewhere in this codebase.)
_credential = None

# Used only when the server cannot be reached and nothing is cached in
# state.json. These reproduce the cadence this agent had when the interval was
# hardcoded, so an agent that can never reach the server behaves as before.
# Reported in every check-in. A named constant rather than a literal buried in
# the payload, and kept in sync with $AgentVersion in AssetlyAgent_Windows.ps1:
# this said "2.0" while the signed release stream was already at 2.1.2, so a
# version a user read back over the phone matched nothing on either platform.
AGENT_VERSION = "2.2.0"

DEFAULT_SCHEDULE = {
    "checkin_interval_seconds": 15552000,   # 180 days
    "cancel_retry_seconds":     86400,      # 24 hours
}

# Only used when the server cannot be reached. The live list arrives per
# company on the department entry of GET /api/v1/inventory/config, and an admin
# edits it in the portal. Kept in sync with DEFAULT_DEPARTMENT_OPTIONS in
# backend/app/field_config.py and $DefaultDepartments in AssetlyAgent_Windows.ps1.
#
# Deliberately one neutral value. This used to carry a real customer's
# department names, which meant any agent that could not reach /config showed
# every other company's employees that customer's org chart. It is not empty
# because a dropdown with no options cannot be submitted at all when the
# department field is required.
DEFAULT_DEPARTMENT_OPTIONS = ["Other"]

# ─── Agent window appearance ──────────────────────────────────────────────────
# Copy and colours arrive on the `ui` key of the same GET /config response that
# carries the fields and the schedule, so an admin editing them in the portal
# reaches this agent on its next run with no rebuild and no re-download --
# exactly as a field toggle does. DEFAULT_AGENT_UI is the offline fallback and
# is kept in sync with DEFAULT_AGENT_UI in backend/app/agent_ui.py (the
# authority) and $DefaultAgentUi in AssetlyAgent_Windows.ps1.
#
# The palette still derives from backend/app/static/assetly.css so that an
# unconfigured window and app.assetly.ge read as one product, but the text
# tokens are lifted from their CSS values: --slate-dim on --navy is roughly
# 2.5:1, well under WCAG's 4.5:1 for body text, which made the form read as a
# wall of grey. The portal holds admin-supplied palettes to the same bar
# (_CONTRAST_PAIRS in backend/app/agent_ui.py) before storing them.
DEFAULT_AGENT_UI = {
    "window_title": "Assetly Inventory Agent",
    "heading": "Who's using this computer?",
    "subheading": "{count} fields, then you're done.",
    "subheading_one": "{count} field, then you're done.",
    "rail_title": "THIS DEVICE",
    "rail_footnote": "Sent to your IT team along with the answers on the right.",
    "submit_label": "Send check-in",
    "cancel_label": "Cancel",
    "success_message": "Thank you, {first_name}!\n\nYour device has been registered.",
    "navy": "#0B1120",           # window background
    "navy_sidebar": "#080E1A",   # device rail
    "navy_mid": "#0F1829",       # input background
    "blue": "#1866F2",           # primary action, focus ring
    "blue_hover": "#1560E6",
    "teal": "#00C2A8",           # brand accent / required marker
    "slate": "#A4B3CC",          # secondary text
    "label": "#92A3BE",          # field labels, rail keys
    "white": "#F4F7FF",          # primary text
    "border_md": "#5A6E99",      # cancel button outline
    "border_input": "#526691",   # input outline at rest
}

AGENT_UI_COLOR_KEYS = [
    k for k in DEFAULT_AGENT_UI
    if k.startswith(("navy", "blue", "border")) or k in ("teal", "slate", "label", "white")
]

# Only the placeholders _expand_ui_text actually substitutes. Anything else in
# braces would reach the employee as a literal "{whatever}", which reads as a
# bug in the agent rather than a typo in the portal.
AGENT_UI_PLACEHOLDERS = {
    "subheading": {"count"},
    "subheading_one": {"count"},
    "success_message": {"first_name"},
}

_HEX_RE = re.compile(r"^#[0-9A-Fa-f]{6}$")
_BRACE_RE = re.compile(r"\{([^{}]*)\}")

# The live palette. Module-level names because the ~45 references across
# InventoryForm read far better as NAVY than as self._ui["navy"], and
# apply_agent_ui below rebinds them once, before any widget exists. That is
# safe here in a way it would not be in a long-lived service: this process
# builds exactly one window from one config fetch and then exits.
NAVY = NAVY_SIDEBAR = NAVY_MID = BLUE = BLUE_HOVER = TEAL = ""
SLATE = SLATE_DIM = WHITE = BORDER = BORDER_MD = BORDER_INPUT = ""


def apply_agent_ui(ui: dict) -> None:
    """Binds the resolved palette to the module-level colour names."""
    globals().update({
        "NAVY": ui["navy"],
        "NAVY_SIDEBAR": ui["navy_sidebar"],
        "NAVY_MID": ui["navy_mid"],
        "BLUE": ui["blue"],
        "BLUE_HOVER": ui["blue_hover"],
        "TEAL": ui["teal"],
        "SLATE": ui["slate"],
        # SLATE_DIM is retained as a name because existing call sites use it,
        # but it now resolves to the readable label colour. Nothing in the
        # window is allowed to sit at the old 2.5:1 any more.
        "SLATE_DIM": ui["label"],
        "WHITE": ui["white"],
        "BORDER": ui["border_input"],
        "BORDER_MD": ui["border_md"],
        "BORDER_INPUT": ui["border_input"],
    })


apply_agent_ui(DEFAULT_AGENT_UI)


def _is_valid_agent_ui(ui) -> bool:
    """Guards against a malformed-but-200-OK response reaching InventoryForm,
    where a missing key raises inside Tkinter's constructor and a bad colour
    string raises TclError mid-build, in both cases with no surrounding
    try/except in main(). Mirrors Test-AgentUi in AssetlyAgent_Windows.ps1.

    Contrast is deliberately not re-checked: the server refuses to store an
    unreadable combination and is the only layer that can report that to the
    admin who caused it."""
    if not isinstance(ui, dict):
        return False
    for key in DEFAULT_AGENT_UI:
        value = ui.get(key)
        if not isinstance(value, str) or not value:
            return False
        if key in AGENT_UI_COLOR_KEYS and not _HEX_RE.match(value):
            return False
    for key in DEFAULT_AGENT_UI:
        if key in AGENT_UI_COLOR_KEYS:
            continue
        allowed = AGENT_UI_PLACEHOLDERS.get(key, set())
        text = ui[key]
        if set(_BRACE_RE.findall(text)) - allowed:
            return False
        if "{" in _BRACE_RE.sub("", text) or "}" in _BRACE_RE.sub("", text):
            return False
    return True


def resolve_agent_ui_from(config: dict, state: dict) -> dict:
    """Fresh server value, else the last known good one, else the built-in.
    The cache is what keeps a laptop that is offline for a week looking like
    its company's agent instead of reverting to stock styling mid-rollout --
    the same reason resolve_schedule_from caches."""
    fresh = (config or {}).get("ui")
    if _is_valid_agent_ui(fresh):
        return fresh
    if fresh is not None:
        log.warning("Server sent an unusable window appearance — ignoring it.")
    cached = (state or {}).get("ui")
    if _is_valid_agent_ui(cached):
        log.warning("Using cached window appearance — server value missing or malformed.")
        return cached
    return dict(DEFAULT_AGENT_UI)


def _expand_ui_text(text: str, **values) -> str:
    """Literal replace, not str.format: the copy is admin-authored, and format
    raises on any brace it does not recognise. _is_valid_agent_ui has already
    rejected unknown placeholders, so this only has to be total."""
    for key, value in values.items():
        text = text.replace("{" + key + "}", str(value))
    return text

# ─── State ────────────────────────────────────────────────────────────────────
def load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}
    except Exception:
        return {}

def save_state(state: dict):
    STATE_FILE.write_text(json.dumps(state, indent=2))

# ─── Credential resolution / enrollment ────────────────────────────────────────
def save_config(cfg: dict):
    """Rewrites config.json, keeping it owner-only. The installers create it
    chmod 600 already; explicitly re-applying that after every write means a
    rewrite can never leave it more permissive, regardless of process umask."""
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))
    try:
        os.chmod(CONFIG_FILE, 0o600)
    except Exception as e:
        log.warning(f"Could not set config.json permissions to 600: {e}")

def enroll(bearer: str) -> str:
    """Exchanges an enrollment token or legacy company key for a per-device
    credential via POST /api/v1/enroll. On any failure this logs and exits --
    callers never get a partial/failed enrollment back to handle."""
    hw = collect_hardware()
    data = json.dumps({
        "serial_number": hw.get("serial_number", ""),
        "hostname":      hw.get("hostname", ""),
    }).encode()
    req = urllib.request.Request(
        ENROLL_API_URL, data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {bearer}",
            "User-Agent": "Mozilla/5.0",
        },
        method="POST",
    )
    try:
        resp = urllib.request.urlopen(req, timeout=15)
        result = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read().decode()).get("detail", str(e))
        except Exception:
            detail = str(e)
        log.error(f"Enrollment failed ({e.code}): {detail}")
        sys.exit(1)
    except Exception as e:
        log.error(f"Enrollment request failed: {e}")
        sys.exit(1)

    credential = result.get("credential")
    if not credential:
        log.error(f"Enrollment response missing 'credential': {result!r}")
        sys.exit(1)
    return credential

def resolve_credential(cfg: dict) -> str:
    """Returns the bearer to authenticate with, enrolling first if needed.

    Order matters: an already-enrolled machine must never fall back to a
    shared secret, and a self-migrating one must drop the company key once it
    has its own credential.
    """
    global _credential
    if cfg.get("device_credential"):
        _credential = cfg["device_credential"]
        return _credential

    bearer = cfg.get("enrollment_token") or cfg.get("company_api_key")
    if not bearer:
        log.error("No device credential, enrollment token, or company key in config.json — cannot authenticate.")
        sys.exit(1)

    log.info("No device credential on file — enrolling…")
    credential = enroll(bearer)
    cfg["device_credential"] = credential
    cfg.pop("enrollment_token", None)
    cfg.pop("company_api_key", None)   # self-migration: never reuse it
    save_config(cfg)
    log.info("Enrolled successfully — device credential saved to config.json.")
    _credential = credential
    return credential

# ─── Due-check guard ──────────────────────────────────────────────────────────
def _is_valid_schedule(schedule) -> bool:
    """Guards against a malformed-but-200-OK schedule reaching the guard, where
    a string or a negative would make the comparison below either raise or
    silently never fire."""
    if not isinstance(schedule, dict):
        return False
    interval = schedule.get("checkin_interval_seconds")
    retry = schedule.get("cancel_retry_seconds")
    for value in (interval, retry):
        # bool is a subclass of int; True would otherwise pass as 1 second.
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            return False
    return retry <= interval


def resolve_schedule_from(config: dict, state: dict) -> dict:
    """Fresh server value, else the last known good one, else the built-in
    default. The cache matters: a laptop offline for a week keeps its
    configured cadence instead of silently reverting to 6 months."""
    fresh = (config or {}).get("schedule")
    if _is_valid_schedule(fresh):
        return fresh
    cached = (state or {}).get("schedule")
    if _is_valid_schedule(cached):
        log.warning("Using cached check-in schedule — server value missing or malformed.")
        return cached
    log.warning("No usable check-in schedule — falling back to built-in defaults.")
    return dict(DEFAULT_SCHEDULE)


def _humanize_seconds(seconds: int) -> str:
    """Human-readable duration for the cancel dialog. The agents cannot import
    backend/app/schedule.py's format_interval, so this is a deliberate small
    duplicate -- keep the two in agreement if either changes."""
    if seconds >= 86400 and seconds % 86400 == 0:
        count = seconds // 86400
        return f"{count} day" if count == 1 else f"{count} days"
    count = max(1, round(seconds / 3600))
    return f"{count} hour" if count == 1 else f"{count} hours"


def should_show_form(state: dict, schedule: dict) -> bool:
    now = datetime.datetime.now()

    last_run = state.get("last_run")
    if last_run:
        elapsed = (now - datetime.datetime.fromisoformat(last_run)).total_seconds()
        # A negative elapsed means the clock moved backwards since the last
        # run. Treating that as due is the safe direction -- the alternative
        # parks the machine until its clock catches up, silently.
        if 0 <= elapsed < schedule["checkin_interval_seconds"]:
            log.info(f"Last check-in {elapsed/3600:.1f} h ago — not due yet. Exiting.")
            return False

    cancelled_at = state.get("cancelled_at")
    if cancelled_at:
        elapsed = (now - datetime.datetime.fromisoformat(cancelled_at)).total_seconds()
        if 0 <= elapsed < schedule["cancel_retry_seconds"]:
            log.info(f"Cancelled {elapsed/3600:.1f} h ago — retry window not reached. Exiting.")
            return False

    return True

# ─── Self-update ──────────────────────────────────────────────────────────────
def self_update():
    """Fetches, verifies, and applies a signed update.

    What changed and why: this used to GET a hardcoded GitHub raw URL, compare
    the downloaded bytes' SHA-256 against its own, and overwrite itself if they
    differed. That hash comparison was change DETECTION, never an integrity
    control -- it compared new against old, never against a known-good value.
    Anyone who could write this file's config, or who held write access to that
    GitHub repository, had code execution on every endpoint in every fleet.

    Now the agent trusts a compiled-in public key instead of a URL. Nothing is
    written to disk until a signature made by the holder of the offline release
    key has been verified over the manifest, and the downloaded bytes have been
    re-hashed against the SHA-256 that signature covers.
    """
    if not UPDATE_SIGNING_PUBLIC_KEY:
        return
    if not CHECKIN_API_URL:
        return
    try:
        log.info("Checking for updates…")
        base = CHECKIN_API_URL.split("/api/v1/")[0]
        req = urllib.request.Request(
            f"{base}/api/v1/agent/manifest",
            headers={"Cache-Control": "no-cache", "Authorization": f"Bearer {_credential}"},
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            envelope = json.loads(resp.read())

        manifest_bytes = envelope["manifest"].encode()
        if not verify_signature(
            manifest_bytes, envelope["signature"], UPDATE_SIGNING_PUBLIC_KEY
        ):
            # Not a warning to shrug at: a failure here means someone served
            # this agent something the release key did not sign.
            log.error("Update REJECTED: manifest signature did not verify.")
            return

        artifact = json.loads(manifest_bytes)["artifacts"]["posix_py"]
        me = Path(sys.argv[0])
        if hashlib.sha256(me.read_bytes()).hexdigest() == artifact["sha256"]:
            log.info("Already up to date.")
            return

        with urllib.request.urlopen(f"{base}{artifact['path']}", timeout=30) as resp:
            new_bytes = resp.read()

        # Re-hash what actually arrived. This is what makes serving the
        # artifact itself over an unauthenticated URL safe: its integrity
        # comes from the signed manifest, not from the transport.
        if hashlib.sha256(new_bytes).hexdigest() != artifact["sha256"]:
            log.error("Update REJECTED: artifact hash does not match the signed manifest.")
            return
        if len(new_bytes) != artifact["size"]:
            log.error("Update REJECTED: artifact size does not match the signed manifest.")
            return

        log.info("Verified update found — applying and restarting.")
        me.write_bytes(new_bytes)
        os.execv(sys.executable, [sys.executable] + sys.argv)
    except Exception as e:
        log.warning(f"Update check skipped: {e}")

# ─── Hardware collection ──────────────────────────────────────────────────────
def _run(cmd: list, sudo: bool = False) -> str:
    try:
        if sudo:
            cmd = ["sudo", "-n"] + cmd
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return r.stdout.strip()
    except Exception:
        return ""

def _clean(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip()) or "N/A"

def get_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "N/A"

def collect_hardware() -> dict:
    hw = {
        "hostname":   socket.gethostname(),
        "ip_address": get_ip(),
    }

    if _sys == "Darwin":
        raw = _run(["system_profiler", "SPHardwareDataType"])

        def _e(label: str) -> str:
            m = re.search(rf"{label}:\s*(.+)", raw, re.IGNORECASE)
            return _clean(m.group(1)) if m else "N/A"

        hw["brand"]         = "Apple"
        hw["model"]         = _e("Model Name") or _e("Model Identifier")
        hw["serial_number"] = _e(r"Serial Number \(system\)") or _e("Serial Number")
        hw["cpu"]           = _run(["sysctl", "-n", "machdep.cpu.brand_string"]) or _e("Chip")
        ram_b               = int(_run(["sysctl", "-n", "hw.memsize"]) or 0)
        hw["ram"]           = f"{round(ram_b / 1024**3)} GB" if ram_b else _e("Memory")
        df                  = _run(["df", "-Hl", "/"])
        lines               = df.splitlines()
        hw["storage"]       = lines[1].split()[1] if len(lines) > 1 else "N/A"
        hw["os"]            = f"macOS {platform.mac_ver()[0]}"

    else:  # Linux
        def _dmi(key: str) -> str:
            # Try /sys first: world-readable on modern distros, needs no
            # privilege, and reads the same SMBIOS field dmidecode does --
            # promoting it ahead of dmidecode is what lets the installer skip
            # provisioning a standing NOPASSWD sudo rule for most machines.
            # dmidecode remains the fallback for systems where /sys/class/dmi
            # isn't populated or readable.
            _sys_map = {
                "system-manufacturer":  "/sys/class/dmi/id/sys_vendor",
                "system-product-name":  "/sys/class/dmi/id/product_name",
                "system-serial-number": "/sys/class/dmi/id/product_serial",
            }
            out = ""
            try:
                out = Path(_sys_map[key]).read_text().strip()
            except Exception:
                pass
            if not out:
                out = _run(["dmidecode", "-s", key], sudo=True)
            if not out:
                out = _run(["dmidecode", "-s", key])
            return _clean(out)

        hw["brand"]         = _dmi("system-manufacturer")
        hw["model"]         = _dmi("system-product-name")
        hw["serial_number"] = _dmi("system-serial-number")

        cpu_raw = _run(["cat", "/proc/cpuinfo"])
        m = re.search(r"model name\s*:\s*(.+)", cpu_raw)
        hw["cpu"] = _clean(m.group(1)) if m else "N/A"

        mem_raw = _run(["cat", "/proc/meminfo"])
        m = re.search(r"MemTotal:\s*(\d+)", mem_raw)
        hw["ram"] = f"{round(int(m.group(1)) / 1024**2)} GB" if m else "N/A"

        blk = _run(["lsblk", "-d", "-o", "NAME,SIZE,MODEL", "--noheadings"])
        hw["storage"] = _clean(blk.splitlines()[0]) if blk else "N/A"
        hw["os"]      = f"Linux {platform.release()}"

    hw["timestamp"] = datetime.datetime.now().isoformat(timespec="seconds")
    return hw

# ─── Offline queue ────────────────────────────────────────────────────────────
def _enqueue(payload: dict):
    items: list = []
    if QUEUE_FILE.exists():
        try:
            items = json.loads(QUEUE_FILE.read_text())
        except Exception:
            pass
    items.append(payload)
    QUEUE_FILE.write_text(json.dumps(items, indent=2))
    log.info(f"Saved to offline queue (total queued: {len(items)})")

def flush_queue():
    if not QUEUE_FILE.exists():
        return
    try:
        items: list = json.loads(QUEUE_FILE.read_text())
    except Exception:
        return
    if not items:
        return

    log.info(f"Flushing {len(items)} queued submission(s)…")
    pending = []
    for payload in items:
        if _post_to_sheets(payload):
            log.info(f"  Flushed entry from {payload.get('timestamp','?')}")
        else:
            pending.append(payload)

    if pending:
        QUEUE_FILE.write_text(json.dumps(pending, indent=2))
        log.warning(f"  {len(pending)} entries still pending (still offline?).")
    else:
        QUEUE_FILE.unlink(missing_ok=True)
        log.info("  Queue fully flushed.")

def _post_to_sheets(payload: dict) -> bool:
    try:
        data = json.dumps(payload).encode()
        req  = urllib.request.Request(
            CHECKIN_API_URL, data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {_credential}",
                "User-Agent": "Mozilla/5.0",
            },
            method="POST",
        )
        resp   = urllib.request.urlopen(req, timeout=15)
        result = json.loads(resp.read().decode())
        return result.get("status") == "ok"
    except urllib.error.HTTPError as e:
        if e.code == 409:
            log.info("Server reports this checkin_id already recorded — treating as success.")
            return True
        if e.code in (401, 403):
            log.error(f"Authentication failed ({e.code}) — device credential in config.json may be invalid or revoked. Not queuing as offline.")
            return False
        log.warning(f"HTTP submit failed: {e}")
        return False
    except Exception as e:
        log.warning(f"HTTP submit failed: {e}")
        return False

DEFAULT_FIELD_CONFIG = {
    "user_fields": [
        {"key": "first_name", "label": "First Name", "required": True, "locked": True},
        {"key": "last_name", "label": "Last Name", "required": True, "locked": True},
        {"key": "email", "label": "Email", "required": True, "locked": True},
        {"key": "department", "label": "Department", "required": False, "locked": False,
         "options": DEFAULT_DEPARTMENT_OPTIONS},
    ],
    "hardware_fields": ["cpu", "ram", "storage", "ip_address"],
}


def _is_valid_field_config(config) -> bool:
    """Guards against a malformed-but-200-OK response reaching InventoryForm,
    where a missing/wrong-typed key would raise inside Tkinter's constructor
    with no surrounding try/except in main()."""
    if not isinstance(config, dict):
        return False
    user_fields = config.get("user_fields")
    hardware_fields = config.get("hardware_fields")
    if not isinstance(user_fields, list) or not isinstance(hardware_fields, list):
        return False
    required_keys = {"key", "label", "required", "locked"}
    for f in user_fields:
        if not (isinstance(f, dict) and required_keys.issubset(f) and isinstance(f["key"], str)):
            return False
        # Optional, and only ever present on department. An options list that
        # arrived empty or wrong-typed would build a dropdown the user cannot
        # pick anything from, so it's rejected here and the defaults are used.
        options = f.get("options")
        if options is not None and not (
            isinstance(options, list)
            and options
            and all(isinstance(o, str) for o in options)
        ):
            return False
    return all(isinstance(key, str) for key in hardware_fields)


def fetch_config() -> dict:
    """Fetches this company's field config AND schedule in one call; falls back
    to DEFAULT_FIELD_CONFIG on any failure (network/auth/parse/malformed-shape)
    so a config-fetch problem never blocks check-in entirely.

    Called before the due-check guard, so its response is what tells the guard
    which interval to use -- and the same response is reused to build the form,
    so this is one call, not two."""
    try:
        req = urllib.request.Request(
            CONFIG_API_URL,
            headers={
                "Authorization": f"Bearer {_credential}",
                "User-Agent": "Mozilla/5.0",
            },
            method="GET",
        )
        resp = urllib.request.urlopen(req, timeout=10)
        config = json.loads(resp.read().decode())
        if not _is_valid_field_config(config):
            raise ValueError(f"Malformed field config response: {config!r}")
        return config
    except Exception as e:
        log.warning(f"Failed to fetch field config, using defaults: {e}")
        return DEFAULT_FIELD_CONFIG


def submit_to_sheets(user_data: dict, hw: dict, enabled_hardware_fields: list) -> bool:
    """Returns True if submitted immediately, False if queued offline."""
    import uuid
    always_sent_hw_keys = {"serial_number", "hostname", "brand", "model", "os", "timestamp"}
    filtered_hw = {
        key: value for key, value in hw.items()
        if key in always_sent_hw_keys or key in enabled_hardware_fields
    }
    payload = {
        **user_data, **filtered_hw,
        "checkin_id":      str(uuid.uuid4()),
        "agent_version":   AGENT_VERSION,
        "submission_type": "online",
        "platform":        {"Darwin": "macos", "Linux": "linux", "Windows": "windows"}.get(_sys, "unknown"),
    }
    if _post_to_sheets(payload):
        return True
    log.warning("No internet — saving to offline queue.")
    _enqueue(payload)
    return False

# ─── GUI ──────────────────────────────────────────────────────────────────────
class InventoryForm(tk.Tk):
    def __init__(self, hw: dict, field_config: dict, schedule: dict, ui: dict):
        super().__init__()
        self.hw           = hw
        self.field_config = field_config
        # Copy only. The colours from the same dict were bound to the
        # module-level tokens by apply_agent_ui before this window was built.
        self.ui           = ui
        # Only used for the cancel dialog's "reminded again in …" line, which
        # has to name this company's actual retry rather than a fixed 24 h.
        self.schedule     = schedule
        self.submitted    = False
        self.user_data: dict = {}
        self._field_widgets: dict = {}   # non-department field key -> tk.Entry

        self.title(self.ui["window_title"])
        self.configure(bg=NAVY)
        self.resizable(False, False)
        self._center()
        self._build()
        self.protocol("WM_DELETE_WINDOW", self._on_cancel)
        self.after(150, self._raise_to_front)

    def _raise_to_front(self):
        try:
            from AppKit import NSApplication
            NSApplication.sharedApplication().activateIgnoringOtherApps_(True)
        except Exception:
            # No pyobjc (the usual case -- this agent has no pip dependencies,
            # and neither the python.org nor the system build ships AppKit).
            # There is deliberately no osascript fallback here: driving
            # "System Events" is an Automation request, so macOS shows the
            # employee a '"python3" wants to control "System Events"' consent
            # dialog before the check-in window ever appears. The Tk calls
            # below raise and focus the window on their own, which is worth
            # more than the small extra reliability that AppleScript bought.
            pass
        self.lift()
        self.attributes("-topmost", True)
        self.after(200, lambda: self.attributes("-topmost", False))
        self.focus_force()

    def _center(self):
        # Device facts sit in the left rail rather than under the form, so the
        # window grows only with the fields themselves — and two short fields
        # share a row, so it grows half as fast as the field count.
        w = 760
        h = 384 + 62 * self._form_rows()
        self.update_idletasks()
        x = (self.winfo_screenwidth()  - w) // 2
        y = (self.winfo_screenheight() - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")

    # Fields whose value is long enough that halving the row would truncate it
    # on screen. Everything else pairs up two-to-a-row.
    FULL_WIDTH_KEYS = {"email"}

    def _layout_slots(self):
        """Assign every configured field a (row, column, columnspan) slot.

        Two short fields share a row; an email — or any field named in
        FULL_WIDTH_KEYS — takes the whole row to itself.
        """
        slots, row, col = [], 0, 0
        for f in self.field_config["user_fields"]:
            if f["key"] in self.FULL_WIDTH_KEYS:
                if col == 1:
                    row, col = row + 1, 0
                slots.append((f, row, 0, 2))
                row += 1
            else:
                slots.append((f, row, col, 1))
                if col == 1:
                    row, col = row + 1, 0
                else:
                    col = 1
        return slots

    def _form_rows(self) -> int:
        slots = self._layout_slots()
        return (slots[-1][1] + 1) if slots else 0

    def _draw_logo(self, parent, width=144, bg=NAVY_SIDEBAR):
        """Paint assetly_logo.svg at `width` pixels wide.

        Tk has no SVG support and PhotoImage only reads GIF/PNG, so the logo is
        drawn from the SVG's own geometry on a Canvas. That keeps the agent a
        single file — there is no image shipped alongside it on a checked-in
        machine — and keeps it sharp at any window scale.
        """
        s = width / 400.0             # the SVG is 400x180 user units
        h = width * 0.45
        c = tk.Canvas(parent, width=width, height=h, bg=bg,
                      highlightthickness=0, bd=0)
        c.pack(anchor="w")

        # backdrop: rect 400x180 rx=18, as two rects plus four corner arcs
        card, r = "#0D1119", 18 * s
        c.create_rectangle(r, 0, width - r, h, fill=card, outline=card)
        c.create_rectangle(0, r, width, h - r, fill=card, outline=card)
        for x, y, start in ((0, 0, 90), (width - 2*r, 0, 0),
                            (width - 2*r, h - 2*r, 270), (0, h - 2*r, 180)):
            c.create_arc(x, y, x + 2*r, y + 2*r, start=start, extent=90,
                         fill=card, outline=card)

        # node-graph mark. The SVG runs a #5FD8BE -> #3AA98F gradient along the
        # edges; a Canvas line takes one colour, so each edge gets its own stop.
        p1, p2, p3 = (70*s, 57*s), (36*s, 123*s), (104*s, 123*s)
        for (a, b), colour in (((p1, p2), "#5FD8BE"),
                               ((p1, p3), "#4CC3A6"),
                               ((p2, p3), "#3AA98F")):
            c.create_line(*a, *b, fill=colour, width=3.5 * s, capstyle="round")

        nr = 7.5 * s
        for (x, y), colour in ((p1, "#F2F5F7"), (p2, "#4ECDB4"), (p3, "#4ECDB4")):
            c.create_oval(x - nr, y - nr, x + nr, y + nr, fill=colour, outline=colour)

        # wordmark: "asset" white + "ly" teal, on the SVG's y=113 baseline
        px = int(round(64 * s))
        f = tkfont.Font(family="Helvetica", size=-px, weight="bold")
        baseline = 113 * s + f.metrics("descent")
        c.create_text(150 * s, baseline, text="asset", font=f,
                      fill="#FFFFFF", anchor="sw")
        c.create_text(150 * s + f.measure("asset"), baseline, text="ly", font=f,
                      fill="#4ECDB4", anchor="sw")

    def _build(self):
        self._style_comboboxes()

        # ── Device rail ───────────────────────────────────────────────────────
        # Everything the machine reports about itself lives here, so the form on
        # the right keeps a fixed height however many fields a company adds.
        rail = tk.Frame(self, bg=NAVY_SIDEBAR, width=196)
        rail.pack(side="left", fill="y")
        rail.pack_propagate(False)

        rail_inner = tk.Frame(rail, bg=NAVY_SIDEBAR)
        rail_inner.pack(fill="both", expand=True, padx=18, pady=18)
        self._draw_logo(rail_inner)

        tk.Label(rail_inner, text=self.ui["rail_title"], font=("Helvetica", 9, "bold"),
                 fg=TEAL, bg=NAVY_SIDEBAR).pack(anchor="w", pady=(20, 8))

        for label, value in self._device_rows():
            tk.Label(rail_inner, text=label.upper(), font=("Helvetica", 9),
                     fg=SLATE_DIM, bg=NAVY_SIDEBAR).pack(anchor="w", pady=(6, 0))
            tk.Label(rail_inner, text=value, font=("Menlo", 10),
                     fg=WHITE, bg=NAVY_SIDEBAR, anchor="w",
                     wraplength=160, justify="left").pack(anchor="w")

        # SLATE, not SLATE_DIM: the footnote is prose, not a field label, and
        # the Windows agent paints it with the same token. Both are contrast-
        # checked against the rail, so this is about the two agents matching.
        tk.Label(rail_inner, text=self.ui["rail_footnote"],
                 font=("Helvetica", 9), fg=SLATE, bg=NAVY_SIDEBAR,
                 wraplength=160, justify="left").pack(anchor="w", side="bottom", pady=(16, 0))

        # ── Form pane ─────────────────────────────────────────────────────────
        pane = tk.Frame(self, bg=NAVY)
        pane.pack(side="left", fill="both", expand=True, padx=24, pady=20)

        tk.Label(pane, text=self._heading(),
                 font=("Helvetica", 16, "bold"), fg=WHITE, bg=NAVY).pack(anchor="w")
        # Two keys rather than a plural rule the agent applies itself: the rule
        # differs by language, and this copy is admin-authored.
        count = len(self.field_config["user_fields"])
        subheading = self.ui["subheading_one"] if count == 1 else self.ui["subheading"]
        tk.Label(pane, text=_expand_ui_text(subheading, count=count),
                 font=("Helvetica", 11), fg=SLATE, bg=NAVY).pack(anchor="w", pady=(3, 0))

        form = tk.Frame(pane, bg=NAVY)
        form.pack(fill="both", expand=True, pady=(18, 0))
        form.columnconfigure(0, weight=1, uniform="col")
        form.columnconfigure(1, weight=1, uniform="col")

        self._v_department = None
        for f, row, col, span in self._layout_slots():
            cell = tk.Frame(form, bg=NAVY)
            cell.grid(row=row, column=col, columnspan=span, sticky="ew",
                      padx=(0, 12) if span == 1 and col == 0 else 0, pady=(0, 14))

            self._label(cell, f["label"], f["required"])
            if f["key"] == "department":
                options = f.get("options") or DEFAULT_DEPARTMENT_OPTIONS
                self._v_department = tk.StringVar(value=options[0])
                ttk.Combobox(
                    cell, textvariable=self._v_department, values=options,
                    state="readonly", font=("Helvetica", 11),
                    style="Assetly.TCombobox",
                ).pack(fill="x")
            else:
                self._field_widgets[f["key"]] = self._entry(cell)

        # ── Actions ───────────────────────────────────────────────────────────
        actions = tk.Frame(pane, bg=NAVY)
        actions.pack(fill="x", side="bottom")
        self._button(actions, self.ui["submit_label"], self._on_submit,
                     fg="#FFFFFF", bg=BLUE, hover=BLUE_HOVER).pack(side="right")
        self._button(actions, self.ui["cancel_label"], self._on_cancel,
                     fg=SLATE, bg=NAVY, hover="#16243A",
                     border=BORDER_MD).pack(side="right", padx=(0, 10))

    def _heading(self) -> str:
        """The company's heading, or platform-native wording if they have not
        set one.

        This agent said "Who's using this Mac?" on macOS long before the
        heading was configurable, and losing that to a generic default would be
        a visible regression for every company that never touches the setting.
        An admin who does set a heading gets exactly what they typed -- second-
        guessing their wording per platform would be worse than the small
        asymmetry here.
        """
        heading = self.ui["heading"]
        if heading == DEFAULT_AGENT_UI["heading"] and sys.platform == "darwin":
            return "Who's using this Mac?"
        return heading

    def _device_rows(self):
        """The hardware facts for the rail, as (label, value) pairs.

        Only what will actually be submitted: the rail promises this is what
        gets sent, and submit_to_sheets() drops every hardware key the company
        has switched off.
        """
        hw = self.hw
        enabled = set(self.field_config["hardware_fields"])
        rows = [
            ("Model",  f"{hw['brand']} {hw['model']}"),
            ("Serial", hw.get("serial_number", "?")),
        ]
        rows += [(label, hw[key])
                 for key, label in (("cpu", "Processor"), ("ram", "Memory"),
                                    ("storage", "Storage"))
                 if key in enabled]
        rows.append(("System", hw["os"]))
        rows.append(("Host", hw["hostname"]))
        if "ip_address" in enabled:
            rows.append(("IP address", hw["ip_address"]))
        return rows

    # ── Portal-styled controls ────────────────────────────────────────────────
    def _style_comboboxes(self):
        """Repaint ttk's combobox in the portal's colours.

        Only the 'clam' theme honours these options; the native aqua and vista
        themes draw the widget themselves and ignore every colour set here.
        """
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            return
        style.configure(
            "Assetly.TCombobox",
            fieldbackground=NAVY_MID, background=NAVY_MID, foreground=WHITE,
            arrowcolor=SLATE, bordercolor=BORDER_INPUT, lightcolor=NAVY_MID,
            darkcolor=NAVY_MID, padding=6, relief="flat",
        )
        style.map("Assetly.TCombobox",
                  fieldbackground=[("readonly", NAVY_MID)],
                  foreground=[("readonly", WHITE)],
                  bordercolor=[("focus", BLUE)])
        # The dropdown list is a Tk listbox owned by Tk, not by ttk, so it is
        # reachable only through the option database.
        self.option_add("*TCombobox*Listbox.background", NAVY_MID)
        self.option_add("*TCombobox*Listbox.foreground", WHITE)
        self.option_add("*TCombobox*Listbox.selectBackground", BLUE)
        self.option_add("*TCombobox*Listbox.selectForeground", "#FFFFFF")

    def _label(self, parent: tk.Frame, text: str, required: bool):
        wrap = tk.Frame(parent, bg=NAVY)
        wrap.pack(anchor="w", pady=(0, 5))
        tk.Label(wrap, text=text.upper(), font=("Helvetica", 9, "bold"),
                 fg=SLATE_DIM, bg=NAVY).pack(side="left")
        if required:
            tk.Label(wrap, text=" *", font=("Helvetica", 9, "bold"),
                     fg=TEAL, bg=NAVY).pack(side="left")

    def _entry(self, parent: tk.Frame) -> tk.Entry:
        # highlightthickness is the border here rather than bd/relief: it is the
        # one border Tk will recolour on focus, which is how the portal marks the
        # focused input.
        e = tk.Entry(parent, font=("Helvetica", 12), bg=NAVY_MID, fg=WHITE,
                     insertbackground=BLUE, relief="flat", bd=0,
                     highlightthickness=1, highlightbackground=BORDER_INPUT,
                     highlightcolor=BLUE, disabledbackground=NAVY_MID)
        e.pack(fill="x", ipady=6, ipadx=8)
        return e

    def _button(self, parent: tk.Frame, text: str, command,
                fg: str, bg: str, hover: str, border: str = None) -> tk.Label:
        """A button drawn as a Label.

        tk.Button ignores bg on macOS — it is drawn by Aqua — which is why the
        old red Submit button rendered as a stock grey one. A Label takes its
        colours everywhere, so the same code gives the same button on every
        platform.
        """
        b = tk.Label(parent, text=text, font=("Helvetica", 12, "bold"),
                     fg=fg, bg=bg, padx=18, pady=9, cursor="hand2",
                     highlightthickness=1, highlightbackground=border or bg,
                     highlightcolor=border or bg)
        b.bind("<Enter>", lambda _e: b.configure(bg=hover))
        b.bind("<Leave>", lambda _e: b.configure(bg=bg))
        b.bind("<Button-1>", lambda _e: command())
        return b

    # ── Validation ────────────────────────────────────────────────────────────
    def _validate(self) -> bool:
        for f in self.field_config["user_fields"]:
            if f["key"] == "department" or not f["required"]:
                continue
            widget = self._field_widgets.get(f["key"])
            if widget is None:
                continue
            value = widget.get().strip()
            if not value:
                messagebox.showwarning("Missing field", f"Please enter your {f['label']}.", parent=self)
                return False
            if f["key"] == "email" and not re.match(r"[^@]+@[^@]+\.[^@]+", value):
                messagebox.showwarning("Invalid email", "Please enter a valid email address.", parent=self)
                return False
        return True

    def _on_submit(self):
        if not self._validate():
            return
        built_in_keys = {"first_name", "last_name", "email"}
        self.user_data = {
            key: widget.get().strip()
            for key, widget in self._field_widgets.items()
            if key in built_in_keys
        }
        if self._v_department is not None:
            self.user_data["department"] = self._v_department.get()
        self.user_data["custom_fields"] = {
            key: widget.get().strip()
            for key, widget in self._field_widgets.items()
            if key not in built_in_keys
        }
        self.submitted = True
        self.destroy()

    def _on_cancel(self):
        retry = _humanize_seconds(self.schedule["cancel_retry_seconds"])
        if messagebox.askyesno(
            "Cancel check-in",
            "Are you sure you want to skip?\n\n"
            "• IT will be notified\n"
            f"• You'll be reminded again in {retry}",
            parent=self,
        ):
            self.submitted = False
            self.destroy()


# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Assetly Inventory Agent")
    parser.add_argument("--force", action="store_true",
                        help="Bypass the check-in interval guard and show the form immediately.")
    args = parser.parse_args()

    log.info("=== Assetly Inventory Agent v2.0 started ===")

    # When launched as a background service (LaunchAgent / systemd), stdout is not
    # a TTY. Wait briefly so the desktop session is fully ready before showing a GUI.
    if not sys.stdout.isatty():
        log.info("Background launch detected — waiting 15 s for desktop to settle…")
        time.sleep(15)

    # 0. Resolve credentials, enrolling first if this machine has none yet.
    #    Must happen before any authenticated call -- flush_queue() below is
    #    the earliest one.
    resolve_credential(_cfg)

    # 1. Self-update (silent, restarts if new version found)
    self_update()

    # 2. Flush any offline-queued submissions
    flush_queue()

    # 3. Fetch this company's config (fields + schedule) BEFORE the guard --
    #    the guard needs the server's interval to decide. Falls back to
    #    defaults on failure. One call: the same response builds the form below.
    state = load_state()
    config = fetch_config()
    schedule = resolve_schedule_from(config, state)
    if schedule != state.get("schedule"):
        state["schedule"] = schedule
        save_state(state)

    # Appearance rides on the same response. Cached for the same reason the
    # schedule is: the window has to look like this company's agent even on a
    # run where /config could not be reached.
    ui = resolve_agent_ui_from(config, state)
    if ui != state.get("ui"):
        state["ui"] = ui
        save_state(state)
    # Must happen before InventoryForm is constructed: the module-level colour
    # tokens are read throughout _build().
    apply_agent_ui(ui)

    # 4. Guard: exit early if not due (skipped when --force is passed)
    if not args.force and not should_show_form(state, schedule):
        sys.exit(0)

    # 5. Collect hardware
    log.info("Collecting hardware information…")
    hw = collect_hardware()
    log.info(json.dumps(hw, indent=2))

    field_config = config

    # 6. Show GUI
    app = InventoryForm(hw, field_config, schedule, ui)
    app.mainloop()

    # ── Cancelled ─────────────────────────────────────────────────────────────
    if not app.submitted:
        state["cancelled_at"] = datetime.datetime.now().isoformat()
        save_state(state)
        log.warning(f"Form cancelled. Will retry in {schedule['cancel_retry_seconds']/3600:.0f} h.")
        sys.exit(0)

    # ── Submitted ─────────────────────────────────────────────────────────────
    log.info("Submitting data to Google Sheets…")
    immediate = submit_to_sheets(app.user_data, hw, field_config["hardware_fields"])

    state["last_run"] = datetime.datetime.now().isoformat()
    state.pop("cancelled_at", None)
    save_state(state)

    # Success dialog
    dialog_msg = _expand_ui_text(ui["success_message"], first_name=app.user_data["first_name"])
    if not immediate:
        dialog_msg += "\n\n(Offline — data will sync automatically.)"
    messagebox.showinfo("Assetly Inventory – Done", dialog_msg)

    log.info("=== Completed successfully ===")


if __name__ == "__main__":
    _init_file_logging()
    main()
