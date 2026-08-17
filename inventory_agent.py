#!/usr/bin/env python3
"""
Assetly Inventory Agent v2.0
Cross-platform (macOS + Linux) — zero pip dependencies.
Config is loaded from  ~/.assetly_inventory/config.json  (written by the installer).
"""

import os, sys, json, platform, subprocess, datetime, hashlib, socket, re, time, argparse
import urllib.request, urllib.error
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox
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
STATE_DIR.mkdir(parents=True, exist_ok=True)

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ]
)
log = logging.getLogger("assetly")

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
GITHUB_RAW_URL   = _cfg.get("github_raw_url", "")

# Resolved lazily by resolve_credential() before the first authenticated call --
# never read at import time, because enrollment may need to run first and write
# a new value back to config.json. (No type hint: this file targets Python 3.9,
# which predates the `str | None` union syntax used elsewhere in this codebase.)
_credential = None

# Used only when the server cannot be reached and nothing is cached in
# state.json. These reproduce the cadence this agent had when the interval was
# hardcoded, so an agent that can never reach the server behaves as before.
DEFAULT_SCHEDULE = {
    "checkin_interval_seconds": 15552000,   # 180 days
    "cancel_retry_seconds":     86400,      # 24 hours
}

# Only used when the server cannot be reached. The live list arrives per
# company on the department entry of GET /api/v1/inventory/config, and an admin
# edits it in the portal. Kept in sync with DEFAULT_DEPARTMENT_OPTIONS in
# backend/app/field_config.py and $DefaultDepartments in AssetlyAgent_Windows.ps1.
DEFAULT_DEPARTMENT_OPTIONS = ["Webiz ERP", "Fundbox", "Playtika", "Artlist", "The5%ers", "Other"]

BRAND_COLOR  = "#1A2B5A"
ACCENT_COLOR = "#E8303A"
BG_COLOR     = "#F5F7FA"

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
    if not GITHUB_RAW_URL:
        return
    try:
        log.info("Checking for updates…")
        req  = urllib.request.Request(GITHUB_RAW_URL, headers={"Cache-Control": "no-cache"})
        resp = urllib.request.urlopen(req, timeout=8)
        new_bytes = resp.read()
        me = Path(sys.argv[0])
        if hashlib.sha256(new_bytes).hexdigest() != hashlib.sha256(me.read_bytes()).hexdigest():
            log.info("Update found — applying and restarting.")
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
            # Try sudo dmidecode first, then /sys fallback
            out = _run(["dmidecode", "-s", key], sudo=True)
            if not out:
                out = _run(["dmidecode", "-s", key])
            if not out:
                _sys_map = {
                    "system-manufacturer":  "/sys/class/dmi/id/sys_vendor",
                    "system-product-name":  "/sys/class/dmi/id/product_name",
                    "system-serial-number": "/sys/class/dmi/id/product_serial",
                }
                try:
                    out = Path(_sys_map[key]).read_text().strip()
                except Exception:
                    pass
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
        "agent_version":   "2.0",
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
    def __init__(self, hw: dict, field_config: dict):
        super().__init__()
        self.hw           = hw
        self.field_config = field_config
        self.submitted    = False
        self.user_data: dict = {}
        self._field_widgets: dict = {}   # non-department field key -> tk.Entry

        self.title("Assetly Inventory Agent")
        self.configure(bg=BG_COLOR)
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
            # osascript fallback — always available on macOS
            try:
                subprocess.Popen(
                    ["osascript", "-e",
                     f'tell application "System Events" to set frontmost of '
                     f'first process whose unix id is {os.getpid()} to true'],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
            except Exception:
                pass
        self.lift()
        self.attributes("-topmost", True)
        self.after(200, lambda: self.attributes("-topmost", False))
        self.focus_force()

    def _center(self):
        # 644 was sized for the four built-in rows. The row count is now
        # whatever the company configured, so the window has to grow with it
        # or added custom fields push the Submit button off-screen.
        w = 520
        h = 644 + 42 * (len(self.field_config["user_fields"]) - 4)
        self.update_idletasks()
        x = (self.winfo_screenwidth()  - w) // 2
        y = (self.winfo_screenheight() - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")

    def _build(self):
        # ── Header bar ────────────────────────────────────────────────────────
        hdr = tk.Frame(self, bg=BRAND_COLOR, height=80)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        logo_shown = False
        logo_file = Path(__file__).parent / "assetly_logo.png"
        if logo_file.exists():
            try:
                self._logo_img = tk.PhotoImage(file=str(logo_file))
                tk.Label(hdr, image=self._logo_img, bg=BRAND_COLOR).pack(
                    side="left", padx=22, pady=14)
                logo_shown = True
            except Exception:
                pass

        if not logo_shown:
            tk.Label(hdr, text="ASSETLY", fg="white", bg=BRAND_COLOR,
                     font=("Helvetica", 30, "bold")).pack(side="left", padx=22, pady=16)

        # Red accent line
        tk.Frame(self, bg=ACCENT_COLOR, height=4).pack(fill="x")

        # ── Welcome text ──────────────────────────────────────────────────────
        wf = tk.Frame(self, bg=BG_COLOR)
        wf.pack(fill="x", padx=26, pady=(18, 4))
        tk.Label(
            wf,
            text="Hello, I am Inventory Agent of Assetly and I need following information",
            wraplength=468, justify="left",
            font=("Helvetica", 12), fg="#1C1C1E", bg=BG_COLOR,
        ).pack(anchor="w")

        # ── Form ──────────────────────────────────────────────────────────────
        form = tk.Frame(self, bg=BG_COLOR)
        form.pack(fill="both", expand=True, padx=26, pady=4)
        form.columnconfigure(1, weight=1)

        self._v_department = None
        row = 0
        for f in self.field_config["user_fields"]:
            suffix = " *" if f["required"] else ""
            if f["key"] == "department":
                tk.Label(form, text=f["label"] + suffix, font=("Helvetica", 11, "bold"),
                         bg=BG_COLOR, anchor="w").grid(row=row, column=0, sticky="w", pady=(10, 2))
                options = f.get("options") or DEFAULT_DEPARTMENT_OPTIONS
                self._v_department = tk.StringVar(value=options[0])
                ttk.Combobox(
                    form, textvariable=self._v_department, values=options,
                    state="readonly", font=("Helvetica", 11), width=36,
                ).grid(row=row, column=1, sticky="ew", padx=(8, 0), pady=(10, 2))
            else:
                widget = self._field(form, f["label"] + suffix, row)
                self._field_widgets[f["key"]] = widget
            row += 1

        # ── Device info preview ───────────────────────────────────────────────
        tk.Frame(self, bg="#D0D5DD", height=1).pack(fill="x", padx=26, pady=(12, 6))
        pf = tk.Frame(self, bg=BG_COLOR)
        pf.pack(fill="x", padx=26)
        tk.Label(pf, text="Device information that will be recorded:",
                 font=("Helvetica", 9, "italic"), fg="#6B7280", bg=BG_COLOR).pack(anchor="w")
        hw = self.hw
        # Only what will actually be submitted: the label above promises
        # "information that will be recorded", and submit_to_sheets() drops
        # every hardware key the company has switched off.
        enabled_hw = set(self.field_config["hardware_fields"])
        lines = [f"  {hw['brand']} {hw['model']}  •  SN: {hw.get('serial_number','?')}  •  {hw['os']}"]
        specs = [
            f"{label}: {hw[key]}"
            for key, label in (("cpu", "CPU"), ("ram", "RAM"), ("storage", "Storage"))
            if key in enabled_hw
        ]
        if specs:
            lines.append("  " + "  •  ".join(specs))
        host_line = f"  Host: {hw['hostname']}"
        if "ip_address" in enabled_hw:
            host_line += f"  •  IP: {hw['ip_address']}"
        lines.append(host_line)
        preview = "\n".join(lines)
        tk.Label(pf, text=preview, font=("Helvetica", 9), fg="#374151",
                 bg=BG_COLOR, justify="left", wraplength=468).pack(anchor="w")

        # ── Buttons ───────────────────────────────────────────────────────────
        bf = tk.Frame(self, bg=BG_COLOR)
        bf.pack(fill="x", padx=26, pady=(10, 20))
        tk.Button(
            bf, text="Cancel", command=self._on_cancel,
            font=("Helvetica", 11), fg="#6B7280", bg="#E5E7EB",
            relief="flat", padx=18, pady=7, cursor="hand2", activebackground="#D1D5DB",
        ).pack(side="right", padx=(8, 0))
        tk.Button(
            bf, text="Submit →", command=self._on_submit,
            font=("Helvetica", 11, "bold"), fg="white", bg=ACCENT_COLOR,
            relief="flat", padx=18, pady=7, cursor="hand2", activebackground="#C0252E",
        ).pack(side="right")

    def _field(self, parent: tk.Frame, label: str, row: int) -> tk.Entry:
        tk.Label(parent, text=label, font=("Helvetica", 11, "bold"),
                 bg=BG_COLOR, anchor="w").grid(row=row, column=0, sticky="w", pady=(10, 2))
        e = tk.Entry(parent, font=("Helvetica", 11), relief="solid", bd=1, width=38)
        e.grid(row=row, column=1, sticky="ew", padx=(8, 0), pady=(10, 2))
        return e

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
        if messagebox.askyesno(
            "Cancel check-in",
            "Are you sure you want to skip?\n\n"
            "• IT will be notified\n"
            "• You'll be reminded again in 24 hours",
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

    # 4. Guard: exit early if not due (skipped when --force is passed)
    if not args.force and not should_show_form(state, schedule):
        sys.exit(0)

    # 5. Collect hardware
    log.info("Collecting hardware information…")
    hw = collect_hardware()
    log.info(json.dumps(hw, indent=2))

    field_config = config

    # 6. Show GUI
    app = InventoryForm(hw, field_config)
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
    dialog_msg = f"Thank you, {app.user_data['first_name']}!\n\nYour device has been registered."
    if not immediate:
        dialog_msg += "\n\n(Offline — data will sync automatically.)"
    messagebox.showinfo("Assetly Inventory – Done", dialog_msg)

    log.info("=== Completed successfully ===")


if __name__ == "__main__":
    main()
