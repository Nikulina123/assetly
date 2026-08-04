#!/usr/bin/env python3
"""
Webiz Inventory Agent v2.0
Cross-platform (macOS + Linux) — zero pip dependencies.
Config is loaded from  ~/.webiz_inventory/config.json  (written by the installer).
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
    STATE_DIR = Path.home() / "Library" / "Application Support" / "WebizInventory"
else:
    STATE_DIR = Path.home() / ".webiz_inventory"

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
log = logging.getLogger("webiz")

# ─── Config ───────────────────────────────────────────────────────────────────
_cfg: dict = {}
if CONFIG_FILE.exists():
    try:
        _cfg = json.loads(CONFIG_FILE.read_text())
    except Exception:
        pass

CHECKIN_API_URL  = _cfg.get("checkin_api_url", "https://api.example.com/api/v1/inventory/checkin")
CONFIG_API_URL   = CHECKIN_API_URL.rsplit("/checkin", 1)[0] + "/config"
COMPANY_API_KEY  = _cfg.get("company_api_key", "")
GITHUB_RAW_URL   = _cfg.get("github_raw_url", "")

INTERVAL_MONTHS  = 6
CANCEL_RETRY_H   = (2/60)   # TEST: 2 minutes — change back to 24 for production

PROJECTS = ["Webiz ERP", "Fundbox", "Playtika", "Artlist", "The5%ers", "Other"]

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

# ─── 6-month + 24 h guard ─────────────────────────────────────────────────────
def _months_diff(d1: datetime.datetime, d2: datetime.datetime) -> float:
    return (d2.year - d1.year) * 12 + d2.month - d1.month + (d2.day - d1.day) / 30.0

def should_show_form(state: dict) -> bool:
    now = datetime.datetime.now()

    last_run = state.get("last_run")
    if last_run:
        diff = _months_diff(datetime.datetime.fromisoformat(last_run), now)
        if diff < INTERVAL_MONTHS:
            log.info(f"Last check-in {diff:.1f} months ago — not due yet. Exiting.")
            return False

    cancelled_at = state.get("cancelled_at")
    if cancelled_at:
        diff_h = (now - datetime.datetime.fromisoformat(cancelled_at)).total_seconds() / 3600
        if diff_h < CANCEL_RETRY_H:
            log.info(f"Cancelled {diff_h:.1f} h ago — retry window not reached. Exiting.")
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
                "Authorization": f"Bearer {COMPANY_API_KEY}",
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
            log.error(f"Authentication failed ({e.code}) — check company_api_key in config.json. Not queuing as offline.")
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
        {"key": "project", "label": "Project", "required": True, "locked": False},
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
    return all(
        isinstance(f, dict) and required_keys.issubset(f) and isinstance(f["key"], str)
        for f in user_fields
    ) and all(isinstance(key, str) for key in hardware_fields)


def fetch_field_config() -> dict:
    """Fetches this company's field config; falls back to DEFAULT_FIELD_CONFIG
    on any failure (network/auth/parse/malformed-shape) so a config-fetch
    problem never blocks check-in entirely."""
    try:
        req = urllib.request.Request(
            CONFIG_API_URL,
            headers={
                "Authorization": f"Bearer {COMPANY_API_KEY}",
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
        self._field_widgets: dict = {}   # non-project field key -> tk.Entry

        self.title("Webiz Inventory Agent")
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
        w, h = 520, 644
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
        logo_file = Path(__file__).parent / "webiz_logo.png"
        if logo_file.exists():
            try:
                self._logo_img = tk.PhotoImage(file=str(logo_file))
                tk.Label(hdr, image=self._logo_img, bg=BRAND_COLOR).pack(
                    side="left", padx=22, pady=14)
                logo_shown = True
            except Exception:
                pass

        if not logo_shown:
            tk.Label(hdr, text="WEBIZ", fg="white", bg=BRAND_COLOR,
                     font=("Helvetica", 30, "bold")).pack(side="left", padx=22, pady=16)

        # Red accent line
        tk.Frame(self, bg=ACCENT_COLOR, height=4).pack(fill="x")

        # ── Welcome text ──────────────────────────────────────────────────────
        wf = tk.Frame(self, bg=BG_COLOR)
        wf.pack(fill="x", padx=26, pady=(18, 4))
        tk.Label(
            wf,
            text="Hello, I am Inventory Agent of Webiz and I need following information",
            wraplength=468, justify="left",
            font=("Helvetica", 12), fg="#1C1C1E", bg=BG_COLOR,
        ).pack(anchor="w")

        # ── Form ──────────────────────────────────────────────────────────────
        form = tk.Frame(self, bg=BG_COLOR)
        form.pack(fill="both", expand=True, padx=26, pady=4)
        form.columnconfigure(1, weight=1)

        self._v_project = None
        row = 0
        for f in self.field_config["user_fields"]:
            suffix = " *" if f["required"] else ""
            if f["key"] == "project":
                tk.Label(form, text=f["label"] + suffix, font=("Helvetica", 11, "bold"),
                         bg=BG_COLOR, anchor="w").grid(row=row, column=0, sticky="w", pady=(10, 2))
                self._v_project = tk.StringVar(value=PROJECTS[0])
                ttk.Combobox(
                    form, textvariable=self._v_project, values=PROJECTS,
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
        preview = (
            f"  {hw['brand']} {hw['model']}  •  SN: {hw.get('serial_number','?')}  •  {hw['os']}\n"
            f"  CPU: {hw['cpu']}  •  RAM: {hw['ram']}  •  Storage: {hw['storage']}\n"
            f"  Host: {hw['hostname']}  •  IP: {hw['ip_address']}"
        )
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
            if f["key"] == "project" or not f["required"]:
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
        if self._v_project is not None:
            self.user_data["project"] = self._v_project.get()
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
    parser = argparse.ArgumentParser(description="Webiz Inventory Agent")
    parser.add_argument("--force", action="store_true",
                        help="Bypass the 6-month interval guard and show the form immediately.")
    args = parser.parse_args()

    log.info("=== Webiz Inventory Agent v2.0 started ===")

    # When launched as a background service (LaunchAgent / systemd), stdout is not
    # a TTY. Wait briefly so the desktop session is fully ready before showing a GUI.
    if not sys.stdout.isatty():
        log.info("Background launch detected — waiting 15 s for desktop to settle…")
        time.sleep(15)

    # 1. Self-update (silent, restarts if new version found)
    self_update()

    # 2. Flush any offline-queued submissions
    flush_queue()

    # 3. Guard: exit early if not due (skipped when --force is passed)
    state = load_state()
    if not args.force and not should_show_form(state):
        sys.exit(0)

    # 4. Collect hardware
    log.info("Collecting hardware information…")
    hw = collect_hardware()
    log.info(json.dumps(hw, indent=2))

    # 4b. Fetch per-company field config (falls back to defaults on failure)
    field_config = fetch_field_config()

    # 5. Show GUI
    app = InventoryForm(hw, field_config)
    app.mainloop()

    # ── Cancelled ─────────────────────────────────────────────────────────────
    if not app.submitted:
        state["cancelled_at"] = datetime.datetime.now().isoformat()
        save_state(state)
        log.warning(f"Form cancelled. Will retry in {CANCEL_RETRY_H}h.")
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
    messagebox.showinfo("Webiz Inventory – Done", dialog_msg)

    log.info("=== Completed successfully ===")


if __name__ == "__main__":
    main()
