#!/bin/bash
# ════════════════════════════════════════════════════════════════════════════════
#  Assetly Inventory Agent — macOS package postinstall
#
#  Runs as root from inside AssetlyAgent_macOS.pkg. Everything the old
#  AssetlyAgent_macOS.sh asked the user to do by hand happens here instead, with
#  no terminal, no chmod, and no Homebrew: macOS Installer executes this script
#  with the package's Scripts directory as the working directory, so
#  inventory_agent.py ships alongside it rather than being fetched from GitHub
#  at install time.
#
#  Installed layout:
#    /Library/Application Support/Assetly/inventory_agent.py   pristine copy
#    /Library/Application Support/Assetly/config.json          seed config
#    /Library/Application Support/Assetly/assetly-launch.sh    per-user launcher
#    /Library/LaunchAgents/com.assetly.inventory.plist         runs at every login
#
#  The agent itself runs per-user, out of the user's own Application Support
#  directory: it rewrites its own file on self-update and writes the device
#  credential back into its config, neither of which works from a root-owned
#  location. The launcher seeds each user's copy on first login.
# ════════════════════════════════════════════════════════════════════════════════

# ─── CONFIGURATION — edit these lines before distributing ────────────────────
CHECKIN_API_URL="https://api.example.com/api/v1/inventory/checkin"   # ← FILL IN (replaced automatically when downloaded from the admin portal)
ENROLLMENT_TOKEN=""                                                   # ← FILL IN (replaced automatically when downloaded from the admin portal)
GITHUB_RAW_URL="https://raw.githubusercontent.com/Nikulina123/Check-in_Agent/main/inventory_agent.py"
# ─────────────────────────────────────────────────────────────────────────────

# Pinned python.org build, used only when the Mac has no usable Python already.
# python.org is the one distribution that reliably ships a Tcl/Tk the current
# macOS accepts -- the system Python 3.9 bundles Tk 8.5, which aborts the moment
# tkinter opens a window on recent macOS, and Homebrew's python3 has no tkinter
# at all unless someone separately installs python-tk.
PYTHON_PKG_URL="https://www.python.org/ftp/python/3.13.7/python-3.13.7-macos11.pkg"
PYTHON_PKG_SIGNER="Python Software Foundation"

set -u

SUPPORT_DIR="/Library/Application Support/Assetly"
AGENT_SRC="$SUPPORT_DIR/inventory_agent.py"
SEED_CONFIG="$SUPPORT_DIR/config.json"
LAUNCHER="$SUPPORT_DIR/assetly-launch.sh"
PLIST_LABEL="com.assetly.inventory"
PLIST_FILE="/Library/LaunchAgents/$PLIST_LABEL.plist"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Installer captures stdout/stderr into /var/log/install.log, which is where an
# admin looks when a deployment misbehaves -- so log generously.
say() { echo "[assetly] $*"; }

# ── Locate a Python 3 whose tkinter can actually open a window ────────────────
# TkVersion is readable straight after `import tkinter`, without instantiating
# Tk(). That matters here: this script runs as root with no GUI session, where
# creating a real window fails even on a perfectly good Python, so an
# instantiation test would reject every candidate.
find_python() {
    local candidates=() py version_dir
    while IFS= read -r version_dir; do
        candidates+=("$version_dir")
    done < <(ls -1d /Library/Frameworks/Python.framework/Versions/3.*/bin/python3 2>/dev/null | sort -Vr)
    candidates+=(/opt/homebrew/bin/python3 /usr/local/bin/python3 /usr/bin/python3)

    for py in "${candidates[@]}"; do
        [ -x "$py" ] || continue
        if "$py" -c 'import sys,tkinter; sys.exit(0 if sys.version_info >= (3, 8) and tkinter.TkVersion >= 8.6 else 1)' >/dev/null 2>&1; then
            echo "$py"
            return 0
        fi
    done
    return 1
}

install_python_from_python_org() {
    local tmp_dir tmp_pkg
    tmp_dir="$(mktemp -d -t assetly-python)" || return 1
    tmp_pkg="$tmp_dir/python.pkg"
    say "Downloading $PYTHON_PKG_URL"
    if ! curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 20 "$PYTHON_PKG_URL" -o "$tmp_pkg"; then
        say "ERROR: could not download the Python installer."
        rm -rf "$tmp_dir"
        return 1
    fi
    # HTTPS already authenticates python.org; checking the package signature
    # additionally proves the bytes on disk are the PSF's own build, and unlike
    # a pinned hash it keeps working when the pinned version is refreshed.
    if ! pkgutil --check-signature "$tmp_pkg" 2>/dev/null | grep -q "$PYTHON_PKG_SIGNER"; then
        say "ERROR: downloaded Python installer is not signed by $PYTHON_PKG_SIGNER — refusing to install it."
        rm -rf "$tmp_dir"
        return 1
    fi
    say "Installing Python…"
    if ! installer -pkg "$tmp_pkg" -target / >/dev/null; then
        say "ERROR: the Python installer failed."
        rm -rf "$tmp_dir"
        return 1
    fi
    rm -rf "$tmp_dir"
    # python.org ships root certificates as a separate opt-in step; without it
    # every HTTPS call the agent makes fails certificate verification.
    local certs
    certs="$(ls -1d "/Applications/Python 3."*/"Install Certificates.command" 2>/dev/null | sort -Vr | head -1)"
    if [ -n "$certs" ]; then
        say "Installing root certificates…"
        /bin/bash "$certs" >/dev/null 2>&1 || say "WARN: certificate step failed; HTTPS check-ins may fail."
    fi
    return 0
}

say "Installing the Assetly Inventory Agent…"

PYTHON3="$(find_python)"
if [ -z "$PYTHON3" ]; then
    say "No Python 3 with a working Tk found — installing one."
    if install_python_from_python_org; then
        PYTHON3="$(find_python)"
    fi
fi
if [ -z "$PYTHON3" ]; then
    say "ERROR: no usable Python 3 (with tkinter/Tk 8.6+) is available and one could not be installed."
    say "       Install Python 3 from https://www.python.org/downloads/ and run this installer again."
    exit 1
fi
say "Using Python: $PYTHON3"

# ── Lay down the shared copies ────────────────────────────────────────────────
mkdir -p "$SUPPORT_DIR"
install -m 644 "$SCRIPT_DIR/inventory_agent.py" "$AGENT_SRC"

# World-readable on purpose: every account on this Mac has to be able to seed
# its own copy at login. The enrollment token it carries is a company-wide
# deployment secret rather than a per-user one, and it is exchanged for a
# per-device credential on first check-in.
cat > "$SEED_CONFIG" <<JSON
{
  "checkin_api_url": "$CHECKIN_API_URL",
  "enrollment_token": "$ENROLLMENT_TOKEN",
  "github_raw_url": "$GITHUB_RAW_URL"
}
JSON
chmod 644 "$SEED_CONFIG"

cat > "$LAUNCHER" <<'LAUNCHER_EOF'
#!/bin/bash
# Runs as the logged-in user, once per login (and on the LaunchAgent interval).
# Seeds this user's own copy of the agent from the shared one, then runs it.
set -u

SUPPORT_DIR="/Library/Application Support/Assetly"
USER_DIR="$HOME/Library/Application Support/AssetlyInventory"
mkdir -p "$USER_DIR"

# Refresh the agent whenever the shared copy is newer -- reinstalling the
# package is how an admin pushes a new agent build to a fleet.
if [ ! -f "$USER_DIR/inventory_agent.py" ] || [ "$SUPPORT_DIR/inventory_agent.py" -nt "$USER_DIR/inventory_agent.py" ]; then
    cp "$SUPPORT_DIR/inventory_agent.py" "$USER_DIR/inventory_agent.py"
fi
# The user's config is never overwritten: after the first check-in it holds a
# device credential that only this machine has, and the seed does not.
if [ ! -f "$USER_DIR/config.json" ]; then
    cp "$SUPPORT_DIR/config.json" "$USER_DIR/config.json"
    chmod 600 "$USER_DIR/config.json"
fi

find_python() {
    local candidates=() py version_dir
    while IFS= read -r version_dir; do
        candidates+=("$version_dir")
    done < <(ls -1d /Library/Frameworks/Python.framework/Versions/3.*/bin/python3 2>/dev/null | sort -Vr)
    candidates+=(/opt/homebrew/bin/python3 /usr/local/bin/python3 /usr/bin/python3)
    for py in "${candidates[@]}"; do
        [ -x "$py" ] || continue
        if "$py" -c 'import sys,tkinter; sys.exit(0 if sys.version_info >= (3, 8) and tkinter.TkVersion >= 8.6 else 1)' >/dev/null 2>&1; then
            echo "$py"
            return 0
        fi
    done
    return 1
}

# Resolved at every run rather than baked in at install time, so the agent
# survives the Python it was installed against being upgraded or removed.
PYTHON3="$(find_python)"
if [ -z "$PYTHON3" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S')  ERROR     No Python 3 with working tkinter found — agent not started." \
        >> "$USER_DIR/agent.log"
    exit 1
fi

exec "$PYTHON3" "$USER_DIR/inventory_agent.py" "$@"
LAUNCHER_EOF
chmod 755 "$LAUNCHER"

# ── LaunchAgent, installed system-wide so it covers every account ─────────────
mkdir -p /Library/LaunchAgents
cat > "$PLIST_FILE" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${PLIST_LABEL}</string>

    <key>ProgramArguments</key>
    <array>
        <string>${LAUNCHER}</string>
    </array>

    <key>RunAtLoad</key>
    <true/>

    <!-- Hourly. This is the wake cadence, not the prompt cadence: the agent
         exits immediately unless the company's configured interval has
         elapsed. It also sets the floor on how short that interval can
         usefully be (see MIN_INTERVAL_SECONDS in backend/app/schedule.py). -->
    <key>StartInterval</key>
    <integer>3600</integer>

    <key>StandardOutPath</key>
    <string>/tmp/assetly-agent.out.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/assetly-agent.err.log</string>

    <!-- Only launch when a GUI session is active -->
    <key>LimitLoadToSessionType</key>
    <string>Aqua</string>
</dict>
</plist>
PLIST
chmod 644 "$PLIST_FILE"

# ── Start it for whoever is logged in right now ───────────────────────────────
# Without this the agent would not run until the next login. A package pushed by
# MDM at the login window has no console user, which is fine: the LaunchAgent
# loads by itself when someone logs in.
CONSOLE_USER="$(stat -f%Su /dev/console 2>/dev/null)"
if [ -n "$CONSOLE_USER" ] && [ "$CONSOLE_USER" != "root" ]; then
    CONSOLE_UID="$(id -u "$CONSOLE_USER" 2>/dev/null)"
    if [ -n "$CONSOLE_UID" ]; then
        # A Mac that previously ran AssetlyAgent_macOS.sh has a per-user
        # LaunchAgent with this same label. Left in place it would shadow the
        # system one and keep running the old, unmanaged copy of the agent.
        CONSOLE_HOME="$(dscl . -read "/Users/$CONSOLE_USER" NFSHomeDirectory 2>/dev/null | sed 's/^NFSHomeDirectory: //')"
        OLD_PLIST="$CONSOLE_HOME/Library/LaunchAgents/$PLIST_LABEL.plist"
        if [ -n "$CONSOLE_HOME" ] && [ -f "$OLD_PLIST" ]; then
            say "Removing the older per-user LaunchAgent left by the shell installer."
            launchctl bootout "gui/$CONSOLE_UID/$PLIST_LABEL" 2>/dev/null
            rm -f "$OLD_PLIST"
        fi
        launchctl bootout "gui/$CONSOLE_UID/$PLIST_LABEL" 2>/dev/null
        launchctl bootstrap "gui/$CONSOLE_UID" "$PLIST_FILE" 2>/dev/null \
            || say "WARN: could not start the agent for $CONSOLE_USER; it will start at their next login."
    fi
fi

say "Installation complete."
exit 0
