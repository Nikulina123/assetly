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
#    /Library/Application Support/Assetly/Assetly Inventory Agent.app
#                                                              icon/name wrapper
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
    return 0
}

# ── Root certificates ─────────────────────────────────────────────────────────
# python.org ships root certificates as a separate opt-in step; without it every
# HTTPS call the agent makes dies with CERTIFICATE_VERIFY_FAILED -- which is not
# a loud failure, because fetch_config() and the update check both degrade to
# their built-in fallbacks. The visible symptom is an agent quietly showing the
# hardcoded department list instead of the company's, and queueing every
# check-in offline.
#
# This deliberately runs for whatever Python was SELECTED, not only for one this
# script installed: the common case is a Mac that already has a python.org build
# whose certificate step was never run. Doing it only inside the installer
# branch (where it used to live) skips exactly the machines that need it.
install_root_certificates() {
    local py="$1" certs version
    # Only python.org framework builds ship the opt-in command; Homebrew and
    # the system Python use certifi or the system store and need nothing here.
    case "$py" in /Library/Frameworks/Python.framework/*) ;; *) return 0 ;; esac
    if "$py" -c 'import ssl,urllib.request; urllib.request.urlopen("https://www.apple.com", timeout=15)' >/dev/null 2>&1; then
        return 0
    fi
    say "This Python cannot verify HTTPS certificates — installing root certificates…"
    # Match the command to the selected interpreter's version rather than taking
    # the newest on disk: a Mac with several python.org versions would otherwise
    # certify one we are not going to run.
    version="$("$py" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null)"
    certs="/Applications/Python $version/Install Certificates.command"
    if [ ! -f "$certs" ]; then
        certs="$(ls -1d "/Applications/Python 3."*/"Install Certificates.command" 2>/dev/null | sort -Vr | head -1)"
    fi
    if [ -n "$certs" ] && [ -f "$certs" ]; then
        /bin/bash "$certs" >/dev/null 2>&1 || say "WARN: certificate step failed."
    else
        # No command on disk (e.g. the .app was removed after install). certifi
        # is what that command installs anyway, so ask pip for it directly.
        "$py" -m pip install --upgrade certifi >/dev/null 2>&1 || true
    fi
    if "$py" -c 'import ssl,urllib.request; urllib.request.urlopen("https://www.apple.com", timeout=15)' >/dev/null 2>&1; then
        say "Root certificates installed."
    else
        say "WARN: HTTPS verification still fails — check-ins and config fetches will not work."
    fi
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
install_root_certificates "$PYTHON3"

# ── App bundle, purely so the agent looks like itself ─────────────────────────
# Without this the check-in window belongs to Python.app: the Dock shows the
# Python rocket and the menu bar and app switcher say "Python". macOS takes both
# from the bundle that owns the process, so Tk's iconphoto cannot change either
# (it is a no-op on Aqua) -- the only fix is for the process to run out of a
# bundle of ours.
#
# The executable has to be a COPY of the framework's Python binary, not a
# symlink or a shell stub: LaunchServices resolves the owning bundle from the
# real path of the running executable, so a symlink lands back on Python.app and
# a stub that execs python hands the identity straight back. Copying is what
# py2app does for the same reason.
#
# Copying breaks the code signature -- Python's signature covers Python.app's
# own Info.plist, which we replace -- and a hardened-runtime binary with a
# broken signature is SIGKILLed on launch (observed: exit 137). So the finished
# bundle is re-signed ad-hoc. /usr/bin/codesign is part of the base OS; no Xcode
# or developer account is involved, and an ad-hoc signature is sufficient for a
# bundle built on the machine that runs it.
APP_BUNDLE="$SUPPORT_DIR/Assetly Inventory Agent.app"

build_app_bundle() {
    local py="$1" py_app_bin iconset sz
    # Only framework builds ship the Python.app whose binary we copy. On
    # Homebrew or the system Python there is nothing to copy, so the bundle is
    # skipped and the launcher falls back to running python directly -- the
    # agent works exactly as before, just with Python's icon.
    py_app_bin="$(dirname "$(dirname "$py")")/Resources/Python.app/Contents/MacOS/Python"
    if [ ! -x "$py_app_bin" ]; then
        say "Python is not a framework build — skipping the app bundle (agent still runs)."
        return 1
    fi

    rm -rf "$APP_BUNDLE"
    mkdir -p "$APP_BUNDLE/Contents/MacOS" "$APP_BUNDLE/Contents/Resources"
    cp "$py_app_bin" "$APP_BUNDLE/Contents/MacOS/AssetlyAgent" || return 1

    cat > "$APP_BUNDLE/Contents/Info.plist" <<'APP_PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>              <string>Assetly Inventory Agent</string>
    <key>CFBundleDisplayName</key>       <string>Assetly Inventory Agent</string>
    <key>CFBundleExecutable</key>        <string>AssetlyAgent</string>
    <key>CFBundleIdentifier</key>        <string>com.assetly.inventory.agent</string>
    <key>CFBundleIconFile</key>          <string>assetly</string>
    <key>CFBundlePackageType</key>       <string>APPL</string>
    <key>CFBundleShortVersionString</key><string>2.0</string>
    <!-- Retina: without this the icon and window render doubled and soft. -->
    <key>NSHighResolutionCapable</key>   <true/>
</dict>
</plist>
APP_PLIST

    # assetly_icon.png ships in the package's Scripts directory alongside this
    # script. sips and iconutil are both part of the base OS.
    if [ -f "$SCRIPT_DIR/assetly_icon.png" ]; then
        iconset="$(mktemp -d -t assetly-iconset)/assetly.iconset"
        mkdir -p "$iconset"
        for sz in 16 32 128 256 512; do
            sips -z "$sz" "$sz" "$SCRIPT_DIR/assetly_icon.png" \
                --out "$iconset/icon_${sz}x${sz}.png" >/dev/null 2>&1
            sips -z "$((sz * 2))" "$((sz * 2))" "$SCRIPT_DIR/assetly_icon.png" \
                --out "$iconset/icon_${sz}x${sz}@2x.png" >/dev/null 2>&1
        done
        iconutil -c icns "$iconset" -o "$APP_BUNDLE/Contents/Resources/assetly.icns" \
            >/dev/null 2>&1 || say "WARN: could not build the icns; the bundle will use a blank icon."
        rm -rf "$(dirname "$iconset")"
    else
        say "WARN: assetly_icon.png missing from the package — bundle will have no icon."
    fi

    if ! codesign --force --sign - --timestamp=none "$APP_BUNDLE" >/dev/null 2>&1; then
        say "WARN: could not sign the app bundle — falling back to plain python."
        rm -rf "$APP_BUNDLE"
        return 1
    fi
    # Prove it actually launches before the launcher is told to prefer it: a
    # bundle that SIGKILLs on start would otherwise take the agent down with it.
    if ! "$APP_BUNDLE/Contents/MacOS/AssetlyAgent" -c 'pass' >/dev/null 2>&1; then
        say "WARN: the app bundle does not launch — falling back to plain python."
        rm -rf "$APP_BUNDLE"
        return 1
    fi
    say "Built $APP_BUNDLE"
    return 0
}

build_app_bundle "$PYTHON3" || true

# ── Lay down the shared copies ────────────────────────────────────────────────
mkdir -p "$SUPPORT_DIR"
install -m 644 "$SCRIPT_DIR/inventory_agent.py" "$AGENT_SRC"

# Enroll at install time, while we are still root and still hold the
# company-wide enrollment token. What persists on this machine is then a
# per-device credential -- individually revocable from the portal, and bound
# to this machine's serial (see backend/app/auth.py), so a leak of this file
# exposes one machine rather than the whole fleet.
#
# The previous behaviour wrote the shared enrollment token here world-readable
# (mode 644), "world-readable on purpose" so every account could seed its own copy at
# login. The requirement was always "each user gets a copy", never "every
# user can read the master" -- the per-user LaunchAgent above (which copies
# this file into each user's own home at 600) satisfies the first without
# the second, as long as the master itself is never world-readable.
# A previous installer version may have left a world-readable seed config
# containing the shared token behind. rm it before writing the new one so
# that file can never linger under the old, less restrictive mode.
rm -f "$SEED_CONFIG"

# Enroll against POST /api/v1/enroll (see backend/app/routers/enroll.py).
ENROLL_API_URL="${CHECKIN_API_URL%/inventory/checkin}/enroll"
SERIAL="$(ioreg -l | awk -F'"' '/IOPlatformSerialNumber/{print $4}')"
CREDENTIAL="$(curl -fsS --max-time 20 -X POST "$ENROLL_API_URL" \
  -H "Authorization: Bearer $ENROLLMENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"serial_number\":\"$SERIAL\",\"hostname\":\"$(hostname)\"}" \
  2>/dev/null | "$PYTHON3" -c 'import json,sys
try:
    print(json.load(sys.stdin)["credential"])
except Exception:
    pass' 2>/dev/null)"

if [ -n "$CREDENTIAL" ]; then
    cat > "$SEED_CONFIG" <<JSON
{
  "checkin_api_url": "$CHECKIN_API_URL",
  "device_credential": "$CREDENTIAL",
  "github_raw_url": "$GITHUB_RAW_URL"
}
JSON
    say "Enrolled at install time; enrollment token discarded."
else
    # No network at imaging time is normal. Fall back to storing the token so
    # each user's agent can enroll itself on first run -- but never
    # world-readable. 600 root:wheel on every path, no exceptions.
    cat > "$SEED_CONFIG" <<JSON
{
  "checkin_api_url": "$CHECKIN_API_URL",
  "enrollment_token": "$ENROLLMENT_TOKEN",
  "github_raw_url": "$GITHUB_RAW_URL"
}
JSON
    say "Could not enroll at install time; deferring enrollment to first run."
fi

chown root:wheel "$SEED_CONFIG"
chmod 600 "$SEED_CONFIG"

# ── Root-owned seeding daemon ──────────────────────────────────────────────────
# $SEED_CONFIG is 0600 root:wheel -- deliberately unreadable by any local user,
# so a leaked file exposes one machine's credential instead of the whole
# fleet's. That means the per-user LaunchAgent below (assetly-launch.sh, which
# runs AS THE LOGGED-IN USER) cannot read it to seed a user's copy -- reading a
# root-owned 0600 file as a non-root user simply fails. Copying the config into
# each user's home therefore has to happen from something running as root:
# this LaunchDaemon. Do not "simplify" this back down to one launcher -- the
# split exists because the two files have different readers by design:
#   - com.assetly.seed   (root)      writes each user's copy from the master.
#   - com.assetly.inventory (user)   reads only its own copy, never the master.
mkdir -p "$SUPPORT_DIR"
cat > "$SUPPORT_DIR/seed_user_config.sh" <<'SEED_EOF'
#!/bin/sh
# Runs as root from com.assetly.seed. Copies the root-owned master config into
# every real user's home, chowned to that user at 0600, so each user gets a
# copy without the master ever being world- or other-user-readable.
SUPPORT_DIR="/Library/Application Support/Assetly"
for home in /Users/*; do
    user="$(basename "$home")"
    case "$user" in Shared|Guest|.*) continue ;; esac
    [ -d "$home" ] || continue
    id "$user" >/dev/null 2>&1 || continue
    target_dir="$home/Library/Application Support/AssetlyInventory"
    target="$target_dir/config.json"
    # The user's own config is never overwritten once it exists: after the
    # first check-in it holds a device credential that only this machine has,
    # and the seed copy does not.
    [ -f "$target" ] && continue
    mkdir -p "$target_dir"
    cp "$SUPPORT_DIR/config.json" "$target"
    chown "$user" "$target_dir" "$target"
    chmod 700 "$target_dir"
    chmod 600 "$target"
done
SEED_EOF
chown root:wheel "$SUPPORT_DIR/seed_user_config.sh"
chmod 755 "$SUPPORT_DIR/seed_user_config.sh"

cat > /Library/LaunchDaemons/com.assetly.seed.plist <<PLIST_SEED
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.assetly.seed</string>

    <key>ProgramArguments</key>
    <array>
        <string>$SUPPORT_DIR/seed_user_config.sh</string>
    </array>

    <key>RunAtLoad</key>
    <true/>

    <!-- Runs every 5 minutes so a user who logs in between installs and the
         next login still gets seeded promptly, without needing a re-login. -->
    <key>StartInterval</key>
    <integer>300</integer>
</dict>
</plist>
PLIST_SEED
chown root:wheel /Library/LaunchDaemons/com.assetly.seed.plist
# Same as the LaunchAgent plist below: launchd requires world-readable plists
# to load them at all, and this one carries no secret -- only a path.
chmod 644 /Library/LaunchDaemons/com.assetly.seed.plist
launchctl bootout system/com.assetly.seed 2>/dev/null
launchctl bootstrap system /Library/LaunchDaemons/com.assetly.seed.plist 2>/dev/null \
    || say "WARN: could not start the seeding daemon now; it will run at next boot."
# Also seed synchronously for whoever is about to be started below, so the
# LaunchAgent started later in this script does not race the daemon's own
# 300s interval on a fresh install.
"$SUPPORT_DIR/seed_user_config.sh" 2>/dev/null || true

cat > "$LAUNCHER" <<'LAUNCHER_EOF'
#!/bin/bash
# Runs as the logged-in user, once per login (and on the LaunchAgent interval).
# Seeds this user's own copy of the agent from the shared one, then runs it.
#
# This launcher never reads $SUPPORT_DIR/config.json: that master file is
# 0600 root:wheel on purpose (see AssetlyAgent_macOS_postinstall.sh), so a
# leaked copy exposes one machine's credential rather than the whole fleet's.
# It is unreadable to this user by design. The root-owned com.assetly.seed
# LaunchDaemon is what copies it into this user's own config.json, chowned to
# them at 0600 -- this script only ever touches its own already-seeded copy.
set -u

SUPPORT_DIR="/Library/Application Support/Assetly"
USER_DIR="$HOME/Library/Application Support/AssetlyInventory"
mkdir -p "$USER_DIR"

# Refresh the agent whenever the shared copy is newer -- reinstalling the
# package is how an admin pushes a new agent build to a fleet. inventory_agent.py
# is not a secret and stays world-readable, unlike config.json.
if [ ! -f "$USER_DIR/inventory_agent.py" ] || [ "$SUPPORT_DIR/inventory_agent.py" -nt "$USER_DIR/inventory_agent.py" ]; then
    cp "$SUPPORT_DIR/inventory_agent.py" "$USER_DIR/inventory_agent.py"
fi

# The seeding daemon may not have run yet (e.g. this is the very first login
# right after install, before its next 300s tick). If this user's config
# hasn't been seeded, there is nothing to run yet -- exit quietly and let the
# next LaunchAgent interval try again, rather than starting the agent with no
# configuration or erroring.
if [ ! -f "$USER_DIR/config.json" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S')  INFO      config.json not seeded yet — waiting for com.assetly.seed." \
        >> "$USER_DIR/agent.log"
    exit 0
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

# The app bundle the installer built, whose only purpose is to give the
# check-in window Assetly's icon and name instead of Python's. Its executable
# is a copy of the Python binary, so it takes the same arguments -- but it is
# pinned to the interpreter present at install time, and that interpreter can
# later be upgraded or removed out from under it. So it is used only when it
# still runs, and find_python below remains the fallback: a broken bundle must
# never mean a missed check-in.
APP_BIN="$SUPPORT_DIR/Assetly Inventory Agent.app/Contents/MacOS/AssetlyAgent"
if [ -x "$APP_BIN" ] && "$APP_BIN" -c 'import tkinter' >/dev/null 2>&1; then
    exec "$APP_BIN" "$USER_DIR/inventory_agent.py" "$@"
fi

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
