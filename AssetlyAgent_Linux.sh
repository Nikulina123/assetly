#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════════════════
#  Assetly Inventory Agent — Linux Installer
#  Single-file: just run this once.  Everything else is automatic.
#
#  Usage:  chmod +x AssetlyAgent_Linux.sh && ./AssetlyAgent_Linux.sh
#  Note:   Does NOT require root, and does not modify sudo configuration by
#          default. The agent reads the hardware serial number from
#          /sys/class/dmi/id/product_serial, which needs no privilege on most
#          modern distributions. Pass --with-dmidecode-sudo only if this
#          machine reports the serial as N/A -- that provisions a narrowly
#          scoped passwordless sudo rule for dmidecode. See --help.
# ════════════════════════════════════════════════════════════════════════════════

# ─── CONFIGURATION — edit these two lines before distributing ────────────────
CHECKIN_API_URL="https://api.example.com/api/v1/inventory/checkin"   # ← FILL IN (replaced automatically when downloaded from the admin portal)
ENROLLMENT_TOKEN=""                                                   # ← FILL IN (replaced automatically when downloaded from the admin portal)
GITHUB_RAW_URL="https://raw.githubusercontent.com/Nikulina123/Check-in_Agent/main/inventory_agent.py"
# ─────────────────────────────────────────────────────────────────────────────

# ─── Command-line flags ────────────────────────────────────────────────────
WITH_DMIDECODE_SUDO=0
for arg in "$@"; do
    case "$arg" in
        --with-dmidecode-sudo)
            WITH_DMIDECODE_SUDO=1
            ;;
        --help|-h)
            echo "Usage: $0 [--with-dmidecode-sudo]"
            echo ""
            echo "  --with-dmidecode-sudo   Provision a passwordless sudo rule for"
            echo "                          dmidecode so the agent can read the hardware"
            echo "                          serial number via dmidecode. Not needed on"
            echo "                          most modern Linux distributions, which expose"
            echo "                          the same serial at /sys/class/dmi/id/product_serial"
            echo "                          without any elevated privilege -- the agent"
            echo "                          already tries that path first. Only pass this"
            echo "                          flag if the agent reports the serial number as"
            echo "                          N/A on this machine."
            exit 0
            ;;
    esac
done

set -uo pipefail   # -e removed so we can show real errors before exiting

# ── Error trap: show what failed and keep terminal open ──────────────────────
_die() {
    local line="$1"
    echo ""
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║  ✗  Installation failed (line $line)                    "
    echo "║     Check the error above, fix it, and re-run.          ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo ""
    exit 1
}
trap '_die $LINENO' ERR

AGENT_DIR="$HOME/.assetly_inventory"
AGENT_FILE="$AGENT_DIR/inventory_agent.py"
CONFIG_FILE="$AGENT_DIR/config.json"
UNIT_DIR="$HOME/.config/systemd/user"
SERVICE_NAME="assetly-inventory"

echo ""
echo "┌─────────────────────────────────────────┐"
echo "│  Assetly Inventory Agent – Linux Setup  │"
echo "└─────────────────────────────────────────┘"
echo ""

# ── Step 1: Locate Python 3 ───────────────────────────────────────────────────
echo "[1/6] Locating Python 3…"
PYTHON3=""
for candidate in python3 python; do
    if command -v "$candidate" &>/dev/null; then
        ver=$("$candidate" --version 2>&1 || true)
        if [[ "$ver" == Python\ 3* ]]; then
            PYTHON3=$(command -v "$candidate")
            echo "      Found: $PYTHON3  ($ver)"
            break
        fi
    fi
done

if [[ -z "$PYTHON3" ]]; then
    echo "      Python 3 not found — attempting to install…"
    if   command -v apt-get &>/dev/null; then sudo apt-get install -y python3
    elif command -v dnf     &>/dev/null; then sudo dnf install -y python3
    elif command -v pacman  &>/dev/null; then sudo pacman -S --noconfirm python
    else
        echo "  [ERROR] Cannot auto-install Python 3. Please install it manually."
        exit 1
    fi
    PYTHON3=$(command -v python3)
fi

# Check tkinter
echo "      Checking tkinter…"
if ! "$PYTHON3" -c "import tkinter" 2>/dev/null; then
    echo "      tkinter missing — installing…"
    if   command -v apt-get &>/dev/null; then sudo apt-get install -y python3-tk
    elif command -v dnf     &>/dev/null; then sudo dnf install -y python3-tkinter
    elif command -v pacman  &>/dev/null; then sudo pacman -S --noconfirm tk
    else
        echo "  [WARN] Could not auto-install tkinter. Install python3-tk manually."
    fi
fi
echo "      Python + tkinter: OK"

# ── Step 2: Configure sudo for dmidecode (hardware serial number) ─────────────
echo ""
if [ "$WITH_DMIDECODE_SUDO" -eq 1 ]; then
    echo "[2/6] Configuring sudo for dmidecode (--with-dmidecode-sudo passed)…"
    SUDOERS_LINE="$USER ALL=(ALL) NOPASSWD: /usr/sbin/dmidecode"
    SUDOERS_FILE="/etc/sudoers.d/assetly-inventory"
    if sudo sh -c "echo '$SUDOERS_LINE' > '$SUDOERS_FILE' && chmod 0440 '$SUDOERS_FILE'" 2>/dev/null; then
        echo "      Sudoers rule created: $SUDOERS_FILE"
    else
        echo "      [WARN] Could not create sudoers rule. Serial Number may show as N/A."
        echo "             To fix: sudo sh -c \"echo '$SUDOERS_LINE' > $SUDOERS_FILE && chmod 0440 $SUDOERS_FILE\""
    fi
else
    echo "[2/6] Skipping dmidecode sudo setup (not requested)."
    echo "      The agent reads the hardware serial number from"
    echo "      /sys/class/dmi/id/product_serial first, which needs no elevated"
    echo "      privilege on most modern distributions. If this machine reports"
    echo "      the serial number as N/A, re-run with --with-dmidecode-sudo."
fi

# ── Step 3: Download the agent ────────────────────────────────────────────────
echo ""
echo "[3/6] Downloading inventory agent from GitHub…"
echo "      URL: $GITHUB_RAW_URL"
mkdir -p "$AGENT_DIR"

DOWNLOAD_OK=false
if command -v curl &>/dev/null; then
    if curl -fL --retry 3 --retry-delay 2 --connect-timeout 15 \
            "$GITHUB_RAW_URL" -o "$AGENT_FILE" 2>&1; then
        DOWNLOAD_OK=true
    fi
fi

if [[ "$DOWNLOAD_OK" == false ]] && command -v wget &>/dev/null; then
    echo "      curl failed — trying wget…"
    if wget --tries=3 --timeout=15 "$GITHUB_RAW_URL" -O "$AGENT_FILE" 2>&1; then
        DOWNLOAD_OK=true
    fi
fi

if [[ "$DOWNLOAD_OK" == false ]]; then
    echo "      curl/wget failed — trying Python urllib…"
    "$PYTHON3" -c "
import urllib.request, sys
try:
    urllib.request.urlretrieve('$GITHUB_RAW_URL', '$AGENT_FILE')
    print('      Downloaded via Python urllib.')
except Exception as e:
    print(f'      urllib failed: {e}', file=sys.stderr)
    sys.exit(1)
" && DOWNLOAD_OK=true
fi

if [[ "$DOWNLOAD_OK" == false ]]; then
    echo ""
    echo "  [ERROR] Could not download inventory_agent.py."
    echo "  Possible causes:"
    echo "    • GitHub repo is private — make it public or check the URL"
    echo "    • File not yet pushed to the repo"
    echo "    • No internet connection"
    echo "  URL tried: $GITHUB_RAW_URL"
    exit 1
fi

if [[ ! -s "$AGENT_FILE" ]]; then
    echo "  [ERROR] Downloaded file is empty."
    exit 1
fi
if head -1 "$AGENT_FILE" | grep -qi "<!DOCTYPE\|<html"; then
    echo "  [ERROR] GitHub returned an HTML page — repo/file may not exist yet."
    echo "  URL: $GITHUB_RAW_URL"
    rm -f "$AGENT_FILE"
    exit 1
fi

chmod +x "$AGENT_FILE"
echo "      ✔  Agent saved to: $AGENT_FILE"

# ── Step 4: Write config ──────────────────────────────────────────────────────
echo ""
echo "[4/6] Writing configuration…"
# Enroll now, while we still hold the company-wide enrollment token, and
# discard it on success. What lands in config.json is then a per-device
# credential -- individually revocable and bound to this machine's serial --
# instead of a 90-day, unlimited-use, company-wide secret sitting in a plain
# file on disk. If there's no network right now (offline imaging is normal),
# fall back to the token so the agent can enroll itself on first run.
ENROLL_API_URL="${CHECKIN_API_URL%/inventory/checkin}/enroll"
SERIAL="$(sudo dmidecode -s system-serial-number 2>/dev/null || true)"
CREDENTIAL="$(curl -fsS --max-time 20 -X POST "$ENROLL_API_URL" \
  -H "Authorization: Bearer $ENROLLMENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"serial_number\":\"$SERIAL\",\"hostname\":\"$(hostname)\"}" \
  2>/dev/null | "$PYTHON3" -c 'import json,sys
try:
    print(json.load(sys.stdin)["credential"])
except Exception:
    pass' 2>/dev/null)"

if [[ -n "$CREDENTIAL" ]]; then
    # github_raw_url is deliberately not written here. GITHUB_RAW_URL above is
    # still used to FETCH the agent during this install -- that download needs a
    # URL -- but inventory_agent.py never reads the config key, so persisting it
    # only made config.json look like it had a knob it does not have. Same
    # removal AssetlyAgent_Windows.ps1 and the macOS postinstall have made.
    cat > "$CONFIG_FILE" <<JSON
{
  "checkin_api_url": "$CHECKIN_API_URL",
  "device_credential": "$CREDENTIAL"
}
JSON
    echo "      Enrolled now; enrollment token discarded."
else
    cat > "$CONFIG_FILE" <<JSON
{
  "checkin_api_url": "$CHECKIN_API_URL",
  "enrollment_token": "$ENROLLMENT_TOKEN"
}
JSON
    echo "      Could not enroll now; the agent will enroll itself on first run."
fi
chmod 600 "$CONFIG_FILE"
echo "      Config: $CONFIG_FILE"

# ── Step 5: First manual run ──────────────────────────────────────────────────
echo ""
echo "[5/6] Running agent for the first time…"
DISPLAY="${DISPLAY:-:0}" "$PYTHON3" "$AGENT_FILE" || true

# ── Step 6: Install systemd user service + timer ─────────────────────────────
echo ""
echo "[6/6] Installing systemd user service and timer…"
mkdir -p "$UNIT_DIR"

cat > "$UNIT_DIR/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=Assetly Inventory Agent
After=graphical-session.target network-online.target
Wants=graphical-session.target

[Service]
Type=oneshot
# 90-second delay so the desktop session is fully ready
ExecStartPre=-/usr/bin/env sleep 90
ExecStart=${PYTHON3} ${AGENT_FILE}
WorkingDirectory=${AGENT_DIR}
Environment=DISPLAY=:0
Environment=DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/%U/bus
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=graphical-session.target
EOF

# Timer: fires at login + re-checks hourly. The agent exits immediately unless
# the company's configured interval has elapsed, so this is the wake cadence,
# not the prompt cadence. Hourly (not daily) because an admin can set an
# interval as short as 12 h in the portal, and a daily timer would silently
# stretch that to 24 h. Matches macOS StartInterval and the Windows task.
cat > "$UNIT_DIR/${SERVICE_NAME}.timer" <<EOF
[Unit]
Description=Assetly Inventory Agent – check-in timer

[Timer]
OnBootSec=2min
OnUnitActiveSec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF

# Enable lingering so user units survive logout (needed if the user has no active session)
loginctl enable-linger "$USER" 2>/dev/null || true

systemctl --user daemon-reload
systemctl --user enable --now "${SERVICE_NAME}.timer"
systemctl --user enable "${SERVICE_NAME}.service"

# ── GPG signing (optional, requires gpg) ─────────────────────────────────────
if command -v gpg &>/dev/null; then
    echo ""
    echo "      GPG found — signing agent script…"
    gpg --batch --yes --armor --detach-sign "$AGENT_FILE" 2>/dev/null && \
        echo "      Signature: ${AGENT_FILE}.asc" || \
        echo "      [WARN] GPG signing failed (no default key?). Agent will still run."
fi

echo ""
echo "✔  Installation complete."
echo ""
echo "   The agent runs at every login via systemd timer."
echo "   It shows the form only when the interval configured in the portal has passed."
echo ""
echo "   Useful commands:"
echo "   systemctl --user status  ${SERVICE_NAME}.timer    # check timer status"
echo "   systemctl --user start   ${SERVICE_NAME}.service  # trigger manually"
echo "   journalctl --user -u     ${SERVICE_NAME}.service  # view logs"
echo "   tail -f ${AGENT_DIR}/agent.log                     # live log"
echo ""
echo "   To uninstall:"
echo "   systemctl --user disable --now ${SERVICE_NAME}.timer ${SERVICE_NAME}.service"
echo "   rm ~/.config/systemd/user/${SERVICE_NAME}.*"
echo "   sudo rm /etc/sudoers.d/assetly-inventory  # only present if --with-dmidecode-sudo was used"
echo ""
