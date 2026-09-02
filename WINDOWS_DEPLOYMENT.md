# Deploying the Windows agent to end-user PCs

Two distribution shapes, both built from the same source and the same
`$AgentVersion`:

| | `AssetlyAgent_Windows.exe` | `AssetlyAgent.msi` |
|---|---|---|
| Who installs it | one user, on their own PC | IT, across a fleet |
| How | download from the portal, double-click | `msiexec /qn`, Intune, SCCM, GPO, PDQ |
| Installs to | `%LOCALAPPDATA%\AssetlyInventory` | `C:\Program Files\Assetly` |
| Scheduled task | per user, registered on first run | machine-wide, registered by the MSI |
| Covers other users of the PC | no | yes |
| Configured by | config block appended by the portal | msiexec properties → `HKLM\SOFTWARE\Assetly\Agent` |
| Updates | signed self-update, automatic | redeploy a newer MSI |
| Uninstall | manual | Add/Remove Programs, or `msiexec /x` |
| Authenticode signature intact on the installed file | **no** — see "Signing" | yes |

The `.exe` is unchanged and remains the default for a single user. The MSI is
additional.

## Deploying the MSI

```
msiexec /i AssetlyAgent.msi /qn ^
        CHECKINAPIURL="https://<portal>/api/v1/inventory/checkin" ^
        ENROLLMENTTOKEN="<company enrollment token>"
```

`PROXYURL` is an optional third property, needed only where the agent should
not use the machine's system proxy setting.

Both values land in `HKLM\SOFTWARE\Assetly\Agent`, which means they can also be
set or corrected by Group Policy preferences on machines that are already
installed, without a redeploy.

Uninstall: `msiexec /x AssetlyAgent.msi /qn`, or Add/Remove Programs. This
removes the binary and the scheduled task. It deliberately leaves
`%LOCALAPPDATA%\AssetlyInventory` in each user's profile, because an MSI
running as SYSTEM cannot reliably enumerate other users' profiles — delete it
by script if a full wipe is required. That directory holds the device
credential, the offline queue, and the log.

The MSI is published to `/static/updates/AssetlyAgent.msi`, alongside the
signed executable and the release manifest.

### What the MSI does not do

It does not deploy the agent to a machine with no logged-on user. The agent
shows a WinForms dialog to a person; its task is registered against
`BUILTIN\Users` with an interactive logon type, so it runs in a real user's
session and stays silent until the configured check-in interval has elapsed.

## Configuration precedence

The agent reads, in order, and stops at the first usable source:

1. `%LOCALAPPDATA%\AssetlyInventory\config.json` — written by the agent after
   enrollment. The only source that holds a device credential, so it must win.
2. `HKLM\SOFTWARE\Assetly\Agent` — the MSI, or Group Policy.
3. The config block appended to the `.exe` by the portal's download button.
4. `config.json` beside the executable — how pre-single-file deployments were
   configured.

## Proxies

The agent uses the system proxy with the logged-on user's credentials. If Edge
can reach the portal, so can the agent. Where the system setting is wrong,
set `PROXYURL` (MSI/GPO) or `proxy_url` in `config.json`.

A 407 from the proxy is logged with an explicit hint rather than as a generic
failure — before this, an agent behind an authenticating proxy failed silently
and looked identical, from the portal, to a machine that was switched off.

## Signing

Code signing is **not** performed in CI, and must not be. The key follows the
same custody rule as the release-signing key: CI that can sign is CI whose
compromise mints artifacts the whole fleet trusts. `release-consistency.yml`
depends on CI's build being unsigned.

Signing happens offline, in `backend/scripts/sign_release.py`, when
`WINDOWS_CODESIGN_CERT_PATH` and `WINDOWS_CODESIGN_PASSWORD` are set. That
script signs the executable, builds the MSI **around the signed executable**,
and signs the MSI too.

```
export WINDOWS_CODESIGN_CERT_PATH=~/.assetly/codesign.pfx
export WINDOWS_CODESIGN_PASSWORD=...
backend/venv/bin/python backend/scripts/sign_release.py \
    --version 2.1.0 --key ~/.assetly/release_key.pem
```

Needs `wix` on PATH (`dotnet tool install --global wix --version 5.*`; WiX v4+
is cross-platform, so this works on macOS). Pass `--no-msi` to publish a
release without an installer.

### The .exe cannot carry a valid signature to an end user

Authenticode covers data appended past the end of the PE image, and the
portal's download button appends a per-company config block to the executable.
That append invalidates the signature. The signed `.exe` is what the
self-update path fetches and what the MSI packages; the *downloaded* `.exe`
is signed-then-modified and will not verify.

Making the direct download verify too means serving the signed executable
unmodified with a `config.json` beside it — a layout the agent already reads
(source 4 above) — instead of appending. That is a backend change and has not
been made. Until then, **the MSI is the only path that puts a validly signed
binary on an end user's machine**, which is what AppLocker/WDAC publisher
rules and clean SmartScreen behaviour depend on.

### Getting a certificate

Since June 2023 the CA/Browser Forum baseline requires code-signing private
keys to be held on hardware or in a qualified cloud signing service, so a
plain `.pfx` is no longer issuable for a new public-trust certificate. The
practical options are a hardware token (works with `signtool`, and with
`osslsigncode` via PKCS#11) or a cloud service such as Azure Trusted Signing.

OV certificates build SmartScreen reputation over time; EV certificates clear
SmartScreen immediately. Timestamping is not optional in either case —
without it every signature expires with the certificate, including on machines
that installed the agent years earlier.

## Still open

- Nothing here has been executed on a Windows machine. There is no pwsh in the
  development environment and no test runs the `.ps1`, so every change to the
  agent and to the installer is eye-reviewed only. A VM pass is the next step:
  install → enroll → form → check-in → reboot → task fires → uninstall.
- The portal has no "Download MSI" button. The file is reachable at
  `/static/updates/AssetlyAgent.msi` once a release is signed; a button is a
  UI change that has not been made.
- Execution from `%LOCALAPPDATA%` still applies to the `.exe` path. Only the
  MSI puts the binary somewhere AppLocker's default rules permit.
