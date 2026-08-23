#Requires -Version 5.1
<#
.SYNOPSIS
    Assetly Inventory Agent for Windows — self-contained, no Python needed.
    First run: Right-click → Run with PowerShell  (or run as any user).
    After that: registered in Task Scheduler, runs silently at every login,
                shows the form only when the company's configured interval has elapsed.
#>

# ════════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION — checkin_api_url/enrollment_token (or company_api_key, or an
#  already-issued device_credential) load from config.json placed next to this
#  script/exe (written by the admin portal's download button).
#
#  Which *fields* the form asks for is NOT configured here: it is fetched per
#  company from GET /api/v1/inventory/config on every run (see Get-FieldConfig),
#  exactly as inventory_agent.py does on macOS/Linux. An admin toggling a field
#  in the portal therefore reaches this agent on its next run, with no rebuild
#  and no redeploy. The hardcoded values below are only fallbacks for when that
#  endpoint cannot be reached.
# ════════════════════════════════════════════════════════════════════════════════
# github_raw_url / github_exe_url are deliberately gone, not just unread: this
# agent used to trust whatever bytes came back from a hardcoded GitHub URL, so
# any local user or process able to rewrite this file's config, or anyone who
# controlled that network path, had persistent code execution on every machine
# that ran it. The update host is now derived from $CheckinApiUrl (below), and
# a compiled-in public key -- not a URL -- is what actually authorises an
# update. See $UpdateSigningPublicKey and Invoke-SelfUpdateExe.

# Windows PowerShell 5.1 still negotiates TLS 1.0 by default on older builds,
# and the backend API refuses that outright. Without this the manifest fetch
# below fails on exactly the machines most in need of an update.
try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {}

# Used only when the server cannot be reached and nothing is cached in
# state.json. Reproduces the cadence this agent had when the interval was
# hardcoded. Kept in sync with DEFAULT_SCHEDULE in inventory_agent.py.
$DefaultSchedule = [PSCustomObject]@{
    checkin_interval_seconds = 15552000   # 180 days
    cancel_retry_seconds     = 86400      # 24 hours
}
$TaskName         = "AssetlyInventoryAgent"
$AgentVersion     = "2.0"
# Fallback only — the live per-company list arrives on the department entry of
# the field config. Kept in sync with DEFAULT_DEPARTMENT_OPTIONS in
# backend/app/field_config.py and inventory_agent.py.
$DefaultDepartments = @("Webiz ERP","Fundbox","Playtika","Artlist","The5%ers","Other")

# ─── Update signing ───────────────────────────────────────────────────────────
# The release signing PUBLIC key, base64 DER (SubjectPublicKeyInfo). Compiled
# in on purpose: the agent trusts this key rather than trusting a URL. Empty
# disables updating entirely -- it never falls back to an unverified path.
# Must be byte-identical to UPDATE_SIGNING_PUBLIC_KEY in inventory_agent.py
# and in the backend environment.
$UpdateSigningPublicKey = ""

$StateDir   = "$env:LOCALAPPDATA\AssetlyInventory"
$StateFile  = "$StateDir\state.json"
$QueueFile  = "$StateDir\queue.json"
$LogFile    = "$StateDir\agent.log"
# Resolve current script/exe path
# - PS1 mode : $MyInvocation.MyCommand.Path holds the .ps1 path
# - EXE mode : $PSCommandPath is null in ps2exe, use Process.MainModule.FileName instead
$ScriptPath = if ($MyInvocation.MyCommand.Path) { $MyInvocation.MyCommand.Path } `
              else { [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName }
# Detect whether we are running as a compiled EXE (ps2exe) or a plain PS1
$IsExe      = $ScriptPath -like "*.exe" -and $ScriptPath -notlike "*powershell*" -and $ScriptPath -notlike "*pwsh*"
$ScriptDest = if ($IsExe) { "$StateDir\AssetlyAgent_Windows.exe" } `
                          else { "$StateDir\AssetlyAgent_Windows.ps1" }

# ── Ensure state dir ─────────────────────────────────────────────────────────
if (-not (Test-Path $StateDir)) { New-Item -ItemType Directory -Path $StateDir -Force | Out-Null }

# ── Logging ──────────────────────────────────────────────────────────────────
function Write-Log {
    param([string]$Msg, [string]$Level = "INFO")
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  $Level  $Msg"
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
    # Write-Host intentionally omitted — ps2exe -NoConsole turns every Write-Host into a popup dialog
}

# ── Read the config block the admin portal appended to this executable ───────
# Downloads are a single .exe with its config baked onto the end of the PE
# image, so there is no second file to lose track of. Windows ignores bytes past
# the length the PE headers declare, so the executable still runs normally.
function Get-EmbeddedConfig {
    if (-not $IsExe) { return $null }
    try {
        $bytes = [System.IO.File]::ReadAllBytes($ScriptPath)
        # The block is at the very end; only the tail is decoded so that
        # arbitrary binary earlier in the image can never look like a marker.
        $tailLength = [Math]::Min(8192, $bytes.Length)
        $tail = [System.Text.Encoding]::UTF8.GetString($bytes, $bytes.Length - $tailLength, $tailLength)

        # Split so that the compiled .exe never contains the marker as one
        # contiguous string. ps2exe embeds this script as plain text, so a
        # whole literal here would put a decoy copy of the marker ~15 KB into
        # the binary -- which the portal's embedder mistook for an
        # already-present config block and truncated the executable at.
        $begin = 'ASSETLY-CONFIG' + '-BEGIN:'
        $end   = ':ASSETLY-CONFIG' + '-END'
        # Not $matches: that is a PowerShell automatic variable.
        $found = [regex]::Matches($tail, [regex]::Escape($begin) + '(.*?)' + [regex]::Escape($end), 'Singleline')
        if ($found.Count -eq 0) { return $null }
        # Last match wins: the live config is whatever sits closest to the end.
        return $found[$found.Count - 1].Groups[1].Value | ConvertFrom-Json
    } catch {
        Write-Log "Failed to read the embedded config block from $ScriptPath : $_" "WARN"
        return $null
    }
}

# ── Resolve the running config ───────────────────────────────────────────────
# Three sources, in decreasing order of how specific they are to this machine:
#   1. %LOCALAPPDATA%\AssetlyInventory\config.json — written by this agent once
#      it has enrolled, so it is the only one holding a device credential.
#   2. the block embedded in the .exe — what a fresh download carries.
#   3. config.json next to the script/exe — how agents deployed before
#      single-file downloads were configured, and still how the plain .ps1 is.
# Returns the parsed config object too (not just checkin_api_url) so
# Resolve-Credential below can read device_credential / enrollment_token /
# company_api_key. The write-back path is always the state directory: the
# embedded block cannot be rewritten in place, and the directory the exe was
# run from is often read-only (a network share, a USB stick, Downloads under a
# managed policy).
function Get-CheckinConfig {
    $ownDir = Split-Path -Path $ScriptPath -Parent
    $sideCarFile = "$ownDir\config.json"
    $stateConfigFile = "$StateDir\config.json"
    $result = @{ CheckinApiUrl = "https://api.example.com/api/v1/inventory/checkin"; Cfg = $null; ConfigFile = $stateConfigFile }

    $cfg = $null
    $source = $null
    if (Test-Path $stateConfigFile) {
        try {
            $cfg = Get-Content $stateConfigFile -Raw | ConvertFrom-Json
            $source = $stateConfigFile
        } catch {
            Write-Log "Failed to parse $stateConfigFile — falling back to the installer's config: $_" "WARN"
        }
    }
    if (-not $cfg) {
        $cfg = Get-EmbeddedConfig
        if ($cfg) { $source = "the config embedded in $ScriptPath" }
    }
    if (-not $cfg -and (Test-Path $sideCarFile)) {
        try {
            $cfg = Get-Content $sideCarFile -Raw | ConvertFrom-Json
            $source = $sideCarFile
        } catch {
            Write-Log "Failed to parse config.json at $sideCarFile — using placeholder values: $_" "WARN"
        }
    }

    if (-not $cfg) {
        Write-Log "No configuration found (no $stateConfigFile, no embedded config block, no $sideCarFile) — using placeholder checkin URL, all submissions will fail auth." "WARN"
        return $result
    }

    $result.Cfg = $cfg
    if ($cfg.checkin_api_url) {
        $result.CheckinApiUrl = $cfg.checkin_api_url
    } else {
        Write-Log "Configuration from $source is missing checkin_api_url — running with a placeholder value." "WARN"
    }
    return $result
}
$CheckinConfig  = Get-CheckinConfig
$CheckinApiUrl  = $CheckinConfig.CheckinApiUrl
$ConfigFilePath = $CheckinConfig.ConfigFile
$Cfg            = $CheckinConfig.Cfg
$EnrollApiUrl   = $CheckinApiUrl -replace '/inventory/checkin$', '/enroll'
$ConfigApiUrl   = $CheckinApiUrl -replace '/checkin$', '/config'

# ════════════════════════════════════════════════════════════════════════════════
#  CREDENTIAL RESOLUTION / ENROLLMENT
#  Mirrors inventory_agent.py's resolve_credential()/enroll(): an already-
#  enrolled machine must never fall back to a shared secret, and a
#  self-migrating one must drop the company key once it has its own credential.
# ════════════════════════════════════════════════════════════════════════════════
function Save-Config($cfgObj, $path) {
    $cfgObj | ConvertTo-Json | Set-Content -Path $path -Encoding UTF8
}

function Invoke-Enroll($bearer) {
    $hw   = Get-Hardware
    $body = @{ serial_number = $hw.serial_number; hostname = $hw.hostname } | ConvertTo-Json -Compress
    try {
        $resp = Invoke-RestMethod -Uri $EnrollApiUrl -Method POST -Body $body `
                    -ContentType "application/json" `
                    -Headers @{ Authorization = "Bearer $bearer" } -TimeoutSec 15
    } catch {
        $detail = $_.Exception.Message
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            try {
                $errBody = $_.ErrorDetails.Message | ConvertFrom-Json
                if ($errBody.detail) { $detail = $errBody.detail }
            } catch {}
        }
        Write-Log "Enrollment failed: $detail" "ERROR"
        exit 1
    }
    if (-not $resp.credential) {
        Write-Log "Enrollment response missing 'credential': $($resp | ConvertTo-Json -Compress)" "ERROR"
        exit 1
    }
    return $resp.credential
}

function Resolve-Credential($cfgObj, $path) {
    if ($cfgObj -and $cfgObj.device_credential) {
        return $cfgObj.device_credential
    }

    $bearer = $null
    if ($cfgObj) {
        if ($cfgObj.enrollment_token) { $bearer = $cfgObj.enrollment_token }
        elseif ($cfgObj.company_api_key) { $bearer = $cfgObj.company_api_key }
    }
    if (-not $bearer) {
        Write-Log "No device credential, enrollment token, or company key in config.json — cannot authenticate." "ERROR"
        exit 1
    }

    Write-Log "No device credential on file — enrolling…"
    $credential = Invoke-Enroll $bearer
    $cfgObj | Add-Member -NotePropertyName device_credential -NotePropertyValue $credential -Force
    foreach ($key in @('enrollment_token', 'company_api_key')) {
        if ($cfgObj.PSObject.Properties.Match($key).Count -gt 0) {
            $cfgObj.PSObject.Properties.Remove($key)
        }
    }
    Save-Config $cfgObj $path
    Write-Log "Enrolled successfully — device credential saved to config.json."
    return $credential
}

# ════════════════════════════════════════════════════════════════════════════════
#  FIELD CONFIGURATION
#  Mirrors inventory_agent.py's fetch_config()/DEFAULT_FIELD_CONFIG. This
#  is what makes a portal change reach this agent: the form below is built from
#  whatever this returns, so enabling, disabling, adding or removing a field in
#  the portal takes effect on the next run without recompiling anything.
# ════════════════════════════════════════════════════════════════════════════════
$DefaultFieldConfig = [PSCustomObject]@{
    user_fields = @(
        [PSCustomObject]@{ key = 'first_name'; label = 'First Name'; required = $true;  locked = $true  }
        [PSCustomObject]@{ key = 'last_name';  label = 'Last Name';  required = $true;  locked = $true  }
        [PSCustomObject]@{ key = 'email';      label = 'Email';      required = $true;  locked = $true  }
        [PSCustomObject]@{ key = 'department'; label = 'Department'; required = $false; locked = $false
                           options = $DefaultDepartments }
    )
    hardware_fields = @('cpu','ram','storage','ip_address')
}

function Test-FieldConfig($Config) {
    <#  Guards against a malformed-but-200-OK response reaching the form, where
        a missing key would surface as a blank label or a dropdown with nothing
        in it rather than as an error anyone can act on. #>
    if ($null -eq $Config) { return $false }
    if ($null -eq $Config.user_fields -or $null -eq $Config.hardware_fields) { return $false }
    foreach ($f in @($Config.user_fields)) {
        if ($null -eq $f) { return $false }
        foreach ($prop in @('key','label','required','locked')) {
            if ($f.PSObject.Properties.Match($prop).Count -eq 0) { return $false }
        }
        if ($f.key -isnot [string] -or -not $f.key) { return $false }
        # Optional, and only ever sent for department.
        if ($f.PSObject.Properties.Match('options').Count -gt 0 -and $null -ne $f.options) {
            $options = @($f.options)
            if ($options.Count -eq 0) { return $false }
            foreach ($option in $options) { if ($option -isnot [string]) { return $false } }
        }
    }
    foreach ($key in @($Config.hardware_fields)) { if ($key -isnot [string]) { return $false } }
    return $true
}

function Get-FieldConfig {
    <# Falls back to the defaults on any failure (network/auth/parse/shape) so a
       config-fetch problem never blocks check-in entirely. #>
    try {
        $config = Invoke-RestMethod -Uri $ConfigApiUrl -Method GET `
                      -Headers @{ Authorization = "Bearer $DeviceCredential" } -TimeoutSec 10
        if (-not (Test-FieldConfig $config)) {
            throw "Malformed field config response: $($config | ConvertTo-Json -Compress -Depth 5)"
        }
        return $config
    } catch {
        Write-Log "Failed to fetch field config, using defaults: $_" "WARN"
        return $DefaultFieldConfig
    }
}

function Test-Schedule($Schedule) {
    <#  Guards against a malformed-but-200-OK schedule reaching the guard,
        where a string or a negative would make the comparison either throw or
        silently never fire. Mirrors _is_valid_schedule in inventory_agent.py. #>
    if ($null -eq $Schedule) { return $false }
    foreach ($prop in @('checkin_interval_seconds','cancel_retry_seconds')) {
        if ($Schedule.PSObject.Properties.Match($prop).Count -eq 0) { return $false }
        $value = $Schedule.$prop
        if ($value -isnot [int] -and $value -isnot [long]) { return $false }
        if ($value -le 0) { return $false }
    }
    return $Schedule.cancel_retry_seconds -le $Schedule.checkin_interval_seconds
}

function Resolve-ScheduleFrom($Config, $State) {
    <# Fresh server value, else last known good, else built-in default. The
       cache matters: a laptop offline for a week keeps its configured cadence
       instead of silently reverting to 6 months. #>
    if ($null -ne $Config -and $Config.PSObject.Properties.Match('schedule').Count -gt 0) {
        if (Test-Schedule $Config.schedule) { return $Config.schedule }
    }
    if ($null -ne $State -and $State.PSObject.Properties.Match('schedule').Count -gt 0) {
        if (Test-Schedule $State.schedule) {
            Write-Log "Using cached check-in schedule — server value missing or malformed." "WARN"
            return $State.schedule
        }
    }
    Write-Log "No usable check-in schedule — falling back to built-in defaults." "WARN"
    return $DefaultSchedule
}

function Format-Duration([long]$Seconds) {
    <#  Human-readable duration for the cancel dialog. The agents cannot import
        backend/app/schedule.py's format_interval, so this is a deliberate small
        duplicate -- it mirrors _humanize_seconds() in inventory_agent.py rule
        for rule (whole days when the value divides exactly into days, else
        hours rounded to at least 1). Keep the two in agreement if either
        changes. #>
    if ($Seconds -ge 86400 -and ($Seconds % 86400) -eq 0) {
        $count = [long]($Seconds / 86400)
        if ($count -eq 1) { return "$count day" }
        return "$count days"
    }
    $count = [long][Math]::Round($Seconds / 3600)
    if ($count -lt 1) { $count = 1 }
    if ($count -eq 1) { return "$count hour" }
    return "$count hours"
}

# ════════════════════════════════════════════════════════════════════════════════
#  AGENT WINDOW APPEARANCE
#  Copy and colours arrive on the `ui` key of the same GET /config response that
#  carries the fields and the schedule, so an admin editing them in the portal
#  reaches this agent on its next run with no rebuild and no re-download --
#  exactly as a field toggle does.
#
#  Contrast is NOT re-checked here. The server refuses to store an unreadable
#  combination (see _CONTRAST_PAIRS in backend/app/agent_ui.py), and it is the
#  only layer that can report the failure to the admin who caused it; repeating
#  the WCAG maths in each agent would mean three places to keep in agreement
#  and a silent fallback where the portal already showed a clear error.
#  Validation here is strictly "will this crash or render as garbage".
# ════════════════════════════════════════════════════════════════════════════════

# Fallback for when /config cannot be reached and nothing is cached. Kept in
# sync with DEFAULT_AGENT_UI in backend/app/agent_ui.py and inventory_agent.py.
$DefaultAgentUi = [PSCustomObject]@{
    window_title    = "Assetly Inventory Agent"
    heading         = "Who's using this computer?"
    subheading      = "{count} fields, then you're done."
    subheading_one  = "{count} field, then you're done."
    rail_title      = "THIS DEVICE"
    rail_footnote   = "Sent to your IT team along with the answers on the right."
    submit_label    = "Send check-in"
    cancel_label    = "Cancel"
    success_message = "Thank you, {first_name}!`n`nYour device has been registered."
    navy            = "#0B1120"
    navy_sidebar    = "#080E1A"
    navy_mid        = "#0F1829"
    blue            = "#1866F2"
    blue_hover      = "#1560E6"
    teal            = "#00C2A8"
    slate           = "#A4B3CC"
    label           = "#92A3BE"
    white           = "#F4F7FF"
    border_md       = "#5A6E99"
    border_input    = "#526691"
}

# Which keys are colours; everything else on $DefaultAgentUi is copy.
$AgentUiColorKeys = @('navy','navy_sidebar','navy_mid','blue','blue_hover','teal',
                      'slate','label','white','border_md','border_input')

function ConvertFrom-HexColor([string]$Hex) {
    <# Assumes Test-AgentUi has already matched the ^#RRGGBB shape. #>
    $raw = $Hex.TrimStart('#')
    return [System.Drawing.Color]::FromArgb(
        [Convert]::ToInt32($raw.Substring(0, 2), 16),
        [Convert]::ToInt32($raw.Substring(2, 2), 16),
        [Convert]::ToInt32($raw.Substring(4, 2), 16))
}

function Test-AgentUi($Ui) {
    <#  Guards against a malformed-but-200-OK response reaching the window,
        where a missing key would surface as a blank heading or an unlabelled
        button and a bad colour would throw mid-paint, leaving a half-drawn
        form the employee cannot use. Mirrors _is_valid_agent_ui in
        inventory_agent.py. #>
    if ($null -eq $Ui) { return $false }
    foreach ($prop in $DefaultAgentUi.PSObject.Properties.Name) {
        if ($Ui.PSObject.Properties.Match($prop).Count -eq 0) { return $false }
        $value = $Ui.$prop
        if ($value -isnot [string] -or $value.Length -eq 0) { return $false }
        if ($AgentUiColorKeys -contains $prop) {
            if ($value -notmatch '^#[0-9A-Fa-f]{6}$') { return $false }
        }
    }
    # Only the two placeholders the substitutions below actually replace. Any
    # other braced token would reach the employee as a literal "{whatever}",
    # which looks like a bug in the agent rather than a typo in the portal.
    foreach ($pair in @(@('subheading','count'), @('subheading_one','count'),
                        @('success_message','first_name'))) {
        $text = $Ui.($pair[0]) -replace [regex]::Escape('{' + $pair[1] + '}'), ''
        if ($text -match '[{}]') { return $false }
    }
    foreach ($prop in @('window_title','heading','rail_title','rail_footnote',
                        'submit_label','cancel_label')) {
        if ($Ui.$prop -match '[{}]') { return $false }
    }
    return $true
}

function Resolve-AgentUiFrom($Config, $State) {
    <# Fresh server value, else last known good, else built-in. The cache is
       what keeps a laptop that is offline for a week looking like its
       company's agent instead of reverting to stock styling mid-rollout --
       the same reason Resolve-ScheduleFrom caches. #>
    if ($null -ne $Config -and $Config.PSObject.Properties.Match('ui').Count -gt 0) {
        if (Test-AgentUi $Config.ui) { return $Config.ui }
        if ($null -ne $Config.ui) {
            Write-Log "Server sent an unusable window appearance — ignoring it." "WARN"
        }
    }
    if ($null -ne $State -and $State.PSObject.Properties.Match('ui').Count -gt 0) {
        if (Test-AgentUi $State.ui) {
            Write-Log "Using cached window appearance — server value missing or malformed." "WARN"
            return $State.ui
        }
    }
    return $DefaultAgentUi
}

function Expand-UiText([string]$Text, [hashtable]$Values) {
    <#  Literal replace, not -f: the copy is admin-authored, and -f would treat
        every brace in it as a format specifier and throw on the first stray
        one. Test-AgentUi has already rejected unknown placeholders. #>
    foreach ($key in $Values.Keys) {
        $Text = $Text.Replace('{' + $key + '}', [string]$Values[$key])
    }
    return $Text
}

# ════════════════════════════════════════════════════════════════════════════════
#  SELF-UPDATE
# ════════════════════════════════════════════════════════════════════════════════
function Get-Sha256([byte[]]$Bytes) {
    # Lowercase hex, no separators -- matches Python's hashlib .hexdigest(),
    # which is the form the signed manifest's artifact hashes are written in.
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash($Bytes)
        return -join ($hash | ForEach-Object { $_.ToString("x2") })
    } finally { $sha.Dispose() }
}

function Read-DerTlv([byte[]]$Data, [int]$Offset) {
    <#  Minimal DER tag-length-value reader. Returns @{ Tag; Value (byte[]);
        NextOffset }. Mirrors read_tlv() in backend/app/update_manifest.py and
        inventory_agent.py's _parse_public_key_der -- the three must stay
        algorithmically identical or agents silently stop trusting valid
        manifests (or worse, start trusting the wrong bytes). #>
    $tag = $Data[$Offset]
    $length = $Data[$Offset + 1]
    $Offset += 2
    if ($length -band 0x80) {
        $n = $length -band 0x7F
        $length = 0
        for ($i = 0; $i -lt $n; $i++) { $length = ($length -shl 8) -bor $Data[$Offset + $i] }
        $Offset += $n
    }
    $value = New-Object byte[] $length
    [Array]::Copy($Data, $Offset, $value, 0, $length)
    return @{ Tag = $tag; Value = $value; NextOffset = $Offset + $length }
}

function ConvertFrom-DerUnsignedInteger([byte[]]$Der) {
    <#  DER encodes INTEGER as a signed big-endian two's-complement value, so a
        positive number whose high bit is set gets a leading 0x00 byte purely
        to keep it from reading as negative. .NET's RSAParameters.Modulus /
        .Exponent instead want the raw big-endian MAGNITUDE with no such
        padding -- passing the DER bytes through unmodified silently produces
        a key one byte too long, which makes every signature verification
        fail with no useful error. Strip exactly one leading 0x00 when it is
        purely this DER sign-padding (length > 1 and first byte is 0x00);
        never strip a genuine 0x00 that is the only byte, and never strip
        more than one, since a real key only ever needs the one padding byte. #>
    if ($Der.Length -gt 1 -and $Der[0] -eq 0x00) {
        $trimmed = New-Object byte[] ($Der.Length - 1)
        [Array]::Copy($Der, 1, $trimmed, 0, $trimmed.Length)
        return $trimmed
    }
    return $Der
}

function Test-ManifestSignature {
    <#  RSA PKCS#1 v1.5 over SHA-256, via .NET. Targets Windows PowerShell 5.1:
        RSA.ImportSubjectPublicKeyInfo() is .NET Core 3.0+/.NET 5+ only and
        does not exist on the .NET Framework CLR that ships PowerShell 5.1, so
        the SubjectPublicKeyInfo DER is walked by hand into an RSAParameters
        struct instead (this path also works unchanged on PowerShell 7+, so
        there is no separate branch to maintain for it).
        Returns $true only on a verified signature; every failure path,
        including a malformed key or signature, returns $false. #>
    param([byte[]]$ManifestBytes, [string]$SignatureB64, [string]$PublicKeyDerB64)

    if (-not $PublicKeyDerB64) { return $false }
    try {
        $der = [Convert]::FromBase64String($PublicKeyDerB64)
        $sig = [Convert]::FromBase64String($SignatureB64)

        # SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey BIT STRING }
        $spki = Read-DerTlv $der 0
        $alg  = Read-DerTlv $spki.Value 0
        $bitstring = Read-DerTlv $spki.Value $alg.NextOffset
        # BIT STRING's first content octet is the count of unused trailing bits.
        $rsaDer = New-Object byte[] ($bitstring.Value.Length - 1)
        [Array]::Copy($bitstring.Value, 1, $rsaDer, 0, $rsaDer.Length)

        # RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
        $rsaSeq   = Read-DerTlv $rsaDer 0
        $modulusT = Read-DerTlv $rsaSeq.Value 0
        $exponentT = Read-DerTlv $rsaSeq.Value $modulusT.NextOffset

        $params = New-Object System.Security.Cryptography.RSAParameters
        $params.Modulus  = ConvertFrom-DerUnsignedInteger $modulusT.Value
        $params.Exponent = ConvertFrom-DerUnsignedInteger $exponentT.Value

        $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
        try {
            $rsa.ImportParameters($params)
            return $rsa.VerifyData(
                $ManifestBytes, $sig,
                [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        } finally { $rsa.Dispose() }
    } catch {
        Write-Log "Signature verification error: $_" "WARN"
        return $false
    }
}

function Find-LastByteSequence([byte[]]$Haystack, [byte[]]$Needle, [int]$SearchFrom) {
    for ($i = $Haystack.Length - $Needle.Length; $i -ge $SearchFrom; $i--) {
        $match = $true
        for ($j = 0; $j -lt $Needle.Length; $j++) {
            if ($Haystack[$i + $j] -ne $Needle[$j]) { $match = $false; break }
        }
        if ($match) { return $i }
    }
    return -1
}

function Split-EmbeddedConfig([byte[]]$Bytes) {
    <#  Separates a configured .exe into the build the CI produced and the
        config block the portal appended, so the two can be compared and
        recombined independently.

        Without this, self-update could never work: the installed exe always
        carries a trailing config block that the published build does not, so
        their hashes differ permanently and every single run would "find an
        update". The search is anchored to the tail for the same reason
        embed_windows_config in backend/app/routers/admin.py anchors its own --
        ps2exe stores this script as plain text, so a copy of the marker sits
        ~15 KB into the image and matching that one would cut the binary in
        half. #>
    $begin = [System.Text.Encoding]::UTF8.GetBytes('ASSETLY-CONFIG' + '-BEGIN:')
    $end   = [System.Text.Encoding]::UTF8.GetBytes(':ASSETLY-CONFIG' + '-END')
    $empty = New-Object byte[] 0
    $parts = @{ Base = $Bytes; Block = $empty }

    if ($Bytes.Length -lt $end.Length) { return $parts }
    for ($j = 0; $j -lt $end.Length; $j++) {
        if ($Bytes[$Bytes.Length - $end.Length + $j] -ne $end[$j]) { return $parts }
    }
    $searchFrom = [Math]::Max(0, $Bytes.Length - 8192)
    $at = Find-LastByteSequence $Bytes $begin $searchFrom
    if ($at -lt 0) { return $parts }

    $base  = New-Object byte[] $at
    $block = New-Object byte[] ($Bytes.Length - $at)
    [Array]::Copy($Bytes, 0, $base,  0, $at)
    [Array]::Copy($Bytes, $at, $block, 0, $block.Length)
    return @{ Base = $base; Block = $block }
}

function Invoke-SelfUpdateExe {
    <#  Fetches, verifies, and applies a signed update.

        Previously this downloaded a GitHub raw .exe and installed it after a
        size-and-MZ-header sanity check. That check defends against a captive
        portal's login page; it does not defend against an attacker-supplied
        valid PE. Nothing is written now until a signature made with the
        offline release key verifies over the manifest, and the downloaded
        bytes re-hash to the value that signature covers. #>
    if (-not $UpdateSigningPublicKey) { return }
    if (-not $CheckinApiUrl) { return }

    $tmp = [System.IO.Path]::GetTempFileName() + ".exe"
    # PowerShell runs `finally` on the way out of `exit`, so the cleanup below
    # would delete the staged executable out from under the cmd.exe that was
    # just scheduled to move it into place -- leaving the old agent running and
    # re-attempting the same update on every login, forever. Ownership of the
    # temp file transfers to cmd.exe on that path, and only on that path.
    $handedOff = $false
    try {
        Write-Log "Checking for updates…"
        $base = $CheckinApiUrl -split '/api/v1/' | Select-Object -First 1
        $envelope = Invoke-RestMethod -Uri "$base/api/v1/agent/manifest" `
            -Headers @{ Authorization = "Bearer $DeviceCredential" } -TimeoutSec 15

        $manifestBytes = [System.Text.Encoding]::UTF8.GetBytes($envelope.manifest)
        if (-not (Test-ManifestSignature $manifestBytes $envelope.signature $UpdateSigningPublicKey)) {
            Write-Log "Update REJECTED: manifest signature did not verify." "ERROR"
            return
        }

        $artifact = ($envelope.manifest | ConvertFrom-Json).artifacts.windows_exe

        # The signed hash covers the BASE image only -- an installed agent
        # carries its own trailing config block, so hashing the whole file
        # would make every machine compute a different hash for one release
        # and update forever.
        $current = Split-EmbeddedConfig ([System.IO.File]::ReadAllBytes($ScriptPath))
        if ((Get-Sha256 $current.Base) -eq $artifact.sha256) {
            Write-Log "Already up to date."
            return
        }

        Invoke-WebRequest -Uri "$base$($artifact.path)" -OutFile $tmp -UseBasicParsing -TimeoutSec 120
        $newBytes = [System.IO.File]::ReadAllBytes($tmp)

        # Cheap early-out, kept from the previous implementation: a captive
        # portal's login page is a perfectly successful HTTP response.
        if ($newBytes.Length -lt 10240 -or $newBytes[0] -ne 0x4D -or $newBytes[1] -ne 0x5A) {
            Write-Log "Update rejected: downloaded $($newBytes.Length) bytes that are not a PE image." "WARN"
            return
        }
        # The control that actually matters: the bytes must match what the
        # release key signed for.
        if ((Get-Sha256 $newBytes) -ne $artifact.sha256) {
            Write-Log "Update REJECTED: artifact hash does not match the signed manifest." "ERROR"
            return
        }

        $combined = New-Object byte[] ($newBytes.Length + $current.Block.Length)
        [Array]::Copy($newBytes, 0, $combined, 0, $newBytes.Length)
        if ($current.Block.Length -gt 0) {
            [Array]::Copy($current.Block, 0, $combined, $newBytes.Length, $current.Block.Length)
        }
        [System.IO.File]::WriteAllBytes($tmp, $combined)

        if ($ScriptPath -eq $ScriptDest) {
            # Windows will not let a running image be overwritten, so hand the
            # swap to a detached cmd.exe that waits for this process to exit.
            Write-Log "Verified update found — scheduling replacement and restart."
            $cmd = "timeout /t 3 /nobreak >nul & move /Y `"$tmp`" `"$ScriptDest`" & " +
                   "start `"`" `"$ScriptDest`""
            Start-Process "cmd.exe" -ArgumentList "/c $cmd" -WindowStyle Hidden
            $handedOff = $true
            exit 0
        }
        # Running from elsewhere (a fresh download in Downloads, say) — the
        # installed copy is not locked, so update it and carry on with this run.
        Write-Log "Verified update found — updating installed copy. Continuing current run."
        Copy-Item -Path $tmp -Destination $ScriptDest -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Log "Update check failed: $_" "WARN"
    } finally {
        if (-not $handedOff) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
    }
}

function Invoke-SelfUpdate {
    if ($IsExe) { Invoke-SelfUpdateExe; return }
    # The .ps1 form is not a signed release artifact: the manifest carries the
    # compiled exe and the POSIX script only. Rather than keep an unverified
    # update path alive for it -- which is exactly the finding this change
    # closes -- a script-form agent does not self-update. Deploy the exe, or
    # push the .ps1 through GPO/MDM.
    return
}

# ════════════════════════════════════════════════════════════════════════════════
#  DUE-CHECK GUARD
# ════════════════════════════════════════════════════════════════════════════════
function Get-State {
    if (Test-Path $StateFile) {
        try { return Get-Content $StateFile -Raw | ConvertFrom-Json }
        catch {}
    }
    return [PSCustomObject]@{ last_run = $null; cancelled_at = $null }
}

function Save-State($state) {
    $state | ConvertTo-Json | Set-Content -Path $StateFile -Encoding UTF8
}

function Test-ShouldRun($Schedule) {
    $state = Get-State
    $now   = Get-Date

    if ($state.last_run) {
        $last    = [datetime]$state.last_run
        $elapsed = ($now - $last).TotalSeconds
        # Negative means the clock moved backwards since the last run. Treating
        # that as due is the safe direction -- the alternative parks the machine
        # until its clock catches up, silently.
        if ($elapsed -ge 0 -and $elapsed -lt $Schedule.checkin_interval_seconds) {
            Write-Log ("Last check-in {0:F1} h ago — not due yet. Exiting." -f ($elapsed / 3600))
            return $false
        }
    }

    if ($state.cancelled_at) {
        $cancelled = [datetime]$state.cancelled_at
        $elapsed   = ($now - $cancelled).TotalSeconds
        if ($elapsed -ge 0 -and $elapsed -lt $Schedule.cancel_retry_seconds) {
            Write-Log ("Cancelled {0:F1} h ago — retry window not reached. Exiting." -f ($elapsed / 3600))
            return $false
        }
    }
    return $true
}

# ════════════════════════════════════════════════════════════════════════════════
#  HARDWARE COLLECTION
# ════════════════════════════════════════════════════════════════════════════════
function Get-Hardware {
    $hw = @{}
    try {
        $cs   = Get-CimInstance Win32_ComputerSystem  -ErrorAction Stop
        $bios = Get-CimInstance Win32_BIOS            -ErrorAction Stop
        $cpu  = Get-CimInstance Win32_Processor       -ErrorAction Stop | Select-Object -First 1
        $disk = Get-CimInstance Win32_DiskDrive       -ErrorAction Stop | Select-Object -First 1
        $os   = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $net  = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" |
                Select-Object -First 1

        $hw.brand   = ($cs.Manufacturer -replace '\s+',' ').Trim()
        $hw.model   = ($cs.Model        -replace '\s+',' ').Trim()
        $hw.serial_number = $bios.SerialNumber.Trim()
        $hw.cpu     = ($cpu.Name        -replace '\s+',' ').Trim()
        $ram_gb     = [math]::Round($cs.TotalPhysicalMemory / 1GB)
        $hw.ram     = "$ram_gb GB"
        $disk_gb    = if ($disk.Size) { [math]::Round($disk.Size / 1GB) } else { "?" }
        $hw.storage = "$disk_gb GB  ($($disk.Model))"
        $hw.os      = "$($os.Caption) $($os.Version)"
        $hw.hostname   = $env:COMPUTERNAME
        $hw.ip_address = if ($net.IPAddress) { $net.IPAddress[0] } else { "N/A" }
        $hw.timestamp  = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss")
    } catch {
        Write-Log "Hardware collection error: $_" "ERROR"
        $hw.brand = $hw.model = $hw.serial_number = $hw.cpu = $hw.ram = $hw.storage = "N/A"
        $hw.os = [System.Environment]::OSVersion.VersionString
        $hw.hostname = $env:COMPUTERNAME
        $hw.ip_address = "N/A"
        $hw.timestamp  = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss")
    }
    return $hw
}

# ════════════════════════════════════════════════════════════════════════════════
#  GOOGLE SHEETS — via Apps Script webhook (no service account needed)
# ════════════════════════════════════════════════════════════════════════════════
function Submit-ToSheets {
    param([hashtable]$Payload)
    try {
        # -Depth matters: custom_fields is a nested hashtable, and at the
        # default depth of 2 it serializes as the literal string
        # "System.Collections.Hashtable" rather than as a JSON object.
        $body = $Payload | ConvertTo-Json -Compress -Depth 10
        $resp = Invoke-RestMethod -Uri $CheckinApiUrl -Method POST -Body $body `
                    -ContentType "application/json" `
                    -Headers @{ Authorization = "Bearer $DeviceCredential" } -TimeoutSec 15
        return ($resp.status -eq "ok")
    } catch {
        $status = $null
        if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
        # 409 means the server already holds this checkin_id: a retry of a
        # submission that did land. Counting it as a failure would re-queue it
        # forever. inventory_agent.py treats it the same way.
        if ($status -eq 409) {
            Write-Log "Server already recorded this checkin_id — treating as success."
            return $true
        }
        # Every failure below is shown to the user as "offline", which is only
        # true of network errors. A 4xx is the server refusing the submission
        # and will refuse every retry identically, so log the status code --
        # after the fact it is the only way to tell the two apart.
        Write-Log "HTTP submit failed (status: $status): $_" "WARN"
        return $false
    }
}

# ── Offline queue ─────────────────────────────────────────────────────────────
function Add-ToQueue($Payload) {
    $items = @()
    if (Test-Path $QueueFile) {
        try { $items = Get-Content $QueueFile -Raw | ConvertFrom-Json }
        catch {}
    }
    $items += $Payload
    $items | ConvertTo-Json -Depth 5 | Set-Content $QueueFile -Encoding UTF8
    Write-Log "Saved to offline queue (total: $($items.Count))"
}

function Flush-Queue {
    if (-not (Test-Path $QueueFile)) { return }
    try {
        $items = @(Get-Content $QueueFile -Raw | ConvertFrom-Json)
    } catch { return }
    if ($items.Count -eq 0) { return }

    Write-Log "Flushing $($items.Count) queued submission(s)…"
    $pending = @()
    foreach ($item in $items) {
        $tbl = @{}
        $item.PSObject.Properties | ForEach-Object { $tbl[$_.Name] = $_.Value }
        # Entries queued by a build that predates checkin_id are rejected 422 on
        # every attempt and would sit here forever. Give them one so they drain,
        # and keep it on the item so a later retry reuses the same key.
        if (-not $tbl.ContainsKey('checkin_id') -or -not $tbl['checkin_id']) {
            $tbl['checkin_id'] = [guid]::NewGuid().ToString()
            $item | Add-Member -NotePropertyName checkin_id -NotePropertyValue $tbl['checkin_id'] -Force
        }
        if (Submit-ToSheets $tbl) {
            Write-Log "  Flushed: $($item.timestamp)"
        } else {
            $pending += $item
        }
    }
    if ($pending.Count -gt 0) {
        $pending | ConvertTo-Json -Depth 5 | Set-Content $QueueFile -Encoding UTF8
        Write-Log "  $($pending.Count) entries still pending."
    } else {
        Remove-Item $QueueFile -Force
        Write-Log "  Queue fully flushed."
    }
}

# ════════════════════════════════════════════════════════════════════════════════
#  WINFORMS GUI
# ════════════════════════════════════════════════════════════════════════════════
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class WinForeground {
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")] public static extern void SwitchToThisWindow(IntPtr hWnd, bool altTab);
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
}
"@

# Without this the process is DPI-unaware, so on any display scaled above 100%
# (the default on most modern laptops) Windows renders the window at 96 DPI and
# bitmap-stretches the result. That blur is what makes the GDI+ logo below look
# like pixels even though it is drawn as vectors -- the drawing is fine, the
# whole window is being scaled up after the fact. Must run before the first
# window handle is created.
try { [void][WinForeground]::SetProcessDPIAware() } catch {}
[System.Windows.Forms.Application]::EnableVisualStyles()

function Show-InventoryForm {
    param([hashtable]$HW, $FieldConfig, $Schedule, $Ui)

    # Everything below is driven by $FieldConfig rather than hardcoded, so the
    # portal's "Check-in fields" settings are what an employee actually sees.
    $userFields  = @($FieldConfig.user_fields)
    $enabledHw   = @($FieldConfig.hardware_fields)
    $builtInKeys = @('first_name','last_name','email','department')

    # Resolved once here rather than inside the two cancel handlers: they are
    # script blocks that close over this scope, so they see it when they fire.
    # This is the only thing an employee ever reads about the schedule, so it
    # has to name this company's actual retry rather than a fixed 24 hours.
    $retryText = Format-Duration $Schedule.cancel_retry_seconds

    # custom_fields is kept separate from user_data because the API takes the
    # built-ins as top-level keys and everything else nested under
    # custom_fields (see CheckinRequest in backend/app/models.py).
    $result   = @{ submitted = $false; user_data = @{}; custom_fields = @{}; closing = $false }
    $controls = @{}   # field key -> the TextBox or ComboBox that collects it

    # ── Design tokens ─────────────────────────────────────────────────────────
    # Server-driven: these come from the company's appearance settings, falling
    # back to $DefaultAgentUi (which reproduces backend/app/static/assetly.css,
    # so an unconfigured window and app.assetly.ge still read as one product).
    #
    # The default palette is chosen so that every text pair clears WCAG 4.5:1
    # and every control outline clears 3:1 against what sits behind it; the
    # portal holds admin-supplied palettes to the same bar before storing them.
    # The previous values did not: --slate-dim on navy is roughly 2.5:1, which
    # is what made the whole form read as a wall of grey.
    $cNavy        = ConvertFrom-HexColor $Ui.navy
    $cNavySidebar = ConvertFrom-HexColor $Ui.navy_sidebar
    $cNavyMid     = ConvertFrom-HexColor $Ui.navy_mid
    $cBlue        = ConvertFrom-HexColor $Ui.blue
    $cBlueHover   = ConvertFrom-HexColor $Ui.blue_hover
    $cTeal        = ConvertFrom-HexColor $Ui.teal
    $cSlate       = ConvertFrom-HexColor $Ui.slate
    $cLabel       = ConvertFrom-HexColor $Ui.label
    $cWhite       = ConvertFrom-HexColor $Ui.white
    $cBorderMd    = ConvertFrom-HexColor $Ui.border_md
    $cBorderInput = ConvertFrom-HexColor $Ui.border_input

    # ── Layout metrics ────────────────────────────────────────────────────────
    # Device facts live in the left rail, so the form grows only with the fields
    # themselves -- and two short fields share a row, so it grows half as fast
    # as the field count.
    $railW   = 196
    $pad     = 24
    $paneX   = $railW + $pad
    $paneW   = 516
    $colW    = 252
    $colGapX = $paneX + $colW + 12
    $rowH    = 62
    $fullWidthKeys = @('email')

    # Assign every field a row and column up front: the window has to be sized
    # before any control is placed.
    $slots = New-Object System.Collections.ArrayList
    $row = 0; $col = 0
    foreach ($field in $userFields) {
        if ($fullWidthKeys -contains $field.key) {
            if ($col -eq 1) { $row++; $col = 0 }
            [void]$slots.Add(@{ field = $field; row = $row; col = 0; full = $true })
            $row++
        } else {
            [void]$slots.Add(@{ field = $field; row = $row; col = $col; full = $false })
            if ($col -eq 1) { $row++; $col = 0 } else { $col = 1 }
        }
    }
    $rowCount = if ($col -eq 1) { $row + 1 } else { $row }

    # ── Form ──────────────────────────────────────────────────────────────────
    $form                  = New-Object System.Windows.Forms.Form
    $form.Text             = $Ui.window_title
    $form.StartPosition    = "CenterScreen"
    $form.FormBorderStyle  = "FixedDialog"
    $form.MaximizeBox      = $false
    $form.BackColor        = $cNavy
    $form.Font             = New-Object System.Drawing.Font("Segoe UI", 10)
    # Every Location/Size below is a literal in 96-DPI pixels, and WinForms only
    # auto-scales controls that exist when the form is constructed -- these are
    # all added afterwards, so automatic scaling would catch none of them and
    # silently double-scale the few it did. Scaling is done explicitly instead,
    # in one pass just before ShowDialog.
    $form.AutoScaleMode    = [System.Windows.Forms.AutoScaleMode]::None

    # ── Device rail ───────────────────────────────────────────────────────────
    # Only the rows that will actually be submitted: the rail promises this is
    # what gets sent, and the payload built in MAIN drops every hardware key the
    # company has switched off.
    $hwRows = [ordered]@{
        "Model"  = "$($HW.brand) $($HW.model)"
        "Serial" = $HW.serial_number
    }
    if ($enabledHw -contains 'cpu')     { $hwRows["Processor"] = $HW.cpu }
    if ($enabledHw -contains 'ram')     { $hwRows["Memory"]    = $HW.ram }
    if ($enabledHw -contains 'storage') { $hwRows["Storage"]   = $HW.storage }
    $hwRows["System"] = $HW.os
    $hwRows["Host"]   = $HW.hostname
    if ($enabledHw -contains 'ip_address') { $hwRows["IP address"] = $HW.ip_address }

    # ── Rail metrics ──────────────────────────────────────────────────────────
    # Declared here, above the height arithmetic that depends on them, and
    # derived rather than written out as a sum of literals. The previous form
    # (`18 + 65 + 26 + 20 + ...`) carried the logo's height as the constant 65
    # while the logo itself was sized further down the function -- so widening
    # the logo silently under-reserved the rail by exactly the difference, and
    # the footnote came to sit on top of the last device row. A layout constant
    # that has to be updated in step with a value defined 20 lines later will
    # eventually be missed; this cannot drift because it reads that value.
    $logoW       = 160
    $logoH       = [int]($logoW * 0.45)
    $railRowsTop = $logoH + 62                             # under logo + "THIS DEVICE"
    $railRowH    = 36
    $railRowsEnd = $railRowsTop + ($railRowH * $hwRows.Count)
    # Four lines at 8pt in a 160px column, for the longest footnote that fits
    # the 140-character cap the portal enforces on it.
    $railFootH   = 56
    $railPadB    = 18

    # ── Pane metrics ──────────────────────────────────────────────────────────
    # Same treatment, and it exposed an off-by-six that predates this change:
    # the old sum reserved 144 + rowH*rowCount, while the pane actually needs
    # $formTop + rowH*rowCount + a gap + the button strip = 162 + rowH*rowCount.
    # Six pixels short is invisible until the pane is the taller of the two
    # columns, which takes about seven user fields -- so a company that added
    # a few custom fields got inputs sitting under the buttons.
    $formTop    = 92                                       # first field label
    $btnAreaH   = 58                                       # button strip + margin
    $paneGap    = 12                                       # fields -> buttons

    $railNeeded = $railRowsEnd + 14 + $railFootH + $railPadB
    $paneNeeded = $formTop + ($rowH * $rowCount) + $paneGap + $btnAreaH
    $clientH    = [Math]::Max($railNeeded, $paneNeeded)
    $form.ClientSize = New-Object System.Drawing.Size(760, $clientH)

    $rail           = New-Object System.Windows.Forms.Panel
    $rail.Location  = New-Object System.Drawing.Point(0, 0)
    $rail.Size      = New-Object System.Drawing.Size($railW, $clientH)
    $rail.BackColor = $cNavySidebar
    $form.Controls.Add($rail)

    # ── Logo ──────────────────────────────────────────────────────────────────
    # assetly_logo.svg, drawn with GDI+ rather than loaded: WinForms has no SVG
    # decoder, and painting the shapes keeps the agent a single self-contained
    # file (the .exe build has no sibling image to read). Every coordinate below
    # is the SVG's own, mapped through $s onto the panel.
    $logoBox           = New-Object System.Windows.Forms.Panel
    $logoBox.Location  = New-Object System.Drawing.Point(18, 18)
    $logoBox.Size      = New-Object System.Drawing.Size($logoW, $logoH)
    $logoBox.BackColor = $cNavySidebar
    $logoBox.Add_Paint({
        param($sender, $e)
        $g = $e.Graphics
        $g.SmoothingMode      = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $g.TextRenderingHint  = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
        # Without HighQuality pixel offset, GDI+ snaps the sub-pixel edges of the
        # circles and strokes below to whole pixels, which is what gave the mark
        # its stair-stepped, "pixelated" look at this size.
        $g.PixelOffsetMode    = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
        $g.InterpolationMode  = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $g.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
        $w = $sender.Width
        $s = $w / 400                                 # SVG user units -> pixels

        $teal  = [System.Drawing.Color]::FromArgb(78, 205, 180)   # #4ECDB4
        $node  = [System.Drawing.Color]::FromArgb(242, 245, 247)  # #F2F5F7

        # The SVG's 400x180 rx=18 backdrop is deliberately not drawn. At #0D1119
        # against the #080E1A rail it is a near-invisible dark rectangle that
        # reads as a mis-sized image box framing the mark rather than as part of
        # the logo. The mark sits directly on the rail instead.

        # node-graph mark: three edges under a 5FD8BE -> 3AA98F gradient
        $p1 = New-Object System.Drawing.PointF (70 * $s), (57 * $s)
        $p2 = New-Object System.Drawing.PointF (36 * $s), (123 * $s)
        $p3 = New-Object System.Drawing.PointF (104 * $s), (123 * $s)
        $grad = New-Object System.Drawing.Drawing2D.LinearGradientBrush `
                    $p1, $p3, `
                    ([System.Drawing.Color]::FromArgb(95, 216, 190)), `
                    ([System.Drawing.Color]::FromArgb(58, 169, 143))
        $pen = New-Object System.Drawing.Pen $grad, (3.5 * $s)
        $pen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
        $pen.EndCap   = [System.Drawing.Drawing2D.LineCap]::Round
        $g.DrawLine($pen, $p1, $p2)
        $g.DrawLine($pen, $p1, $p3)
        $g.DrawLine($pen, $p2, $p3)

        # the three nodes (r = 7.5)
        $nr = 7.5 * $s
        $g.FillEllipse((New-Object System.Drawing.SolidBrush $node), ($p1.X - $nr), ($p1.Y - $nr), (2*$nr), (2*$nr))
        $tealBrush = New-Object System.Drawing.SolidBrush $teal
        $g.FillEllipse($tealBrush, ($p2.X - $nr), ($p2.Y - $nr), (2*$nr), (2*$nr))
        $g.FillEllipse($tealBrush, ($p3.X - $nr), ($p3.Y - $nr), (2*$nr), (2*$nr))

        # wordmark: "asset" white + "ly" teal, sitting on the SVG's y=113 baseline
        $fontPx = 64 * $s
        $fam    = New-Object System.Drawing.FontFamily "Segoe UI"
        $font   = New-Object System.Drawing.Font $fam, $fontPx, `
                      ([System.Drawing.FontStyle]::Bold), ([System.Drawing.GraphicsUnit]::Pixel)
        $ascent = $fontPx * $fam.GetCellAscent([System.Drawing.FontStyle]::Bold) / $fam.GetEmHeight([System.Drawing.FontStyle]::Bold)
        $top    = (113 * $s) - $ascent
        $left   = 150 * $s
        $fmt    = [System.Drawing.StringFormat]::GenericTypographic
        $g.DrawString("asset", $font, [System.Drawing.Brushes]::White, $left, $top, $fmt)
        $left  += $g.MeasureString("asset", $font, [System.Drawing.PointF]::Empty, $fmt).Width
        $g.DrawString("ly", $font, $tealBrush, $left, $top, $fmt)
    })
    $rail.Controls.Add($logoBox)

    $railTitle           = New-Object System.Windows.Forms.Label
    $railTitle.Text      = $Ui.rail_title
    $railTitle.Location  = New-Object System.Drawing.Point(18, ($logoH + 38))
    $railTitle.Size      = New-Object System.Drawing.Size(160, 18)
    $railTitle.Font      = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
    $railTitle.ForeColor = $cTeal
    $rail.Controls.Add($railTitle)

    $ry = $railRowsTop
    foreach ($key in $hwRows.Keys) {
        $kLbl           = New-Object System.Windows.Forms.Label
        $kLbl.Text      = $key.ToUpper()
        $kLbl.Location  = New-Object System.Drawing.Point(18, $ry)
        $kLbl.Size      = New-Object System.Drawing.Size(160, 15)
        $kLbl.Font      = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
        $kLbl.ForeColor = $cLabel
        $rail.Controls.Add($kLbl)

        $vLbl              = New-Object System.Windows.Forms.Label
        $vLbl.Text         = $hwRows[$key]
        $vLbl.Location     = New-Object System.Drawing.Point(18, ($ry + 15))
        $vLbl.Size         = New-Object System.Drawing.Size(160, 17)
        $vLbl.Font         = New-Object System.Drawing.Font("Consolas", 9)
        $vLbl.ForeColor    = $cWhite
        $vLbl.AutoEllipsis = $true
        $rail.Controls.Add($vLbl)

        $ry += $railRowH
    }

    $railFoot           = New-Object System.Windows.Forms.Label
    $railFoot.Text      = $Ui.rail_footnote
    # Anchored to the bottom of the window, which $railNeeded above has already
    # guaranteed clears the last device row.
    $railFoot.Location  = New-Object System.Drawing.Point(18, ($clientH - $railPadB - $railFootH))
    $railFoot.Size      = New-Object System.Drawing.Size(160, $railFootH)
    $railFoot.Font      = New-Object System.Drawing.Font("Segoe UI", 8)
    $railFoot.ForeColor = $cSlate
    $rail.Controls.Add($railFoot)

    # ── Form pane ─────────────────────────────────────────────────────────────
    $heading           = New-Object System.Windows.Forms.Label
    $heading.Text      = $Ui.heading
    $heading.Location  = New-Object System.Drawing.Point($paneX, 22)
    $heading.Size      = New-Object System.Drawing.Size($paneW, 28)
    $heading.Font      = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
    $heading.ForeColor = $cWhite
    $form.Controls.Add($heading)

    $subHeading           = New-Object System.Windows.Forms.Label
    # Two keys rather than a plural rule the agent applies itself: the rule
    # differs by language, and this copy is admin-authored.
    #
    # Picked into a variable first, deliberately. `if` is a statement, not an
    # expression, so `Expand-UiText ( if ... )` is a parse error in Windows
    # PowerShell 5.1 -- inside plain parentheses in argument position the
    # parser expects an expression and reads `if` as a command name, failing at
    # runtime with "The term 'if' is not recognized as the name of a cmdlet".
    # `$( ... )` would also work; a named variable is plainer.
    $subHeadingTemplate = if ($userFields.Count -eq 1) { $Ui.subheading_one }
                          else { $Ui.subheading }
    $subHeading.Text      = Expand-UiText $subHeadingTemplate @{ count = $userFields.Count }
    $subHeading.Location  = New-Object System.Drawing.Point($paneX, 52)
    $subHeading.Size      = New-Object System.Drawing.Size($paneW, 20)
    $subHeading.Font      = New-Object System.Drawing.Font("Segoe UI", 9.5)
    $subHeading.ForeColor = $cSlate
    $form.Controls.Add($subHeading)

    # ── Input rows ────────────────────────────────────────────────────────────
    # Two short fields to a row, an email to itself. Nothing here knows which
    # fields exist; that is entirely the portal's call.
    foreach ($slot in $slots) {
        $field = $slot.field
        $x = if ($slot.col -eq 1) { $colGapX } else { $paneX }
        $w = if ($slot.full) { $paneW } else { $colW }
        $y = $formTop + ($rowH * $slot.row)

        $lbl           = New-Object System.Windows.Forms.Label
        $lbl.Text      = $field.label.ToUpper()
        $lbl.Location  = New-Object System.Drawing.Point($x, $y)
        $lbl.Size      = New-Object System.Drawing.Size(($w - 14), 16)
        $lbl.Font      = New-Object System.Drawing.Font("Segoe UI", 8.5, [System.Drawing.FontStyle]::Bold)
        $lbl.ForeColor = $cLabel
        # Labels are admin-authored now, so one can be longer than the column.
        # An ellipsis at least says so, where a plain clip silently cuts a word.
        $lbl.AutoEllipsis = $true
        $form.Controls.Add($lbl)

        if ($field.required) {
            $star           = New-Object System.Windows.Forms.Label
            $star.Text      = "*"
            # Pinned to the far edge of the column, the asterisk read as a stray
            # mark belonging to the *next* field rather than to this label. Sit
            # it against the end of the label text, falling back to the column
            # edge when an admin-authored label is long enough to fill the row.
            $lblTextW = [System.Windows.Forms.TextRenderer]::MeasureText($lbl.Text, $lbl.Font).Width
            $starX    = [Math]::Min(($x + $lblTextW - 2), ($x + $w - 12))
            $star.Location  = New-Object System.Drawing.Point($starX, $y)
            $star.Size      = New-Object System.Drawing.Size(12, 16)
            $star.Font      = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
            $star.ForeColor = $cTeal
            $form.Controls.Add($star)
        }

        if ($field.key -eq 'department') {
            # A DropDownList combo paints its text area and its list with the
            # system window colours no matter what BackColor says -- which is
            # why this one alone came out white-on-black in the middle of a dark
            # form. Owner-drawing is the only way to make it match: DrawItem
            # then owns both the closed control and every row of the open list.
            $ctrl               = New-Object System.Windows.Forms.ComboBox
            $ctrl.DropDownStyle = "DropDownList"
            $ctrl.FlatStyle     = "Flat"
            $ctrl.DrawMode      = "OwnerDrawFixed"
            $ctrl.BackColor     = $cNavyMid
            $ctrl.ForeColor     = $cWhite
            $ctrl.Location      = New-Object System.Drawing.Point($x, ($y + 20))
            $ctrl.Size          = New-Object System.Drawing.Size($w, 30)
            $ctrl.ItemHeight    = 22
            $ctrl.Font          = New-Object System.Drawing.Font("Segoe UI", 10)
            $ctrl.Add_DrawItem({
                param($sender, $e)
                # Selected here means "row under the cursor in the open list",
                # not "the chosen value" -- so it is the hover highlight. Cast
                # to [int] before -band: the operator is defined on integers,
                # and leaning on PowerShell's enum coercion inside a paint
                # handler risks an exception on a code path that runs for every
                # row of every repaint.
                $hot  = ([int]$e.State -band [int][System.Windows.Forms.DrawItemState]::Selected) -ne 0
                $fill = if ($hot) { $cBlue } else { $cNavyMid }
                $brush = New-Object System.Drawing.SolidBrush $fill
                try {
                    $e.Graphics.FillRectangle($brush, $e.Bounds)
                } finally {
                    $brush.Dispose()
                }
                if ($e.Index -ge 0) {
                    $e.Graphics.TextRenderingHint =
                        [System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit
                    # Built up front rather than inline: `New-Object Type a, b`
                    # takes its arguments as one array, which is easy to break
                    # by accident when the call is wrapped across lines inside
                    # another call's argument list.
                    $textRect = New-Object System.Drawing.Rectangle(
                        ($e.Bounds.X + 6), $e.Bounds.Y,
                        ($e.Bounds.Width - 6), $e.Bounds.Height)
                    $flags = [System.Windows.Forms.TextFormatFlags]::VerticalCenter -bor
                             [System.Windows.Forms.TextFormatFlags]::EndEllipsis
                    [System.Windows.Forms.TextRenderer]::DrawText(
                        $e.Graphics, $sender.Items[$e.Index].ToString(), $sender.Font,
                        $textRect, $cWhite, $flags)
                }
            }.GetNewClosure())
            $options = if ($field.PSObject.Properties.Match('options').Count -gt 0 -and $field.options) {
                @($field.options)
            } else {
                $DefaultDepartments
            }
            $options | ForEach-Object { $ctrl.Items.Add($_) | Out-Null }
            if ($ctrl.Items.Count -gt 0) { $ctrl.SelectedIndex = 0 }
            $form.Controls.Add($ctrl)
        } else {
            # A TextBox draws its own border in a system colour that cannot be
            # set, so it goes borderless inside a panel that is the border --
            # which also gives us somewhere to show focus, as the portal does.
            $wrap           = New-Object System.Windows.Forms.Panel
            $wrap.Location  = New-Object System.Drawing.Point($x, ($y + 20))
            $wrap.Size      = New-Object System.Drawing.Size($w, 30)
            $wrap.BackColor = $cBorderInput

            $inner           = New-Object System.Windows.Forms.Panel
            $inner.Location  = New-Object System.Drawing.Point(1, 1)
            $inner.Size      = New-Object System.Drawing.Size(($w - 2), 28)
            $inner.BackColor = $cNavyMid
            $wrap.Controls.Add($inner)

            $ctrl             = New-Object System.Windows.Forms.TextBox
            $ctrl.BorderStyle = "None"
            $ctrl.BackColor   = $cNavyMid
            $ctrl.ForeColor   = $cWhite
            $ctrl.Font        = New-Object System.Drawing.Font("Segoe UI", 10)
            $ctrl.Location    = New-Object System.Drawing.Point(8, 5)
            $ctrl.Width       = $w - 18
            $inner.Controls.Add($ctrl)

            # GotFocus/LostFocus fire on the TextBox; the border they recolour
            # is the wrapper, captured here so the handlers can reach it.
            $wrapRef = $wrap
            $ctrl.Add_GotFocus({ $wrapRef.BackColor = $cBlue }.GetNewClosure())
            $ctrl.Add_LostFocus({ $wrapRef.BackColor = $cBorderInput }.GetNewClosure())

            $form.Controls.Add($wrap)
        }

        $controls[$field.key] = $ctrl
    }

    # ── Buttons ───────────────────────────────────────────────────────────────
    $btnY = $clientH - $btnAreaH

    $btnSubmit             = New-Object System.Windows.Forms.Button
    $btnSubmit.Text        = $Ui.submit_label
    $btnSubmit.Size        = New-Object System.Drawing.Size(130, 34)
    $btnSubmit.Location    = New-Object System.Drawing.Point(($paneX + $paneW - 130), $btnY)
    $btnSubmit.Font        = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $btnSubmit.BackColor   = $cBlue
    $btnSubmit.ForeColor   = [System.Drawing.Color]::White
    $btnSubmit.FlatStyle   = "Flat"
    $btnSubmit.FlatAppearance.BorderSize = 0
    $btnSubmit.FlatAppearance.MouseOverBackColor = $cBlueHover
    $form.Controls.Add($btnSubmit)

    $btnCancel             = New-Object System.Windows.Forms.Button
    $btnCancel.Text        = $Ui.cancel_label
    $btnCancel.Size        = New-Object System.Drawing.Size(90, 34)
    $btnCancel.Location    = New-Object System.Drawing.Point(($paneX + $paneW - 230), $btnY)
    $btnCancel.Font        = New-Object System.Drawing.Font("Segoe UI", 10)
    $btnCancel.BackColor   = $cNavyMid
    $btnCancel.ForeColor   = $cWhite
    $btnCancel.FlatStyle   = "Flat"
    $btnCancel.FlatAppearance.BorderSize  = 1
    $btnCancel.FlatAppearance.BorderColor = $cBorderMd
    $form.Controls.Add($btnCancel)

    # ── Event handlers ────────────────────────────────────────────────────────
    $btnSubmit.Add_Click({
        $values = @{}
        foreach ($field in $userFields) {
            $ctrl = $controls[$field.key]
            if ($null -eq $ctrl) { continue }
            $value = if ($ctrl -is [System.Windows.Forms.ComboBox]) {
                if ($null -ne $ctrl.SelectedItem) { $ctrl.SelectedItem.ToString() } else { "" }
            } else {
                $ctrl.Text.Trim()
            }

            if ($field.required -and -not $value) {
                [System.Windows.Forms.MessageBox]::Show(
                    "Please enter your $($field.label).", "Missing field") | Out-Null
                return
            }
            # Format-checked only when there is something to check; whether it
            # is mandatory at all is the portal's decision, not this agent's.
            if ($field.key -eq 'email' -and $value -and $value -notmatch '^[^@]+@[^@]+\.[^@]+$') {
                [System.Windows.Forms.MessageBox]::Show(
                    "Please enter a valid email address.", "Invalid email") | Out-Null
                return
            }
            $values[$field.key] = $value
        }

        foreach ($key in $values.Keys) {
            if ($builtInKeys -contains $key) {
                $result.user_data[$key] = $values[$key]
            } else {
                $result.custom_fields[$key] = $values[$key]
            }
        }
        $result.submitted = $true
        $form.Close()
    })

    $btnCancel.Add_Click({
        $ans = [System.Windows.Forms.MessageBox]::Show(
            "Are you sure you want to skip?`n`n• You'll be reminded again in $retryText",
            "Cancel check-in",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        if ($ans -eq "Yes") { $result.closing = $true; $result.submitted = $false; $form.Close() }
    })

    $form.Add_FormClosing({
        param($s, $e)
        # Skip if already confirmed (Submit or Cancel-Yes already handled it)
        if ($result.submitted -or $result.closing) { return }
        # X button — treat same as Cancel
        $ans = [System.Windows.Forms.MessageBox]::Show(
            "Are you sure you want to skip?`n`n• You'll be reminded again in $retryText",
            "Cancel check-in",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        if ($ans -eq "Yes") {
            $result.closing = $true
            $result.submitted = $false
        } else {
            $e.Cancel = $true   # block the close
        }
    })

    $form.Add_Load({
        $form.WindowState = [System.Windows.Forms.FormWindowState]::Normal
        [WinForeground]::ShowWindow($form.Handle, 9)     # SW_RESTORE
        [WinForeground]::SetForegroundWindow($form.Handle)
        [WinForeground]::SwitchToThisWindow($form.Handle, $true)
        $form.TopMost = $true
        $form.Activate()
        $form.TopMost = $false   # release TopMost after focus so user can alt-tab away
    })

    # Now that the process is DPI-aware, Windows no longer stretches the window
    # for us -- so on a 150% display the 96-DPI layout above would come out
    # crisp but two-thirds the intended physical size. Scale it once, here,
    # after every control is in place: Control.Scale walks the whole tree and
    # scales bounds and the explicit fonts with it.
    try {
        $gfx = $form.CreateGraphics()
        try { $dpiFactor = $gfx.DpiX / 96.0 } finally { $gfx.Dispose() }
        if ($dpiFactor -gt 1.01) { $form.Scale([float]$dpiFactor) }
    } catch {
        Write-Log "DPI scaling of the form failed, showing it unscaled: $_" "WARN"
    }

    $form.ShowDialog() | Out-Null
    return $result
}

# ════════════════════════════════════════════════════════════════════════════════
#  TASK SCHEDULER REGISTRATION (runs on first install)
# ════════════════════════════════════════════════════════════════════════════════
function Register-StartupTask {
    # Copy script to a stable path so the task still works if the original is deleted
    Copy-Item -Path $ScriptPath -Destination $ScriptDest -Force

    # EXE runs directly; PS1 needs the powershell.exe wrapper
    $action = if ($IsExe) {
        New-ScheduledTaskAction -Execute $ScriptDest
    } else {
        New-ScheduledTaskAction -Execute "powershell.exe" `
            -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -NonInteractive -File `"$ScriptDest`""
    }

    $triggerLogon       = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
    $triggerLogon.Delay = "PT1M30S"   # wait 90 s for desktop to be ready (ISO 8601 format)

    # Hourly trigger so the 24-h cancel retry fires even when the user stays logged in
    $triggerHourly = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) `
        -RepetitionInterval (New-TimeSpan -Hours 1) `
        -RepetitionDuration (New-TimeSpan -Days 9999)

    $settings = New-ScheduledTaskSettingsSet `
        -ExecutionTimeLimit (New-TimeSpan -Hours 1) `
        -MultipleInstances  IgnoreNew
    # Allow running on battery — set via CIM properties (parameter name varies by PS version)
    $settings.DisallowStartIfOnBatteries = $false
    $settings.StopIfGoingOnBatteries     = $false

    $principal = New-ScheduledTaskPrincipal `
        -UserId   "$env:USERDOMAIN\$env:USERNAME" `
        -LogonType Interactive `
        -RunLevel Limited

    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Register-ScheduledTask -TaskName $TaskName -Action $action `
        -Trigger @($triggerLogon, $triggerHourly) `
        -Settings $settings -Principal $principal `
        -Description "Assetly Inventory Agent — checks in on the schedule configured in the portal" | Out-Null

    Write-Log "Task Scheduler task '$TaskName' registered."
}

# ════════════════════════════════════════════════════════════════════════════════
#  MAIN
# ════════════════════════════════════════════════════════════════════════════════
Write-Log "=== Assetly Inventory Agent started ==="

# Resolve credentials, enrolling first if this machine has none yet. Must
# happen before any authenticated call -- Flush-Queue below is the earliest one.
$DeviceCredential = Resolve-Credential $Cfg $ConfigFilePath

# Register startup task if not already registered
$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if (-not $task) {
    Write-Log "First run — registering startup task…"
    Register-StartupTask
}

# Self-update check
Invoke-SelfUpdate

# Flush offline queue
Flush-Queue

# Fetch this company's config (fields + schedule) BEFORE the guard -- the guard
# needs the server's interval to decide. One call: the same response builds the
# form below.
$state       = Get-State
$fieldConfig = Get-FieldConfig
$schedule    = Resolve-ScheduleFrom $fieldConfig $state
$agentUi     = Resolve-AgentUiFrom  $fieldConfig $state

if (-not (Test-Schedule $state.schedule) -or
    $state.schedule.checkin_interval_seconds -ne $schedule.checkin_interval_seconds -or
    $state.schedule.cancel_retry_seconds     -ne $schedule.cancel_retry_seconds) {
    $state | Add-Member -NotePropertyName schedule -NotePropertyValue $schedule -Force
    Save-State $state
}

# Cached for the same reason the schedule is: the window has to look like this
# company's agent even on a run where /config could not be reached. Compared as
# serialized JSON because these are ~20 string properties and there is no
# cheaper structural equality for a PSCustomObject -- the point of comparing at
# all is to avoid rewriting state.json on every single run.
$agentUiJson = $agentUi | ConvertTo-Json -Compress
if (($state.PSObject.Properties.Match('ui').Count -eq 0) -or
    (($state.ui | ConvertTo-Json -Compress) -ne $agentUiJson)) {
    $state | Add-Member -NotePropertyName ui -NotePropertyValue $agentUi -Force
    Save-State $state
}

# Guard: exit if not due
if (-not (Test-ShouldRun $schedule)) { exit 0 }

# Collect hardware
Write-Log "Collecting hardware information…"
$hw = Get-Hardware
Write-Log "HW: $($hw | ConvertTo-Json -Compress)"

$enabledHwFields = @($fieldConfig.hardware_fields)

# Show GUI
$res = Show-InventoryForm -HW $hw -FieldConfig $fieldConfig -Schedule $schedule -Ui $agentUi

# ── Cancelled ─────────────────────────────────────────────────────────────────
if (-not $res.submitted) {
    $state = Get-State
    $state | Add-Member -NotePropertyName cancelled_at -NotePropertyValue (Get-Date -Format "o") -Force
    Save-State $state

    Write-Log ("Form cancelled. Will retry in {0:F0} h." -f ($schedule.cancel_retry_seconds / 3600))
    exit 0
}

# ── Submitted ─────────────────────────────────────────────────────────────────
$ud = $res.user_data
$payload = @{
    # Required by the API, and an idempotency key: generated once here and
    # carried through into the offline queue, so retrying a submission that
    # actually landed answers 409 "duplicate" instead of recording it twice.
    checkin_id      = [guid]::NewGuid().ToString()
    timestamp       = $hw.timestamp
    first_name      = $ud.first_name
    last_name       = $ud.last_name
    email           = $ud.email
    hostname        = $hw.hostname
    brand           = $hw.brand
    model           = $hw.model
    serial_number   = $hw.serial_number
    os              = $hw.os
    agent_version   = $AgentVersion
    submission_type = "online"
    platform        = "windows"
    custom_fields   = $res.custom_fields
}
# Department is a configurable field, so it is only sent when the company has
# it enabled -- sending an empty string would overwrite a device's recorded
# department with nothing on the next check-in.
if ($ud.ContainsKey('department')) { $payload.department = $ud.department }
# Same for the hardware fields: a company that switched CPU off should not
# have CPU stored anyway.
foreach ($key in @('cpu','ram','storage','ip_address')) {
    if ($enabledHwFields -contains $key) { $payload[$key] = $hw[$key] }
}

Write-Log "Submitting to Google Sheets…"
$immediate = Submit-ToSheets -Payload $payload
if (-not $immediate) {
    Add-ToQueue $payload
}

# Update state
$state = Get-State
$state | Add-Member -NotePropertyName last_run     -NotePropertyValue (Get-Date -Format "o") -Force
$state | Add-Member -NotePropertyName cancelled_at -NotePropertyValue $null                  -Force
Save-State $state

# Success dialog
$dialogMsg = Expand-UiText $agentUi.success_message @{ first_name = $ud.first_name }
if (-not $immediate) { $dialogMsg += "`n`n(Offline — data will sync automatically.)" }
[System.Windows.Forms.MessageBox]::Show($dialogMsg, $agentUi.window_title,
    [System.Windows.Forms.MessageBoxButtons]::OK,
    [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null

Write-Log "=== Completed successfully ==="
