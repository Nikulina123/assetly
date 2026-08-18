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
$GitHubRawUrl  = "https://raw.githubusercontent.com/Nikulina123/Check-in_agent/refs/heads/main/AssetlyAgent_Windows.ps1"
# The compiled agent updates itself from the build CI commits to the repository,
# which is the same artifact the portal serves for "Download for Windows".
$GitHubExeUrl  = "https://raw.githubusercontent.com/Nikulina123/Check-in_agent/refs/heads/main/backend/static/AssetlyAgent_Windows.exe"

# Windows PowerShell 5.1 still negotiates TLS 1.0 by default on older builds,
# which raw.githubusercontent.com refuses outright. Without this the self-update
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
#  SELF-UPDATE
# ════════════════════════════════════════════════════════════════════════════════
function Get-Sha256([byte[]]$Bytes) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha.ComputeHash($Bytes)) } finally { $sha.Dispose() }
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
    <#  A compiled agent used to be a dead end: Invoke-SelfUpdate returned
        immediately for an .exe, so every fix had to be hand-carried to every
        machine. It now replaces itself from the same artifact the portal
        serves, carrying its own config block across so an exe that updates
        before it has ever enrolled still knows its URL and token. #>
    if (-not $GitHubExeUrl -or $GitHubExeUrl -like "*YOUR_ORG*") { return }
    $tmp = [System.IO.Path]::GetTempFileName() + ".exe"
    # PowerShell runs `finally` on the way out of `exit`, so the cleanup below
    # would delete the staged executable out from under the cmd.exe that was
    # just scheduled to move it into place -- leaving the old agent running and
    # re-attempting the same update on every login, forever. Ownership of the
    # temp file transfers to cmd.exe on that path, and only on that path.
    $handedOff = $false
    try {
        Write-Log "Checking for updates…"
        Invoke-WebRequest -Uri $GitHubExeUrl -OutFile $tmp -UseBasicParsing -TimeoutSec 60
        $newBytes = [System.IO.File]::ReadAllBytes($tmp)

        # Same check Build_Windows_EXE.ps1 makes on its own output. A captive
        # portal's login page is a perfectly successful HTTP response, and
        # writing one over the agent would brick it on the employee's machine.
        if ($newBytes.Length -lt 10240 -or $newBytes[0] -ne 0x4D -or $newBytes[1] -ne 0x5A) {
            Write-Log "Update rejected: downloaded $($newBytes.Length) bytes that are not a PE image." "WARN"
            return
        }

        $current = Split-EmbeddedConfig ([System.IO.File]::ReadAllBytes($ScriptPath))
        if ((Get-Sha256 $current.Base) -eq (Get-Sha256 $newBytes)) { return }

        $combined = New-Object byte[] ($newBytes.Length + $current.Block.Length)
        [Array]::Copy($newBytes, 0, $combined, 0, $newBytes.Length)
        if ($current.Block.Length -gt 0) {
            [Array]::Copy($current.Block, 0, $combined, $newBytes.Length, $current.Block.Length)
        }
        [System.IO.File]::WriteAllBytes($tmp, $combined)

        if ($ScriptPath -eq $ScriptDest) {
            # Windows will not let a running image be overwritten, so hand the
            # swap to a detached cmd.exe that waits for this process to exit.
            Write-Log "Update found — scheduling replacement and restart."
            $cmd = "timeout /t 3 /nobreak >nul & move /Y `"$tmp`" `"$ScriptDest`" & " +
                   "start `"`" `"$ScriptDest`""
            Start-Process "cmd.exe" -ArgumentList "/c $cmd" -WindowStyle Hidden
            $handedOff = $true
            exit 0
        }
        # Running from elsewhere (a fresh download in Downloads, say) — the
        # installed copy is not locked, so update it and carry on with this run.
        Write-Log "Update found — updating installed copy. Continuing current run."
        Copy-Item -Path $tmp -Destination $ScriptDest -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Log "Update check failed: $_" "WARN"
    } finally {
        if (-not $handedOff) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
    }
}

function Invoke-SelfUpdate {
    if ($IsExe) { Invoke-SelfUpdateExe; return }
    if (-not $GitHubRawUrl -or $GitHubRawUrl -like "*YOUR_ORG*") { return }
    try {
        Write-Log "Checking for updates…"
        $new  = (Invoke-WebRequest -Uri $GitHubRawUrl -UseBasicParsing -TimeoutSec 8).Content
        $cur  = Get-Content -Path $ScriptPath -Raw -ErrorAction SilentlyContinue
        # Compare the hash *strings*: -ne between two byte[] operands is
        # PowerShell's element-wise filter, not an equality test, so the old
        # form here only worked by accident of an empty array being falsy.
        $hash = { param($s) Get-Sha256 ([System.Text.Encoding]::UTF8.GetBytes($s)) }
        if ((&$hash $new) -ne (&$hash $cur)) {
            $tmp = [System.IO.Path]::GetTempFileName() + ".ps1"
            $new | Out-File -FilePath $tmp -Encoding UTF8
            if ($ScriptPath -eq $ScriptDest) {
                # Running from installed location — replace and restart silently
                Write-Log "Update found — scheduling replacement and restart."
                $cmd = "timeout /t 2 /nobreak >nul & copy /Y `"$tmp`" `"$ScriptDest`" & " +
                       "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ScriptDest`""
                Start-Process "cmd.exe" -ArgumentList "/c $cmd" -WindowStyle Hidden
                exit 0
            } else {
                # Running from another location (e.g. Downloads) — update installed copy silently, keep going
                Write-Log "Update found — updating installed copy. Continuing current run."
                Copy-Item -Path $tmp -Destination $ScriptDest -Force -ErrorAction SilentlyContinue
                Remove-Item $tmp -Force -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-Log "Update check failed: $_" "WARN"
    }
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
}
"@

function Show-InventoryForm {
    param([hashtable]$HW, $FieldConfig, $Schedule)

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

    # ── Form ──────────────────────────────────────────────────────────────────
    $form                  = New-Object System.Windows.Forms.Form
    $form.Text             = "Assetly Inventory Agent"
    $form.ClientSize       = New-Object System.Drawing.Size(520, 684)
    $form.StartPosition    = "CenterScreen"
    $form.FormBorderStyle  = "FixedDialog"
    $form.MaximizeBox      = $false
    $form.BackColor        = [System.Drawing.Color]::FromArgb(245, 247, 250)
    $form.Font             = New-Object System.Drawing.Font("Segoe UI", 10)

    # ── Header bar ────────────────────────────────────────────────────────────
    $hdr           = New-Object System.Windows.Forms.Panel
    $hdr.Location  = New-Object System.Drawing.Point(0, 0)
    $hdr.Size      = New-Object System.Drawing.Size(520, 80)
    $hdr.BackColor = [System.Drawing.Color]::FromArgb(26, 43, 90)

    # ── Logo ──────────────────────────────────────────────────────────────────
    # assetly_logo.svg, drawn with GDI+ rather than loaded: WinForms has no SVG
    # decoder, and painting the shapes keeps the agent a single self-contained
    # file (the .exe build has no sibling image to read). Every coordinate below
    # is the SVG's own, mapped through $s onto the header.
    $logoBox          = New-Object System.Windows.Forms.Panel
    $logoBox.Location = New-Object System.Drawing.Point(16, 4)
    $logoBox.Size     = New-Object System.Drawing.Size(160, 72)   # 400x180 * 0.4
    $logoBox.BackColor = [System.Drawing.Color]::FromArgb(26, 43, 90)
    $logoBox.Add_Paint({
        param($sender, $e)
        $g = $e.Graphics
        $g.SmoothingMode     = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAlias
        $s = 160 / 400                                  # SVG user units -> pixels

        $teal  = [System.Drawing.Color]::FromArgb(78, 205, 180)   # #4ECDB4
        $node  = [System.Drawing.Color]::FromArgb(242, 245, 247)  # #F2F5F7

        # backdrop: rect 400x180 rx=18
        $r  = 18 * $s
        $bg = New-Object System.Drawing.Drawing2D.GraphicsPath
        $bg.AddArc(0, 0, 2*$r, 2*$r, 180, 90)
        $bg.AddArc(160 - 2*$r, 0, 2*$r, 2*$r, 270, 90)
        $bg.AddArc(160 - 2*$r, 72 - 2*$r, 2*$r, 2*$r, 0, 90)
        $bg.AddArc(0, 72 - 2*$r, 2*$r, 2*$r, 90, 90)
        $bg.CloseFigure()
        $bgBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(13, 17, 25))
        $g.FillPath($bgBrush, $bg)

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
    $hdr.Controls.Add($logoBox)

    $form.Controls.Add($hdr)

    # ── Red accent line ───────────────────────────────────────────────────────
    $accent           = New-Object System.Windows.Forms.Panel
    $accent.Location  = New-Object System.Drawing.Point(0, 80)
    $accent.Size      = New-Object System.Drawing.Size(520, 4)
    $accent.BackColor = [System.Drawing.Color]::FromArgb(232, 48, 58)
    $form.Controls.Add($accent)

    # ── Welcome text ──────────────────────────────────────────────────────────
    $welcome           = New-Object System.Windows.Forms.Label
    $welcome.Text      = "Hello, I am Inventory Agent of Assetly and I need following information"
    $welcome.Location  = New-Object System.Drawing.Point(26, 96)
    $welcome.Size      = New-Object System.Drawing.Size(468, 40)
    $welcome.Font      = New-Object System.Drawing.Font("Segoe UI", 11)
    $form.Controls.Add($welcome)

    # ── Input rows ────────────────────────────────────────────────────────────
    # One row per configured field, in the order the server sent them. Nothing
    # here knows which fields exist; that is entirely the portal's call.
    $yPos = 148

    foreach ($field in $userFields) {
        $lbl          = New-Object System.Windows.Forms.Label
        $lbl.Text     = if ($field.required) { "$($field.label) *" } else { $field.label }
        $lbl.Location = New-Object System.Drawing.Point(26, ($yPos + 4))
        $lbl.Size     = New-Object System.Drawing.Size(120, 22)
        $lbl.Font     = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
        # Labels are admin-authored now, so one can be longer than the column.
        # An ellipsis at least says so, where a plain clip silently cuts a word.
        $lbl.AutoEllipsis = $true
        $form.Controls.Add($lbl)

        if ($field.key -eq 'department') {
            $ctrl                 = New-Object System.Windows.Forms.ComboBox
            $ctrl.DropDownStyle   = "DropDownList"
            $options = if ($field.PSObject.Properties.Match('options').Count -gt 0 -and $field.options) {
                @($field.options)
            } else {
                $DefaultDepartments
            }
            $options | ForEach-Object { $ctrl.Items.Add($_) | Out-Null }
            if ($ctrl.Items.Count -gt 0) { $ctrl.SelectedIndex = 0 }
        } else {
            $ctrl = New-Object System.Windows.Forms.TextBox
        }
        $ctrl.Location = New-Object System.Drawing.Point(152, $yPos)
        $ctrl.Size     = New-Object System.Drawing.Size(342, 28)
        $ctrl.Font     = New-Object System.Drawing.Font("Segoe UI", 10)
        $form.Controls.Add($ctrl)

        $controls[$field.key] = $ctrl
        $yPos += 44
    }

    # ── Separator ─────────────────────────────────────────────────────────────
    $sep           = New-Object System.Windows.Forms.Panel
    $sep.Location  = New-Object System.Drawing.Point(26, ($yPos + 10))
    $sep.Size      = New-Object System.Drawing.Size(468, 1)
    $sep.BackColor = [System.Drawing.Color]::FromArgb(208, 213, 221)
    $form.Controls.Add($sep)
    $yPos += 22

    # ── Device info preview ───────────────────────────────────────────────────
    $lblHint           = New-Object System.Windows.Forms.Label
    $lblHint.Text      = "Device information that will be recorded:"
    $lblHint.Location  = New-Object System.Drawing.Point(26, $yPos)
    $lblHint.Size      = New-Object System.Drawing.Size(468, 20)
    $lblHint.Font      = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $lblHint.ForeColor = [System.Drawing.Color]::FromArgb(55, 65, 81)
    $form.Controls.Add($lblHint)
    $yPos += 24

    # Only the rows that will actually be submitted: the label above promises
    # "information that will be recorded", and the payload built in MAIN drops
    # every hardware key the company has switched off.
    $hwRows = [ordered]@{
        "Device" = "$($HW.brand) $($HW.model)"
        "Serial" = $HW.serial_number
        "OS"     = $HW.os
    }
    if ($enabledHw -contains 'cpu')     { $hwRows["CPU"]     = $HW.cpu }
    if ($enabledHw -contains 'ram')     { $hwRows["RAM"]     = $HW.ram }
    if ($enabledHw -contains 'storage') { $hwRows["Storage"] = $HW.storage }
    $hwRows["Hostname"] = if ($enabledHw -contains 'ip_address') {
        "$($HW.hostname)  /  $($HW.ip_address)"
    } else {
        $HW.hostname
    }
    $hwPanelHeight = 16 + (18 * $hwRows.Count)

    $hwPanel           = New-Object System.Windows.Forms.Panel
    $hwPanel.Location  = New-Object System.Drawing.Point(26, $yPos)
    $hwPanel.Size      = New-Object System.Drawing.Size(468, $hwPanelHeight)
    $hwPanel.BackColor = [System.Drawing.Color]::FromArgb(229, 234, 242)
    $form.Controls.Add($hwPanel)

    $ry = 8
    foreach ($key in $hwRows.Keys) {
        $kLbl           = New-Object System.Windows.Forms.Label
        $kLbl.Text      = "${key}:"
        $kLbl.Location  = New-Object System.Drawing.Point(10, $ry)
        $kLbl.Size      = New-Object System.Drawing.Size(72, 18)
        $kLbl.Font      = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
        $kLbl.ForeColor = [System.Drawing.Color]::FromArgb(55, 65, 81)
        $hwPanel.Controls.Add($kLbl)

        $vLbl           = New-Object System.Windows.Forms.Label
        $vLbl.Text      = $hwRows[$key]
        $vLbl.Location  = New-Object System.Drawing.Point(86, $ry)
        $vLbl.Size      = New-Object System.Drawing.Size(374, 18)
        $vLbl.Font      = New-Object System.Drawing.Font("Segoe UI", 9)
        $vLbl.ForeColor = [System.Drawing.Color]::FromArgb(31, 41, 55)
        $hwPanel.Controls.Add($vLbl)

        $ry += 18
    }
    $yPos += $hwPanelHeight + 8

    # ── Buttons ───────────────────────────────────────────────────────────────
    $btnSubmit             = New-Object System.Windows.Forms.Button
    $btnSubmit.Text        = "Submit"
    $btnSubmit.Location    = New-Object System.Drawing.Point(330, ($yPos + 8))
    $btnSubmit.Size        = New-Object System.Drawing.Size(90, 32)
    $btnSubmit.Font        = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $btnSubmit.BackColor   = [System.Drawing.Color]::FromArgb(232, 48, 58)
    $btnSubmit.ForeColor   = [System.Drawing.Color]::White
    $btnSubmit.FlatStyle   = "Flat"
    $btnSubmit.FlatAppearance.BorderSize = 0
    $form.Controls.Add($btnSubmit)

    $btnCancel             = New-Object System.Windows.Forms.Button
    $btnCancel.Text        = "Cancel"
    $btnCancel.Location    = New-Object System.Drawing.Point(430, ($yPos + 8))
    $btnCancel.Size        = New-Object System.Drawing.Size(76, 32)
    $btnCancel.Font        = New-Object System.Drawing.Font("Segoe UI", 10)
    $btnCancel.BackColor   = [System.Drawing.Color]::FromArgb(229, 231, 235)
    $btnCancel.FlatStyle   = "Flat"
    $btnCancel.FlatAppearance.BorderSize = 0
    $form.Controls.Add($btnCancel)

    # The row count is now whatever the company configured, so the window is
    # sized to its contents instead of to a fixed guess -- otherwise adding a
    # couple of custom fields pushes Submit off the bottom edge.
    $form.ClientSize = New-Object System.Drawing.Size(520, ($yPos + 56))

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

if (-not (Test-Schedule $state.schedule) -or
    $state.schedule.checkin_interval_seconds -ne $schedule.checkin_interval_seconds -or
    $state.schedule.cancel_retry_seconds     -ne $schedule.cancel_retry_seconds) {
    $state | Add-Member -NotePropertyName schedule -NotePropertyValue $schedule -Force
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
$res = Show-InventoryForm -HW $hw -FieldConfig $fieldConfig -Schedule $schedule

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
$dialogMsg = "Thank you, $($ud.first_name)!`n`nYour device has been registered."
if (-not $immediate) { $dialogMsg += "`n`n(Offline — data will sync automatically.)" }
[System.Windows.Forms.MessageBox]::Show($dialogMsg, "Assetly Inventory – Done",
    [System.Windows.Forms.MessageBoxButtons]::OK,
    [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null

Write-Log "=== Completed successfully ==="
