#Requires -Version 5.1
<#
.SYNOPSIS
    Compiles AssetlyAgent_Windows.ps1 into the executable the admin portal
    serves for "Download for Windows".

.DESCRIPTION
    The real build logic lives here rather than in Build_Windows_EXE.cmd so that
    CI and a local double-click compile the same way, with the same ps2exe
    flags. The .cmd is now a thin wrapper around this script.

    Output defaults to backend\static\, which is the exact path the backend
    reads (WINDOWS_EXE_PATH in backend/app/config.py) and the directory
    vercel.json bundles into the deployed function. Building anywhere else
    produces an executable the portal will not find.

    Must run under Windows PowerShell 5.1 on Windows: ps2exe compiles through
    the .NET C# compiler and does not work on PowerShell Core or on macOS.

    The version stamped into the executable is read out of the agent source
    rather than hardcoded here.

    This build deliberately does NOT Authenticode-sign its output, and must not
    be changed to. The code-signing key follows the same custody rule as the
    release key: it never enters CI, because CI that can sign is CI whose
    compromise produces artifacts the whole fleet trusts. Signing happens
    offline in backend/scripts/sign_release.py, and
    .github/workflows/release-consistency.yml compares this always-unsigned
    output against the manifest's unsigned_sha256 to prove the signed release
    was built from the current source. Signing here would break that check.
#>
[CmdletBinding()]
param(
    [string]$InputFile  = "$PSScriptRoot\AssetlyAgent_Windows.ps1",
    [string]$OutputFile = "$PSScriptRoot\backend\static\AssetlyAgent_Windows.exe"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $InputFile)) {
    throw "Agent source not found at $InputFile"
}

# ── Version ──────────────────────────────────────────────────────────────────
# Read from the agent source instead of being hardcoded. These two numbers used
# to drift -- the script reported 2.0 in every check-in while the executable's
# Properties dialog said 1.0.0.0 -- which made a version a user read off their
# own machine impossible to match against anything in the portal.
$versionMatch = [regex]::Match(
    (Get-Content -LiteralPath $InputFile -Raw),
    '(?m)^\$AgentVersion\s*=\s*"([0-9]+(?:\.[0-9]+){1,3})"')
if (-not $versionMatch.Success) {
    throw "Could not find a `$AgentVersion assignment in $InputFile. It is the single source of truth for the build version; do not hardcode one here instead."
}
$agentVersion = $versionMatch.Groups[1].Value
# ps2exe requires four components; the agent declares three.
$fileVersion = $agentVersion
while (($fileVersion -split '\.').Count -lt 4) { $fileVersion = "$fileVersion.0" }
Write-Host "[0/3] Agent version from source: $agentVersion (file version $fileVersion)"

if (-not (Get-Module ps2exe -ListAvailable)) {
    Write-Host "[1/3] Installing ps2exe from the PowerShell Gallery..."
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    Install-Module ps2exe -Force -Scope CurrentUser -Repository PSGallery
} else {
    Write-Host "[1/3] ps2exe already installed."
}
Import-Module ps2exe

Write-Host "[2/3] Compiling $InputFile ..."
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $OutputFile) | Out-Null
Invoke-ps2exe -InputFile $InputFile -OutputFile $OutputFile `
    -NoConsole -STA `
    -Title 'Assetly Inventory Agent' `
    -Description 'Assetly device inventory check-in agent' `
    -Company 'Assetly' `
    -Version $fileVersion

# ps2exe reports success on some failures that leave no usable output, and a
# truncated or non-PE file would only surface as an unexplained "this app can't
# run on your PC" on an employee's machine.
Write-Host "[3/3] Verifying the build..."
if (-not (Test-Path $OutputFile)) {
    throw "ps2exe reported success but produced no file at $OutputFile"
}
$bytes = [System.IO.File]::ReadAllBytes($OutputFile)
if ($bytes.Length -lt 10240) {
    throw "$OutputFile is only $($bytes.Length) bytes - too small to be a real build"
}
if ($bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) {
    throw "$OutputFile is not a PE image (missing the MZ header)"
}

Write-Host ""
Write-Host "  Built: $OutputFile ($([math]::Round($bytes.Length / 1KB, 1)) KiB, version $fileVersion)"
