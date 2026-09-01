#Requires -Version 5.1
<#
.SYNOPSIS
    Builds AssetlyAgent.msi — the per-machine installer IT deploys through
    Intune, SCCM, GPO or PDQ.

.DESCRIPTION
    The .exe is not replaced by this: it stays the artifact the portal serves
    for a single user installing the agent on their own machine, and it stays
    the artifact the self-update path downloads. The MSI is the additional,
    fleet-deployment shape of the same binary.

    Requires the WiX v5 dotnet tool. Produces an UNSIGNED MSI: signing is done
    offline by backend/scripts/sign_release.py, on the release owner's machine,
    around the already-signed executable. Nothing in CI holds a signing key.

    This script is the convenience wrapper for building and testing an MSI on a
    Windows machine. The release path does not call it -- sign_release.py
    invokes `wix build` directly, because WiX v4+ is cross-platform and the
    release owner is not necessarily on Windows.

.NOTES
    Version, like the executable's, is read from $AgentVersion in the agent
    source. There is one version number in this repository and this is not
    where it lives.
#>
[CmdletBinding()]
param(
    [string]$AgentSource = "$PSScriptRoot\..\AssetlyAgent_Windows.ps1",
    [string]$AgentExe    = "$PSScriptRoot\..\backend\static\AssetlyAgent_Windows.exe",
    [string]$OutputFile  = "$PSScriptRoot\..\backend\static\AssetlyAgent.msi"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $AgentExe)) {
    throw "No agent executable at $AgentExe. Run Build_Windows_EXE.ps1 first — the MSI packages its output, it does not compile anything itself."
}

# ── Version, from the same single source the .exe build reads ────────────────
$versionMatch = [regex]::Match(
    (Get-Content -LiteralPath $AgentSource -Raw),
    '(?m)^\$AgentVersion\s*=\s*"([0-9]+(?:\.[0-9]+){1,3})"')
if (-not $versionMatch.Success) {
    throw "Could not find a `$AgentVersion assignment in $AgentSource."
}
$agentVersion = $versionMatch.Groups[1].Value
Write-Host "[1/3] Agent version from source: $agentVersion"

# ── WiX ──────────────────────────────────────────────────────────────────────
Write-Host "[2/3] Ensuring the WiX toolset is available..."
if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
    dotnet tool install --global wix --version 5.*
    # The tool lands in ~\.dotnet\tools, which is only on PATH for shells
    # started after the install.
    $env:PATH = "$env:PATH;$env:USERPROFILE\.dotnet\tools"
}
wix --version

# ── Build ────────────────────────────────────────────────────────────────────
Write-Host "[3/3] Building $OutputFile ..."
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $OutputFile) | Out-Null

# -arch x64: ProgramFiles6432Folder resolves to "Program Files" rather than
# "Program Files (x86)". The packaged executable is AnyCPU, so it runs either
# way; the point is that IT and end users find it where they expect.
wix build "$PSScriptRoot\AssetlyAgent.wxs" `
    -arch x64 `
    -d "AgentVersion=$agentVersion" `
    -d "AgentExe=$(Resolve-Path $AgentExe)" `
    -d "TaskScript=$PSScriptRoot\Install-AssetlyTask.ps1" `
    -d "MarkerFile=$PSScriptRoot\assetly-managed.marker" `
    -o $OutputFile
if ($LASTEXITCODE -ne 0) { throw "wix build failed with exit code $LASTEXITCODE" }

if (-not (Test-Path $OutputFile)) {
    throw "wix reported success but produced no file at $OutputFile"
}

$size = (Get-Item $OutputFile).Length
Write-Host ""
Write-Host "  Built: $OutputFile ($([math]::Round($size / 1KB, 1)) KiB, version $agentVersion)"
