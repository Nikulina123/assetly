#Requires -Version 5.1
<#
.SYNOPSIS
    Registers (or removes) the machine-wide Assetly Inventory Agent scheduled
    task. Invoked by the MSI's custom actions; also runnable by hand for
    recovery.

.DESCRIPTION
    Two things make this a script rather than a schtasks command line:

    1. The task needs two triggers. A logon trigger alone would mean a laptop
       that stays logged in for weeks never re-fires, so the 24-hour
       cancel-retry window would never come round; an hourly repetition alone
       would miss the "just logged in, desktop is ready" moment the form wants.
       schtasks cannot express both in one invocation.

    2. The principal is a GROUP, not a user. The old per-user registration in
       the agent itself bound the task to whoever happened to run the
       downloaded .exe, so a second user of the same PC was never inventoried.
       Registering against BUILTIN\Users with an interactive logon type means
       the task exists once, machine-wide, and runs in the session of whichever
       user is actually logged on -- which is what makes the GUI appear for
       them rather than in an invisible session 0.

    Runs as SYSTEM under the MSI. Everything it does is machine-scope, so it
    needs no per-user context.
#>
[CmdletBinding()]
param(
    [string]$ExePath,
    [switch]$Remove
)

$ErrorActionPreference = "Stop"
$TaskName = "AssetlyInventoryAgent"

# Best-effort log beside the MSI's own, since a custom action's output is not
# otherwise visible anywhere. ProgramData rather than the install directory:
# the install directory is removed during uninstall while this is still
# writing to it.
$LogDir  = Join-Path $env:ProgramData "Assetly"
$LogFile = Join-Path $LogDir "install.log"
function Write-InstallLog {
    param([string]$Msg)
    try {
        if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
        Add-Content -Path $LogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  $Msg" -Encoding UTF8
    } catch {}
}

if ($Remove) {
    Write-InstallLog "Removing scheduled task '$TaskName'."
    # SilentlyContinue, and the script still exits 0: an uninstall must never
    # be blocked by a task that is already gone.
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-InstallLog "Removal complete."
    exit 0
}

if (-not $ExePath) { throw "-ExePath is required when registering the task." }
if (-not (Test-Path $ExePath)) { throw "No agent executable at $ExePath" }

Write-InstallLog "Registering scheduled task '$TaskName' for $ExePath"

$action = New-ScheduledTaskAction -Execute $ExePath

# Any user's logon, after a delay that lets the desktop finish coming up --
# the form is a WinForms dialog and appearing mid-logon puts it behind the
# shell. Was 90 seconds, which real use showed reads as "nothing happened":
# the screen stays empty long enough that a person concludes the agent is
# broken. 40 seconds is still past the shell settling on an ordinary machine
# and short enough to feel like a consequence of logging in.
$triggerLogon       = New-ScheduledTaskTrigger -AtLogOn
$triggerLogon.Delay = "PT40S"

# Indefinite hourly repetition. The start boundary is deliberately in the past
# so the repetition is already live rather than waiting for a first occurrence.
$triggerHourly = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) `
    -RepetitionInterval (New-TimeSpan -Hours 1) `
    -RepetitionDuration (New-TimeSpan -Days 9999)

$settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit (New-TimeSpan -Hours 1) `
    -MultipleInstances  IgnoreNew
# Laptops are the machines most likely to be missed entirely if the default
# battery rules are left in place.
$settings.DisallowStartIfOnBatteries = $false
$settings.StopIfGoingOnBatteries     = $false

# S-1-5-32-545 rather than the localised name "Users": on a German or French
# Windows the literal string does not resolve and registration fails.
$principal = New-ScheduledTaskPrincipal `
    -GroupId   "S-1-5-32-545" `
    -RunLevel  Limited

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName $TaskName `
    -Action    $action `
    -Trigger   @($triggerLogon, $triggerHourly) `
    -Settings  $settings `
    -Principal $principal `
    -Description "Assetly Inventory Agent — checks in on the schedule configured in the portal" | Out-Null

Write-InstallLog "Registration complete."
