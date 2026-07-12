<#
.SYNOPSIS
    Registers Sentinel Backup as a Windows Scheduled Task.

.DESCRIPTION
    The original design ran an infinite `while True: sleep(6h)` loop in a
    console window. That has three problems a paying customer will hit:

      1. Close the window (or reboot) and the backup silently stops forever.
      2. It never runs when the machine was asleep at the scheduled moment.
      3. It holds a Python process resident for the sake of sleeping.

    Task Scheduler fixes all three. It survives reboot, runs missed jobs on
    wake, and costs nothing while idle.

.EXAMPLE
    .\Install-SentinelTask.ps1 -IntervalHours 6

.EXAMPLE
    .\Install-SentinelTask.ps1 -RunOnDriveConnect
#>

[CmdletBinding()]
param(
    [int]$IntervalHours = 6,
    [string]$TaskName = "SentinelBackup",
    [switch]$RunOnDriveConnect,
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$Target     = Join-Path $ScriptDir "sentinel_backup.py"

if ($Uninstall) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "Removed scheduled task '$TaskName'." -ForegroundColor Green
    return
}

if (-not (Test-Path $Target)) { throw "sentinel_backup.py not found in $ScriptDir" }

# pythonw.exe runs with no console window - the backup happens invisibly.
$Python = (Get-Command pythonw.exe -ErrorAction SilentlyContinue).Source
if (-not $Python) { $Python = (Get-Command python.exe -ErrorAction Stop).Source }

$Action = New-ScheduledTaskAction -Execute $Python `
    -Argument "`"$Target`" run --quiet" -WorkingDirectory $ScriptDir

$Triggers = @(
    New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) `
        -RepetitionInterval (New-TimeSpan -Hours $IntervalHours)
    New-ScheduledTaskTrigger -AtLogOn
)

$Settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -DontStopOnIdleEnd `
    -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 10) `
    -ExecutionTimeLimit (New-TimeSpan -Hours 4) `
    -MultipleInstances IgnoreNew   # never let two cycles race each other

Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Triggers `
    -Settings $Settings -Description "Sentinel Backup - verified sync to external drive" `
    -Force | Out-Null

Write-Host "Installed '$TaskName': runs every $IntervalHours hour(s) and at logon." -ForegroundColor Green
Write-Host "  Test it now : Start-ScheduledTask -TaskName $TaskName"
Write-Host "  Check status: python `"$Target`" status"
Write-Host "  Remove it   : .\Install-SentinelTask.ps1 -Uninstall"

if ($RunOnDriveConnect) {
    Write-Host "`nTo also fire the moment the drive is plugged in, run as Administrator:" -ForegroundColor Yellow
    Write-Host '  Create a task with an Event trigger on Log=Microsoft-Windows-Kernel-PnP/Device Configuration, ID=410'
}
