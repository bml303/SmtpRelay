<#
.SYNOPSIS
    Removes the SMTP Relay Windows service and every artifact it created.

.DESCRIPTION
    Stops and unregisters the service, then removes:
      - the Apps & features registry entry
      - the Event Log source registration (deleting the service does NOT do this)
      - the firewall rule created by install.ps1 -OpenFirewall
      - -InstallDir, including the bundled CPython runtime
      - -ConfigDir, only when -RemoveConfig is passed

    Finishes by re-checking each location and reporting anything that survived,
    so a clean-slate reinstall can be trusted rather than assumed.

    Run from an ELEVATED prompt.

.EXAMPLE
    # Clean slate - remove everything, including configuration:
    powershell -ExecutionPolicy Bypass -File .\uninstall.ps1 -RemoveConfig

.EXAMPLE
    # Upgrade in place - keep C:\ProgramData\SmtpRelay\config.toml:
    powershell -ExecutionPolicy Bypass -File .\uninstall.ps1
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string] $InstallDir  = (Join-Path $env:ProgramFiles 'SmtpRelay'),
    [string] $ConfigDir   = (Join-Path $env:ProgramData 'SmtpRelay'),
    [string] $ServiceName = 'SmtpRelay',
    [switch] $RemoveConfig
)

$ErrorActionPreference = 'Continue'
Set-StrictMode -Version Latest

$Python = Join-Path $InstallDir 'python\python.exe'

function Write-Step { param([string] $Message) Write-Host "`n==> $Message" -ForegroundColor Cyan }
function Write-Ok   { param([string] $Message) Write-Host "    $Message" -ForegroundColor Green }
function Write-Warn2{ param([string] $Message) Write-Host "    $Message" -ForegroundColor Yellow }

# ------------------------------------------------------------------ service

Write-Step "Removing service '$ServiceName'"

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -ne 'Stopped') {
        Write-Host "    stopping..."
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        # Give uvicorn time to drain; the service allows up to 30s.
        for ($i = 0; $i -lt 15; $i++) {
            if ((Get-Service -Name $ServiceName -ErrorAction SilentlyContinue).Status -eq 'Stopped') { break }
            Start-Sleep -Seconds 1
        }
    }

    $removed = $false
    if (Test-Path $Python) {
        Push-Location $InstallDir
        try {
            & $Python -m app.windows_service remove 2>&1 | Out-Null
            $removed = ($LASTEXITCODE -eq 0)
        } finally {
            Pop-Location
        }
    }

    if (-not $removed) {
        # The venv may already be gone or broken; the SCM entry is independent.
        & sc.exe delete $ServiceName | Out-Null
        $removed = ($LASTEXITCODE -eq 0)
    }

    if ($removed) { Write-Ok "Service removed" }
    else { Write-Warn2 "Could not remove the service; try 'sc.exe delete $ServiceName' manually." }
} else {
    Write-Ok "Service not installed"
}

# ----------------------------------------------------------------- registry

Write-Step "Removing Add/Remove Programs entry"
$uninstallKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$ServiceName"
if (Test-Path $uninstallKey) {
    Remove-Item $uninstallKey -Recurse -Force
    Write-Ok "Registry entry removed"
} else {
    Write-Ok "No registry entry present"
}

# -------------------------------------------------------------------- files

Write-Step "Removing $InstallDir"
if (Test-Path $InstallDir) {
    Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path $InstallDir) {
        Write-Warn2 "Some files remain (in use, or a permissions problem). Delete manually:"
        Write-Warn2 "  Remove-Item '$InstallDir' -Recurse -Force"
    } else {
        Write-Ok "Removed"
    }
} else {
    Write-Ok "Not present"
}

Write-Step "Configuration"
if ($RemoveConfig) {
    if (Test-Path $ConfigDir) {
        Remove-Item $ConfigDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Ok "Removed $ConfigDir"
    } else {
        Write-Ok "$ConfigDir not present"
    }
} else {
    Write-Warn2 "Preserved $ConfigDir (pass -RemoveConfig to delete it)."
}

# ----------------------------------------------------------------- event log

Write-Step "Removing Event Log source registration"
# install.ps1 registers this (the virtual service account cannot). Deleting the
# service does NOT remove it, so it would otherwise survive every reinstall
# carrying stale message-file paths.
$eventLogKey = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\$ServiceName"
if (Test-Path $eventLogKey) {
    Remove-Item $eventLogKey -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path $eventLogKey) { Write-Warn2 "Could not remove $eventLogKey" }
    else { Write-Ok "Event Log source removed" }
} else {
    Write-Ok "No Event Log source registered"
}

# ------------------------------------------------------------------ firewall

Write-Step "Removing firewall rule"
$ruleName = "SMTP Relay ($ServiceName)"
$rules = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
if ($rules) {
    $rules | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    if (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue) {
        Write-Warn2 "Could not remove rule '$ruleName'"
    } else {
        Write-Ok "Removed '$ruleName'"
    }
} else {
    Write-Ok "No rule named '$ruleName'"
}

# -------------------------------------------------------------- verification

Write-Step "Verifying nothing remains"
$residue = @()
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) { $residue += "service '$ServiceName'" }
if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName") { $residue += "SCM registry key" }
if (Test-Path $eventLogKey) { $residue += "Event Log source" }
if (Test-Path $uninstallKey) { $residue += "Apps & features entry" }
if (Test-Path $InstallDir) { $residue += $InstallDir }
if ($RemoveConfig -and (Test-Path $ConfigDir)) { $residue += $ConfigDir }
if (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue) { $residue += "firewall rule" }

if ($residue.Count -gt 0) {
    Write-Warn2 ("Still present: " + ($residue -join '; '))
    Write-Warn2 "A service marked for deletion keeps its SCM key until every handle"
    Write-Warn2 "to it closes. If that is the only residue, reboot and re-check."
} else {
    Write-Ok "Clean - no residue detected"
}

Write-Host "`nUninstall complete." -ForegroundColor Green
