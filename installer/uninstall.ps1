<#
.SYNOPSIS
    Removes the SMTP Relay Windows service and its installation.

.DESCRIPTION
    Stops and unregisters the service, removes the Add/Remove Programs entry and
    deletes -InstallDir. Configuration under -ConfigDir is PRESERVED unless
    -RemoveConfig is passed, so a reinstall keeps the existing settings.

    Run from an ELEVATED prompt.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\uninstall.ps1
    powershell -ExecutionPolicy Bypass -File .\uninstall.ps1 -RemoveConfig
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

$VenvPython = Join-Path $InstallDir '.venv\Scripts\python.exe'

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
    if (Test-Path $VenvPython) {
        Push-Location $InstallDir
        try {
            & $VenvPython -m app.windows_service remove 2>&1 | Out-Null
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

Write-Host "`nUninstall complete." -ForegroundColor Green
