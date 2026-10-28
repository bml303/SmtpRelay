<#
.SYNOPSIS
    Installs the SMTP Relay Windows service from an offline payload.

.DESCRIPTION
    Creates a venv under -InstallDir, installs every dependency from the bundled
    wheels directory with --no-index (no internet, no C/C++ compiler), seeds
    configuration into -ConfigDir, and registers the service with the SCM.

    Run from an ELEVATED prompt, from inside the payload directory.

.PARAMETER InstallDir
    Read-only program location. Default: C:\Program Files\SmtpRelay

.PARAMETER ConfigDir
    Mutable configuration location. Default: C:\ProgramData\SmtpRelay
    Deliberately NOT under InstallDir: Program Files is wiped on upgrade and is
    readable by all local users, which matters if config.toml holds credentials.

.PARAMETER Start
    Start the service once installation succeeds.

.PARAMETER Force
    Overwrite an existing InstallDir instead of aborting.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\install.ps1
    powershell -ExecutionPolicy Bypass -File .\install.ps1 -Start
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string] $InstallDir  = (Join-Path $env:ProgramFiles 'SmtpRelay'),
    [string] $ConfigDir   = (Join-Path $env:ProgramData 'SmtpRelay'),
    [string] $ServiceName = 'SmtpRelay',
    # Virtual service account: a per-service SID with no admin rights and no
    # password to rotate. It still presents the computer account on the network,
    # so NTLM/Kerberos SMTP auth works. Unlike NetworkService it is not shared
    # with every other service on the box, so the ACL grants below are readable
    # by this service alone.
    [string] $ServiceAccount = "NT SERVICE\$ServiceName",
    [string] $PythonVersion = '3.15',
    [string] $PythonExecutable,
    [int]    $ApiPort = 8000,
    [switch] $OpenFirewall,
    [switch] $Start,
    [switch] $Force
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$PayloadDir = $PSScriptRoot
$WheelDir   = Join-Path $PayloadDir 'wheels'
$VenvDir    = Join-Path $InstallDir '.venv'
$VenvPython = Join-Path $VenvDir 'Scripts\python.exe'
$VenvPip    = Join-Path $VenvDir 'Scripts\pip.exe'

function Write-Step { param([string] $Message) Write-Host "`n==> $Message" -ForegroundColor Cyan }
function Write-Ok   { param([string] $Message) Write-Host "    $Message" -ForegroundColor Green }
function Write-Warn2{ param([string] $Message) Write-Host "    $Message" -ForegroundColor Yellow }

function Stop-WithError {
    param([string] $Message, [string] $Hint)
    Write-Host "`nERROR: $Message" -ForegroundColor Red
    if ($Hint) { Write-Host "       $Hint" -ForegroundColor Yellow }
    exit 1
}

function Invoke-Checked {
    param([string] $What, [scriptblock] $Action)
    & $Action
    if ($LASTEXITCODE -ne 0) {
        Stop-WithError "$What failed (exit $LASTEXITCODE)."
    }
}

# ---------------------------------------------------------------- validation

Write-Step "Validating payload in $PayloadDir"

foreach ($required in @($WheelDir, (Join-Path $PayloadDir 'app'), (Join-Path $PayloadDir 'pyproject.toml'))) {
    if (-not (Test-Path $required)) {
        Stop-WithError "Payload is incomplete: '$required' is missing." `
            "Run install.ps1 from inside the extracted payload directory."
    }
}

$Version = 'unknown'
$ManifestPath = Join-Path $PayloadDir 'MANIFEST.json'
if (Test-Path $ManifestPath) {
    $manifest = Get-Content $ManifestPath -Raw | ConvertFrom-Json
    $Version = $manifest.version
    Write-Ok "SmtpRelay $Version for $($manifest.platform) / cp$($manifest.python_version -replace '\.','')"
    if ($manifest.python_version -and $manifest.python_version -ne $PythonVersion) {
        Write-Warn2 "Payload was built for Python $($manifest.python_version) but -PythonVersion is $PythonVersion."
    }
} else {
    Write-Warn2 "No MANIFEST.json; continuing without version metadata."
}

$wheelCount = (Get-ChildItem $WheelDir -Filter '*.whl' -ErrorAction SilentlyContinue).Count
if ($wheelCount -lt 20) {
    Stop-WithError "Only $wheelCount wheels in '$WheelDir'; the bundle looks truncated."
}
Write-Ok "$wheelCount wheels available for offline install"

if ((Test-Path $InstallDir) -and -not $Force) {
    Stop-WithError "'$InstallDir' already exists." "Re-run with -Force to replace it."
}

# ------------------------------------------------------------------- python

Write-Step "Locating a Python interpreter (>= 3.11)"

$probe = 'import sys; print("%d.%d" % sys.version_info[:2])'
$resolved = $null

if ($PythonExecutable) {
    $candidates = @(, @($PythonExecutable, @()))
} else {
    $candidates = @()
    if (Get-Command py.exe -ErrorAction SilentlyContinue) {
        $candidates += , @('py.exe', @("-$PythonVersion"))
        $candidates += , @('py.exe', @('-3'))
    }
    $candidates += , @('python.exe', @())
}

foreach ($candidate in $candidates) {
    $exe = $candidate[0]
    $pre = $candidate[1]
    try {
        $out = & $exe @pre -c $probe 2>$null
    } catch { $out = $null }
    if ($LASTEXITCODE -eq 0 -and $out) {
        $resolved = [pscustomobject]@{ Exe = $exe; PreArgs = $pre; Version = $out.Trim() }
        break
    }
}

if (-not $resolved) {
    Stop-WithError "No usable Python interpreter found." `
        "Install Python 3.11+ from python.org, or pass -PythonExecutable 'C:\path\to\python.exe'."
}

$major, $minor = $resolved.Version.Split('.') | ForEach-Object { [int] $_ }
if ($major -lt 3 -or ($major -eq 3 -and $minor -lt 11)) {
    Stop-WithError "Python $($resolved.Version) is too old; 3.11 or newer is required."
}
Write-Ok "Using $($resolved.Exe) $($resolved.PreArgs -join ' ') (Python $($resolved.Version))"

# ------------------------------------------------------------------ install

Write-Step "Preparing $InstallDir"
if (Test-Path $InstallDir) { Remove-Item $InstallDir -Recurse -Force }
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null

foreach ($item in @('app', 'pyproject.toml', 'README.md', 'config.example.toml', 'requirements.txt')) {
    $src = Join-Path $PayloadDir $item
    if (Test-Path $src) { Copy-Item $src -Destination $InstallDir -Recurse -Force }
}
Write-Ok "Application files copied"

Write-Step "Creating virtual environment"
Invoke-Checked "venv creation" { & $resolved.Exe @($resolved.PreArgs) -m venv $VenvDir }
if (-not (Test-Path $VenvPython)) { Stop-WithError "venv was created but '$VenvPython' is missing." }
Write-Ok "venv at $VenvDir"

# setuptools/wheel come from the bundle: Python 3.12+ venvs no longer include
# setuptools, and pip's build isolation would otherwise contact PyPI.
Write-Step "Installing build backend (offline)"
Invoke-Checked "build backend install" {
    & $VenvPip install --no-index --find-links $WheelDir --quiet setuptools wheel
}
Write-Ok "setuptools + wheel"

Write-Step "Installing dependencies from bundled wheels (offline)"
Invoke-Checked "dependency install" {
    & $VenvPip install --no-index --find-links $WheelDir --quiet -r (Join-Path $InstallDir 'requirements.txt')
}
Write-Ok "dependencies installed"

Write-Step "Installing smtp-relay"
# --no-deps: requirements.txt already pinned and installed everything.
# --no-build-isolation: use the setuptools just installed, no PyPI access.
Invoke-Checked "project install" {
    & $VenvPip install --no-index --find-links $WheelDir --no-deps --no-build-isolation --quiet $InstallDir
}
Write-Ok "smtp-relay $Version installed"

# ------------------------------------------------------------------- config

Write-Step "Configuring $ConfigDir"
New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
$configFile = Join-Path $ConfigDir 'config.toml'

if (Test-Path $configFile) {
    Write-Ok "config.toml already present - left untouched"
} else {
    Copy-Item (Join-Path $PayloadDir 'config.example.toml') $configFile
    Write-Warn2 "Seeded config.toml from the template. EDIT IT BEFORE STARTING:"
    Write-Warn2 "  notepad `"$configFile`""
}

# ACLs are applied after service registration, in the "Permissions" step below:
# the virtual service account SID (NT SERVICE\<name>) must exist before it can be
# granted anything, and granting only SYSTEM/Administrators here would lock the
# service out of its own configuration.
Write-Ok "ACLs applied after service registration"

# ------------------------------------------------------------------ service

Write-Step "Registering service '$ServiceName'"
Push-Location $InstallDir
try {
    & $VenvPython -m app.windows_service install
    $installExit = $LASTEXITCODE
} finally {
    Pop-Location
}

if ($installExit -ne 0) {
    Stop-WithError "Service registration failed (exit $installExit)." `
        "Try: & '$VenvPython' '$(Join-Path $VenvDir 'Scripts\pywin32_postinstall.py')' -install"
}
Write-Ok "Service registered"

& sc.exe config $ServiceName start= auto | Out-Null
& sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null
Write-Ok "Start type: automatic; restart on failure enabled"

# -------------------------------------------------------------- permissions

Write-Step "Applying least-privilege permissions"

# A virtual service account needs no password, and the SCM grants it
# SeServiceLogonRight automatically. A *named* account would additionally need
# that right granted in secpol.msc, or the service fails to start with error
# 1069 ("The service did not start due to a logon failure") - pywin32 does not
# grant it for you.
& sc.exe config $ServiceName obj= $ServiceAccount | Out-Null
if ($LASTEXITCODE -ne 0) {
    Stop-WithError "sc.exe could not set the account to '$ServiceAccount' (exit $LASTEXITCODE)." `
        "Re-run with -ServiceAccount 'NT AUTHORITY\NetworkService' to fall back."
}
Write-Ok "Service account: $ServiceAccount"

# The SID contains a space, so icacls needs the identity quoted while the
# permission bits stay outside the quotes.
$grantInstall = "`"$ServiceAccount`":(OI)(CI)RX"
$grantConfig  = "`"$ServiceAccount`":(OI)(CI)R"

& icacls.exe $InstallDir /grant $grantInstall | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Warn2 "Could not grant read+execute on '$InstallDir' (icacls exit $LASTEXITCODE)."
} else {
    Write-Ok "read+execute on $InstallDir"
}

# Strip inheritance on the config dir: it may hold an SMTP password or API token,
# and ProgramData subfolders otherwise inherit read access for standard users.
& icacls.exe $ConfigDir /inheritance:r `
    /grant 'SYSTEM:(OI)(CI)F' /grant 'Administrators:(OI)(CI)F' /grant $grantConfig | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Warn2 "Could not tighten ACLs on '$ConfigDir' (icacls exit $LASTEXITCODE)."
} else {
    Write-Ok "$ConfigDir : SYSTEM+Administrators full, service read-only"
}
# Note the service gets no write access anywhere: it logs to the Event Log, so it
# never needs to create a file.

# ------------------------------------------------------------------ firewall

if ($OpenFirewall) {
    Write-Step "Opening inbound TCP $ApiPort"
    try {
        New-NetFirewallRule -DisplayName "SMTP Relay ($ServiceName)" `
            -Direction Inbound -Protocol TCP -LocalPort $ApiPort -Action Allow | Out-Null
        Write-Ok "Inbound rule created for TCP $ApiPort"
        Write-Warn2 "Make sure api.port in config.toml matches $ApiPort."
    } catch {
        Write-Warn2 "Could not create the firewall rule: $($_.Exception.Message)"
    }
} else {
    Write-Step "Firewall"
    Write-Ok "Skipped - pass -OpenFirewall to allow inbound TCP $ApiPort"
    Write-Warn2 "Only needed if api.host is bound to something other than 127.0.0.1."
    Write-Warn2 "Before doing that, check the port is not in a WinNAT exclusion:"
    Write-Warn2 "  netsh int ipv4 show excludedportrange protocol=tcp"
}

# Add/Remove Programs entry.
$uninstallScript = Join-Path $InstallDir 'uninstall.ps1'
Copy-Item (Join-Path $PayloadDir 'uninstall.ps1') $uninstallScript -Force
$uninstallKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$ServiceName"
New-Item -Path $uninstallKey -Force | Out-Null
Set-ItemProperty -Path $uninstallKey -Name 'DisplayName'     -Value 'SMTP Relay'
Set-ItemProperty -Path $uninstallKey -Name 'DisplayVersion'   -Value $Version
Set-ItemProperty -Path $uninstallKey -Name 'Publisher'        -Value 'softbase.tech'
Set-ItemProperty -Path $uninstallKey -Name 'InstallLocation'  -Value $InstallDir
Set-ItemProperty -Path $uninstallKey -Name 'UninstallString'  -Value "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$uninstallScript`" -InstallDir `"$InstallDir`" -ConfigDir `"$ConfigDir`" -ServiceName `"$ServiceName`""
Set-ItemProperty -Path $uninstallKey -Name 'NoModify' -Value 1 -Type DWord
Set-ItemProperty -Path $uninstallKey -Name 'NoRepair' -Value 1 -Type DWord
Write-Ok "Listed in Apps & features"

# ------------------------------------------------------------------- finish

if ($Start) {
    Write-Step "Starting service"
    & $VenvPython -m app.windows_service start
    Start-Sleep -Seconds 2
    $state = (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue).Status
    if ($state -eq 'Running') {
        Write-Ok "Service is running"
    } else {
        Write-Warn2 "Service state is '$state'. Check the Application event log, source SmtpRelay."
    }
}

Write-Host @"

Installation complete.

  Program files : $InstallDir
  Configuration : $configFile
  Service name  : $ServiceName
  Runs as       : $ServiceAccount
  Python        : $VenvPython

Next steps:
  1. Edit the configuration:   notepad "$configFile"
  2. Verify config discovery:  & '$VenvPython' -c "from app.config import _candidate_paths; [print(p) for p in _candidate_paths(None)[0]]"
  3. Console test run:         & '$VenvPython' -m app.windows_service debug
  4. Start the service:        & '$VenvPython' -m app.windows_service start
  5. Read the logs:            Get-EventLog -LogName Application -Source SmtpRelay -Newest 20

Exposing the API beyond this machine:
  - set api.host in config.toml to the interface you want (e.g. 0.0.0.0)
  - set api.ssl_certfile / api.ssl_keyfile, and api.token or
    api.ssl_cert_reqs = "required"
  - re-run install.ps1 with -OpenFirewall (or add the rule yourself)

The application refuses to start if api.host is non-loopback without both TLS and
client authentication, so it cannot silently become a cleartext open relay. Before
picking a port, confirm it is outside the WinNAT exclusion ranges:
  netsh int ipv4 show excludedportrange protocol=tcp
"@ -ForegroundColor Green
