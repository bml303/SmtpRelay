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

.PARAMETER PfxPath
    A PKCS#12 (.pfx/.p12) file holding the API's TLS certificate and key. It is
    imported into Cert:\LocalMachine\My with an EXPORTABLE key, the service
    account is granted read access to that key, and api.ssl_cert_thumbprint in
    config.toml is pointed at it. The passphrase is asked for interactively
    unless -PfxPassword is given; it is used once and never stored.

.PARAMETER PfxPassword
    SecureString passphrase for -PfxPath. Omit to be prompted. Only usable when
    the script runs in the current session; `powershell -File` passes arguments
    as text, so a SecureString cannot cross that boundary - use the prompt.

.PARAMETER CertThumbprint
    Use a certificate that is already in Cert:\LocalMachine\My instead of
    importing one. Its key must be exportable. Grants and config as for -PfxPath.

.PARAMETER Start
    Start the service once installation succeeds.

.PARAMETER Force
    Overwrite an existing InstallDir instead of aborting.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\install.ps1
    powershell -ExecutionPolicy Bypass -File .\install.ps1 -Start
    powershell -ExecutionPolicy Bypass -File .\install.ps1 -PfxPath C:\certs\relay.pfx -Start
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
    [int]    $ApiPort = 8000,
    # TLS certificate for the API, see the "API TLS certificate" step below.
    [string]       $PfxPath,
    [securestring] $PfxPassword,
    [string]       $CertThumbprint,
    [switch] $OpenFirewall,
    [switch] $Start,
    [switch] $Force
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$PayloadDir = $PSScriptRoot
$WheelDir   = Join-Path $PayloadDir 'wheels'
$RuntimeSrc = Join-Path $PayloadDir 'python'
$RuntimeDir = Join-Path $InstallDir 'python'
# The bundled runtime IS the environment: no venv, so no pyvenv.cfg whose
# `home=` would point back into some user's Python installation.
$Python     = Join-Path $RuntimeDir 'python.exe'

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

foreach ($required in @($WheelDir, (Join-Path $RuntimeSrc 'python.exe'), (Join-Path $PayloadDir 'app'), (Join-Path $PayloadDir 'pyproject.toml'))) {
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
    Write-Ok "SmtpRelay $Version for $($manifest.platform), bundled CPython $($manifest.runtime_version)"
} else {
    Write-Warn2 "No MANIFEST.json; continuing without version metadata."
}

$wheelCount = (Get-ChildItem $WheelDir -Filter '*.whl' -ErrorAction SilentlyContinue).Count
if ($wheelCount -lt 12) {
    Stop-WithError "Only $wheelCount wheels in '$WheelDir'; the bundle looks truncated."
}
Write-Ok "$wheelCount wheels available for offline install"

if ((Test-Path $InstallDir) -and -not $Force) {
    Stop-WithError "'$InstallDir' already exists." "Re-run with -Force to replace it."
}

# Certificate switches are checked - and the passphrase asked for - before
# anything is changed, so a typo here cannot leave a half-installed service.
if ($PfxPath -and $CertThumbprint) {
    Stop-WithError "-PfxPath and -CertThumbprint are mutually exclusive." `
        "Import a file with -PfxPath, or point at a certificate already in the store with -CertThumbprint."
}
if ($PfxPath) {
    if (-not (Test-Path $PfxPath -PathType Leaf)) {
        Stop-WithError "PFX file '$PfxPath' not found."
    }
    $PfxPath = (Resolve-Path $PfxPath).Path
    if (-not $PfxPassword) {
        $PfxPassword = Read-Host -Prompt "Passphrase for $PfxPath (empty if it has none)" -AsSecureString
    }
    Write-Ok "Will import $PfxPath into Cert:\LocalMachine\My"
}
if ($CertThumbprint) {
    $CertThumbprint = ($CertThumbprint -replace '[\s:\-]', '').ToUpperInvariant()
    if ($CertThumbprint -notmatch '^[0-9A-F]{40}$') {
        Stop-WithError "-CertThumbprint must be the 40-digit SHA-1 thumbprint as shown by certlm.msc." `
            "List candidates with: Get-ChildItem Cert:\LocalMachine\My | Format-Table Thumbprint, Subject, NotAfter"
    }
    Write-Ok "Will use certificate $CertThumbprint from Cert:\LocalMachine\My"
}

# An existing service must be deleted and re-created, never updated in place.
# pywin32's `install` falls through to `update` (ChangeServiceConfig) when the
# service exists, and an account set that way is what breaks virtual-account
# logon - see the registration step for the full story.
$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingService) {
    if (-not $Force) {
        Stop-WithError "Service '$ServiceName' is already registered." `
            "Run uninstall.ps1 first, or re-run with -Force to replace it."
    }
    if ($existingService.Status -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    }
    & sc.exe delete $ServiceName | Out-Null
    $deadline = (Get-Date).AddSeconds(15)
    while (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        if ((Get-Date) -gt $deadline) {
            Stop-WithError "Service '$ServiceName' is still registered after 'sc.exe delete'." `
                "Close services.msc and any 'sc.exe query' windows (they hold the service open), then re-run."
        }
        Start-Sleep -Milliseconds 500
    }
    Write-Ok "Removed the existing service registration"
}

# ------------------------------------------------------------------ install

Write-Step "Preparing $InstallDir"
if (Test-Path $InstallDir) { Remove-Item $InstallDir -Recurse -Force }
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null

# The bundled CPython runtime is copied in alongside the application. No
# interpreter discovery and no venv: the runtime directory IS the environment, so
# nothing depends on a Python that happens to be installed for some user.
foreach ($item in @('python', 'app', 'pyproject.toml', 'README.md', 'config.example.toml', 'requirements.txt')) {
    $src = Join-Path $PayloadDir $item
    if (-not (Test-Path $src)) { Stop-WithError "Payload is missing '$item'." }
    Copy-Item $src -Destination $InstallDir -Recurse -Force
}
if (-not (Test-Path $Python)) { Stop-WithError "Copied runtime has no '$Python'." }

$runtimeVersion = (& $Python -c "import sys; print('.'.join(map(str, sys.version_info[:3])))" | Select-Object -Last 1)
if ($LASTEXITCODE -ne 0 -or -not $runtimeVersion) {
    Stop-WithError "The bundled interpreter at '$Python' will not run." `
        "This usually means the payload architecture does not match the machine."
}
Write-Ok "Bundled CPython $runtimeVersion at $RuntimeDir"

Write-Step "Bootstrapping pip (offline)"
# ensurepip installs from the pip wheel bundled inside the runtime, so no network.
& $Python -m ensurepip 2>&1 | Out-Null
& $Python -c "import pip" 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    # Fallback: run pip straight out of the bundled wheel via zipimport.
    Write-Warn2 "ensurepip left pip unimportable; bootstrapping from the bundled wheel."
    $pipWheel = Get-ChildItem $WheelDir -Filter 'pip-*.whl' | Select-Object -First 1
    if (-not $pipWheel) { Stop-WithError "No pip wheel in '$WheelDir' to bootstrap from." }
    Invoke-Checked "pip bootstrap" {
        & $Python (Join-Path $pipWheel.FullName 'pip') install --no-index --find-links $WheelDir --quiet --no-warn-script-location pip
    }
}
$pipVersion = ((& $Python -m pip --version 2>&1 | Out-String) -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -Last 1)
if ($LASTEXITCODE -ne 0 -or -not $pipVersion) { Stop-WithError "pip is not runnable after bootstrap." }
Write-Ok $pipVersion.Trim()

Write-Step "Installing build backend (offline)"
# --no-warn-script-location throughout: the runtime's Scripts\ directory is
# private to this service and deliberately never on PATH, so pip's advice to
# add it is noise on every install.
# setuptools is needed to build the project's own wheel; pip's build isolation
# would otherwise contact PyPI.
Invoke-Checked "build backend install" {
    & $Python -m pip install --no-index --find-links $WheelDir --quiet --no-warn-script-location setuptools
}
Write-Ok "setuptools"

Write-Step "Installing dependencies from bundled wheels (offline)"
Invoke-Checked "dependency install" {
    & $Python -m pip install --no-index --find-links $WheelDir --quiet --no-warn-script-location -r (Join-Path $InstallDir 'requirements.txt')
}
Write-Ok "dependencies installed"

Write-Step "Installing smtp-relay"
# --no-deps: requirements.txt already pinned and installed everything.
# --no-build-isolation: use the setuptools just installed, no PyPI access.
Invoke-Checked "project install" {
    & $Python -m pip install --no-index --find-links $WheelDir --no-deps --no-build-isolation --quiet --no-warn-script-location $InstallDir
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

# The account is passed to CreateService here (pywin32's --username goes
# straight through), which is the canonical form, rather than patched in
# afterwards with `sc.exe config obj=`. --startup auto replaces a later
# `sc.exe config start=`.
#
# What actually went wrong on a Windows 11 build 28000 ARM64 host, so nobody
# re-diagnoses it: after the first failed logon of NT SERVICE\<name>, LSA kept
# answering 1332 ERROR_NONE_MAPPED for that *name* - across service deletion
# and re-creation, with either creation method, any binary, any display name
# and any casing - while every fresh name resolved instantly. The SCM then
# fails every start with 1069 and System event 7038 "No mapping between account
# names and security IDs". It is in-memory state: a reboot cleared it and the
# same registration then started fine. The LSA check in the permissions step
# turns this into an installer error with that advice, instead of a service
# that cannot start.
#
# A virtual service account takes no password. "Log on as a service" is held by
# NT SERVICE\ALL SERVICES in the default policy, so nothing has to be granted.
Push-Location $InstallDir
try {
    & $Python -m app.windows_service --username $ServiceAccount --startup auto install
    $installExit = $LASTEXITCODE
} finally {
    Pop-Location
}

if ($installExit -ne 0) {
    Stop-WithError "Service registration failed (exit $installExit)." `
        "Try: & '$Python' '$(Join-Path $RuntimeDir 'Scripts\pywin32_postinstall.py')' -install"
}
Write-Ok "Service registered"

& sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null
Write-Ok "Start type: automatic; restart on failure enabled"

# ----------------------------------------------------------- event log source

Write-Step "Registering Event Log source '$ServiceName'"
# Two writers share this source, with message tables in two different files:
#   - Python's NTEventLogHandler (app log records) uses event ID 1, whose "%1"
#     template lives in win32service.pyd;
#   - pywin32's servicemanager (start/stop/SvcRun failures, IDs 0x400000FF etc.)
#     has its table in servicemanager.pyd.
# EventMessageFile accepts a semicolon-separated list and the Event Log service
# searches them in order. Without this key, Event Viewer shows every record as
# "The description for Event ID ... cannot be found".
#
# It has to be done HERE, elevated. NTEventLogHandler tries to register the
# source on first use and silently ignores access denied; under LocalSystem that
# used to succeed, under the virtual service account it never can.
$win32Dir = Join-Path $RuntimeDir 'Lib\site-packages\win32'
$messageFiles = @('win32service.pyd', 'servicemanager.pyd') | ForEach-Object { Join-Path $win32Dir $_ }
foreach ($file in $messageFiles) {
    if (-not (Test-Path $file)) {
        Stop-WithError "Event message file missing: $file" "The pywin32 install in the bundled runtime is incomplete."
    }
}
$eventLogKey = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\$ServiceName"
try {
    New-Item -Path $eventLogKey -Force | Out-Null
    New-ItemProperty -Path $eventLogKey -Name EventMessageFile -Value ($messageFiles -join ';') -PropertyType ExpandString -Force | Out-Null
    New-ItemProperty -Path $eventLogKey -Name TypesSupported -Value 7 -PropertyType DWord -Force | Out-Null
} catch {
    Stop-WithError "Could not register the Event Log source at $eventLogKey." $_.Exception.Message
}
Write-Ok "EventMessageFile: win32service.pyd;servicemanager.pyd"

# -------------------------------------------------------------- permissions

Write-Step "Applying least-privilege permissions"

Write-Ok "Service account: $ServiceAccount (set at creation)"

# CreateService leaves SERVICE_SID_TYPE at NONE, which means the service process
# never receives the virtual SID in its token and every ACL grant to that SID is
# inert. Set it before granting anything, and read it back.
& sc.exe sidtype $ServiceName unrestricted | Out-Null
if ($LASTEXITCODE -ne 0) {
    Stop-WithError "sc.exe could not set SERVICE_SID_TYPE to unrestricted (exit $LASTEXITCODE)." `
        "Without it the virtual account SID is never in the service token."
}
Write-Ok "SERVICE_SID_TYPE: unrestricted"

# Read both back, so a silently-ignored change is visible here rather than
# surfacing later as an unrelated permissions or start failure.
$qc = (& sc.exe qc $ServiceName) -join "`n"
if ($qc -match '(?m)^\s*SERVICE_START_NAME\s*:\s*(.+)$') {
    Write-Ok "Confirmed start name: $($Matches[1].Trim())"
} else {
    Write-Warn2 "Could not read SERVICE_START_NAME from 'sc.exe qc' (localized output?)."
}

$qsid = (& sc.exe qsidtype $ServiceName) -join "`n"
if ($qsid -match '(?m)^\s*SERVICE_SID_TYPE\s*:\s*(.+)$') {
    $sidType = $Matches[1].Trim()
    if ($sidType -eq 'NONE') {
        Stop-WithError "SERVICE_SID_TYPE is still NONE after 'sc.exe sidtype'." `
            "The service would run without its virtual SID, so no ACL could apply."
    }
    Write-Ok "Confirmed SID type: $sidType"
} else {
    Write-Warn2 "Could not read SERVICE_SID_TYPE from 'sc.exe qsidtype' (localized output?)."
}

# Resolve the account to a SID. For the virtual account `sc.exe showsid`
# computes it directly from the service name (match on the SID token only, so
# localized output does not matter). Any other account - e.g. -ServiceAccount
# 'NT AUTHORITY\NetworkService' - goes through name lookup; showsid would return
# the virtual SID for it, which is the wrong principal to grant.
$isVirtualAccount = $ServiceAccount -match '^NT SERVICE\\'
$serviceSid = $null
if ($isVirtualAccount) {
    $showsid = (& sc.exe showsid $ServiceName) -join "`n"
    if ($showsid -match 'S-1-5-80-[0-9-]+') { $serviceSid = $Matches[0] }
}

# LSA must agree, whatever the account. This is the same lookup the SCM performs
# at logon: if it fails here, the service would fail to start with 1069 and
# System event 7038 "No mapping between account names and security IDs", and
# every ACL grant below would be aimed at a principal that cannot log on.
try {
    $ntAccount = New-Object System.Security.Principal.NTAccount($ServiceAccount)
    $lsaSid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
} catch {
    Stop-WithError "LSA cannot resolve '$ServiceAccount' (the SCM would fail the logon with 1069 / event 7038)." `
        ("The service was created with that account, so this is host state, not the installer. " +
         "Seen once after a failed logon of the same name: LSA kept answering 'no mapping' for it " +
         "until a REBOOT. Reboot and re-run this installer with -Force. " +
         "If it persists, re-run with -ServiceAccount 'NT AUTHORITY\NetworkService'.")
}
if (-not $serviceSid) {
    $serviceSid = $lsaSid
} elseif ($serviceSid -ne $lsaSid) {
    Stop-WithError "sc.exe showsid ($serviceSid) and LSA ($lsaSid) disagree about '$ServiceAccount'." `
        "The service name and the account name must match exactly."
}
Write-Ok "$ServiceAccount -> $serviceSid (confirmed by LSA)"

# icacls CANNOT be used for a virtual service account. Even the documented
# "*S-1-5-80-..." numeric form fails with 1332 ERROR_NONE_MAPPED, because icacls
# performs its own SID->name lookup and a virtual service SID has no name in the
# account database. Confirmed on Windows 11 ARM64 with SERVICE_SID_TYPE already
# UNRESTRICTED, and with the "NT SERVICE\<name>" form too. Setting the SID type
# makes the SID appear in the service token; it does not create a name for it.
#
# The .NET ACL API takes a SecurityIdentifier object directly and never calls
# LookupAccountSid, so it is the only route that works here.
try {
    $sidObj = New-Object System.Security.Principal.SecurityIdentifier($serviceSid)
} catch {
    Stop-WithError "Could not build a SecurityIdentifier from '$serviceSid'." `
        $_.Exception.Message
}

function New-AclRule {
    param(
        [System.Security.Principal.IdentityReference] $Identity,
        [System.Security.AccessControl.FileSystemRights] $Rights
    )
    # ContainerInherit+ObjectInherit is the .NET equivalent of icacls "(OI)(CI)".
    New-Object System.Security.AccessControl.FileSystemAccessRule(
        $Identity,
        $Rights,
        ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
         [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow)
}

$aclFailures = @()

# InstallDir: additive grant only. Program Files' inherited defaults are left
# intact - the service needs read+execute on the runtime and nothing more.
try {
    $acl = Get-Acl -Path $InstallDir
    $acl.AddAccessRule((New-AclRule $sidObj 'ReadAndExecute'))
    Set-Acl -Path $InstallDir -AclObject $acl
    Write-Ok "read+execute on $InstallDir"
} catch {
    $aclFailures += "$InstallDir ($($_.Exception.Message))"
}

# ConfigDir: strip inheritance, because it may hold an SMTP password or API token
# and ProgramData subfolders otherwise inherit read access for standard users.
# Then grant SYSTEM and Administrators full control and the service read-only.
# Side effect: the interactive user loses access, so editing config.toml now
# requires an elevated editor. That is the intended trade for protecting secrets.
try {
    $acl = Get-Acl -Path $ConfigDir
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($existing in @($acl.Access)) { $acl.RemoveAccessRule($existing) | Out-Null }
    # Well-known SIDs, so no name resolution is involved here either.
    $systemSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
    $adminsSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $acl.AddAccessRule((New-AclRule $systemSid 'FullControl'))
    $acl.AddAccessRule((New-AclRule $adminsSid 'FullControl'))
    $acl.AddAccessRule((New-AclRule $sidObj 'Read'))
    Set-Acl -Path $ConfigDir -AclObject $acl
    Write-Ok "$ConfigDir : SYSTEM+Administrators full, service read-only"
} catch {
    $aclFailures += "$ConfigDir ($($_.Exception.Message))"
}
# The service gets no write access anywhere: it logs to the Event Log, so it
# never needs to create a file.

if ($aclFailures.Count -gt 0) {
    # Fatal, not a warning: without these grants the service cannot read its own
    # runtime or configuration, and would fail at start with an unrelated error.
    Stop-WithError ("Could not set permissions on: " + ($aclFailures -join '; ') + ".") `
        ("Do NOT retry with icacls - it cannot grant to a virtual service SID at all " +
         "(1332 ERROR_NONE_MAPPED, even in *S-1-5-80-... form). Use Get-Acl/Set-Acl " +
         "with a SecurityIdentifier built from the output of:`n" +
         "  sc.exe showsid $ServiceName")
}

# ------------------------------------------------------- API TLS certificate

# The relay's TLS is OpenSSL (Python's ssl module), which cannot sign with a
# CNG key handle. With api.ssl_cert_thumbprint set, the service therefore
# exports the certificate WITH its key through CryptoAPI at every start and
# loads that - which is only possible for a key imported as exportable. Hence
# Import-PfxCertificate -Exportable below, and the exportability check for a
# pre-existing certificate. The key still never exists as a file the operator
# manages, needs no passphrase in config.toml, and is replaced in certlm.msc
# like any other machine certificate. Whoever needs a NON-exportable key must
# terminate TLS in IIS or HTTP.sys in front of the relay (api.behind_tls_proxy).
$certificate = $null
if ($PfxPath -or $CertThumbprint) {
    Write-Step "API TLS certificate"
    $storePath = 'Cert:\LocalMachine\My'

    if ($PfxPath) {
        try {
            $importArgs = @{ FilePath = $PfxPath; CertStoreLocation = $storePath; Exportable = $true }
            if ($PfxPassword -and $PfxPassword.Length -gt 0) { $importArgs.Password = $PfxPassword }
            $certificate = Import-PfxCertificate @importArgs
        } catch {
            Stop-WithError "Could not import '$PfxPath' into $storePath." $_.Exception.Message
        }
        Write-Ok "Imported $($certificate.Thumbprint) into $storePath (exportable key)"
    } else {
        $certificate = Get-Item (Join-Path $storePath $CertThumbprint) -ErrorAction SilentlyContinue
        if (-not $certificate) {
            Stop-WithError "No certificate with thumbprint $CertThumbprint in $storePath." `
                "List candidates with: Get-ChildItem Cert:\LocalMachine\My | Format-Table Thumbprint, Subject, NotAfter"
        }
        Write-Ok "Found $CertThumbprint in $storePath"
    }

    if (-not $certificate.HasPrivateKey) {
        Stop-WithError "Certificate $($certificate.Thumbprint) has no private key." `
            "The relay needs the key to serve TLS; import a PFX that contains it (-PfxPath)."
    }
    if ($certificate.NotAfter -lt (Get-Date)) {
        Write-Warn2 "This certificate EXPIRED on $($certificate.NotAfter). Clients will reject it."
    }

    # Machine keys live as files under ProgramData\Microsoft\Crypto - CNG (Key
    # Storage Provider) and legacy CAPI keys in different subfolders - and the key
    # object knows its own file name. Granting read on that file is exactly what
    # certlm.msc's "Manage Private Keys" does. Exportability is checked here, in
    # the installer, because the service's own error for it only shows at start.
    $privateKey = $null; $uniqueName = $null; $exportable = $false
    try {
        $privateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate)
        if (-not $privateKey) {
            $privateKey = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($certificate)
        }
    } catch {
        Stop-WithError "Cannot open the private key of $($certificate.Thumbprint)." $_.Exception.Message
    }
    if (-not $privateKey) {
        Stop-WithError "The private key of $($certificate.Thumbprint) is neither RSA nor ECDSA, or is not accessible." `
            "Only RSA and ECDSA certificates are supported."
    }
    if ($privateKey.PSObject.Properties['Key'] -and $privateKey.Key) {
        # CNG: Microsoft Software Key Storage Provider (what Import-PfxCertificate uses).
        $uniqueName = $privateKey.Key.UniqueName
        $exportable = ($privateKey.Key.ExportPolicy -band [System.Security.Cryptography.CngExportPolicies]::AllowExport) -ne 0
    } elseif ($privateKey.PSObject.Properties['CspKeyContainerInfo'] -and $privateKey.CspKeyContainerInfo) {
        # Legacy CAPI cryptographic service provider.
        $uniqueName = $privateKey.CspKeyContainerInfo.UniqueKeyContainerName
        $exportable = $privateKey.CspKeyContainerInfo.Exportable
    }
    if (-not $exportable) {
        Stop-WithError "The private key of $($certificate.Thumbprint) is NOT exportable, so the service cannot use it." `
            ("Re-import the PFX through this installer (-PfxPath imports with -Exportable). If the key must stay " +
             "non-exportable, terminate TLS in IIS or HTTP.sys in front of the relay and set " +
             "api.behind_tls_proxy = true instead - see README.md, 'Certificate sources'.")
    }
    $cryptoRoot = Join-Path $env:ProgramData 'Microsoft\Crypto'
    $keyFile = $null
    if ($uniqueName) {
        $keyFile = Get-ChildItem -Path $cryptoRoot -Recurse -File -Filter $uniqueName -ErrorAction SilentlyContinue | Select-Object -First 1
    }
    if (-not $keyFile) {
        Stop-WithError "Could not locate the private key file of $($certificate.Thumbprint) under $cryptoRoot." `
            "Grant read access to $ServiceAccount by hand: certlm.msc > Personal > Certificates > right-click > All Tasks > Manage Private Keys."
    }
    # Same .NET route as above: icacls cannot address a virtual service SID.
    try {
        $keyAcl = Get-Acl -Path $keyFile.FullName
        $keyAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $sidObj,
            [System.Security.AccessControl.FileSystemRights]::Read,
            [System.Security.AccessControl.AccessControlType]::Allow)))
        Set-Acl -Path $keyFile.FullName -AclObject $keyAcl
    } catch {
        Stop-WithError "Could not grant $ServiceAccount read access on the private key ($($keyFile.FullName))." $_.Exception.Message
    }
    Write-Ok "Private key readable by $ServiceAccount ($($keyFile.Name))"

    # Point config.toml at the certificate: replace an existing (even commented)
    # ssl_cert_thumbprint line, or add one directly under [api]. Character
    # classes instead of '.' and '\s' so CRLF line endings survive the edit.
    $thumbLine = "ssl_cert_thumbprint = `"$($certificate.Thumbprint)`""
    # .NET IO on purpose: Windows PowerShell 5.1 reads BOM-less UTF-8 as ANSI and
    # its -Encoding UTF8 writes a BOM, which tomllib rejects. Read and write
    # UTF-8 without BOM explicitly, on both PowerShell editions.
    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    $content = [System.IO.File]::ReadAllText($configFile, [System.Text.Encoding]::UTF8)
    if ($content -match '(?m)^[ \t]*#?[ \t]*ssl_cert_thumbprint[ \t]*=[^\r\n]*') {
        $content = $content -replace '(?m)^[ \t]*#?[ \t]*ssl_cert_thumbprint[ \t]*=[^\r\n]*', $thumbLine
    } elseif ($content -match '(?m)^\[api\][ \t]*$') {
        $content = $content -replace '(?m)^\[api\][ \t]*$', "[api]`r`n$thumbLine"
    } else {
        $content = "[api]`r`n$thumbLine`r`n`r`n" + $content
    }
    [System.IO.File]::WriteAllText($configFile, $content, $utf8NoBom)
    Write-Ok "config.toml: api.$thumbLine"
    foreach ($other in @('ssl_certfile', 'ssl_pfxfile')) {
        if ($content -match "(?m)^[ \t]*$other[ \t]*=") {
            Write-Warn2 "config.toml also sets api.$other - the service refuses to start with two certificate sources. Remove one."
        }
    }
    Write-Ok "Subject $($certificate.Subject), valid until $($certificate.NotAfter.ToString('yyyy-MM-dd'))"
    Write-Warn2 "Remember: api.host must be non-loopback and api.token set for remote clients to use it."
}

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
    & $Python -m app.windows_service start
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
  Runtime       : $Python (bundled CPython $runtimeVersion)
  Certificate   : $(if ($certificate) { "$($certificate.Thumbprint) (Cert:\LocalMachine\My, until $($certificate.NotAfter.ToString('yyyy-MM-dd')))" } else { 'none - API serves plain HTTP on loopback' })

Next steps:
  1. Edit the configuration:   notepad "$configFile"
  2. Verify config discovery:  & '$Python' -c "from app.config import _candidate_paths; [print(p) for p in _candidate_paths(None)[0]]"
  3. Console test run:         & '$Python' -m app.windows_service debug
  4. Start the service:        & '$Python' -m app.windows_service start
  5. Read the logs:            Get-EventLog -LogName Application -Source SmtpRelay -Newest 20

No system Python is used or required: the runtime lives in $RuntimeDir and is
private to this service.

Exposing the API beyond this machine:
  - set api.host in config.toml to the interface you want (e.g. 0.0.0.0)
  - give it a certificate: re-run install.ps1 -Force -PfxPath <file.pfx> (or
    -CertThumbprint <existing>), or set api.ssl_certfile / api.ssl_keyfile or
    api.ssl_pfxfile by hand
  - set api.token (or api.ssl_cert_reqs = "required" for mutual TLS)
  - re-run install.ps1 with -OpenFirewall (or add the rule yourself)

The application refuses to start if api.host is non-loopback without both TLS and
client authentication, so it cannot silently become a cleartext open relay. Before
picking a port, confirm it is outside the WinNAT exclusion ranges:
  netsh int ipv4 show excludedportrange protocol=tcp
"@ -ForegroundColor Green
