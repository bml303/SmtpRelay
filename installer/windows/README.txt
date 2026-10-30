SMTP Relay - Windows payload
============================

This directory is a complete, offline installation of the SMTP Relay Windows
service: a private CPython runtime, every dependency as a wheel, the
application, and the installer scripts. Nothing is downloaded during
installation and no system Python is used or required.

Contents
--------
  install.ps1          installer (elevated PowerShell)
  uninstall.ps1        uninstaller (elevated PowerShell)
  python\              bundled CPython runtime, copied to the install dir
  wheels\              pinned dependencies, installed offline
  app\                 the application
  config.example.toml  annotated configuration template
  MANIFEST.json        version, platform, file hashes; checked by install
  SBOM.cdx.json        CycloneDX software bill of materials
  README.md            full project documentation (Markdown)

Before you start
----------------
  * Use the payload built for this machine's CPU: win_amd64 for x64,
    win_arm64 for ARM64. Check with:   $env:PROCESSOR_ARCHITECTURE
    MANIFEST.json names the platform the payload was built for.
  * Everything below runs from an ELEVATED PowerShell prompt, started inside
    this directory. "-ExecutionPolicy Bypass" is needed because the scripts
    are unsigned; it does not change the machine's policy.
  * Nothing is written outside the two locations below unless you ask:
      Program files   C:\Program Files\SmtpRelay   (-InstallDir)
      Configuration   C:\ProgramData\SmtpRelay     (-ConfigDir)

Install
-------
  powershell -ExecutionPolicy Bypass -File .\install.ps1

  Options:
    -Start                  start the service when the install succeeds
    -OpenFirewall           add an inbound rule for the API port (-ApiPort,
                            default 8000); not needed while api.host stays
                            on 127.0.0.1
    -PfxPath <file.pfx>     import the API's TLS certificate into
                            Cert:\LocalMachine\My with an exportable key,
                            grant the service account read access to the
                            key, and point config.toml at it. The passphrase
                            is prompted for and never stored.
    -CertThumbprint <hex>   same, for a certificate already in the store
                            (its key must be exportable)
    -Force                  replace an existing installation (see Upgrade)
    -InstallDir, -ConfigDir, -ServiceName, -ServiceAccount, -ApiPort

  The installer verifies the payload against MANIFEST.json, copies the
  runtime, installs the wheels offline, seeds config.toml from the template
  (an existing config.toml is never overwritten), registers the service
  "SmtpRelay" (display name "SMTP Relay") under the virtual account
  NT SERVICE\SmtpRelay, registers the Event Log source, and applies
  least-privilege ACLs: the service can read the config and nothing else.

Configure
---------
  notepad C:\ProgramData\SmtpRelay\config.toml

  At minimum: [smtp] host/port, username AND password (or neither),
  [policy] sender and allowed_domains. The sender must be an address the
  SMTP account is allowed to use. Comments in the file explain every key.
  Passwords may be kept out of the file by setting the environment variable
  RELAY_SMTP_PASSWORD for the service instead.

Check before starting
---------------------
  & 'C:\Program Files\SmtpRelay\python\python.exe' -m app --check

  This loads the configuration and the API certificate exactly as the
  service would, then holds one SMTP session with the mailhost: DNS,
  connect, STARTTLS or implicit TLS with certificate verification, AUTH
  with the configured credentials, MAIL FROM with the configured sender,
  then RSET and QUIT. NOTHING IS SENT. Each line is marked ok, WARN, FAIL
  or skip; the exit code is 0 (passed, warnings allowed), 1 (a probe
  failed) or 2 (the configuration does not load). Passwords are never
  printed. Typical findings: a commented-out username while the mailhost
  requires AUTH, a sender the account does not own, port 587 configured as
  implicit TLS, an expired certificate. Add --no-smtp to skip the mailhost.

  Run it elevated: it reads the same %ProgramData%\SmtpRelay\config.toml
  the service reads. Whether the service account itself may read the
  certificate's private key is established by the installer's ACL step;
  if that is wrong, the service logs it at start (see Logs).

Start and verify
----------------
  & 'C:\Program Files\SmtpRelay\python\python.exe' -m app.windows_service start
  Invoke-RestMethod http://127.0.0.1:8000/health

  (use https:// and the real host once a certificate is configured; with
  mutual TLS the request needs a client certificate.) Other subcommands:
  stop, restart, debug (runs the service in this console with logs on
  stderr - the quickest way to see a startup error).

Logs
----
  Get-EventLog -LogName Application -Source SmtpRelay -Newest 20

  Everything the service logs goes to the Application event log, source
  "SmtpRelay": startup, configuration errors, each request, each delivery
  failure with the mailhost's reply.

Upgrade
-------
  From the new payload's directory:

  powershell -ExecutionPolicy Bypass -File .\install.ps1 -Force -Start

  -Force stops and removes the old service registration, replaces the
  program directory, and keeps C:\ProgramData\SmtpRelay\config.toml as it
  is. If the previous install used -PfxPath or -CertThumbprint, pass
  -CertThumbprint <same thumbprint> again so the key grant is re-applied.
  Run the check afterwards.

Uninstall
---------
  powershell -ExecutionPolicy Bypass -File .\uninstall.ps1
  powershell -ExecutionPolicy Bypass -File .\uninstall.ps1 -RemoveConfig

  Stops and deletes the service, removes the Apps & features entry, the
  Event Log source, the firewall rule created by -OpenFirewall, and the
  program directory. The configuration directory is KEPT unless
  -RemoveConfig is given, because it may hold the only copy of your
  settings. The uninstaller ends by re-checking every location and
  reporting anything that survived. A certificate imported with -PfxPath
  stays in Cert:\LocalMachine\My; remove it with certlm.msc if it is no
  longer needed.

Exposing the API beyond this machine
------------------------------------
  The service refuses to start with api.host set to anything but loopback
  unless it serves TLS (a certificate via -PfxPath / -CertThumbprint, or
  api.ssl_certfile) AND clients must authenticate (api.token, or
  api.ssl_cert_reqs = "required" for mutual TLS). This is deliberate: an
  unauthenticated relay on the network is an open relay. Then open the
  port (-OpenFirewall) and run the check again.

More
----
  README.md in this directory is the full documentation: API, status
  codes, every configuration key, TLS options, certificate sources,
  operational notes.
