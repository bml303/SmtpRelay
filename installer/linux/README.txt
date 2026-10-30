SMTP Relay - Linux payload
==========================

This directory is a complete, offline installation of the SMTP Relay as a
systemd service: a private CPython runtime, every dependency as a wheel, the
application, and the installer scripts. Nothing is downloaded during
installation, no compiler is needed, and no system Python is used.

Contents
--------
  install.sh           installer (run as root)
  uninstall.sh         uninstaller (run as root)
  smtp-relay.service   hardened systemd unit template, rendered by install.sh
  python/              bundled CPython runtime, copied to the install dir
  wheels/              pinned dependencies, installed offline
  app/                 the application
  config.example.toml  annotated configuration template
  MANIFEST.json        version, platform, file hashes; checked by install
  SBOM.cdx.json        CycloneDX software bill of materials
  README.md            full project documentation (Markdown)
  LICENSE              MIT

Before you start
----------------
  * Use the payload built for this machine's CPU: linux_x86_64 or
    linux_aarch64. Check with:   uname -m        (x86_64 / aarch64)
    MANIFEST.json names the platform the payload was built for.
  * systemd must be running (a VM or bare metal; not an unprivileged
    container - use the container image there instead).
  * glibc-based distribution (Debian, Ubuntu, RHEL and derivatives, SUSE).
    The bundled runtime is not for Alpine/musl.
  * Nothing is written outside these locations unless you ask:
      Program files   /opt/smtp-relay      (--install-dir)
      Configuration   /etc/smtp-relay      (--config-dir)
      Unit            /etc/systemd/system/smtp-relay.service
      Account         smtp-relay           (--user; no home, shell or password)

Install
-------
  tar xzf SmtpRelay-<version>-linux_x86_64-cp315.tar.gz
  cd SmtpRelay-<version>-linux_x86_64-cp315
  sudo ./install.sh

  Options:
    --start                 start the service when the install succeeds and
                            wait until /health answers
    --force                 replace an existing installation (see Upgrade)
    --install-dir DIR  --config-dir DIR  --service-name NAME  --user NAME

  The installer verifies the payload against MANIFEST.json with the bundled
  interpreter (which also proves the payload matches this machine's
  architecture), creates the system account, copies the runtime and the
  application, installs the wheels offline, seeds config.toml from the
  template (an existing config.toml is never overwritten; mode 0640,
  root:smtp-relay, so only root and the service can read secrets), renders
  the unit, reloads systemd and enables the service.

Configure
---------
  sudoedit /etc/smtp-relay/config.toml

  At minimum: [smtp] host/port, username AND password (or neither),
  [policy] sender and allowed_domains. The sender must be an address the
  SMTP account is allowed to use. Comments in the file explain every key.
  To keep the password out of the file, give the service an environment
  file instead:

    sudo systemctl edit smtp-relay
      [Service]
      EnvironmentFile=/etc/smtp-relay/env      # RELAY_SMTP_PASSWORD=...
    sudo install -m 0640 -o root -g smtp-relay /dev/null /etc/smtp-relay/env

Check before starting
---------------------
  sudo -u smtp-relay /opt/smtp-relay/python/bin/python3 -m app --check --config /etc/smtp-relay/config.toml

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

  Running it as the service account (sudo -u smtp-relay) makes file
  permissions part of the test: a config, certificate or key the service
  cannot read fails here instead of at the first start. If the password
  lives in an environment file, prefix the command with
  "RELAY_SMTP_PASSWORD=..." or source that file first.

Start and verify
----------------
  sudo systemctl start smtp-relay
  systemctl status smtp-relay
  curl -s http://127.0.0.1:8000/health

  (use https:// and the real host once a certificate is configured; with
  mutual TLS the request needs a client certificate.)

Logs
----
  journalctl -u smtp-relay -f

  The service logs to stderr, hence to the journal: startup, configuration
  errors, each request, each delivery failure with the mailhost's reply.
  There is no file logging.

Upgrade
-------
  From the new payload's directory:

  sudo ./install.sh --force --start

  --force stops the service, replaces /opt/smtp-relay, keeps
  /etc/smtp-relay/config.toml and the service account, and re-renders the
  unit. Run the check afterwards.

Uninstall
---------
  sudo ./uninstall.sh
  sudo ./uninstall.sh --remove-config

  Stops and disables the service, removes the unit and /opt/smtp-relay, and
  deletes the service account (keep it with --keep-user). The configuration
  directory is KEPT unless --remove-config is given, because it may hold the
  only copy of your settings.

Exposing the API beyond this machine
------------------------------------
  The service refuses to start with api.host set to anything but loopback
  unless it serves TLS (api.ssl_certfile + api.ssl_keyfile, or a PKCS#12
  file via api.ssl_pfxfile) or declares a TLS-terminating reverse proxy
  (api.behind_tls_proxy = true), AND clients must authenticate (api.token,
  or api.ssl_cert_reqs = "required" for mutual TLS). This is deliberate: an
  unauthenticated relay on the network is an open relay. Open the port in
  the host firewall yourself and run the check again. Binding a port below
  1024 needs a drop-in with AmbientCapabilities=CAP_NET_BIND_SERVICE.

More
----
  README.md in this directory is the full documentation: API, status
  codes, every configuration key, TLS options, certificate sources,
  operational notes.
