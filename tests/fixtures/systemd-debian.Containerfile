# Throwaway systemd host for exercising installer/linux end to end:
#   scripts/test_linux_installer.sh
# Debian because most targets are Debian/Ubuntu; the installer itself is
# distro-agnostic (bash, systemd, useradd).
FROM docker.io/library/debian:trixie-slim
RUN apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends systemd systemd-sysv ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && systemctl mask systemd-logind.service getty.target console-getty.service
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
