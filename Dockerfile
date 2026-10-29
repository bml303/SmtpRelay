# syntax=docker/dockerfile:1.7
#
# Multi-arch image for linux/amd64 and linux/arm64. Nothing here is
# architecture-specific: the base image and pydantic-core's manylinux wheels
# come per platform from their registries, so one buildx invocation covers both:
#
#   docker buildx build --platform linux/amd64,linux/arm64 -t smtp-relay:0.2.0 .
#
# The container binds 0.0.0.0 (it is unreachable otherwise), which triggers the
# network-exposure rule in app/config.py. That rule is NOT relaxed by the image.
# The operator must either mount a certificate and set RELAY_API_SSL_CERTFILE, or
# declare RELAY_API_BEHIND_TLS_PROXY=true - and in both cases set RELAY_API_TOKEN
# (or required mTLS). Without that the container exits with code 2 and a message
# naming the missing pieces. See compose.yaml for the usual shape.

ARG PYTHON_VERSION=3.15

# --- build: resolve and install into a relocatable venv -----------------------
FROM docker.io/library/python:${PYTHON_VERSION}-slim AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /src
COPY pyproject.toml requirements.txt README.md ./
COPY app ./app

# requirements.txt is the pinned runtime set, used here as a *constraints* file
# so the project's own metadata drives what is installed and the pins drive the
# versions. Its Windows-only pywin32 pin is skipped by its sys_platform marker.
RUN python -m venv /opt/smtp-relay \
 && /opt/smtp-relay/bin/pip install -c requirements.txt . \
 && /opt/smtp-relay/bin/pip check \
 && find /opt/smtp-relay -name '__pycache__' -type d -prune -exec rm -rf {} +

# --- runtime -------------------------------------------------------------------
FROM docker.io/library/python:${PYTHON_VERSION}-slim

ARG VERSION=dev
LABEL org.opencontainers.image.title="smtp-relay" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.description="REST-to-SMTP relay: JSON in, allowlisted mail out through a configured mailhost."

# Dedicated unprivileged account. /etc/smtp-relay is the POSIX config location
# the app searches; it stays root-owned and read-only to the service, matching
# the Windows install where the service account gets read access only.
RUN groupadd --system --gid 10001 relay \
 && useradd --system --uid 10001 --gid relay \
      --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin relay \
 && install -d -m 0755 -o root -g root /etc/smtp-relay

COPY --from=build /opt/smtp-relay /opt/smtp-relay
COPY docker/healthcheck.py /opt/smtp-relay/healthcheck.py

ENV PATH=/opt/smtp-relay/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    # Required for the published port to reach the process. Deliberately the
    # ONLY exposure-related default: the TLS/auth decision stays with the operator.
    RELAY_API_HOST=0.0.0.0

WORKDIR /etc/smtp-relay
USER relay:relay
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["python", "/opt/smtp-relay/healthcheck.py"]

ENTRYPOINT ["python", "-m", "app"]
