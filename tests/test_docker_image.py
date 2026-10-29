"""Static guards for the container image.

Building the image needs a registry and a container engine, so CI does not do
it here. What can be checked from the files alone is what would otherwise ship
a leaky or privileged image: that secrets cannot be baked in, that the process
is unprivileged, and that the image does not quietly make the network-exposure
decision on the operator's behalf.
"""

from __future__ import annotations

import py_compile
import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = PROJECT_ROOT / "Dockerfile"
DOCKERIGNORE = PROJECT_ROOT / ".dockerignore"
HEALTHCHECK = PROJECT_ROOT / "docker" / "healthcheck.py"


def _dockerfile_instructions() -> list[str]:
    lines = []
    for raw in DOCKERFILE.read_text().splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            lines.append(line)
    return lines


def test_config_toml_can_never_enter_an_image_layer():
    """Belt and braces: not COPYd, and ignored even if someone adds a COPY."""
    copies = [line for line in _dockerfile_instructions() if line.startswith("COPY")]
    assert copies, "expected COPY instructions"
    for line in copies:
        assert re.search(r"\bconfig\.toml\b", line) is None, line
        assert " . " not in line and not line.endswith(" ."), (
            f"COPY of the whole context would include config.toml: {line}"
        )

    ignored = {line.strip() for line in DOCKERIGNORE.read_text().splitlines()}
    assert "config.toml" in ignored
    assert ".venv" in ignored


def test_runtime_stage_drops_root():
    instructions = _dockerfile_instructions()
    users = [line for line in instructions if line.startswith("USER ")]
    assert users, "no USER instruction - the service would run as root"
    assert "root" not in users[-1].split()[1]
    # USER must come before the ENTRYPOINT it applies to.
    assert instructions.index(users[-1]) < next(
        i for i, line in enumerate(instructions) if line.startswith("ENTRYPOINT")
    )


def test_image_does_not_preempt_the_exposure_decision():
    """RELAY_API_HOST=0.0.0.0 is unavoidable in a container; the TLS/auth half of
    the rule must stay with the operator, so the image must not default either
    the proxy opt-out or a token."""
    text = DOCKERFILE.read_text()
    assert "RELAY_API_HOST=0.0.0.0" in text
    assert "RELAY_API_BEHIND_TLS_PROXY" not in re.sub(r"#.*", "", text), (
        "the image must not set RELAY_API_BEHIND_TLS_PROXY itself"
    )
    assert "RELAY_API_TOKEN" not in re.sub(r"#.*", "", text)


def test_entrypoint_is_the_console_entry_point():
    assert 'ENTRYPOINT ["python", "-m", "app"]' in DOCKERFILE.read_text()


def test_healthcheck_script_compiles(tmp_path):
    py_compile.compile(str(HEALTHCHECK), cfile=str(tmp_path / "hc.pyc"), doraise=True)
    assert 'CMD ["python", "/opt/smtp-relay/healthcheck.py"]' in DOCKERFILE.read_text()
