"""Small, checked OpenSSL subprocess boundary."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess


class OpenSSLError(RuntimeError):
    """Raised when a checked OpenSSL command fails."""


def require_openssl() -> None:
    """Raise a clear error when the required OpenSSL executable is unavailable."""
    if shutil.which("openssl") is None:
        raise OpenSSLError("openssl is required")


def run(command: list[str], *, env: dict[str, str] | None = None, capture: bool = False) -> str:
    """Run an argument-vector OpenSSL command and translate failures safely."""
    try:
        completed = subprocess.run(command, check=True, env=env, text=True, capture_output=capture)
    except subprocess.CalledProcessError as error:
        raise OpenSSLError(f"OpenSSL failed ({error.returncode}): {' '.join(command[:2])}") from error
    return completed.stdout if capture else ""


def config_env(
    *,
    pki_dir: Path | None = None,
    san: str | None = None,
    digest: str | None = None,
    ca_key: Path | None = None,
    ca_cert: Path | None = None,
) -> dict[str, str]:
    """Return the minimal environment consumed by the external OpenSSL config."""
    env = os.environ.copy()
    env["PKI_DIR"] = str(pki_dir) if pki_dir else "/nonexistent"
    env["CERT_SAN"] = san or "DNS:unused.invalid"
    env["PKI_DIGEST"] = digest or "sha384"
    base = pki_dir or Path("/nonexistent")
    env["CA_KEY"] = str(ca_key or base / "private/root-ca.key")
    env["CA_CERT"] = str(ca_cert or base / "certs/root-ca.crt")
    return env
