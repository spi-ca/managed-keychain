"""Safe, shell-free OpenSSL operations for the managed PKI hierarchy."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime
import fcntl
import os
from pathlib import Path
import tempfile
from typing import Iterator

from .openssl import config_env, run
from .settings import CryptoPolicy, Domain, Profile, Settings


def _reject_symlink(path: Path) -> None:
    """Reject a symlink at any existing component of an absolute path."""
    path = path.absolute()
    for component in (path, *path.parents):
        if component.is_symlink():
            raise ValueError(f"refusing symlink path: {component}")


def _mkdir(path: Path, mode: int) -> None:
    """Create a directory without changing permissions of an existing path."""
    _reject_symlink(path)
    missing: list[Path] = []
    current = path
    while not current.exists():
        if current.is_symlink():
            raise ValueError(f"refusing symlink path: {current}")
        missing.append(current)
        current = current.parent
    if not current.is_dir():
        raise ValueError(f"not a directory: {current}")
    for directory in reversed(missing):
        directory.mkdir(mode=mode)
    _reject_symlink(path)


def _check_new_file(path: Path) -> None:
    _reject_symlink(path)
    if path.exists() or path.is_symlink():
        raise ValueError(f"refusing to overwrite existing file: {path}")


@contextmanager
def _new_output(path: Path, mode: int) -> Iterator[Path]:
    """Yield a private temporary output path and publish it without overwrite."""
    _check_new_file(path)
    _mkdir(path.parent, 0o700)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        os.close(descriptor)
        yield temporary
        os.chmod(temporary, mode)
        # link() fails atomically if a competing writer created the destination.
        os.link(temporary, path)
    except FileExistsError as error:
        raise ValueError(f"refusing to overwrite existing file: {path}") from error
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)


def _write_new(path: Path, data: bytes, mode: int = 0o644) -> None:
    with _new_output(path, mode) as temporary:
        temporary.write_bytes(data)


def write_immutable_metadata(path: Path, data: bytes) -> None:
    """Persist immutable public record metadata without replacing prior state."""
    _write_new(path, data, 0o644)


def ca_crypto_metadata_path(ca_dir: Path) -> Path:
    """Return the immutable crypto-policy record stored with one CA state."""
    return ca_dir / "crypto-policy.json"


def write_ca_crypto_metadata(ca_dir: Path, crypto: CryptoPolicy) -> None:
    """Record the CA key and issuer-signing policy selected at creation time."""
    payload = (
        f'{{"curve":"{crypto.curve}","digest":"{crypto.digest}","version":1}}\n'.encode(
            "ascii"
        )
    )
    write_immutable_metadata(ca_crypto_metadata_path(ca_dir), payload)


@contextmanager
def _replace_output(path: Path, mode: int) -> Iterator[Path]:
    """Yield a temporary file and atomically replace one managed regular file."""
    _reject_symlink(path)
    if path.exists() and not path.is_file():
        raise ValueError(f"not a regular file: {path}")
    _mkdir(path.parent, 0o700)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        os.close(descriptor)
        yield temporary
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)


@contextmanager
def _ca_lock(ca_dir: Path) -> Iterator[None]:
    """Serialize OpenSSL CA database access for one mutable issuer state."""
    db_dir = ca_dir / "db"
    _mkdir(db_dir, 0o700)
    lock_path = db_dir / ".managed-keychain.lock"
    _reject_symlink(lock_path)
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _validate_san(profile: Profile, kind: str, san: str | None) -> None:
    if profile.requires_san != bool(san):
        expected = "required" if profile.requires_san else "not allowed"
        raise ValueError(f"--san is {expected} for {kind}")
    if san is not None and ("\n" in san or "\r" in san or "\x00" in san):
        raise ValueError("--san must not contain control characters")


def _validate_subject(subject: str) -> None:
    if not subject.startswith("/") or "\n" in subject or "\r" in subject or "\x00" in subject:
        raise ValueError("subject must be an OpenSSL /field=value DN without control characters")


def _private_key(path: Path) -> None:
    _reject_symlink(path)
    if not path.is_file():
        raise ValueError(f"missing private key: {path}")
    if path.stat().st_mode & 0o077:
        raise ValueError(f"private key permissions are too broad: {path}")


def _certificate_not_after(certificate: Path) -> datetime:
    output = run(["openssl", "x509", "-in", str(certificate), "-noout", "-enddate"], capture=True)
    try:
        value = output.strip().split("=", 1)[1]
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
    except (IndexError, ValueError) as error:
        raise ValueError(f"unable to read certificate expiry: {certificate}") from error


def _capped_days(requested_days: int, issuer_certificate: Path) -> int:
    """Cap a child to whole remaining issuer days, never extending its expiry."""
    remaining = (_certificate_not_after(issuer_certificate) - datetime.now(UTC)).days
    days = min(requested_days, remaining)
    if days < 1:
        raise ValueError("issuer certificate expires too soon to issue a child certificate")
    return days


def _ca_layout(directory: Path) -> None:
    for name, mode in (("private", 0o700), ("certs", 0o755), ("db", 0o700), ("issued", 0o755), ("csr", 0o755)):
        _mkdir(directory / name, mode)


def _initialize_database(directory: Path) -> None:
    index = directory / "db/index.txt"
    serial = directory / "db/serial"
    crlnumber = directory / "db/crlnumber"
    _check_new_file(index)
    _check_new_file(serial)
    _check_new_file(crlnumber)
    _write_new(index, b"", 0o600)
    _write_new(serial, b"1000\n", 0o600)
    _write_new(crlnumber, b"1000\n", 0o600)


def _domain_intermediate(settings: Settings, domain: str) -> tuple[Domain, Path, Path]:
    configured = settings.domain(domain)
    ca_dir = configured.ca_dir
    key = ca_dir / "private/intermediate.key"
    cert = ca_dir / "certs/intermediate.crt"
    _private_key(key)
    _reject_symlink(cert)
    if not cert.is_file():
        raise ValueError(f"{domain} intermediate certificate is missing")
    return configured, key, cert


def init_ca(settings: Settings, config: Path, pki_dir: Path, subject: str) -> None:
    """Create a new root CA only in a previously nonexistent directory.

    A failure deliberately leaves the newly created directory for inspection;
    it never recursively deletes a caller-supplied directory.
    """
    _validate_subject(subject)
    _reject_symlink(pki_dir)
    if pki_dir.exists():
        raise ValueError(f"refusing to initialize an existing CA directory: {pki_dir}")
    _mkdir(pki_dir, 0o700)
    _ca_layout(pki_dir)
    _initialize_database(pki_dir)
    key = pki_dir / "private/root-ca.key"
    cert = pki_dir / "certs/root-ca.crt"
    old_umask = os.umask(0o077)
    try:
        with _new_output(key, 0o600) as temporary_key:
            run(
                [
                    "openssl",
                    "genpkey",
                    "-algorithm",
                    "EC",
                    "-pkeyopt",
                    f"ec_paramgen_curve:{settings.root_crypto.curve}",
                    "-out",
                    str(temporary_key),
                ]
            )
        with _new_output(cert, 0o644) as temporary_cert:
            command = [
                "openssl",
                "req",
                "-new",
                "-x509",
                "-config",
                str(config),
                "-extensions",
                "root_ca",
                "-key",
                str(key),
                "-days",
                str(settings.root_validity_days),
                "-subj",
                subject,
                "-out",
                str(temporary_cert),
            ]
            run(command, env=config_env(pki_dir=pki_dir, digest=settings.root_crypto.digest))
            run(["openssl", "verify", "-CAfile", str(temporary_cert), str(temporary_cert)])
        write_ca_crypto_metadata(pki_dir, settings.root_crypto)
    finally:
        os.umask(old_umask)


def init_intermediate(settings: Settings, config: Path, domain: str) -> Path:
    """Create one configured intermediate signed by the configured root CA."""
    root_key = settings.root_dir / "private/root-ca.key"
    root_cert = settings.root_dir / "certs/root-ca.crt"
    _private_key(root_key)
    _reject_symlink(root_cert)
    if not root_cert.is_file():
        raise ValueError("Root CA certificate is missing")
    configured = settings.domain(domain)
    directory = configured.ca_dir
    _reject_symlink(directory)
    if directory.exists():
        raise ValueError(f"refusing to initialize an existing {domain} intermediate: {directory}")
    _mkdir(directory, 0o700)
    _ca_layout(directory)
    _initialize_database(directory)
    key = directory / "private/intermediate.key"
    csr = directory / "csr/intermediate.csr"
    cert = directory / "certs/intermediate.crt"
    subject = settings.root_subject.rsplit("/CN=", 1)[0] + f"/CN={configured.intermediate_common_name}"
    old_umask = os.umask(0o077)
    try:
        with _new_output(key, 0o600) as temporary_key:
            run(
                [
                    "openssl",
                    "genpkey",
                    "-algorithm",
                    "EC",
                    "-pkeyopt",
                    f"ec_paramgen_curve:{configured.crypto.curve}",
                    "-out",
                    str(temporary_key),
                ]
            )
        with _new_output(csr, 0o644) as temporary_csr:
            command = [
                "openssl",
                "req",
                "-new",
                "-config",
                str(config),
                "-key",
                str(key),
                "-subj",
                subject,
                "-out",
                str(temporary_csr),
            ]
            run(command, env=config_env(digest=configured.crypto.digest))
        with _ca_lock(settings.root_dir):
            with _new_output(cert, 0o644) as temporary_cert:
                command = [
                    "openssl",
                    "ca",
                    "-batch",
                    "-notext",
                    "-config",
                    str(config),
                    "-extensions",
                    "intermediate_ca",
                    "-days",
                    str(_capped_days(settings.intermediate_validity_days, root_cert)),
                    "-in",
                    str(csr),
                    "-out",
                    str(temporary_cert),
                ]
                run(
                    command,
                    env=config_env(
                        pki_dir=settings.root_dir,
                        digest=settings.root_crypto.digest,
                        ca_key=root_key,
                        ca_cert=root_cert,
                    ),
                )
                run(["openssl", "verify", "-CAfile", str(root_cert), str(temporary_cert)])
        write_ca_crypto_metadata(directory, configured.crypto)
    finally:
        os.umask(old_umask)
    return cert


def create_csr(
    settings: Settings,
    config: Path,
    kind: str,
    key: Path,
    csr: Path,
    subject: str,
    san: str | None,
    crypto: CryptoPolicy,
) -> None:
    """Generate a leaf key and CSR using the leaf's own crypto policy.

    The CSR digest is selected by the subject key owner. It does not control
    the digest that the configured issuer uses on the resulting certificate.
    """
    profile = settings.profile(kind)
    _validate_san(profile, kind, san)
    _validate_subject(subject)
    _check_new_file(key)
    _check_new_file(csr)
    old_umask = os.umask(0o077)
    try:
        with _new_output(key, 0o600) as temporary_key:
            run(
                [
                    "openssl",
                    "genpkey",
                    "-algorithm",
                    "EC",
                    "-pkeyopt",
                    f"ec_paramgen_curve:{crypto.curve}",
                    "-out",
                    str(temporary_key),
                ]
            )
        with _new_output(csr, 0o644) as temporary_csr:
            command = [
                "openssl",
                "req",
                "-new",
                "-config",
                str(config),
                "-key",
                str(key),
                "-subj",
                subject,
                "-out",
                str(temporary_csr),
            ]
            if san:
                command.extend(["-addext", f"subjectAltName={san}"])
            run(command, env=config_env(digest=crypto.digest))
            run(["openssl", "req", "-in", str(temporary_csr), "-noout", "-verify"])
    finally:
        os.umask(old_umask)


def serving_chain_path(certificate: Path) -> Path:
    """Return the TLS leaf-plus-intermediate serving-chain filename."""
    return certificate.with_suffix(".chain.crt")


def export_tls_serving_chain(settings: Settings, certificate: Path) -> Path:
    """Create a missing immutable TLS leaf-plus-intermediate serving chain."""
    _, _, intermediate = _domain_intermediate(settings, "tls")
    _reject_symlink(certificate)
    if not certificate.is_file():
        raise ValueError(f"TLS leaf certificate is missing: {certificate}")
    chain = serving_chain_path(certificate)
    _write_new(chain, certificate.read_bytes() + intermediate.read_bytes())
    return chain


def issue(
    settings: Settings,
    config: Path,
    pki_dir: Path,
    kind: str,
    csr: Path,
    cert: Path,
    san: str | None,
) -> Path | None:
    """Issue a leaf only from its configured domain intermediate.

    TLS issuance additionally creates and returns a leaf-first serving chain
    containing the leaf and its TLS intermediate (never the root).
    """
    profile = settings.profile(kind)
    _validate_san(profile, kind, san)
    expected_dir = settings.domain(profile.issuer_domain).ca_dir
    if pki_dir.expanduser().resolve(strict=False) != expected_dir:
        raise ValueError(
            f"{kind} must be issued by the configured {profile.issuer_domain} intermediate"
        )
    _, ca_key, ca_cert = _domain_intermediate(settings, profile.issuer_domain)
    root_cert = settings.root_dir / "certs/root-ca.crt"
    _reject_symlink(root_cert)
    if not root_cert.is_file():
        raise ValueError("Root CA certificate is missing")
    _reject_symlink(csr)
    if not csr.is_file():
        raise ValueError(f"CSR is missing: {csr}")
    _check_new_file(cert)
    chain = serving_chain_path(cert) if profile.issuer_domain == "tls" else None
    if chain is not None:
        _check_new_file(chain)
    with _ca_lock(expected_dir):
        with _new_output(cert, 0o644) as temporary_cert:
            command = [
                "openssl",
                "ca",
                "-batch",
                "-notext",
                "-config",
                str(config),
                "-extensions",
                profile.extension,
                "-days",
                str(_capped_days(settings.leaf_validity_days, ca_cert)),
                "-in",
                str(csr),
                "-out",
                str(temporary_cert),
            ]
            run(
                command,
                env=config_env(
                    pki_dir=expected_dir,
                    san=san,
                    digest=settings.domain(profile.issuer_domain).crypto.digest,
                    ca_key=ca_key,
                    ca_cert=ca_cert,
                ),
            )
            verify_command = [
                "openssl",
                "verify",
                "-CAfile",
                str(root_cert),
                "-untrusted",
                str(ca_cert),
                "-purpose",
                "any",
                str(temporary_cert),
            ]
            run(verify_command)
        if chain is not None:
            _write_new(chain, cert.read_bytes() + ca_cert.read_bytes())
    return chain


def refresh_crl(settings: Settings, config: Path, domain: str) -> Path:
    """Generate a CRL signed with the configured intermediate issuer digest."""
    configured, ca_key, ca_cert = _domain_intermediate(settings, domain)
    crl = configured.ca_dir / "crl" / "issuer.crl"
    with _ca_lock(configured.ca_dir):
        with _replace_output(crl, 0o644) as temporary_crl:
            command = [
                "openssl",
                "ca",
                "-gencrl",
                "-config",
                str(config),
                "-out",
                str(temporary_crl),
            ]
            run(
                command,
                env=config_env(
                    pki_dir=configured.ca_dir,
                    digest=configured.crypto.digest,
                    ca_key=ca_key,
                    ca_cert=ca_cert,
                ),
            )
    return crl


def revoke(settings: Settings, config: Path, domain: str, certificate: Path) -> Path:
    """Revoke a leaf and regenerate the CRL with its issuer's digest policy.

    The certificate record remains in OpenSSL's index. This intentionally
    cannot reissue an identity: callers must select a new generation.
    """
    configured, ca_key, ca_cert = _domain_intermediate(settings, domain)
    _reject_symlink(certificate)
    if not certificate.is_file():
        raise ValueError(f"certificate is missing: {certificate}")
    with _ca_lock(configured.ca_dir):
        command = [
            "openssl",
            "ca",
            "-batch",
            "-config",
            str(config),
            "-revoke",
            str(certificate),
        ]
        run(
            command,
            env=config_env(
                pki_dir=configured.ca_dir,
                digest=configured.crypto.digest,
                ca_key=ca_key,
                ca_cert=ca_cert,
            ),
        )
    return refresh_crl(settings, config, domain)


def export_node_ca_chain(settings: Settings, domain: str) -> Path:
    """Write a public intermediate-plus-root trust bundle for one node domain."""
    if domain not in {"tls", "kubernetes"}:
        raise ValueError(f"unknown node trust domain: {domain}")
    _, _, intermediate = _domain_intermediate(settings, domain)
    root = settings.root_dir / "certs/root-ca.crt"
    _reject_symlink(root)
    if not root.is_file():
        raise ValueError("Root CA certificate is missing")
    destination = settings.domain(domain).directory / "node-ca-chain.crt"
    _write_new(destination, intermediate.read_bytes() + root.read_bytes())
    return destination


def kernel_export_paths(settings: Settings) -> tuple[Path, Path, Path]:
    """Return public kernel trust export paths: root, intermediate, and leaf."""
    trust = settings.kernel_dir / "trust"
    return (
        trust / "root-ca.crt",
        trust / "code-signing-intermediate.crt",
        trust / "module-signing-leaf.crt",
    )


def preflight_kernel_exports(settings: Settings) -> None:
    """Reject existing or symlinked public kernel export destinations."""
    for path in kernel_export_paths(settings):
        _check_new_file(path)


def export_kernel_public_material(settings: Settings, leaf: Path) -> tuple[Path, Path, Path]:
    """Export public root, code-signing intermediate, and signer leaf files.

    These files are exports for an administrator to evaluate and install
    manually.  Creating them does not register a trust anchor anywhere.
    """
    root_destination, intermediate_destination, leaf_destination = kernel_export_paths(settings)
    _, _, intermediate = _domain_intermediate(settings, "code-signing")
    root = settings.root_dir / "certs/root-ca.crt"
    _reject_symlink(root)
    _reject_symlink(leaf)
    if not root.is_file() or not leaf.is_file():
        raise ValueError("Root CA certificate or module-signing leaf is missing")
    preflight_kernel_exports(settings)
    _write_new(root_destination, root.read_bytes())
    _write_new(intermediate_destination, intermediate.read_bytes())
    _write_new(leaf_destination, leaf.read_bytes())
    return root_destination, intermediate_destination, leaf_destination


def kernel_leaf_export_paths(settings: Settings, name: str, generation: int) -> tuple[Path, Path, Path, Path]:
    """Return immutable kernel export paths for one signer generation."""
    directory = settings.kernel_dir / name / f"generation-{generation}"
    return (
        directory / "trust/root-ca.crt",
        directory / "trust/code-signing-intermediate.crt",
        directory / "trust/leaf.crt",
        directory / "module-signing-key.pem",
    )


def kernel_leaf_export_is_complete(settings: Settings, name: str, generation: int) -> bool:
    """Return whether all immutable exports for a signer generation exist."""
    paths = kernel_leaf_export_paths(settings, name, generation)
    existing = [path.exists() or path.is_symlink() for path in paths]
    if any(existing) and not all(existing):
        raise ValueError(f"kernel export is incomplete: {paths[-1].parent}")
    if all(existing):
        for path in paths:
            _reject_symlink(path)
            if not path.is_file():
                raise ValueError(f"kernel export is not a regular file: {path}")
        return True
    return False


def kernel_active_generation_path(settings: Settings, name: str) -> Path:
    """Return the atomic active-generation selector for a signer identity."""
    return settings.kernel_dir / name / "active-generation"


def read_kernel_active_generation(settings: Settings, name: str) -> int | None:
    """Read an optional active signer selector, rejecting malformed state."""
    path = kernel_active_generation_path(settings, name)
    _reject_symlink(path)
    if not path.exists():
        return None
    if not path.is_file():
        raise ValueError(f"kernel active selector is not a regular file: {path}")
    value = path.read_text(encoding="ascii").strip()
    if value == "none":
        return None
    try:
        generation = int(value)
    except ValueError as error:
        raise ValueError(f"kernel active selector is invalid: {path}") from error
    if generation < 1:
        raise ValueError(f"kernel active selector is invalid: {path}")
    return generation


def set_kernel_active_generation(settings: Settings, name: str, generation: int | None) -> Path:
    """Atomically select one exported signer generation, or explicitly none."""
    path = kernel_active_generation_path(settings, name)
    payload = "none\n" if generation is None else f"{generation}\n"
    with _replace_output(path, 0o644) as temporary:
        temporary.write_text(payload, encoding="ascii")
    return path


def export_kernel_leaf_material(
    settings: Settings, name: str, generation: int, key: Path, leaf: Path
) -> tuple[Path, Path, Path, Path]:
    """Export immutable code-signing material for one signer generation.

    The active signer is selected separately by ``active-generation`` so a
    rotation never overwrites historical material or exposes a revoked key as
    the current one.
    """
    _, _, intermediate = _domain_intermediate(settings, "code-signing")
    root = settings.root_dir / "certs/root-ca.crt"
    _private_key(key)
    _reject_symlink(root)
    _reject_symlink(leaf)
    if not root.is_file() or not leaf.is_file():
        raise ValueError("Root CA certificate or code-signing leaf is missing")
    root_export, intermediate_export, leaf_export, key_export = kernel_leaf_export_paths(
        settings, name, generation
    )
    for destination in (root_export, intermediate_export, leaf_export, key_export):
        _check_new_file(destination)
    _write_new(root_export, root.read_bytes())
    _write_new(intermediate_export, intermediate.read_bytes())
    _write_new(leaf_export, leaf.read_bytes())
    _write_new(key_export, key.read_bytes() + leaf.read_bytes(), 0o600)
    return root_export, intermediate_export, leaf_export, key_export


def export_kernel_code_signing_ca(settings: Settings) -> Path:
    """Export the public code-signing intermediate; never install trust."""
    _, _, source = _domain_intermediate(settings, "code-signing")
    destination = settings.kernel_dir / "trust/code-signing-intermediate.crt"
    _write_new(destination, source.read_bytes())
    return destination
