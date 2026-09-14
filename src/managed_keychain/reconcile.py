"""Read-only planning and explicit application of declarative PKI policy."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import json
from pathlib import Path
from typing import Any

from .openssl import run
from .pki import (
    ca_crypto_metadata_path,
    create_csr,
    export_kernel_leaf_material,
    export_node_ca_chain,
    export_tls_serving_chain,
    kernel_active_generation_path,
    kernel_leaf_export_is_complete,
    read_kernel_active_generation,
    refresh_crl,
    init_ca,
    init_intermediate,
    issue,
    revoke,
    serving_chain_path,
    set_kernel_active_generation,
    write_immutable_metadata,
)
from .settings import CryptoPolicy, Leaf, Settings


@dataclass(frozen=True)
class Operation:
    """One human-readable reconciliation action returned by :func:`plan`."""

    action: str
    target: Path | str

    def __str__(self) -> str:
        """Format a stable CLI plan line."""
        return f"{self.action}: {self.target}"


def _record_dir(settings: Settings, domain: str, name: str, generation: int) -> Path:
    """Return the immutable state directory for one named leaf generation."""
    return settings.domain(domain).directory / "identities" / name / f"generation-{generation}"


def _paths(settings: Settings, leaf: Leaf) -> tuple[Path, Path, Path]:
    """Return private key, CSR, and certificate paths for the configured generation."""
    record = _record_dir(settings, leaf.domain, leaf.name, leaf.generation)
    return record / "private/key.pem", record / "csr/request.csr", record / "issued/certificate.crt"


def _metadata_path(settings: Settings, domain: str, name: str, generation: int) -> Path:
    """Return the immutable intent metadata filename for a leaf generation."""
    return _record_dir(settings, domain, name, generation) / "metadata.json"


def _leaf_metadata(leaf: Leaf) -> dict[str, str | int | None]:
    """Return immutable issuance intent, including the leaf's effective crypto."""
    return {
        "version": 2,
        "name": leaf.name,
        "generation": leaf.generation,
        "profile": leaf.profile,
        "domain": leaf.domain,
        "subject": leaf.subject,
        "san": leaf.san,
        "curve": leaf.crypto.curve,
        "digest": leaf.crypto.digest,
    }


def _read_metadata(path: Path) -> dict[str, Any]:
    """Read one persisted immutable record declaration without repairing it."""
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"immutable metadata is missing: {path}; increase generation to replace it")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"immutable metadata is invalid: {path}; increase generation to replace it") from error
    if not isinstance(value, dict):
        raise ValueError(f"immutable metadata is invalid: {path}; increase generation to replace it")
    return value


def _assert_current_metadata(settings: Settings, leaf: Leaf) -> None:
    """Reject drift in immutable identity and leaf cryptographic policy fields."""
    metadata = _read_metadata(_metadata_path(settings, leaf.domain, leaf.name, leaf.generation))
    if metadata != _leaf_metadata(leaf):
        raise ValueError(
            f"{leaf.name} generation {leaf.generation} immutable identity or crypto policy changed; "
            "increase generation to issue a replacement"
        )


def _expected_ca_crypto(crypto: CryptoPolicy) -> dict[str, str | int]:
    """Return the exact immutable CA crypto-policy metadata representation."""
    return {"version": 1, "curve": crypto.curve, "digest": crypto.digest}


def _assert_ca_crypto(ca_dir: Path, crypto: CryptoPolicy, label: str) -> None:
    """Fail closed when an existing CA's configured cryptographic policy drifts."""
    path = ca_crypto_metadata_path(ca_dir)
    try:
        metadata = _read_metadata(path)
    except ValueError as error:
        raise ValueError(
            f"{label} crypto-policy metadata is absent or invalid; it cannot be safely rekeyed. "
            "Restore the prior policy metadata or bootstrap a new CA hierarchy."
        ) from error
    if metadata != _expected_ca_crypto(crypto):
        raise ValueError(
            f"{label} cryptographic policy changed; existing CA keys are never rekeyed. "
            "Restore its recorded curve/digest or bootstrap a new CA hierarchy."
        )


def _assert_existing_ca_crypto(settings: Settings) -> None:
    """Validate policy metadata for every complete CA before planning mutations."""
    root_cert = settings.root_dir / "certs/root-ca.crt"
    if root_cert.is_file():
        _assert_ca_crypto(settings.root_dir, settings.root_crypto, "root CA")
    for name, domain in settings.domains.items():
        certificate = domain.ca_dir / "certs/intermediate.crt"
        if certificate.is_file():
            _assert_ca_crypto(domain.ca_dir, domain.crypto, f"{name} intermediate")


def _prior_record(settings: Settings, name: str, generation: int) -> tuple[dict[str, Any], Path]:
    """Find exactly one persisted prior record across configured issuer domains."""
    records = [
        _record_dir(settings, domain, name, generation)
        for domain in settings.domains
        if _record_dir(settings, domain, name, generation).exists()
    ]
    if not records:
        raise ValueError(f"cannot revoke absent {name} generation {generation}")
    if len(records) != 1:
        raise ValueError(f"ambiguous persisted record for {name} generation {generation}")
    record = records[0]
    metadata = _read_metadata(record / "metadata.json")
    domain = metadata.get("domain")
    if (
        metadata.get("version") not in {1, 2}
        or metadata.get("name") != name
        or metadata.get("generation") != generation
        or not isinstance(domain, str)
        or domain not in settings.domains
        or record != _record_dir(settings, domain, name, generation)
    ):
        raise ValueError(f"immutable metadata is invalid: {record / 'metadata.json'}")
    certificate = record / "issued/certificate.crt"
    if certificate.is_symlink() or not certificate.is_file():
        raise ValueError(f"cannot revoke absent {name} generation {generation}")
    return metadata, certificate


def _serial(certificate: Path) -> str:
    """Read an existing certificate serial without modifying PKI state."""
    output = run(["openssl", "x509", "-in", str(certificate), "-noout", "-serial"], capture=True)
    try:
        return output.strip().split("=", 1)[1].upper()
    except IndexError as error:
        raise ValueError(f"unable to read certificate serial: {certificate}") from error


def _crl_needs_refresh(settings: Settings, domain: str) -> bool:
    """Return whether a revoked issuer has no CRL or one nearing nextUpdate."""
    crl = settings.domain(domain).ca_dir / "crl/issuer.crl"
    if not crl.is_file():
        return True
    output = run(["openssl", "crl", "-in", str(crl), "-noout", "-nextupdate"], capture=True)
    try:
        next_update = output.strip().split("=", 1)[1]
        expiry = datetime.strptime(next_update, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
    except (IndexError, ValueError) as error:
        raise ValueError(f"unable to read CRL nextUpdate: {crl}") from error
    return (expiry - datetime.now(UTC)).days < settings.crl_refresh_before_days


def _issuer_has_revocations(settings: Settings, domain: str) -> bool:
    """Read issuer history, including records no longer declared by the policy."""
    index = settings.domain(domain).ca_dir / "db/index.txt"
    if not index.is_file():
        raise ValueError(f"issuer database is missing: {index}")
    return any(line.startswith("R\t") for line in index.read_text(encoding="utf-8").splitlines())


def _is_revoked(settings: Settings, domain: str, certificate: Path) -> bool:
    """Look up a leaf serial in its issuer's real OpenSSL index database."""
    index = settings.domain(domain).ca_dir / "db/index.txt"
    if not index.is_file():
        raise ValueError(f"issuer database is missing: {index}")
    serial = _serial(certificate)
    for line in index.read_text(encoding="utf-8").splitlines():
        fields = line.split("\t")
        if len(fields) >= 4 and fields[3].upper() == serial:
            return fields[0] == "R"
    raise ValueError(f"certificate is not recorded by configured {domain} issuer: {certificate}")


def _ca_operations(settings: Settings) -> list[Operation]:
    """Plan root and all configured intermediate CA prerequisites."""
    operations: list[Operation] = []
    root_cert = settings.root_dir / "certs/root-ca.crt"
    if not root_cert.is_file():
        if settings.root_dir.exists():
            raise ValueError(f"root CA is incomplete; refusing to reuse: {settings.root_dir}")
        operations.append(Operation("create root CA", settings.root_dir))
    for domain in sorted(settings.domains):
        cert = settings.domain(domain).ca_dir / "certs/intermediate.crt"
        if not cert.is_file():
            if settings.domain(domain).ca_dir.exists():
                raise ValueError(f"{domain} intermediate is incomplete; refusing to reuse")
            operations.append(Operation("create intermediate", domain))
    return operations


def _record_has_any_state(settings: Settings, leaf: Leaf) -> bool:
    """Return whether an unissued configured record contains any immutable state."""
    key, csr, _ = _paths(settings, leaf)
    metadata = _metadata_path(settings, leaf.domain, leaf.name, leaf.generation)
    return any(path.exists() or path.is_symlink() for path in (key, csr, metadata))


def plan(settings: Settings) -> list[Operation]:
    """Calculate desired changes without creating, deleting, or rewriting files."""
    if not settings.openssl_config.is_file():
        raise ValueError(f"OpenSSL configuration is missing: {settings.openssl_config}")
    _assert_existing_ca_crypto(settings)
    operations = _ca_operations(settings)
    revocation_domains: set[str] = set()

    for name in sorted(settings.leaves):
        leaf = settings.leaves[name]
        key, csr, certificate = _paths(settings, leaf)
        if certificate.is_file():
            _assert_current_metadata(settings, leaf)
            revoked = _is_revoked(settings, leaf.domain, certificate)
            if leaf.desired == "active" and revoked:
                raise ValueError(
                    f"{name} generation {leaf.generation} is revoked; increase generation to issue a replacement"
                )
            if leaf.desired == "revoked" and not revoked:
                operations.append(Operation("revoke leaf and refresh CRL", certificate))
                revocation_domains.add(leaf.domain)
            if leaf.domain == "tls" and not serving_chain_path(certificate).is_file():
                operations.append(Operation("export TLS serving chain", certificate))
        elif leaf.desired == "active":
            if _record_has_any_state(settings, leaf):
                raise ValueError(f"{name} generation {leaf.generation} is incomplete; refusing to replace it")
            operations.append(Operation("issue leaf", f"{name} generation {leaf.generation}"))
        else:
            raise ValueError(f"cannot revoke absent {name} generation {leaf.generation}")

        for generation in leaf.revoked_generations:
            metadata, prior_certificate = _prior_record(settings, name, generation)
            domain = metadata["domain"]
            assert isinstance(domain, str)  # Validated by _prior_record.
            if not _is_revoked(settings, domain, prior_certificate):
                operations.append(Operation("revoke prior generation and refresh CRL", prior_certificate))
                revocation_domains.add(domain)

    for domain in sorted(settings.domains):
        ca_cert = settings.domain(domain).ca_dir / "certs/intermediate.crt"
        if ca_cert.is_file() and _issuer_has_revocations(settings, domain):
            if domain not in revocation_domains and _crl_needs_refresh(settings, domain):
                operations.append(Operation("refresh issuer CRL", domain))

    for domain in ("tls", "kubernetes"):
        bundle = settings.domain(domain).directory / "node-ca-chain.crt"
        if not bundle.is_file():
            operations.append(Operation("export public CA bundle", bundle))

    for leaf in settings.leaves.values():
        if leaf.domain != "code-signing":
            continue
        _, _, certificate = _paths(settings, leaf)
        active_generation = leaf.generation if leaf.desired == "active" else None
        if active_generation is not None:
            if not kernel_leaf_export_is_complete(settings, leaf.name, leaf.generation):
                operations.append(Operation("export kernel signer material", f"{leaf.name} generation {leaf.generation}"))
        selected = read_kernel_active_generation(settings, leaf.name)
        if selected != active_generation:
            target: Path | str = kernel_active_generation_path(settings, leaf.name)
            action = "select active kernel signer" if active_generation is not None else "deactivate kernel signer"
            operations.append(Operation(action, target))
    return operations


def _write_metadata(settings: Settings, leaf: Leaf) -> None:
    """Persist issuance intent after a successfully issued immutable certificate."""
    path = _metadata_path(settings, leaf.domain, leaf.name, leaf.generation)
    payload = json.dumps(_leaf_metadata(leaf), indent=2, sort_keys=True).encode("utf-8") + b"\n"
    write_immutable_metadata(path, payload)


def apply(settings: Settings) -> list[Operation]:
    """Apply a fresh plan; this is the only path which mutates PKI state."""
    planned = plan(settings)
    # Establish CA prerequisites first. All later leaf operations preflight
    # their issuer before generating a private key.
    if not (settings.root_dir / "certs/root-ca.crt").is_file():
        init_ca(settings, settings.openssl_config, settings.root_dir, settings.root_subject)
    for domain in sorted(settings.domains):
        if not (settings.domain(domain).ca_dir / "certs/intermediate.crt").is_file():
            init_intermediate(settings, settings.openssl_config, domain)

    for name in sorted(settings.leaves):
        leaf = settings.leaves[name]
        key, csr, certificate = _paths(settings, leaf)
        if leaf.desired == "active" and not certificate.is_file():
            create_csr(
                settings,
                settings.openssl_config,
                leaf.profile,
                key,
                csr,
                leaf.subject,
                leaf.san,
                leaf.crypto,
            )
            issue(
                settings,
                settings.openssl_config,
                settings.domain(leaf.domain).ca_dir,
                leaf.profile,
                csr,
                certificate,
                leaf.san,
            )
            _write_metadata(settings, leaf)
        elif leaf.desired == "revoked" and certificate.is_file() and not _is_revoked(
            settings, leaf.domain, certificate
        ):
            revoke(settings, settings.openssl_config, leaf.domain, certificate)
        if certificate.is_file() and leaf.domain == "tls" and not serving_chain_path(certificate).is_file():
            export_tls_serving_chain(settings, certificate)

        for generation in leaf.revoked_generations:
            metadata, prior_certificate = _prior_record(settings, name, generation)
            domain = metadata["domain"]
            assert isinstance(domain, str)  # Validated by _prior_record.
            if not _is_revoked(settings, domain, prior_certificate):
                revoke(settings, settings.openssl_config, domain, prior_certificate)

    # Revocation may predate the current policy declaration. Refresh from the
    # issuer database rather than from only the leaves still declared above.
    for domain in sorted(settings.domains):
        ca_cert = settings.domain(domain).ca_dir / "certs/intermediate.crt"
        if ca_cert.is_file() and _issuer_has_revocations(settings, domain) and _crl_needs_refresh(settings, domain):
            refresh_crl(settings, settings.openssl_config, domain)

    for domain in ("tls", "kubernetes"):
        bundle = settings.domain(domain).directory / "node-ca-chain.crt"
        if not bundle.is_file():
            export_node_ca_chain(settings, domain)

    for leaf in settings.leaves.values():
        if leaf.domain != "code-signing":
            continue
        key, _, certificate = _paths(settings, leaf)
        active_generation = leaf.generation if leaf.desired == "active" else None
        if active_generation is not None:
            if not kernel_leaf_export_is_complete(settings, leaf.name, leaf.generation):
                export_kernel_leaf_material(settings, leaf.name, leaf.generation, key, certificate)
        if read_kernel_active_generation(settings, leaf.name) != active_generation:
            set_kernel_active_generation(settings, leaf.name, active_generation)
    return planned
