"""Validated declarative policy loading for managed-keychain."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
import re
import tomllib

_CURVE_ALIASES = {
    "prime256v1": "prime256v1",
    "p256": "prime256v1",
    "secp384r1": "secp384r1",
    "p384": "secp384r1",
    "secp521r1": "secp521r1",
    "p521": "secp521r1",
}
_DIGESTS = frozenset({"sha256", "sha384", "sha512"})
_DEFAULT_CURVE = "secp384r1"
_DEFAULT_DIGEST = "sha384"
_ALLOWED_EXTENSIONS = frozenset({"tls_server", "tls_client", "code_signing"})
_ALLOWED_DOMAINS = frozenset({"tls", "kubernetes", "code-signing"})
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")


@dataclass(frozen=True)
class CryptoPolicy:
    """The target EC key curve and the digest used when this identity signs."""

    curve: str
    digest: str


@dataclass(frozen=True)
class Profile:
    """A permitted leaf extension and the only intermediate which may issue it."""

    extension: str
    requires_san: bool
    issuer_domain: str


@dataclass(frozen=True)
class Domain:
    """Persistent state, subject policy, and crypto policy for one issuer."""

    name: str
    directory: Path
    intermediate_common_name: str
    crypto: CryptoPolicy

    @property
    def ca_dir(self) -> Path:
        """Return this intermediate's OpenSSL CA directory."""
        return self.directory / "ca"


@dataclass(frozen=True)
class Leaf:
    """One declaratively managed certificate identity and immutable generation."""

    name: str
    profile: str
    domain: str
    desired: str
    generation: int
    subject: str
    san: str | None
    revoked_generations: tuple[int, ...]
    crypto: CryptoPolicy


@dataclass(frozen=True)
class Settings:
    """Validated policy with all configured filesystem paths made absolute."""

    default_crypto: CryptoPolicy
    root_crypto: CryptoPolicy
    root_validity_days: int
    intermediate_validity_days: int
    leaf_validity_days: int
    crl_refresh_before_days: int
    root_dir: Path
    kernel_dir: Path
    root_subject: str
    module_subject: str
    domains: dict[str, Domain]
    profiles: dict[str, Profile]
    leaves: dict[str, Leaf]
    openssl_config: Path

    @property
    def curve(self) -> str:
        """Return the common default curve for compatibility with callers."""
        return self.default_crypto.curve

    @property
    def digest(self) -> str:
        """Return the common default signing digest for compatibility with callers."""
        return self.default_crypto.digest

    @property
    def default_pki_dir(self) -> Path:
        """Return the root CA directory (legacy compatibility alias)."""
        return self.root_dir

    @property
    def tls_dir(self) -> Path:
        """Return TLS state directory."""
        return self.domains["tls"].directory

    @property
    def kubernetes_dir(self) -> Path:
        """Return Kubernetes state directory."""
        return self.domains["kubernetes"].directory

    @property
    def code_signing_dir(self) -> Path:
        """Return code-signing state directory."""
        return self.domains["code-signing"].directory

    def domain(self, name: str) -> Domain:
        """Return a configured domain or a clear configuration error."""
        try:
            return self.domains[name]
        except KeyError as error:
            raise ValueError(f"unknown configured domain: {name}") from error

    def profile(self, name: str) -> Profile:
        """Return an allowed leaf profile, accepting TOML underscore spelling."""
        try:
            return self.profiles[name.replace("_", "-")]
        except KeyError as error:
            raise ValueError(f"unknown leaf profile: {name}") from error


def _mapping(value: Any, label: str) -> dict[str, Any]:
    """Require a TOML table."""
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a TOML table")
    return value


def _text(value: Any, label: str) -> str:
    """Require one non-empty, single-line TOML string."""
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    if "\x00" in value or "\n" in value or "\r" in value:
        raise ValueError(f"{label} must not contain control characters")
    return value


def _days(value: Any, label: str) -> int:
    """Require a positive integer duration or generation."""
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _resolve(value: Any, base: Path, label: str) -> Path:
    """Resolve a configured path relative to its documented base."""
    raw = Path(_text(value, label)).expanduser()
    return (raw if raw.is_absolute() else base / raw).resolve(strict=False)


def _curve(value: Any, label: str) -> str:
    """Normalize a supported OpenSSL EC curve name or common P-curve alias."""
    normalized = _text(value, label).lower()
    try:
        return _CURVE_ALIASES[normalized]
    except KeyError as error:
        raise ValueError(
            f"{label} must be one of prime256v1/P256, secp384r1/P384, secp521r1/P521"
        ) from error


def _digest(value: Any, label: str) -> str:
    """Normalize one supported SHA-2 signing digest."""
    normalized = _text(value, label).lower()
    if normalized not in _DIGESTS:
        raise ValueError(f"{label} must be one of SHA256, SHA384, SHA512")
    return normalized


def _crypto(raw: dict[str, Any], inherited: CryptoPolicy, label: str) -> CryptoPolicy:
    """Read a curve/digest override, inheriting absent values from ``inherited``."""
    if "curve" in raw:
        curve = _curve(raw["curve"], f"{label}.curve")
    else:
        curve = inherited.curve
    if "digest" in raw:
        digest = _digest(raw["digest"], f"{label}.digest")
    else:
        digest = inherited.digest
    return CryptoPolicy(curve=curve, digest=digest)


def _subject(values: dict[str, Any], common_name: str) -> str:
    """Build a safe OpenSSL ``-subj`` DN from TOML identity fields."""
    fields = (
        ("C", _text(values.get("country"), "subject.country")),
        ("ST", _text(values.get("state"), "subject.state")),
        ("L", _text(values.get("locality"), "subject.locality")),
        ("O", _text(values.get("organization"), "subject.organization")),
        ("CN", _text(common_name, "subject common_name")),
    )
    return "".join(f"/{field}={value.replace('/', r'\\/')}" for field, value in fields)


def _leaf_subject(defaults: dict[str, Any], raw: dict[str, Any], label: str) -> str:
    """Build a leaf DN, allowing an identity-specific subject table override."""
    values = defaults | _mapping(raw.get("subject", {}), f"{label}.subject")
    common_name = _text(raw.get("common_name"), f"{label}.common_name")
    return _subject(values, common_name)


def _domains(
    raw_domains: dict[str, Any], base_dir: Path, default_crypto: CryptoPolicy
) -> dict[str, Domain]:
    """Load required trust domains and their inherited crypto policies."""
    domains: dict[str, Domain] = {}
    for name in _ALLOWED_DOMAINS:
        raw = _mapping(raw_domains.get(name), f"domains.{name}")
        domains[name] = Domain(
            name=name,
            directory=_resolve(raw.get("directory"), base_dir, f"domains.{name}.directory"),
            intermediate_common_name=_text(
                raw.get("intermediate_common_name"),
                f"domains.{name}.intermediate_common_name",
            ),
            crypto=_crypto(raw, default_crypto, f"domains.{name}"),
        )
    return domains


def _profiles(raw_profiles: dict[str, Any], domains: dict[str, Domain]) -> dict[str, Profile]:
    """Load permitted leaf profiles and validate their configured issuers."""
    profiles: dict[str, Profile] = {}
    for name, raw_value in raw_profiles.items():
        raw = _mapping(raw_value, f"profiles.{name}")
        label = f"profiles.{name}"
        profile = Profile(
            extension=_text(raw.get("extension"), f"{label}.extension"),
            requires_san=raw.get("requires_san"),
            issuer_domain=_text(raw.get("issuer_domain"), f"{label}.issuer_domain"),
        )
        if not isinstance(profile.requires_san, bool):
            raise ValueError(f"{label}.requires_san must be true or false")
        if profile.extension not in _ALLOWED_EXTENSIONS or profile.issuer_domain not in domains:
            raise ValueError(f"{label} has an invalid extension or issuer_domain")
        profiles[name.replace("_", "-")] = profile
    if not profiles:
        raise ValueError("at least one leaf profile is required")
    return profiles


def _leaves(
    raw_leaves: dict[str, Any],
    defaults: dict[str, Any],
    profiles: dict[str, Profile],
    default_crypto: CryptoPolicy,
) -> dict[str, Leaf]:
    """Load immutable leaf declarations and their inherited crypto policies."""
    leaves: dict[str, Leaf] = {}
    for name, raw_value in raw_leaves.items():
        if not isinstance(name, str) or not _NAME.fullmatch(name):
            raise ValueError("leaf names must use letters, digits, '.', '_' or '-'")
        raw = _mapping(raw_value, f"leaves.{name}")
        label = f"leaves.{name}"
        profile_name = _text(raw.get("profile"), f"{label}.profile").replace("_", "-")
        profile = profiles.get(profile_name)
        if profile is None:
            raise ValueError(f"{label}.profile is not configured: {profile_name}")
        domain = _text(raw.get("domain"), f"{label}.domain")
        if domain != profile.issuer_domain:
            raise ValueError(
                f"{label}.domain must match {profile_name}'s issuer_domain ({profile.issuer_domain})"
            )
        desired = _text(raw.get("desired", "active"), f"{label}.desired")
        if desired not in {"active", "revoked"}:
            raise ValueError(f"{label}.desired must be active or revoked")
        san = raw.get("san")
        if san is not None:
            san = _text(san, f"{label}.san")
        if profile.requires_san != bool(san):
            required = "required" if profile.requires_san else "not allowed"
            raise ValueError(f"{label}.san is {required} for {profile_name}")
        generation = _days(raw.get("generation", 1), f"{label}.generation")
        revoked_raw = raw.get("revoked_generations", [])
        if not isinstance(revoked_raw, list):
            raise ValueError(f"{label}.revoked_generations must be an array of prior generations")
        revoked_generations = tuple(
            _days(value, f"{label}.revoked_generations[{index}]")
            for index, value in enumerate(revoked_raw)
        )
        if len(set(revoked_generations)) != len(revoked_generations):
            raise ValueError(f"{label}.revoked_generations must not contain duplicates")
        if any(value >= generation for value in revoked_generations):
            raise ValueError(
                f"{label}.revoked_generations must contain only generations below {generation}"
            )
        leaves[name] = Leaf(
            name=name,
            profile=profile_name,
            domain=domain,
            desired=desired,
            generation=generation,
            subject=_leaf_subject(defaults, raw, label),
            san=san,
            revoked_generations=revoked_generations,
            crypto=_crypto(raw, default_crypto, label),
        )
    return leaves


def load(config_path: Path) -> Settings:
    """Load and validate one explicit TOML policy file.

    ``[pki]`` supplies common P384/SHA384 defaults.  ``[pki.root]``, each
    ``[domains.<name>]``, and each ``[leaves.<name>]`` may override ``curve``
    and ``digest``. Relative paths resolve below ``[pki].base_dir`` relative to
    this file.
    """
    config_path = config_path.expanduser().resolve(strict=False)
    if config_path.is_symlink() or not config_path.is_file():
        raise ValueError(f"configuration file is missing or is a symlink: {config_path}")
    try:
        with config_path.open("rb") as file:
            data = tomllib.load(file)
    except tomllib.TOMLDecodeError as error:
        raise ValueError(f"invalid TOML configuration: {error}") from error

    pki = _mapping(data.get("pki"), "pki")
    paths = _mapping(data.get("paths"), "paths")
    subject = _mapping(data.get("subject"), "subject")
    default_crypto = CryptoPolicy(
        _curve(pki.get("curve", _DEFAULT_CURVE), "pki.curve"),
        _digest(pki.get("digest", _DEFAULT_DIGEST), "pki.digest"),
    )
    root_table = _mapping(pki.get("root", {}), "pki.root")
    root_crypto = _crypto(root_table, default_crypto, "pki.root")
    base_dir = _resolve(pki.get("base_dir", "."), config_path.parent, "pki.base_dir")
    domain_table = _mapping(data.get("domains"), "domains")
    domains = _domains(domain_table, base_dir, default_crypto)
    profiles = _profiles(_mapping(data.get("profiles"), "profiles"), domains)
    leaves = _leaves(
        _mapping(data.get("leaves", {}), "leaves"),
        subject,
        profiles,
        default_crypto,
    )
    root_ca = _mapping(subject.get("root_ca"), "subject.root_ca")
    module_signing = _mapping(subject.get("module_signing"), "subject.module_signing")
    return Settings(
        default_crypto=default_crypto,
        root_crypto=root_crypto,
        root_validity_days=_days(pki.get("root_validity_days"), "pki.root_validity_days"),
        intermediate_validity_days=_days(
            pki.get("intermediate_validity_days"),
            "pki.intermediate_validity_days",
        ),
        leaf_validity_days=_days(pki.get("leaf_validity_days"), "pki.leaf_validity_days"),
        crl_refresh_before_days=_days(
            pki.get("crl_refresh_before_days", 7),
            "pki.crl_refresh_before_days",
        ),
        root_dir=_resolve(paths.get("root_dir"), base_dir, "paths.root_dir"),
        kernel_dir=_resolve(paths.get("kernel_dir"), base_dir, "paths.kernel_dir"),
        root_subject=_subject(
            subject,
            _text(root_ca.get("common_name"), "subject.root_ca.common_name"),
        ),        module_subject=_subject(
            subject,
            _text(module_signing.get("common_name"), "subject.module_signing.common_name"),
        ),
        domains=domains,
        profiles=profiles,
        leaves=leaves,
        openssl_config=_resolve(
            pki.get("openssl_config", "pki.cnf"),
            config_path.parent,
            "pki.openssl_config",
        ),
    )
