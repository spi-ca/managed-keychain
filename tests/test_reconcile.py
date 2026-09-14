"""Temporary-state integration and regression tests for declarative reconciliation."""
from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest

from managed_keychain.reconcile import apply, plan
from managed_keychain.settings import load


OPENSSL = shutil.which("openssl")
PROJECT = Path(__file__).resolve().parents[1]


def policy(
    directory: Path,
    *,
    mysql_desired: str = "active",
    mysql_generation: int = 1,
    mysql_revoked_generations: str = "",
    module_desired: str = "active",
    module_generation: int = 1,
    module_revoked_generations: str = "",
    pki_curve: str = "secp384r1",
    pki_digest: str = "sha384",
    root_crypto: str = "",
    tls_crypto: str = "",
    mysql_crypto: str = "",
) -> Path:
    """Create one external policy pointing all generated state into ``directory``."""
    config = directory / "keychain.toml"
    config.write_text(textwrap.dedent(f"""\
        [pki]
        curve = "{pki_curve}"
        digest = "{pki_digest}"
        root_validity_days = 36525
        intermediate_validity_days = 3652
        leaf_validity_days = 1095
        base_dir = "{directory}"
        openssl_config = "{PROJECT / 'config/pki.cnf'}"
        {root_crypto}
        [paths]
        root_dir = "state/ca"
        kernel_dir = "state/kernel"
        [subject]
        country = "KR"
        state = "Seoul"
        locality = "Seoul"
        organization = "Test"
        [subject.root_ca]
        common_name = "Test Root CA"
        [subject.module_signing]
        common_name = "spi-ca kernel code-sign"
        [domains.tls]
        directory = "state/tls"
        intermediate_common_name = "TLS Intermediate"
        {tls_crypto}
        [domains.kubernetes]
        directory = "state/kubernetes"
        intermediate_common_name = "Kubernetes Intermediate"
        [domains.code-signing]
        directory = "state/code-signing"
        intermediate_common_name = "Code-signing Intermediate"
        [profiles.tls_server]
        extension = "tls_server"
        requires_san = true
        issuer_domain = "tls"
        [profiles.kubernetes_server]
        extension = "tls_server"
        requires_san = true
        issuer_domain = "kubernetes"
        [profiles.tls_server_alt]
        extension = "tls_server"
        requires_san = true
        issuer_domain = "tls"
        [profiles.code_signing]
        extension = "code_signing"
        requires_san = false
        issuer_domain = "code-signing"
        [leaves.mysql]
        profile = "tls-server"
        domain = "tls"
        desired = "{mysql_desired}"
        generation = {mysql_generation}
        common_name = "mysql.test"
        san = "DNS:mysql.test"
        {mysql_crypto}
        {mysql_revoked_generations}
        [leaves.api]
        profile = "kubernetes-server"
        domain = "kubernetes"
        desired = "active"
        generation = 1
        common_name = "api.test"
        san = "DNS:api.test"
        [leaves.module]
        profile = "code-signing"
        domain = "code-signing"
        desired = "{module_desired}"
        generation = {module_generation}
        common_name = "spi-ca kernel code-sign"
        {module_revoked_generations}
    """), encoding="utf-8")
    return config


@unittest.skipUnless(OPENSSL, "OpenSSL is required for PKI integration tests")
class ReconcileTests(unittest.TestCase):
    """Exercise real OpenSSL state only below a temporary test directory."""

    def setUp(self) -> None:
        """Allocate a fresh external policy and state location."""
        self.temp = tempfile.TemporaryDirectory(prefix="managed-keychain-test-")
        self.root = Path(self.temp.name)
        self.config = policy(self.root)

    def tearDown(self) -> None:
        """Remove temporary certificates and keys after each test."""
        self.temp.cleanup()

    def settings(self):
        """Load the current temporary policy."""
        return load(self.config)

    def test_plan_is_read_only_and_apply_is_idempotent(self) -> None:
        """Plan writes nothing; one apply creates all domains and a second plans no changes."""
        changes = plan(self.settings())
        self.assertTrue(changes)
        self.assertFalse((self.root / "state").exists())
        apply(self.settings())
        self.assertEqual(plan(self.settings()), [])
        for domain in ("tls", "kubernetes", "code-signing"):
            self.assertTrue((self.root / f"state/{domain}/ca/certs/intermediate.crt").is_file())
        self.assertTrue((self.root / "state/tls/node-ca-chain.crt").is_file())
        self.assertTrue((self.root / "state/kubernetes/node-ca-chain.crt").is_file())
        self.assertTrue((self.root / "state/kernel/module/generation-1/module-signing-key.pem").is_file())
        self.assertEqual((self.root / "state/kernel/module/active-generation").read_text(), "1\n")
        self.assertEqual((self.root / "state/tls/ca/db/serial").read_text().strip(), "1001")
        self.assertEqual((self.root / "state/tls/identities/mysql/generation-1/private/key.pem").stat().st_mode & 0o777, 0o600)

    def _openssl_text(self, *command: str) -> str:
        """Return OpenSSL diagnostic text or fail the integration test clearly."""
        return subprocess.run(
            ["openssl", *command],
            check=True,
            capture_output=True,
            text=True,
        ).stdout

    def assert_key_curve(self, key: Path, expected: str) -> None:
        """Assert an EC private key's OpenSSL curve OID."""
        output = self._openssl_text("ec", "-in", str(key), "-noout", "-text", "-param_out")
        self.assertIn(f"ASN1 OID: {expected}", output)

    def assert_signature_digest(self, command: list[str], expected: str) -> None:
        """Assert the signature algorithm reported by a certificate-like object."""
        output = self._openssl_text(*command)
        self.assertIn(f"Signature Algorithm: ecdsa-with-{expected}", output)

    def test_mixed_crypto_hierarchy_uses_target_curves_and_issuer_digests(self) -> None:
        """Real OpenSSL output distinguishes key-owner and issuer signing policy."""
        self.config = policy(
            self.root,
            pki_curve="P256",
            pki_digest="SHA256",
            root_crypto='[pki.root]\ncurve = "P384"\ndigest = "SHA512"',
            tls_crypto='curve = "P256"\ndigest = "SHA256"',
            mysql_crypto='curve = "P521"\ndigest = "SHA512"',
        )
        apply(self.settings())

        root_key = self.root / "state/ca/private/root-ca.key"
        tls_key = self.root / "state/tls/ca/private/intermediate.key"
        leaf_key = self.root / "state/tls/identities/mysql/generation-1/private/key.pem"
        root_certificate = self.root / "state/ca/certs/root-ca.crt"
        tls_certificate = self.root / "state/tls/ca/certs/intermediate.crt"
        leaf_certificate = self.root / "state/tls/identities/mysql/generation-1/issued/certificate.crt"
        csr = self.root / "state/tls/identities/mysql/generation-1/csr/request.csr"
        crl = self.root / "state/tls/ca/crl/issuer.crl"

        self.assert_key_curve(root_key, "secp384r1")
        self.assert_key_curve(tls_key, "prime256v1")
        self.assert_key_curve(leaf_key, "secp521r1")
        self.assert_signature_digest(["x509", "-in", str(root_certificate), "-noout", "-text"], "SHA512")
        # Root, not TLS, signs the intermediate certificate.
        self.assert_signature_digest(["x509", "-in", str(tls_certificate), "-noout", "-text"], "SHA512")
        # TLS issuer, not the P-521 leaf, signs the leaf certificate and CRL.
        self.assert_signature_digest(["x509", "-in", str(leaf_certificate), "-noout", "-text"], "SHA256")
        self.assert_signature_digest(["req", "-in", str(csr), "-noout", "-text"], "SHA512")

        self.config = policy(
            self.root,
            mysql_desired="revoked",
            pki_curve="P256",
            pki_digest="SHA256",
            root_crypto='[pki.root]\ncurve = "P384"\ndigest = "SHA512"',
            tls_crypto='curve = "P256"\ndigest = "SHA256"',
            mysql_crypto='curve = "P521"\ndigest = "SHA512"',
        )
        apply(self.settings())
        self.assert_signature_digest(["crl", "-in", str(crl), "-noout", "-text"], "SHA256")
        self.assertEqual(plan(self.settings()), [])

    def test_crypto_policy_drift_never_rekeys_existing_ca_or_leaf(self) -> None:
        """Persisted metadata rejects changed issuer policy and leaf crypto intent."""
        self.config = policy(
            self.root,
            tls_crypto='digest = "SHA256"',
            mysql_crypto='curve = "P521"',
        )
        apply(self.settings())
        original_root = (self.root / "state/ca/private/root-ca.key").read_bytes()
        original_tls = (self.root / "state/tls/ca/private/intermediate.key").read_bytes()

        self.config.write_text(
            self.config.read_text(encoding="utf-8").replace(
                'digest = "sha384"',
                'digest = "sha512"',
                1,
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "root CA cryptographic policy changed"):
            plan(self.settings())
        self.assertEqual((self.root / "state/ca/private/root-ca.key").read_bytes(), original_root)

        self.config = policy(self.root, tls_crypto='digest = "SHA512"', mysql_crypto='curve = "P521"')
        with self.assertRaisesRegex(ValueError, "tls intermediate cryptographic policy changed"):
            plan(self.settings())
        self.assertEqual((self.root / "state/tls/ca/private/intermediate.key").read_bytes(), original_tls)

        self.config = policy(self.root, tls_crypto='digest = "SHA256"', mysql_crypto='curve = "P256"')
        with self.assertRaisesRegex(ValueError, "immutable identity or crypto policy changed"):
            plan(self.settings())

    def test_revoke_persists_history_and_crl_rejects_leaf(self) -> None:
        """Changing desired state to revoked modifies the issuer DB, not the record path."""
        apply(self.settings())
        self.config = policy(self.root, mysql_desired="revoked")
        apply(self.settings())
        certificate = self.root / "state/tls/identities/mysql/generation-1/issued/certificate.crt"
        crl = self.root / "state/tls/ca/crl/issuer.crl"
        self.assertTrue(certificate.is_file())
        self.assertTrue(crl.is_file())
        result = subprocess.run(["openssl", "verify", "-crl_check", "-CAfile", str(self.root / "state/ca/certs/root-ca.crt"), "-untrusted", str(self.root / "state/tls/ca/certs/intermediate.crt"), "-CRLfile", str(crl), str(certificate)], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("certificate revoked", result.stderr)
        self.assertEqual(plan(self.settings()), [])

    def test_renewal_requires_new_generation_and_preserves_old_record(self) -> None:
        """A replacement is an explicit generation change rather than an overwrite."""
        apply(self.settings())
        self.config = policy(self.root, mysql_desired="revoked")
        apply(self.settings())
        self.config = policy(self.root, mysql_generation=2)
        apply(self.settings())
        first = self.root / "state/tls/identities/mysql/generation-1/issued/certificate.crt"
        second = self.root / "state/tls/identities/mysql/generation-2/issued/certificate.crt"
        self.assertTrue(first.is_file())
        self.assertTrue(second.is_file())
        self.assertNotEqual(first.read_bytes(), second.read_bytes())

    def test_incomplete_record_does_not_replace_unrelated_state(self) -> None:
        """A failed preflight leaves already issued identities intact."""
        apply(self.settings())
        sentinel = self.root / "state/api-sentinel"
        sentinel.write_text("keep")
        broken = self.root / "state/tls/identities/mysql/generation-2/private/key.pem"
        broken.parent.mkdir(parents=True)
        broken.write_text("partial")
        self.config = policy(self.root, mysql_generation=2)
        with self.assertRaisesRegex(ValueError, "incomplete"):
            apply(self.settings())
        self.assertEqual(sentinel.read_text(), "keep")

    def test_existing_generation_rejects_immutable_identity_drift(self) -> None:
        """Subject, SAN, and profile changes require an explicit new generation."""
        apply(self.settings())
        original = self.config.read_text(encoding="utf-8")
        for old, new in (
            ('common_name = "mysql.test"', 'common_name = "mysql-drift.test"'),
            ('san = "DNS:mysql.test"', 'san = "DNS:mysql-drift.test"'),
            ('profile = "tls-server"', 'profile = "tls-server-alt"'),
        ):
            with self.subTest(attribute=old):
                self.config.write_text(original.replace(old, new, 1), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "increase generation"):
                    plan(self.settings())
        self.config.write_text(original, encoding="utf-8")

    def test_absent_revoked_generation_is_rejected(self) -> None:
        """A revoked declaration cannot silently become a perpetual no-op."""
        self.config = policy(self.root, mysql_desired="revoked")
        with self.assertRaisesRegex(ValueError, "cannot revoke absent mysql generation 1"):
            plan(self.settings())

    def test_prior_generation_revocation_persists_and_refreshes_from_issuer_history(self) -> None:
        """An active successor can declaratively revoke a prior immutable record."""
        apply(self.settings())
        self.config = policy(
            self.root,
            mysql_generation=2,
            mysql_revoked_generations="revoked_generations = [1]",
        )
        apply(self.settings())
        first = self.root / "state/tls/identities/mysql/generation-1/issued/certificate.crt"
        second = self.root / "state/tls/identities/mysql/generation-2/issued/certificate.crt"
        self.assertTrue(first.is_file())
        self.assertTrue(second.is_file())
        self.assertTrue((self.root / "state/tls/ca/crl/issuer.crl").is_file())

        # Remove the declarative historical target and the CRL. The retained
        # OpenSSL database, not current leaf declarations, still drives repair.
        self.config = policy(self.root, mysql_generation=2)
        (self.root / "state/tls/ca/crl/issuer.crl").unlink()
        self.assertIn("refresh issuer CRL", [operation.action for operation in plan(self.settings())])
        apply(self.settings())
        self.assertEqual(plan(self.settings()), [])

    def test_kernel_rotation_uses_immutable_exports_and_atomic_active_selection(self) -> None:
        """A new signer export is planned, selected, and can revoke its predecessor."""
        apply(self.settings())
        first_key = self.root / "state/kernel/module/generation-1/module-signing-key.pem"
        self.config = policy(self.root, module_generation=2)
        actions = [operation.action for operation in plan(self.settings())]
        self.assertIn("export kernel signer material", actions)
        self.assertIn("select active kernel signer", actions)
        apply(self.settings())
        second_key = self.root / "state/kernel/module/generation-2/module-signing-key.pem"
        active = self.root / "state/kernel/module/active-generation"
        self.assertTrue(first_key.is_file())
        self.assertTrue(second_key.is_file())
        self.assertNotEqual(first_key.read_bytes(), second_key.read_bytes())
        self.assertEqual(active.read_text(), "2\n")

        self.config = policy(
            self.root,
            module_generation=2,
            module_revoked_generations="revoked_generations = [1]",
        )
        apply(self.settings())
        self.assertTrue(first_key.is_file())  # Historical material is not deleted.
        self.assertEqual(active.read_text(), "2\n")

        self.config = policy(
            self.root,
            module_desired="revoked",
            module_generation=2,
            module_revoked_generations="revoked_generations = [1]",
        )
        apply(self.settings())
        self.assertEqual(active.read_text(), "none\n")
        self.assertEqual(plan(self.settings()), [])


class ConfigurationTests(unittest.TestCase):
    """Cover no-default discovery and source-package hygiene without state creation."""

    def test_cli_requires_config_outside_checkout(self) -> None:
        """Installed or arbitrary working directories must provide an external policy."""
        result = subprocess.run(["uv", "run", "managed-keychain", "plan"], cwd=tempfile.gettempdir(), capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("pass --config", result.stderr)

    def test_rejects_invalid_crypto_algorithm_values(self) -> None:
        """Only documented P-curve aliases and SHA-2 digest values are accepted."""
        with tempfile.TemporaryDirectory(prefix="managed-keychain-config-") as temporary:
            root = Path(temporary)
            config = policy(root)
            original = config.read_text(encoding="utf-8")
            for old, new, expected in (
                ('curve = "secp384r1"', 'curve = "P224"', "pki.curve"),
                ('digest = "sha384"', 'digest = "sha1"', "pki.digest"),
                (
                    'san = "DNS:mysql.test"',
                    'san = "DNS:mysql.test"\ncurve = "rsa"',
                    "leaves.mysql.curve",
                ),
                (
                    'san = "DNS:mysql.test"',
                    'san = "DNS:mysql.test"\ndigest = "md5"',
                    "leaves.mysql.digest",
                ),
            ):
                with self.subTest(value=new):
                    config.write_text(original.replace(old, new, 1), encoding="utf-8")
                    with self.assertRaisesRegex(ValueError, expected):
                        load(config)

    def test_source_has_no_packaged_policy_or_private_material(self) -> None:
        """Only root ``config/`` is canonical and package code contains no defaults."""
        self.assertFalse((PROJECT / "src/managed_keychain/resources").exists())
        self.assertFalse(any((PROJECT / "src").rglob("*.key")))
        self.assertFalse(any((PROJECT / "src").rglob("*.crt")))


if __name__ == "__main__":
    unittest.main()
