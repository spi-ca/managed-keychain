"""Command-line interface for declarative managed-keychain reconciliation."""
from __future__ import annotations

import argparse
from pathlib import Path

from .openssl import OpenSSLError, require_openssl, run
from .reconcile import apply, plan
from .settings import load


def _config_path(value: Path | None) -> Path:
    """Resolve an explicit configuration or the checkout-local conventional path."""
    if value is not None:
        return value
    discovered = Path.cwd() / "config" / "keychain.toml"
    if discovered.is_file():
        return discovered
    raise ValueError(
        "no configuration discovered at ./config/keychain.toml; pass --config /path/to/keychain.toml"
    )


def _print_operations(operations: list[object]) -> None:
    """Print a concise stable representation of a plan or apply result."""
    if not operations:
        print("No changes.")
        return
    for operation in operations:
        print(operation)


def _inspect_certificate(certificate: Path) -> None:
    """Print the complete OpenSSL certificate report for the selected file."""
    command = [
        "openssl",
        "x509",
        "-in",
        str(certificate),
        "-noout",
        "-subject",
        "-issuer",
        "-dates",
        "-text",
    ]
    run(command)


def main() -> None:
    """Parse commands and run only the explicitly selected operation."""
    parser = argparse.ArgumentParser(description="Declarative OpenSSL PKI reconciliation")
    parser.add_argument("--config", type=Path, help="external keychain.toml policy file")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("plan", help="read desired changes only; never writes")
    sub.add_parser("apply", help="apply the declarative policy")
    inspect = sub.add_parser("inspect", help="read certificate metadata")
    inspect.add_argument("--certificate", type=Path, required=True)
    args = parser.parse_args()
    try:
        settings = load(_config_path(args.config))
        if args.command == "plan":
            _print_operations(plan(settings))
        elif args.command == "apply":
            require_openssl()
            _print_operations(apply(settings))
        else:
            require_openssl()
            # Repeated -ext options are not cumulative on all OpenSSL releases;
            # a full text dump reliably reports every requested extension.
            _inspect_certificate(args.certificate)
    except (ValueError, OpenSSLError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
