"""The vaultkeeper daemon entry point."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from . import backend, envelope, fingerprint, kem
from .identity import NodeIdentity
from .settings import Settings

logger = logging.getLogger("vaultkeeper")

DEFAULT_CONFIG = "config/vaultkeeper.yaml"


def run(config_path: str) -> int:
    """Start a node: load settings, build an identity, seal one probe secret."""
    settings = Settings.load(config_path)
    identity = NodeIdentity.generate()
    responder = kem.MeshResponder.generate()

    data_key = envelope.new_data_key()
    store = backend.open_backend(settings.backend, data_key)

    payload = b"postgres://vaultkeeper:rotate-me@db.internal:5432/ledger"
    reference = fingerprint.of(payload)
    store.put(reference, payload)

    manifest = f"{reference} backend={settings.backend}".encode()
    signature = identity.sign_manifest(manifest)

    logger.info(
        "node ready backend=%s cipher=%s fingerprint=%s sig=%dB mesh_key=%dB",
        settings.backend,
        settings.envelope_cipher,
        fingerprint.short(reference),
        len(signature),
        len(responder.public_bytes()),
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="vaultkeeper", description="secrets sync daemon")
    parser.add_argument("--config", default=DEFAULT_CONFIG, help="path to the node config")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    if not Path(args.config).exists():
        parser.error(f"config not found: {args.config}")
    return run(args.config)


if __name__ == "__main__":
    raise SystemExit(main())
