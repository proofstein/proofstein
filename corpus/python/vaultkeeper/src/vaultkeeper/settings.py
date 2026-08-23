"""Runtime settings, read from config/vaultkeeper.yaml."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    """The subset of the config file the daemon actually uses."""

    backend: str
    envelope_cipher: str
    manifest_signature: str
    mesh_key_agreement: str
    fingerprint_hash: str
    attestation_profile: str
    key_file: str

    @classmethod
    def load(cls, path: str | Path) -> "Settings":
        values = _read_flat_yaml(Path(path))
        return cls(
            backend=values.get("storage.backend", "sealed-memory"),
            envelope_cipher=values.get("crypto.envelope_cipher", ""),
            manifest_signature=values.get("crypto.manifest_signature", ""),
            mesh_key_agreement=values.get("crypto.mesh_key_agreement", ""),
            fingerprint_hash=values.get("ledger.fingerprint_hash", ""),
            attestation_profile=values.get("crypto.attestation_profile", "compact"),
            key_file=values.get("crypto.key_file", ""),
        )


def _read_flat_yaml(path: Path) -> dict[str, str]:
    """Read the flat ``section.key`` subset of YAML the daemon needs.

    A full YAML parser is not worth the dependency for a dozen scalars.
    """
    values: dict[str, str] = {}
    section = ""
    for raw in path.read_text(encoding="utf-8").splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        key, sep, value = stripped.partition(":")
        if not sep:
            continue
        key = key.strip()
        value = value.strip().strip("\"'")
        if not value:
            section = key
            continue
        if not raw.startswith((" ", "\t")):
            section = ""
        values[f"{section}.{key}" if section else key] = value
    return values
