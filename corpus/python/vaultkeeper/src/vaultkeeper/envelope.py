"""Envelope encryption for secrets in transit between vaults.

Every secret leaves a vault wrapped in an envelope: a fresh data key seals the
payload, and the data key itself is wrapped for the destination vault.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_BYTES = 12
DATA_KEY_BYTES = 32


@dataclass(frozen=True)
class Envelope:
    """A sealed secret and the nonce needed to open it."""

    nonce: bytes
    ciphertext: bytes

    def to_wire(self) -> bytes:
        return self.nonce + self.ciphertext

    @classmethod
    def from_wire(cls, blob: bytes) -> "Envelope":
        if len(blob) <= NONCE_BYTES:
            raise ValueError("envelope: payload too short")
        return cls(nonce=blob[:NONCE_BYTES], ciphertext=blob[NONCE_BYTES:])


def new_data_key() -> bytes:
    """Return a fresh data key for one envelope."""
    return os.urandom(DATA_KEY_BYTES)


def seal(data_key: bytes, plaintext: bytes, associated: bytes) -> Envelope:
    """Seal a secret under a one-shot data key."""
    if len(data_key) != DATA_KEY_BYTES:
        raise ValueError(f"envelope: data key must be {DATA_KEY_BYTES} bytes")
    aead = AESGCM(data_key)
    nonce = os.urandom(NONCE_BYTES)
    return Envelope(nonce=nonce, ciphertext=aead.encrypt(nonce, plaintext, associated))


def open_envelope(data_key: bytes, envelope: Envelope, associated: bytes) -> bytes:
    """Reverse :func:`seal`."""
    aead = AESGCM(data_key)
    return aead.decrypt(envelope.nonce, envelope.ciphertext, associated)
