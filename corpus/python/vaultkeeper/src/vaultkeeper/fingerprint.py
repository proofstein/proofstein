"""Content fingerprints for the sync ledger.

``hashlib`` is imported under a local name so the ledger code reads the same way
it did before the move off the old vendored hashing helper.
"""

from __future__ import annotations

import hashlib as digestlib

FINGERPRINT_PREFIX = "vk1"


def of(payload: bytes) -> str:
    """Return the ledger fingerprint of a payload."""
    digest = digestlib.sha256(payload).hexdigest()
    return f"{FINGERPRINT_PREFIX}:{digest}"


def matches(payload: bytes, fingerprint: str) -> bool:
    """Report whether a payload still carries the recorded fingerprint."""
    return of(payload) == fingerprint


def short(fingerprint: str) -> str:
    """Return the display form used in log lines."""
    _, _, digest = fingerprint.partition(":")
    return digest[:12]
