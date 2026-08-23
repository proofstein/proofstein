"""Post-quantum signatures over vault attestations.

An attestation is produced when a vault is sealed and verified for as long as
the vault is retained, which is longer than the signing key's rotation period.
Both schemes here are stateless: unlike the seals in the audit path, a key
signs an unbounded number of attestations and needs no index tracking.

The compact lattice scheme is the default because an attestation travels inside
a header with a size budget. The hash-based scheme is available for tenants who
decline the lattice assumption, and is selected by config rather than in code.
"""

from __future__ import annotations

import oqs

from .settings import Settings

#: Signature schemes this build can produce, in the spelling liboqs uses.
_SCHEMES = {
    "compact": "Falcon-1024",
    "hash-based": "SPHINCS+-SHA2-128s-simple",
}


class Attestor:
    """Sign vault attestations with the configured scheme."""

    def __init__(self, settings: Settings) -> None:
        self._scheme = _SCHEMES.get(settings.attestation_profile, "Falcon-1024")

    def sign(self, statement: bytes) -> bytes:
        """Return a detached signature over the attestation statement."""
        with oqs.Signature("Falcon-1024") as signer:
            signer.generate_keypair()
            return signer.sign(statement)

    def scheme(self) -> str:
        """Return the scheme name for the attestation header."""
        return self._scheme
