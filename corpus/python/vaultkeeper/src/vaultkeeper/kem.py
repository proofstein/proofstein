"""Key agreement for the vault mesh.

Vault contents outlive the machines that hold them by years, so mesh key
agreement is post-quantum. The wrapped data keys inside an envelope are the part
an attacker would want to record now and open later.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import mlkem


@dataclass
class MeshResponder:
    """Holds the decapsulation half of a mesh key pair."""

    private_key: mlkem.MLKEM768PrivateKey

    @classmethod
    def generate(cls) -> "MeshResponder":
        return cls(private_key=mlkem.MLKEM768PrivateKey.generate())

    def public_bytes(self) -> bytes:
        """Return the encapsulation key published in the mesh directory."""
        return self.private_key.public_key().public_bytes_raw()

    def accept(self, ciphertext: bytes) -> bytes:
        """Recover the shared secret an initiator encapsulated to us."""
        return self.private_key.decapsulate(ciphertext)


def initiate(peer_public: bytes) -> tuple[bytes, bytes]:
    """Encapsulate a fresh shared secret to a peer.

    Returns ``(shared_secret, ciphertext)``.
    """
    encapsulation_key = mlkem.MLKEM768PublicKey.from_public_bytes(peer_public)
    return encapsulation_key.encapsulate()
