"""Long-lived key material for a vaultkeeper node.

A node holds three keys. The RSA key exists only to keep the 2019-era audit
export working; new deployments never use it for anything else.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

AUDIT_KEY_BITS = 2048


@dataclass
class NodeIdentity:
    """The keys a node needs before it can join a vault mesh."""

    audit_export: rsa.RSAPrivateKey
    peer_tls: ec.EllipticCurvePrivateKey
    manifest: ed25519.Ed25519PrivateKey

    @classmethod
    def generate(cls) -> "NodeIdentity":
        audit = rsa.generate_private_key(public_exponent=65537, key_size=AUDIT_KEY_BITS)
        peer = ec.generate_private_key(ec.SECP256R1())
        manifest = ed25519.Ed25519PrivateKey.generate()
        return cls(audit_export=audit, peer_tls=peer, manifest=manifest)

    def sign_manifest(self, manifest: bytes) -> bytes:
        """Sign a sync manifest so peers can verify it came from this node."""
        return self.manifest.sign(manifest)

    def sign_audit_export(self, export: bytes) -> bytes:
        """Sign an audit export for the compliance archive."""
        return self.audit_export.sign(
            export,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )

    def peer_public_bytes(self) -> bytes:
        """Return the peer TLS public key in DER form."""
        return self.peer_tls.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
