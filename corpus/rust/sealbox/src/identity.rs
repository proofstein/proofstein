//! Node identity.
//!
//! A node signs its manifests with Ed25519. The P-256 key terminates mutual TLS
//! to peer nodes, and the RSA key exists only because the archive gateway still
//! verifies with it.

use aes_gcm::aead::OsRng;
use ed25519_dalek::{Signer, SigningKey};
use p256::ecdsa::SigningKey as EcdsaSigningKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use sha2::{Digest, Sha256};

const ARCHIVE_KEY_BITS: usize = 2048;

/// The keys a node needs before it can join a cluster.
pub struct Identity {
    manifest: SigningKey,
    peer_tls: EcdsaSigningKey,
    archive_gateway: RsaPrivateKey,
}

impl Identity {
    /// Build a fresh identity. Production nodes load these from the keystore.
    pub fn generate() -> Result<Self, rsa::Error> {
        let manifest = SigningKey::generate(&mut OsRng);
        let peer_tls = EcdsaSigningKey::random(&mut OsRng);
        let archive_gateway = RsaPrivateKey::new(&mut rand::thread_rng(), ARCHIVE_KEY_BITS)?;
        Ok(Self {
            manifest,
            peer_tls,
            archive_gateway,
        })
    }

    /// Sign a blob manifest.
    pub fn sign_manifest(&self, manifest: &[u8]) -> Vec<u8> {
        self.manifest.sign(manifest).to_bytes().to_vec()
    }

    /// Return the thumbprint of the peer TLS public key.
    pub fn peer_thumbprint(&self) -> Vec<u8> {
        let encoded = self.peer_tls.verifying_key().to_sec1_bytes();
        Sha256::digest(encoded).to_vec()
    }

    /// Modulus size of the archive gateway key, in bytes.
    pub fn archive_key_size(&self) -> usize {
        self.archive_gateway.size()
    }
}
