//! Key agreement for cluster replication.
//!
//! Blobs are retained for the life of the contract that produced them, so the
//! replication key is agreed post-quantum. A recorded replication stream should
//! not become readable later.

use fips203::ml_kem_768;
use fips203::traits::{KeyGen, SerDes};

/// The decapsulation half of a node's replication key pair.
pub struct Responder {
    decapsulation_key: ml_kem_768::DecapsKey,
    encapsulation_key: ml_kem_768::EncapsKey,
}

impl Responder {
    /// Generate a fresh replication key pair.
    pub fn generate() -> Result<Self, &'static str> {
        let (encapsulation_key, decapsulation_key) = ml_kem_768::KG::try_keygen()?; //@PS rust-l1-mlkem|ML-KEM-768|1|algorithm|cluster replication key agreement
        Ok(Self {
            decapsulation_key,
            encapsulation_key,
        })
    }

    /// Return the encapsulation key published in the cluster directory.
    pub fn encapsulation_key_bytes(&self) -> Vec<u8> {
        self.encapsulation_key.clone().into_bytes().to_vec()
    }

    /// Size of the decapsulation key, in bytes.
    pub fn decapsulation_key_len(&self) -> usize {
        self.decapsulation_key.clone().into_bytes().len()
    }
}
