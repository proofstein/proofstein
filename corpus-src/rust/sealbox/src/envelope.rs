//! Blob sealing.
//!
//! Every blob that reaches the object store is sealed first, so a leaked
//! bucket listing is not a leaked blob.

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};

pub const NONCE_BYTES: usize = 12;
pub const DATA_KEY_BYTES: usize = 32;

/// A sealed blob and the nonce needed to open it.
#[derive(Clone, Debug)]
pub struct Sealed {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl Sealed {
    /// Pack a sealed blob for the wire.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.nonce.len() + self.ciphertext.len());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Unpack a wire blob.
    pub fn from_wire(blob: &[u8]) -> Result<Self, Error> {
        if blob.len() <= NONCE_BYTES {
            return Err(Error::Malformed);
        }
        Ok(Self {
            nonce: blob[..NONCE_BYTES].to_vec(),
            ciphertext: blob[NONCE_BYTES..].to_vec(),
        })
    }
}

/// What can go wrong while sealing.
#[derive(Debug)]
pub enum Error {
    KeyLength,
    Malformed,
    Aead,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::KeyLength => write!(f, "data key must be {DATA_KEY_BYTES} bytes"),
            Error::Malformed => write!(f, "sealed blob is malformed"),
            Error::Aead => write!(f, "authenticated encryption failed"),
        }
    }
}

impl std::error::Error for Error {}

/// Return a fresh data key for one blob.
pub fn new_data_key() -> Vec<u8> {
    Aes256Gcm::generate_key(&mut OsRng).to_vec()
}

/// Seal a blob.
pub fn seal(data_key: &[u8], plaintext: &[u8]) -> Result<Sealed, Error> {
    if data_key.len() != DATA_KEY_BYTES {
        return Err(Error::KeyLength);
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(data_key)); //@PS rust-l1-aesgcm|AES-256-GCM|1|algorithm|blob AEAD
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, plaintext).map_err(|_| Error::Aead)?;
    Ok(Sealed {
        nonce: nonce.to_vec(),
        ciphertext,
    })
}

/// Reverse [`seal`].
pub fn open(data_key: &[u8], sealed: &Sealed) -> Result<Vec<u8>, Error> {
    if data_key.len() != DATA_KEY_BYTES {
        return Err(Error::KeyLength);
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(data_key));
    let nonce = Nonce::from_slice(&sealed.nonce);
    cipher
        .decrypt(nonce, sealed.ciphertext.as_ref())
        .map_err(|_| Error::Aead)
}
