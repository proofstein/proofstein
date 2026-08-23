//! Content fingerprints for the blob index.
//!
//! The hash is imported under a local name so the index code did not have to
//! change when the digest was swapped during the 0.4 rewrite.

use sha2::Digest;
use sha2::Sha256 as ContentHash; //@PS +rust-l2-sha256

pub const PREFIX: &str = "sb1";

/// Return the index fingerprint of a blob.
pub fn of(blob: &[u8]) -> String {
    let digest = ContentHash::digest(blob); //@PS rust-l2-sha256|SHA-256|2|algorithm|aliased import: sha2::Sha256 imported as ContentHash
    format!("{PREFIX}:{}", hex(&digest))
}

/// Report whether a blob still carries the recorded fingerprint.
pub fn matches(blob: &[u8], fingerprint: &str) -> bool {
    of(blob) == fingerprint
}

/// The display form used in log lines.
pub fn short(fingerprint: &str) -> String {
    fingerprint
        .split_once(':')
        .map(|(_, digest)| digest.chars().take(12).collect())
        .unwrap_or_default()
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}
