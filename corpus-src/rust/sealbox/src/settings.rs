//! Runtime settings, read from config/sealbox.toml.
//!
//! Only the flat `[section] key = value` subset is supported. A full TOML parser
//! is not worth the dependency for a dozen scalars.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;

/// The subset of the config file the daemon uses.
#[derive(Debug, Clone)]
pub struct Settings {
    pub store: String,
    pub blob_cipher: String,
    pub manifest_signature: String,
    pub replication_key_agreement: String,
    pub index_hash: String,
    pub key_file: String,
}

impl Settings {
    /// Load settings from disk.
    pub fn load(path: impl AsRef<Path>) -> io::Result<Self> {
        let values = read_flat_toml(path.as_ref())?;
        let get = |key: &str| values.get(key).cloned().unwrap_or_default();
        Ok(Self {
            store: values
                .get("store.backend")
                .cloned()
                .unwrap_or_else(|| "sealed-memory".to_string()),
            blob_cipher: get("crypto.blob_cipher"),
            manifest_signature: get("crypto.manifest_signature"),
            replication_key_agreement: get("crypto.replication_key_agreement"),
            index_hash: get("index.fingerprint_hash"),
            key_file: get("crypto.key_file"),
        })
    }
}

fn read_flat_toml(path: &Path) -> io::Result<HashMap<String, String>> {
    let mut values = HashMap::new();
    let mut section = String::new();

    for raw in fs::read_to_string(path)?.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            section = name.trim().to_string();
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim().trim_matches(['"', '\''].as_ref());
        let full = if section.is_empty() {
            key.to_string()
        } else {
            format!("{section}.{key}")
        };
        values.insert(full, value.to_string());
    }
    Ok(values)
}
