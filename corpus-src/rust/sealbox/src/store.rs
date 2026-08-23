//! Blob stores.
//!
//! Stores are resolved by the name in the config file and reached through the
//! table below, so adding one does not mean touching main.

use std::collections::HashMap;

use crate::envelope;

/// What the daemon needs from a blob store.
pub trait Store {
    fn put(&mut self, key: &str, blob: &[u8]) -> Result<(), envelope::Error>;
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, envelope::Error>;
}

/// A store that seals every blob before it is written.
pub struct SealedStore {
    data_key: Vec<u8>,
    items: HashMap<String, Vec<u8>>,
}

impl SealedStore {
    fn new(data_key: Vec<u8>) -> Self {
        Self {
            data_key,
            items: HashMap::new(),
        }
    }
}

impl Store for SealedStore {
    fn put(&mut self, key: &str, blob: &[u8]) -> Result<(), envelope::Error> {
        let sealed = envelope::seal(&self.data_key, blob)?; //@PS rust-l3-wrapper|AES-256-GCM|3|algorithm|AEAD reached only through the store table
        self.items.insert(key.to_string(), sealed.to_wire());
        Ok(())
    }

    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, envelope::Error> {
        match self.items.get(key) {
            None => Ok(None),
            Some(wire) => {
                let sealed = envelope::Sealed::from_wire(wire)?;
                envelope::open(&self.data_key, &sealed).map(Some)
            }
        }
    }
}

type StoreFactory = fn(Vec<u8>) -> Box<dyn Store>;

fn build_sealed_store(data_key: Vec<u8>) -> Box<dyn Store> {
    Box::new(SealedStore::new(data_key))
}

/// Store names as they appear in config/sealbox.toml.
fn registry() -> HashMap<&'static str, StoreFactory> {
    HashMap::from([
        ("sealed-memory", build_sealed_store as StoreFactory),
        ("sealed-scratch", build_sealed_store as StoreFactory),
    ])
}

/// Resolve a store by config name.
pub fn open(name: &str, data_key: Vec<u8>) -> Result<Box<dyn Store>, String> {
    let table = registry();
    let factory = table
        .get(name)
        .ok_or_else(|| format!("store: unknown store {name}"))?;
    Ok(factory(data_key)) //@PS +rust-l3-wrapper
}
