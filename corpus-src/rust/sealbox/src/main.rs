//! sealbox -- encrypted blob store node.
//!
//! Seals blobs on the way in, signs the manifests that index them, and agrees a
//! replication key with the rest of the cluster.

mod envelope;
mod fingerprint;
mod identity;
mod kem;
mod settings;
mod store;

use std::process;

const DEFAULT_CONFIG: &str = "config/sealbox.toml";

fn main() {
    let config_path = std::env::args().nth(1).unwrap_or_else(|| DEFAULT_CONFIG.to_string());

    if let Err(err) = run(&config_path) {
        eprintln!("sealbox: {err}");
        process::exit(1);
    }
}

fn run(config_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let settings = settings::Settings::load(config_path)?;
    let identity = identity::Identity::generate()?;
    let responder = kem::Responder::generate()?;

    let data_key = envelope::new_data_key();
    let mut blobs = store::open(&settings.store, data_key)?;

    let blob = b"sealbox: object=invoice-2026-07-0184 bytes=48211 owner=acct-90213";
    let reference = fingerprint::of(blob);
    blobs.put(&reference, blob)?;

    let round_tripped = blobs.get(&reference)?.ok_or("blob vanished after write")?;
    if !fingerprint::matches(&round_tripped, &reference) {
        return Err("blob did not survive the round trip".into());
    }

    let manifest = format!("{reference} store={}", settings.store);
    let signature = identity.sign_manifest(manifest.as_bytes());

    println!(
        "node ready store={} cipher={} sig={} kex={} index={} keyfile={}",
        settings.store,
        settings.blob_cipher,
        settings.manifest_signature,
        settings.replication_key_agreement,
        settings.index_hash,
        settings.key_file,
    );
    println!(
        "  fingerprint={} sig={}B thumbprint={}B archive_key={}B repl_key={}B/{}B",
        fingerprint::short(&reference),
        signature.len(),
        identity.peer_thumbprint().len(),
        identity.archive_key_size(),
        responder.encapsulation_key_bytes().len(),
        responder.decapsulation_key_len(),
    );
    Ok(())
}
