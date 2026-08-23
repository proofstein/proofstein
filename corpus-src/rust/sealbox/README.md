# sealbox

Encrypted blob store node. Seals blobs on the way in, signs the manifests that
index them, and agrees a replication key with the rest of the cluster.

## Building

```
cargo build --locked
cargo run --locked
```

## Layout

| Path                 | What lives there                            |
| -------------------- | ------------------------------------------- |
| `src/main.rs`        | entry point                                  |
| `src/envelope.rs`    | blob sealing                                 |
| `src/identity.rs`    | manifest, peer mTLS, and archive keys        |
| `src/kem.rs`         | replication key agreement                    |
| `src/store.rs`       | blob stores, resolved by config name         |
| `src/fingerprint.rs` | fingerprints for the blob index              |
| `src/settings.rs`    | the flat TOML subset the node reads          |

## Dependency pins

Every version is exact-pinned. The RustCrypto crates are held at the
`rand_core` 0.6 generation on purpose: the 0.11 / 3.0 releases moved to a newer
`rand_core` and do not interoperate with each other yet. ML-KEM comes from
`fips203` rather than `ml-kem`, because `ml-kem` 0.2 does not build against the
`kem` 0.3 traits that Cargo now resolves.

## Retention

Blobs are retained for the life of the contract that produced them, so the
replication key is agreed post-quantum. A recorded replication stream should not
become readable later just because the hardware aged out.

## Test material

`keys/` holds throwaway keys and a self-signed certificate for the integration
tests. They are not secret and are not used anywhere else.
