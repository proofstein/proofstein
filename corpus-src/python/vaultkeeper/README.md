# vaultkeeper

Secrets sync daemon for vault meshes. Each node envelope-encrypts the secrets it
holds, signs the sync manifests it publishes, and agrees per-peer keys with the
rest of the mesh.

## Running

```
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/pip install -e .
.venv/bin/vaultkeeper --config config/vaultkeeper.yaml
```

## Layout

| Path                            | What lives there                            |
| ------------------------------- | ------------------------------------------- |
| `src/vaultkeeper/envelope.py`   | envelope encryption for secrets in transit  |
| `src/vaultkeeper/identity.py`   | the three long-lived node keys              |
| `src/vaultkeeper/kem.py`        | mesh key agreement                          |
| `src/vaultkeeper/backend.py`    | storage backends, resolved by config name   |
| `src/vaultkeeper/fingerprint.py`| content fingerprints for the sync ledger    |
| `src/vaultkeeper/settings.py`   | the flat YAML subset the daemon reads       |

## Why the mesh is post-quantum

Vault contents outlive the machines holding them by years. The wrapped data keys
inside an envelope are exactly the thing worth recording now to open later, so
mesh key agreement uses ML-KEM. Envelope payloads themselves stay on AES-GCM.

## Deployment

`deploy/values.yaml` holds the Helm values; anything under `crypto` is rendered
into the node ConfigMap and overrides the image defaults.

## Test material

`secrets/` holds throwaway keys and a self-signed certificate for the local
integration tests. They are not secret and are not used anywhere else.
