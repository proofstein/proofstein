# session-broker

Issues sealed sessions and signs the short-lived tokens that reference them.

## Running

```
npm ci
npm run build
npm start
```

## Layout

| Path                  | What lives there                                  |
| --------------------- | ------------------------------------------------- |
| `src/index.ts`        | entry point                                        |
| `src/envelope.ts`     | session payload sealing                            |
| `src/identity.ts`     | token signing, legacy JWKS, and upstream mTLS keys |
| `src/kem.ts`          | key agreement with the identity provider           |
| `src/store.ts`        | session stores, resolved by config name            |
| `src/fingerprint.ts`  | fingerprints for the replay cache                  |
| `src/settings.ts`     | the flat YAML subset the broker reads              |

## Why @noble/post-quantum

Node's `crypto` module has no ML-KEM, so upstream key agreement uses the
audited pure-JS implementation instead. It has no native build step, which
keeps `npm ci` working on the ARM builders.

## Legacy JWKS

Two downstream services still poll the RSA-backed JWKS endpoint. It is kept
alive behind `crypto.legacy_jwks_signature` and should go away once both have
moved to the Ed25519 token path.

## Test material

`keys/` holds throwaway keys and a self-signed certificate for the local
integration tests. They are not secret and are not used anywhere else.
