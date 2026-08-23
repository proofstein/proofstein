# tinyattest

Attestation helper for field devices. Produces a signed, sealed attestation
report and agrees a session key with the verifier.

## Building

```
make
make check
```

Requires OpenSSL 3.5 or newer. Earlier releases have no ML-KEM, and the
verifier session key needs it.

## Layout

| Path               | What lives there                                  |
| ------------------ | ------------------------------------------------- |
| `src/main.c`       | entry point                                        |
| `src/seal.c`       | report AEAD                                        |
| `src/identity.c`   | the three device keys                              |
| `src/kem.c`        | verifier session key agreement                     |
| `src/transport.c`  | report transports, resolved by config name         |
| `src/digest.c`     | report digests                                     |
| `src/config.c`     | the flat `key = value` config reader               |

## Porting

`src/digest.c` reaches the digest API through local macros so the helper can be
built against the vendored mbedTLS shim on the two platforms that still lack a
system OpenSSL.

## Test material

`keys/` holds throwaway keys and a self-signed certificate used by `make check`.
They are not secret and are not used anywhere else.
