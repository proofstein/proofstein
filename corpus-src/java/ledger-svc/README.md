# ledger-svc

Append-only ledger node. Seals segments before they reach the write-ahead log,
signs each block, and replicates to peers over an agreed key.

## Building

```
mvn package
mvn exec:java
```

`JAVA_HOME` must point at a JDK. The build targets release 21.

## Layout

| Path                                    | What lives there                          |
| --------------------------------------- | ----------------------------------------- |
| `io/proofstein/ledger/App.java`         | entry point                                |
| `io/proofstein/ledger/crypto/Envelope`  | segment sealing                            |
| `io/proofstein/ledger/crypto/Identity`  | block signing, peer mTLS, settlement keys  |
| `io/proofstein/ledger/crypto/Kem`       | replication key agreement                  |
| `io/proofstein/ledger/store`            | segment stores, resolved by config name    |
| `io/proofstein/ledger/crypto/Fingerprint` | fingerprints for the ledger index        |

## Replication and the JDK version

Replication traffic carries settled balances that stay sensitive for the whole
statutory retention period, so the replication key is agreed with ML-KEM. That
provider only exists on Java 24 and newer. The build targets 21 so the service
still compiles and runs on the older nodes in the fleet; those fall back to the
classical group and log which path they took.

## Audit seals and key exhaustion

Archived segments are sealed with XMSS and the firmware manifest with HSS/LMS.
Both are stateful: the parameters fix how many signatures a key can ever
produce, and reusing a one-time index breaks the scheme outright.

## Settlement export

The clearing house still verifies settlement exports with a 2016-vintage
toolchain, which is why that one path is `SHA256withRSA` rather than Ed25519.

## Test material

`keys/` holds a throwaway PKCS#12 keystore and signing key used by the
integration tests. They are not secret and are not used anywhere else.
