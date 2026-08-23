# beacon-relay

Accepts telemetry beacons from field devices, seals them, and mirrors them to
peer relays.

## Running

```
go build ./...
./beacon-relay -config configs/relay.yaml
```

The relay speaks plain HTTP on loopback. Everything facing the devices is
terminated by the edge config in `deploy/nginx.conf`.

## Layout

| Path                  | What lives there                                      |
| --------------------- | ----------------------------------------------------- |
| `cmd/beacon-relay`    | entry point                                            |
| `internal/seal`       | payload AEAD, resolved through a transport registry    |
| `internal/identity`   | the three long-lived keys a relay carries              |
| `internal/session`    | post-quantum key agreement for peer mirroring          |
| `internal/digest`     | content addressing for the dedup cache                 |
| `internal/config`     | the small YAML subset the relay reads                  |

## Peer links

Peer mirroring carries fleet telemetry that stays sensitive well past the
lifetime of the hardware, so the peer link key exchange is ML-KEM rather than
classical ECDH. Device uplinks are short-lived and still use the edge's
ECDHE suites.

## Test material

`testdata/` holds throwaway keys and a self-signed certificate used by the
integration tests. They are not secret and are not used anywhere else.
