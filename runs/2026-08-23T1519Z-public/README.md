# 2026-08-23T1519Z, public corpus

| | |
|---|---|
| corpus commit | `49c979d3e8a3b0f7ef063ea89d61cea5c30ea889` |
| assets | 124 |
| rule | detection is **file + algorithm + layer**; the line is recorded and reported, never scored (METHODOLOGY.md §3.3) |
| cdxgen | 12.8.2, the control, held at the same version across every run |
| pqprobe-static | 3.6.0 |

## Scores

| tool | scored assets | all |
|---|---|---|
| cdxgen 12.8.2 | 124 | 5% (6/124) |
| pqprobe-static 3.6.0 | 124 | 96% (119/124) |

Full tables in `results/results.md`, scored under the judgement tables of
2026-10-07 (docs/pending-review.md entries 14 to 16).

## False positives

cdxgen was charged none.

pqprobe-static was charged one, a phantom algorithm: `Falcon-512` at
`session-broker/src/attest.ts:41`, a configuration value naming a scheme the
project does not implement. Falcon is not planted in `session-broker`.

Both tools' documents were schema-valid, and none pointed at a file that is not
in the project.

## Environment

cdxgen is invoked through the pinned image `ghcr.io/cyclonedx/cdxgen:12.8.2` via
`tools/cdxgen-docker.sh`. pqprobe-static comes from `${PQPROBE_STATIC_BIN}`; the
manifest records the path it resolved to and that file's sha256.
