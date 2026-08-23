# 2026-08-23T1254Z, public corpus

| | |
|---|---|
| corpus commit | `f09fb250ec2cf358db695a3162ac0cf336e80daa` |
| assets | 124 |
| rule | detection is **file + algorithm + layer**; the line is recorded and reported, never scored (METHODOLOGY.md §3.3) |
| cdxgen | 12.8.2, the control, held at the same version across every run |
| pqprobe-static | 3.6.0 |

## Scores

| tool | all |
|---|---|
| cdxgen 12.8.2 | 5% (6/124) |
| pqprobe-static 3.6.0 | 96% (119/124) |

Neither tool was charged a false positive. Full tables in `results/results.md`.

## Environment

cdxgen is invoked through the pinned image `ghcr.io/cyclonedx/cdxgen:12.8.2`
via `tools/cdxgen-docker.sh`. pqprobe-static comes from
`${PQPROBE_STATIC_BIN}`; the manifest records the path it resolved to and that
file's sha256.
