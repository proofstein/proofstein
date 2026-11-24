# 2026-10-22T1005Z, public corpus

|  |  |
|---|---|
| date | 2026-10-22T10:05:44Z |
| corpus commit | `c071f75`, tree clean |
| assets | 124 |

## How each tool was run

**cdxgen 12.8.2** writes CycloneDX itself. `tools/cdxgen-docker.sh --json-pretty --include-crypto -o <output> <project>` runs it in the image `ghcr.io/cyclonedx/cdxgen@sha256:d2a9f784c6d3d71a9d143dd69e6ca43fdb340282b1e43d1b99ad07e9321a4783`. It records source files in `properties[].SrcFile`, without line numbers.

**pqprobe 4.0.2** writes CycloneDX itself: `pqprobe --output cbom scan .` from the project root, exit 1 accepted. The manifest records the binary's sha256.

## Scores

| tool | scored assets | detection rate | claim precision | false positives |
|---|---|---|---|---|
| cdxgen 12.8.2 | 124 | 5% (6/124) | 20% (4/20) | 0 |
| pqprobe 4.0.2 | 124 | 96% (119/124) | 67% (130/193) | 0 |

Full tables in `results/results.md`.

## By language

| language | cdxgen 12.8.2 | pqprobe 4.0.2 |
|---|---|---|
| c | 0% (0/19) | 95% (18/19) |
| go | 0% (0/19) | 100% (19/19) |
| java | 8% (2/25) | 96% (24/25) |
| javascript | 15% (3/20) | 95% (19/20) |
| python | 4% (1/23) | 96% (22/23) |
| rust | 0% (0/18) | 94% (17/18) |

## False positives

None.

12 of 12 documents were schema-valid. No document pointed at a file outside its project.
