# 2026-11-24T1156Z, holdout

|  |  |
|---|---|
| date | 2026-11-24T11:59:28Z |
| corpus commit | `f366ff5`, holdout variants generated from it with an unpublished seed |
| assets | 131 |

## How each tool was run

The generators ran over the holdout variants of the six projects, with the definitions of `runs/2026-11-24T1156Z-public/generators.json`.

Both corpora were built with `tools/build-all.sh` in the image of `tools/build.Dockerfile` (image id `sha256:3d16c8bfbf683df091999be2894de91ff1d561a285a16da96f8d15d6ec3b4864`), 6 of 6 projects each. The generators other than cdxgen ran in that image through `harness/in-image.sh`, which mounts the project, this repository and the tool binaries read-only. cdxgen ran from its own images through `tools/cdxgen-docker.sh`.

**cdxgen 12.8.2** writes CycloneDX itself: `tools/cdxgen-docker.sh --json-pretty --include-crypto -o <output> <project>`, in `ghcr.io/cyclonedx/cdxgen@sha256:d2a9f784c6d3d71a9d143dd69e6ca43fdb340282b1e43d1b99ad07e9321a4783`. It records source files in `properties[].SrcFile`, without line numbers.

**pqprobe 5.1.2** writes CycloneDX itself: `pqprobe --output cbom scan .` from the project root, exit 1 accepted.

## Scores

| tool | scored assets | detection rate | claim precision | false positives |
|---|---|---|---|---|
| cdxgen 12.8.2 | 131 | 5% (6/131) | 20% (4/20) | 0 |
| pqprobe 5.1.2 | 131 | 96% (126/131) | 67% (144/214) | 0 |

Full tables in `results/results.md`.

## By language

| language | cdxgen 12.8.2 | pqprobe 5.1.2 |
|---|---|---|
| c | 0% (0/23) | 96% (22/23) |
| go | 0% (0/19) | 100% (19/19) |
| java | 8% (2/25) | 96% (24/25) |
| javascript | 13% (3/23) | 96% (22/23) |
| python | 4% (1/23) | 96% (22/23) |
| rust | 0% (0/18) | 94% (17/18) |

## False positives

None.

12 of 12 documents were schema-valid. No document pointed at a file outside its project.
