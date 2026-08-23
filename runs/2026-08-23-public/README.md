# 2026-08-23, public corpus

| | |
|---|---|
| corpus commit | `4497df4e34fe422aee686a94d99f605330bab2e4` |
| assets | 124 |
| rule | detection is **file + algorithm + layer**; the line is recorded and reported, never scored (METHODOLOGY.md §3.3) |
| line tolerance | 2, which sets the reported `located` column only |
| cdxgen | 12.8.2, the control, held at the same version as the 2026-07-27, 2026-07-28 and 2026-08-01 runs |
| pqprobe-static | 3.5.0 |

## Scores

| tool | all |
|---|---|
| cdxgen 12.8.2 | 5% (6/124) |
| pqprobe-static 3.5.0 | 90% (111/124) |

Neither tool was charged a false positive. Full tables in `results/results.md`.

## What changed since the 2026-08-01 run

Two things moved at once, and they are separable in the tables rather than in
this summary:

- **The rule.** The 2026-08-01 run required file *and line*. This run does not. cdxgen
  emits no line numbers, so its score moves off zero for the first time.
- **The corpus.** 108 assets to 124, adding post-quantum signature families the
  corpus did not previously test at all.
- **pqprobe-static.** 3.1.0 to 3.5.0.

Because all three moved together, this run does not attribute the change to any
one of them. the 2026-07-27, 2026-07-28 and 2026-08-01 runs remain the record for the old rule.

## Reproducing this run

```bash
export PQPROBE_STATIC_BIN=/path/to/pqprobe-static-v3.5.0
python3 tools/collect-cboms.py --config runs/generators.json --out runs/<date>-public
./score.py --cboms runs/<date>-public/cboms --out runs/<date>-public/results
```

`runs/generators.json` carries `${PQPROBE_STATIC_BIN}` rather than a literal
path, because a build root lives on whichever machine has the disk for it. The
variable is expanded when the config loads; if it is unset the run fails
immediately, naming the variable, rather than scanning with an empty or
unexpanded path and attributing the result to a binary that did not produce it.
cdxgen needs no variable, it runs from a pinned image.

The manifest still records the **resolved** path and that file's sha256. A
config says what to run; a run record says what ran.

`runs/generators-run4.json` is the literal-path snapshot this run was executed
from, kept as the historical artifact. New runs should use `generators.json`.

## Environment

cdxgen was invoked through the pinned official image
`ghcr.io/cyclonedx/cdxgen:12.8.2` via `tools/cdxgen-docker.sh`, because this
host has no Node toolchain. The argument list is unchanged from earlier runs.
Reported paths are `/src/...` rather than an absolute host path; the scorer
resolves by longest matching suffix, so this affects nothing in matching.
