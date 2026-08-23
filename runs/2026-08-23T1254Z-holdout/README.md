# 2026-08-23T1254Z, holdout

Holdout companion to `runs/2026-08-23T1254Z-public/`. **Fresh seed, not published.**

| | |
|---|---|
| corpus commit | `f09fb250ec2cf358db695a3162ac0cf336e80daa` (templates the variants derive from) |
| assets | 124 |
| rule | detection is **file + algorithm + layer** (METHODOLOGY.md §3.3) |
| cdxgen | 12.8.2 |
| pqprobe-static | 3.6.0 |

## Scores

| tool | all |
|---|---|
| cdxgen 12.8.2 | 5% (6/124) |
| pqprobe-static 3.6.0 | 96% (119/124) |

Identical to the public corpus for both tools, in every layer and every project.

## Seed and CBOMs

The seed was passed explicitly on the command line, is held by the maintainer,
and appears nowhere in this repository: not in this manifest, not in the
generated ground truth, which is gitignored and deleted after the run. It is
**not** any template default in `corpus-src/*/proofstein.json`; those are spent
values that `generate-holdout.py` falls back to when no `--seed` is given.

The CBOMs are withheld under METHODOLOGY.md §6 and archived privately. Their
twelve SHA-256 digests are committed in `manifest.json`, so a reviewer can
re-score unaltered documents against a commitment fixed before anyone could
check it. `tools/withhold-cboms.py --verify` confirms an archive against them.

## What this run supports

An identical public and holdout score is a robustness result: the transforms
change line numbers, symbol names, file locations and config ordering, and
neither tool's score moved.

What it may be cited *as* is bounded by
[docs/pending-review.md](../../docs/pending-review.md) entry 7, which is open.
This is a blind holdout, fresh unpublished seed and withheld documents, so it is
not excluded from generalisation claims the way an exposed one is.
