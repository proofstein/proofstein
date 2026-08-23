#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ottenheimer GmbH
"""Withhold a run's CBOMs from the repository, under a published digest.

METHODOLOGY.md §6 limits published holdout material to the scores and the
transform description. A generator's CBOM is neither: it carries the holdout's
file paths, its line numbers and, for tools that quote the matched line, its
source text. Committing those republishes most of the answer key the unpublished
seed exists to protect.

Withholding them costs something real, though. A run whose inputs are secret and
whose outputs are absent is a run a reader must take on trust, and a benchmark
maintained by a party with a tool in it is the last place trust should be the
mechanism.

So the CBOMs move to a private archive and their SHA-256 digests are recorded in
the committed manifest. The public gets a commitment made *before* anyone could
check it. A reviewer under NDA -- the external review offered in METHODOLOGY.md
§9.1 -- gets the archive, re-scores it, and confirms both the published scores
and that the documents are the ones the digests name. Neither party needs the
seed.

    tools/withhold-cboms.py --run runs/2026-08-01-holdout \
        --archive ~/proofstein-private/holdout-cboms

    tools/withhold-cboms.py --run runs/2026-08-01-holdout \
        --archive ~/proofstein-private/holdout-cboms --verify

``--verify`` re-hashes the archive against the manifest and is the check a
reviewer runs. It is also the check that catches an archive that has drifted,
which is the failure mode that would make the digests worthless.

The archive path is environment-specific and is deliberately not recorded in the
manifest: it is a location, not evidence, and a path in a public file is an
invitation. The manifest records what the documents *are*.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def digest_directory(directory: Path) -> dict[str, dict[str, object]]:
    """Digest every CBOM in a directory, keyed by filename.

    Sorted so the manifest is stable across runs and platforms: a digest block
    that reorders itself would show up as a diff and teach a reader to ignore
    diffs in it.
    """
    return {
        path.name: {"sha256": sha256_file(path), "bytes": path.stat().st_size}
        for path in sorted(directory.glob("*.json"))
    }


def load_manifest(run: Path) -> tuple[Path, dict]:
    manifest_path = run / "manifest.json"
    if not manifest_path.is_file():
        raise SystemExit(f"no manifest at {manifest_path}")
    return manifest_path, json.loads(manifest_path.read_text(encoding="utf-8"))


def verify(run: Path, archive: Path) -> int:
    _, manifest = load_manifest(run)
    block = manifest.get("withheld_cboms")
    if not block:
        raise SystemExit(f"{run}/manifest.json records no withheld CBOMs")

    recorded = block["files"]
    if not archive.is_dir():
        raise SystemExit(f"no such archive directory: {archive}")

    present = digest_directory(archive)
    failures = 0

    for name, expected in sorted(recorded.items()):
        actual = present.get(name)
        if actual is None:
            print(f"  MISSING  {name}")
            failures += 1
        elif actual["sha256"] != expected["sha256"]:
            print(f"  MISMATCH {name}")
            print(f"           manifest {expected['sha256']}")
            print(f"           archive  {actual['sha256']}")
            failures += 1
        else:
            print(f"  ok       {name}")

    for name in sorted(set(present) - set(recorded)):
        # Not a failure: an archive may hold more than one run. But an unrecorded
        # document sitting beside recorded ones is worth naming, because "the
        # archive matches" should not be said about files nobody vouched for.
        print(f"  extra    {name} (present in archive, not in manifest)")

    print()
    if failures:
        print(f"{failures} of {len(recorded)} withheld CBOMs failed verification")
        return 1
    print(f"all {len(recorded)} withheld CBOMs match the manifest")
    return 0


def withhold(run: Path, archive: Path, keep: bool) -> int:
    manifest_path, manifest = load_manifest(run)
    cboms = run / "cboms"

    if not cboms.is_dir():
        if manifest.get("withheld_cboms"):
            raise SystemExit(
                f"{run}/cboms is already withheld; use --verify to check the archive"
            )
        raise SystemExit(f"no such directory: {cboms}")

    documents = sorted(cboms.glob("*.json"))
    if not documents:
        raise SystemExit(f"no CBOMs in {cboms}")

    archive.mkdir(parents=True, exist_ok=True)
    files = digest_directory(cboms)

    # Copy and verify before removing anything. A move that half-succeeds would
    # destroy the only copy of a run's evidence.
    for path in documents:
        destination = archive / path.name
        shutil.copy2(path, destination)
        if sha256_file(destination) != files[path.name]["sha256"]:
            raise SystemExit(f"copy verification failed for {path.name}; nothing removed")

    manifest["withheld_cboms"] = {
        "reason": (
            "Holdout CBOMs carry the variants' file paths, line numbers and matched "
            "source lines. Publishing them would republish most of what the "
            "unpublished seed protects (METHODOLOGY.md §6), so they are archived "
            "privately and committed here only as digests."
        ),
        "count": len(files),
        "algorithm": "sha256",
        "verify_with": "tools/withhold-cboms.py --run <run> --archive <path> --verify",
        "files": files,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    if not keep:
        shutil.rmtree(cboms)

    print(f"archived {len(files)} CBOMs to {archive}")
    print(f"recorded {len(files)} sha256 digests in {manifest_path.relative_to(REPO_ROOT)}")
    print("removed" if not keep else "kept", f"{cboms.relative_to(REPO_ROOT)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--run", type=Path, required=True, help="run directory")
    parser.add_argument("--archive", type=Path, required=True, help="private archive directory")
    parser.add_argument(
        "--verify",
        action="store_true",
        help="re-hash the archive against the manifest instead of withholding",
    )
    parser.add_argument(
        "--keep",
        action="store_true",
        help="archive and record digests without removing the run's cboms/",
    )
    args = parser.parse_args(argv)

    run = args.run.resolve()
    archive = args.archive.resolve()

    if args.verify:
        return verify(run, archive)
    return withhold(run, archive, keep=args.keep)


if __name__ == "__main__":
    sys.exit(main())
