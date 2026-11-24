#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ottenheimer GmbH
"""Withhold a run's CBOMs from the repository, under a published digest.

METHODOLOGY.md §6 limits published holdout material to the scores and the
transform description. A generator's CBOM carries the holdout's file paths, its
line numbers and, for tools that quote the matched line, its source text.

The tool copies the CBOMs to a private archive, records each one's SHA-256
digest and size in the committed manifest, and removes the run's cboms/
directory unless --keep is given.

    tools/withhold-cboms.py --run runs/<run-id> --archive <archive-dir>

    tools/withhold-cboms.py --run runs/<run-id> --archive <archive-dir> --verify

``--verify`` re-hashes the archive against the manifest and fails if any
recorded document is missing or its digest differs. Documents in the archive
that the manifest does not record are listed but do not fail verification.

The archive path is not recorded in the manifest.
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

    Sorted so the manifest is stable across runs and platforms.
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
        # Not a failure: an archive may hold more than one run. Listed so the
        # unrecorded documents are visible.
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
            "Holdout CBOMs are archived privately and recorded here as digests "
            "(METHODOLOGY.md §6)."
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
