#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ottenheimer GmbH
"""Emit the shipped corpus and ground truth from annotated templates.

Reads ``corpus-src/<language>/<project>/`` and writes:

  * ``corpus/<language>/<project>/``  -- byte-identical to the template except
    that trailing ``@PS`` annotations are removed. Because annotations are
    always trailing, line numbers are preserved exactly.
  * ``ground-truth/<project>.json``   -- one entry per planted asset.

Run ``--check`` in CI to assert the committed corpus matches the templates.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from psmarkers import LAYERS, MARKER, AliasLocation, AnnotationError, parse_text  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = REPO_ROOT / "corpus-src"
OUT_ROOT = REPO_ROOT / "corpus"
GT_ROOT = REPO_ROOT / "ground-truth"

# Files copied verbatim; never scanned for annotations.
BINARY_SUFFIXES = frozenset({".jks", ".p12", ".der", ".png", ".jar", ".keystore"})

SKIP_DIRS = frozenset({".git", "__pycache__", "node_modules", "target", "build", ".gradle"})


def is_binary(path: Path) -> bool:
    return path.suffix.lower() in BINARY_SUFFIXES


#: Project metadata consumed by the generator, never shipped as corpus source.
METADATA_FILENAME = "proofstein.json"


def iter_template_files(project_dir: Path):
    for path in sorted(project_dir.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(project_dir)
        if any(part in SKIP_DIRS for part in relative.parts):
            continue
        if relative.as_posix() == METADATA_FILENAME:
            continue
        yield path


def build_project(project_dir: Path, out_dir: Path) -> list[dict]:
    """Materialise one project, returning its ground-truth entries."""
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    collected: list = []
    aliases: list[AliasLocation] = []
    seen_ids: dict[str, str] = {}

    for src in iter_template_files(project_dir):
        rel = src.relative_to(project_dir)
        dest = out_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)

        if is_binary(src):
            shutil.copy2(src, dest)
            continue

        raw = src.read_text(encoding="utf-8")
        clean, annotations, file_aliases = parse_text(raw, src.name, rel.as_posix())

        # Safety net. A template whose extension has no comment style mapped is
        # copied through untouched, which would ship the answer key inside the
        # corpus -- an LLM-based generator reads comments. Fail loudly instead.
        if MARKER in clean:
            raise AnnotationError(
                f"{rel.as_posix()}: {MARKER} survived into the emitted corpus. "
                f"Add this file's extension to psmarkers._COMMENT_STYLES."
            )

        dest.write_text(clean, encoding="utf-8")
        shutil.copymode(src, dest)

        aliases.extend(file_aliases)
        for ann in annotations:
            if ann.id in seen_ids:
                raise AnnotationError(
                    f"duplicate annotation id {ann.id!r} in {rel.as_posix()} "
                    f"(already used by {seen_ids[ann.id]})"
                )
            seen_ids[ann.id] = rel.as_posix()
            collected.append(ann)

    by_id = {ann.id: ann for ann in collected}
    for alias in aliases:
        target = by_id.get(alias.target_id)
        if target is None:
            raise AnnotationError(
                f"{alias.file}:{alias.line}: '+{alias.target_id}' refers to an unknown annotation id"
            )
        if (alias.file, alias.line) == (target.file, target.line):
            raise AnnotationError(
                f"{alias.file}:{alias.line}: '+{alias.target_id}' duplicates the primary location"
            )
        target.accept_locations.append((alias.file, alias.line))

    entries = [ann.to_ground_truth() for ann in collected]

    # Whole-file assets -- key material, certificates, keystores, and binary
    # manifests -- cannot carry a trailing comment, so they are declared in the
    # project's proofstein.json instead. They anchor at line 1.
    for spec in project_metadata(project_dir).get("file_assets", []):
        missing = {"id", "path", "algorithm", "layer", "cyclonedx_asset_type"} - set(spec)
        if missing:
            raise AnnotationError(f"{project_dir.name}: file_asset missing keys {sorted(missing)}: {spec}")
        if spec["id"] in seen_ids:
            raise AnnotationError(f"{project_dir.name}: duplicate asset id {spec['id']!r} in file_assets")
        seen_ids[spec["id"]] = spec["path"]
        if not (out_dir / spec["path"]).exists():
            raise AnnotationError(f"{project_dir.name}: file_asset path does not exist: {spec['path']}")
        layer = int(spec["layer"])
        if layer not in LAYERS:
            raise AnnotationError(f"{project_dir.name}: file_asset layer {layer} out of range")
        entry = {
            "id": spec["id"],
            "file": spec["path"],
            "line": int(spec.get("line", 1)),
            "algorithm": spec["algorithm"],
            "layer": layer,
            "layer_name": LAYERS[layer],
            "cyclonedx_asset_type": spec["cyclonedx_asset_type"],
        }
        if spec.get("note"):
            entry["note"] = spec["note"]
        entries.append(entry)

    entries.sort(key=lambda e: (e["file"], e["line"]))
    return entries


def project_metadata(project_dir: Path) -> dict:
    meta_path = project_dir / "proofstein.json"
    if not meta_path.exists():
        raise FileNotFoundError(f"{project_dir} is missing proofstein.json (project metadata)")
    return json.loads(meta_path.read_text(encoding="utf-8"))


def discover_projects() -> list[tuple[str, Path]]:
    found: list[tuple[str, Path]] = []
    if not SRC_ROOT.exists():
        return found
    for lang_dir in sorted(SRC_ROOT.iterdir()):
        if not lang_dir.is_dir() or lang_dir.name in SKIP_DIRS:
            continue
        for proj_dir in sorted(lang_dir.iterdir()):
            if proj_dir.is_dir() and proj_dir.name not in SKIP_DIRS:
                found.append((lang_dir.name, proj_dir))
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="verify committed output matches templates; write nothing")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    projects = discover_projects()
    if not projects:
        print(f"no projects found under {SRC_ROOT}", file=sys.stderr)
        return 1

    GT_ROOT.mkdir(parents=True, exist_ok=True)
    stale = 0
    summary: list[tuple[str, str, int, dict[int, int]]] = []

    for language, proj_dir in projects:
        name = proj_dir.name
        meta = project_metadata(proj_dir)
        out_dir = OUT_ROOT / language / name

        if args.check:
            staging = OUT_ROOT / language / f".check-{name}"
            entries = build_project(proj_dir, staging)
            differs = not _dirs_equal(staging, out_dir)
            shutil.rmtree(staging, ignore_errors=True)
        else:
            entries = build_project(proj_dir, out_dir)
            differs = False

        by_layer: dict[int, int] = {}
        for entry in entries:
            by_layer[entry["layer"]] = by_layer.get(entry["layer"], 0) + 1

        missing = sorted(set(LAYERS) - set(by_layer))
        if missing:
            print(f"ERROR: {name}: no assets planted in layer(s) {missing}", file=sys.stderr)
            return 1

        doc = {
            "project": name,
            "language": language,
            "corpus_path": f"corpus/{language}/{name}",
            "build": meta.get("build", []),
            "description": meta.get("description", ""),
            "toolchain": meta.get("toolchain", {}),
            "layer_counts": {str(k): by_layer[k] for k in sorted(by_layer)},
            "asset_count": len(entries),
            "assets": entries,
        }
        gt_path = GT_ROOT / f"{name}.json"
        rendered = json.dumps(doc, indent=2, sort_keys=False) + "\n"

        if args.check:
            current = gt_path.read_text(encoding="utf-8") if gt_path.exists() else ""
            if current != rendered or differs:
                print(f"STALE: {name} (regenerate with tools/build-corpus.py)", file=sys.stderr)
                stale += 1
        else:
            gt_path.write_text(rendered, encoding="utf-8")

        summary.append((language, name, len(entries), by_layer))

    if not args.quiet:
        width = max(len(n) for _, n, _, _ in summary)
        print(f"{'project'.ljust(width)}  lang        assets  layers 1-6")
        for language, name, count, by_layer in summary:
            spread = " ".join(str(by_layer.get(layer, 0)).rjust(2) for layer in sorted(LAYERS))
            print(f"{name.ljust(width)}  {language.ljust(10)}  {str(count).rjust(6)}  {spread}")
        total = sum(c for _, _, c, _ in summary)
        print(f"{'TOTAL'.ljust(width)}  {''.ljust(10)}  {str(total).rjust(6)}")

    if args.check and stale:
        return 1
    return 0


def _dirs_equal(staging: Path, shipped: Path) -> bool:
    """Compare generated output against what is committed.

    Only files the generator produces are compared. The shipped tree also
    accumulates build artifacts -- ``target/``, ``node_modules/``, object files,
    linked binaries -- which are git-ignored and must not make a clean corpus
    look stale.
    """
    if not shipped.exists():
        return False

    generated = {p.relative_to(staging): p for p in staging.rglob("*") if p.is_file()}
    for relative, produced in generated.items():
        counterpart = shipped / relative
        if not counterpart.is_file():
            return False
        if produced.read_bytes() != counterpart.read_bytes():
            return False
    return True


if __name__ == "__main__":
    raise SystemExit(main())
