#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ottenheimer GmbH
"""Generate holdout variants of the corpus from the same templates.

The public corpus is, by construction, something a vendor can tune against: the
files are published, so are the answers. A tool that improves on it may have
learned to find cryptography, or may have learned to find *this* cryptography.
The holdout separates those two.

Variants are produced by transforms that change the surface a tool matches on
while leaving the cryptography identical:

* **shift**    -- a header block moves every line number.
* **rename**   -- wrapper functions, types and import aliases get new names.
* **relocate** -- files move within their package.
* **reconfigure** -- config keys are reordered and, where declared, an
  algorithm is swapped for a different member of its family.

Ground truth is recomputed from the transformed templates rather than adjusted,
so it cannot drift: the same annotation parser produces both.

Holdout output is written to ``holdout/`` and ``ground-truth-holdout/``, both of
which are git-ignored. Per METHODOLOGY.md, holdout scores are reported
separately from public-corpus scores and never averaged together.
"""

from __future__ import annotations

import argparse
import json
import random
import re
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import importlib.util  # noqa: E402

from psmarkers import MARKER  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "build_corpus", Path(__file__).resolve().parent / "build-corpus.py"
)
_build_corpus = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_build_corpus)

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = REPO_ROOT / "corpus-src"
OUT_ROOT = REPO_ROOT / "holdout"
GT_ROOT = REPO_ROOT / "ground-truth-holdout"

TEXT_SKIP_SUFFIXES = frozenset({".pem", ".p12", ".jks", ".der", ".png", ".jar", ".lock"})

HEADER_COMMENT = {
    "//": [
        "// Generated variant. Do not edit by hand.",
        "//",
        "// This file is part of a Proofstein holdout case. It is the same",
        "// program as its public counterpart with different names and layout.",
        "",
    ],
    "#": [
        "# Generated variant. Do not edit by hand.",
        "#",
        "# This file is part of a Proofstein holdout case. It is the same",
        "# program as its public counterpart with different names and layout.",
        "",
    ],
}


def comment_prefix(path: Path) -> str | None:
    suffix = path.suffix.lower()
    if suffix in {".go", ".java", ".js", ".ts", ".rs", ".c", ".h"}:
        return "//"
    if suffix in {".py", ".yaml", ".yml", ".conf", ".toml", ".properties", ".cfg", ".options"}:
        return "#"
    return None


def is_text(path: Path) -> bool:
    return path.suffix.lower() not in TEXT_SKIP_SUFFIXES


def apply_renames(text: str, renames: dict[str, str]) -> str:
    """Rename identifiers on word boundaries, longest name first."""
    for old in sorted(renames, key=len, reverse=True):
        text = re.sub(rf"\b{re.escape(old)}\b", renames[old], text)
    return text


def apply_shift(text: str, path: Path, enabled: bool) -> str:
    """Prepend a header so every line number moves."""
    if not enabled:
        return text
    prefix = comment_prefix(path)
    if prefix is None:
        return text
    lines = text.split("\n")
    # Keep a shebang, package declaration or license header first.
    insert_at = 0
    if lines and lines[0].startswith("#!"):
        insert_at = 1
    header = HEADER_COMMENT[prefix]
    return "\n".join(lines[:insert_at] + header + lines[insert_at:])


def _split_annotation(line: str) -> tuple[str, str]:
    """Split a template line into (code, annotation_including_delimiter)."""
    index = line.find(MARKER)
    if index < 0:
        return line, ""
    # Back up to the comment delimiter that introduces the annotation.
    for delimiter in ("/*", "//", "#", "<!--"):
        found = line.rfind(delimiter, 0, index)
        if found >= 0:
            return line[:found], line[found:]
    return line, ""


def apply_substitutions(text: str, substitutions: list[dict]) -> str:
    """Swap an algorithm for another member of its family, marker included.

    Both the value and the annotation are rewritten, so the ground truth for
    the variant states what the variant actually contains.
    """
    for rule in substitutions:
        old, new = rule["from"], rule["to"]
        old_algorithm = rule.get("from_algorithm", old)
        new_algorithm = rule.get("to_algorithm", new)
        out = []
        for line in text.split("\n"):
            if old in line:
                code, annotation = _split_annotation(line)
                code = code.replace(old, new)
                if annotation:
                    annotation = annotation.replace(old_algorithm, new_algorithm)
                    if old != old_algorithm:
                        annotation = annotation.replace(old, new)
                line = code + annotation
            out.append(line)
        text = "\n".join(out)
    return text


def shuffle_config_blocks(text: str, path: Path, rng: random.Random) -> str:
    """Reorder sibling key/value lines inside each config section.

    Only contiguous runs of same-indent ``key: value`` or ``key = value`` lines
    are permuted, which preserves validity in YAML, TOML and .properties alike.
    A run containing a line the parser cannot classify is left untouched.
    """
    if path.suffix.lower() not in {".yaml", ".yml", ".toml", ".properties", ".conf"}:
        return text

    pattern = re.compile(r"^(?P<indent>[ \t]*)(?P<key>[A-Za-z_][\w.\-]*)\s*(?P<sep>[:=])\s*(?P<value>\S.*)$")
    lines = text.split("\n")
    out: list[str] = []
    run: list[tuple[str, str]] = []  # (indent, line)

    def flush() -> None:
        if len(run) > 1:
            indents = {indent for indent, _ in run}
            if len(indents) == 1:
                block = [line for _, line in run]
                rng.shuffle(block)
                out.extend(block)
                run.clear()
                return
        out.extend(line for _, line in run)
        run.clear()

    for line in lines:
        match = pattern.match(line)
        if match and not line.lstrip().startswith("#"):
            run.append((match.group("indent"), line))
        else:
            flush()
            out.append(line)
    flush()
    return "\n".join(out)


def build_variant(project_dir: Path, staging: Path, spec: dict, rng: random.Random) -> None:
    """Write a transformed copy of a project's templates into ``staging``."""
    renames: dict[str, str] = spec.get("rename_symbols", {}) or {}
    relocations: dict[str, str] = spec.get("rename_files", {}) or {}
    substitutions: list[dict] = spec.get("substitutions", []) or []
    shift = spec.get("shift_lines", True)
    shuffle = spec.get("shuffle_config", True)

    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)

    for source in sorted(project_dir.rglob("*")):
        if not source.is_file():
            continue
        relative = source.relative_to(project_dir)
        if any(part in {".git", "node_modules", "target", "dist", "__pycache__"} for part in relative.parts):
            continue

        destination_name = relocations.get(relative.as_posix(), relative.as_posix())
        # A renamed symbol that is also a filename stem moves the file with it.
        destination = staging / destination_name
        destination.parent.mkdir(parents=True, exist_ok=True)

        if not is_text(source):
            shutil.copy2(source, destination)
            continue

        text = source.read_text(encoding="utf-8")
        if relative.name != "proofstein.json":
            text = apply_renames(text, renames)
            text = apply_substitutions(text, substitutions)
            text = shuffle_config_blocks(text, source, rng) if shuffle else text
            text = apply_shift(text, source, shift)
        destination.write_text(text, encoding="utf-8")
        shutil.copymode(source, destination)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--seed", type=int, default=None, help="RNG seed (default: from the spec)")
    parser.add_argument("--project", action="append", help="limit to named project(s)")
    parser.add_argument("--out", type=Path, default=OUT_ROOT)
    parser.add_argument("--ground-truth-out", type=Path, default=GT_ROOT)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    projects = _build_corpus.discover_projects()
    if args.project:
        wanted = set(args.project)
        projects = [(lang, path) for lang, path in projects if path.name in wanted]
    if not projects:
        print("no matching projects", file=sys.stderr)
        return 1

    args.ground_truth_out.mkdir(parents=True, exist_ok=True)
    summary = []

    with tempfile.TemporaryDirectory(prefix="proofstein-holdout-") as tmp:
        tmp_root = Path(tmp)
        for language, project_dir in projects:
            name = project_dir.name
            metadata = _build_corpus.project_metadata(project_dir)
            spec = metadata.get("holdout") or {}
            seed = args.seed if args.seed is not None else spec.get("seed", 0)
            rng = random.Random(f"{name}:{seed}")

            staging = tmp_root / name
            build_variant(project_dir, staging, spec, rng)

            variant_name = spec.get("variant_name", f"{name}-v")
            out_dir = args.out / language / variant_name
            entries = _build_corpus.build_project(staging, out_dir)
            (out_dir / "proofstein.json").unlink(missing_ok=True)

            by_layer: dict[int, int] = {}
            for entry in entries:
                by_layer[entry["layer"]] = by_layer.get(entry["layer"], 0) + 1

            document = {
                "project": variant_name,
                "derived_from": name,
                "language": language,
                "corpus_path": f"{args.out.name}/{language}/{variant_name}",
                "build": metadata.get("build", []),
                "description": metadata.get("description", ""),
                "toolchain": metadata.get("toolchain", {}),
                "holdout": True,
                "seed": seed,
                "layer_counts": {str(k): by_layer[k] for k in sorted(by_layer)},
                "asset_count": len(entries),
                "assets": entries,
            }
            (args.ground_truth_out / f"{variant_name}.json").write_text(
                json.dumps(document, indent=2) + "\n", encoding="utf-8"
            )
            summary.append((variant_name, language, len(entries), by_layer))

    if not args.quiet:
        width = max(len(n) for n, _, _, _ in summary)
        print(f"{'variant'.ljust(width)}  lang        assets  layers 1-6")
        for variant, language, count, by_layer in summary:
            spread = " ".join(str(by_layer.get(layer, 0)).rjust(2) for layer in range(1, 7))
            print(f"{variant.ljust(width)}  {language.ljust(10)}  {str(count).rjust(6)}  {spread}")
        print(f"\nwrote {args.out} and {args.ground_truth_out}")
        print("Holdout scores are reported separately from public-corpus scores; see METHODOLOGY.md.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
