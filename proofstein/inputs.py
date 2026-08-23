# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ottenheimer GmbH
"""Finding CBOMs to score, in either supported layout.

Two input shapes are supported:

**A raw CBOM directory** (``--cboms``). Filenames follow::

    <project>__<tool>.json

The separator is a *double* underscore on purpose. BF-CBOM's own convention is
``<repo_full_name with "/" -> "_">_<worker>.json``
(``coordinator/utils.py:551``), which cannot be split unambiguously: given
``acme_beacon-relay_cdxgen.json`` there is no way to know where the repo name
ends and the worker name begins without already knowing the worker list. In a
bundle that ambiguity is harmless because the worker is also a directory level;
for a flat directory Proofstein requires a separator that cannot collide.

A ``<tool>/<project>.json`` subdirectory layout is accepted as well.

**A BF-CBOM artifact bundle** (``--bundle``), either a ``cboms_<id>.zip`` or an
already-extracted directory, laid out as::

    <insp_id>/<worker>/<repo_full_name>_<worker>.json

The worker is taken from the directory level, which is unambiguous, and the
project is recovered by stripping the ``_<worker>.json`` suffix and matching the
trailing path segment against the known project names.
"""

from __future__ import annotations

import zipfile
from dataclasses import dataclass
from pathlib import Path

RAW_SEPARATOR = "__"


@dataclass
class CbomInput:
    """One CBOM to score."""

    project: str
    tool: str
    raw: str
    source: str


def _match_project(candidate: str, known_projects: set[str]) -> str | None:
    """Resolve a repo or file stem onto a known project name."""
    cleaned = candidate.strip().strip("/")
    if cleaned in known_projects:
        return cleaned
    # BF-CBOM stores "owner/repo" with the slash replaced by an underscore.
    for project in sorted(known_projects, key=len, reverse=True):
        if cleaned == project or cleaned.endswith(f"_{project}") or cleaned.endswith(f"/{project}"):
            return project
    return None


def discover_raw_directory(root: Path, known_projects: set[str]) -> tuple[list[CbomInput], list[str]]:
    """Collect CBOMs from a raw directory."""
    found: list[CbomInput] = []
    problems: list[str] = []

    for path in sorted(root.rglob("*.json")):
        relative = path.relative_to(root)
        stem = path.stem

        project: str | None = None
        tool: str | None = None

        if RAW_SEPARATOR in stem:
            left, _, right = stem.partition(RAW_SEPARATOR)
            project = _match_project(left, known_projects)
            tool = right.strip()
        elif len(relative.parts) >= 2:
            # <tool>/<project>.json
            tool = relative.parts[-2]
            project = _match_project(stem, known_projects)

        if not project or not tool:
            problems.append(
                f"{relative}: cannot tell project and tool apart; "
                f"expected <project>{RAW_SEPARATOR}<tool>.json or <tool>/<project>.json"
            )
            continue

        found.append(
            CbomInput(
                project=project,
                tool=tool,
                raw=path.read_text(encoding="utf-8", errors="replace"),
                source=str(relative),
            )
        )

    return found, problems


def discover_bundle(path: Path, known_projects: set[str]) -> tuple[list[CbomInput], list[str]]:
    """Collect CBOMs from a BF-CBOM artifact bundle (zip or directory)."""
    if path.is_dir():
        entries = [
            (p.relative_to(path).as_posix(), p.read_text(encoding="utf-8", errors="replace"))
            for p in sorted(path.rglob("*.json"))
        ]
    elif zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            entries = [
                (name, archive.read(name).decode("utf-8", errors="replace"))
                for name in sorted(archive.namelist())
                if name.endswith(".json") and not name.endswith("/")
            ]
    else:
        return [], [f"{path}: not a directory and not a zip archive"]

    found: list[CbomInput] = []
    problems: list[str] = []

    for name, raw in entries:
        parts = name.split("/")
        if len(parts) < 2:
            problems.append(f"{name}: bundle entries are expected at <insp_id>/<worker>/<file>.json")
            continue

        # The worker is the directory immediately above the file. This is the
        # unambiguous half of BF-CBOM's layout.
        tool = parts[-2]
        stem = parts[-1]
        if stem.endswith(".json"):
            stem = stem[: -len(".json")]
        # Strip the redundant "_<worker>" suffix the writer appends.
        if stem.endswith(f"_{tool}"):
            stem = stem[: -len(f"_{tool}")]

        project = _match_project(stem, known_projects)
        if project is None:
            problems.append(f"{name}: repo '{stem}' does not correspond to a corpus project")
            continue

        found.append(CbomInput(project=project, tool=tool, raw=raw, source=name))

    return found, problems
