#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ottenheimer GmbH
"""Run CBOM generators over the corpus and record exactly what was run.

    tools/collect-cboms.py --config runs/generators.json --out runs/<id>-public

Run ids are UTC to the minute: ``2026-08-23T1254Z-public``.

Writes one CycloneDX document per (project, tool) under ``<out>/cboms/`` using
the documented ``<project>__<tool>.json`` convention, plus ``<out>/manifest.json``.

**The manifest is the artifact, not the matrix.** A results table that cannot be
regenerated from its manifest did not happen. The manifest therefore records:

* the corpus commit, and whether the tree was dirty when the run started;
* every tool's self-reported version, the sha256 of the binary or package that
  produced it, and the exact argument vector used;
* a digest of the three judgement tables (METHODOLOGY.md §9.1), so a score that
  moves because a table moved is attributable rather than invisible;
* per-invocation exit status, duration, output size and stderr tail, including
  for invocations that failed.

A tool that fails on a project is recorded as a failure. It is *not* written as
an empty CBOM, because the scorer excludes absent (project, tool) pairs rather
than scoring them as zero, and a fabricated empty document would turn "did not
run" into "found nothing".
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

GROUND_TRUTH = REPO_ROOT / "ground-truth"


def sha256_file(path: Path) -> str | None:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def judgement_table_digest() -> dict:
    """Digest the tables that encode judgement rather than fact.

    METHODOLOGY.md §9.1 requires table changes to be attributable. Recording a
    digest per table means a reader can tell whether a score moved because a
    generator changed or because we did.
    """
    from proofstein.cbom import LINE_PROPERTY_NAMES, LOCATION_PROPERTY_NAMES, OID_ALGORITHMS
    from proofstein.matching import _FAMILY_MARKERS, _TOKEN_ALIASES, _WHOLE_TOKEN_ONLY

    sys.path.insert(0, str(REPO_ROOT))
    from score import KNOWN_UNPLANTED  # noqa: PLC0415

    def digest(value) -> str:
        return hashlib.sha256(
            json.dumps(value, sort_keys=True, default=list).encode("utf-8")
        ).hexdigest()[:16]

    return {
        "oid_algorithms": {"entries": len(OID_ALGORITHMS), "sha256_16": digest(OID_ALGORITHMS)},
        "location_property_names": {
            "entries": len(LOCATION_PROPERTY_NAMES),
            "sha256_16": digest(sorted(LOCATION_PROPERTY_NAMES)),
        },
        "line_property_names": {
            "entries": len(LINE_PROPERTY_NAMES),
            "sha256_16": digest(sorted(LINE_PROPERTY_NAMES)),
        },
        "token_aliases": {"entries": len(_TOKEN_ALIASES), "sha256_16": digest(_TOKEN_ALIASES)},
        "family_markers": {
            "entries": len(_FAMILY_MARKERS),
            "sha256_16": digest([list(pair) for pair in _FAMILY_MARKERS]),
        },
        "whole_token_only": {
            "entries": len(_WHOLE_TOKEN_ONLY),
            "sha256_16": digest(sorted(_WHOLE_TOKEN_ONLY)),
        },
        # Which fabricated algorithm names are forgiven, and where. Moving an
        # entry from a scoped to a corpus-wide form silently lowers every tool's
        # false-positive count, so the digest travels with the run.
        "known_unplanted": {
            "entries": len(KNOWN_UNPLANTED),
            "sha256_16": digest(sorted(str(tuple(entry)) if isinstance(entry, tuple) else str(entry) for entry in KNOWN_UNPLANTED)),
        },
    }


def git(*args: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(REPO_ROOT), *args], capture_output=True, text=True, timeout=20
        )
        return result.stdout.strip() if result.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def git_status_paths() -> list[str]:
    """Return the paths git reports as not clean.

    Parsed separately from :func:`git` because porcelain v1 status codes are two
    columns wide and may begin with a space (`` M path``). Stripping the output
    as a whole would eat that space on the first line and shift its path by one
    character, which is exactly the kind of quiet off-by-one that turns a
    publishability gate into a rubber stamp.
    """
    try:
        result = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "status", "--porcelain"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if result.returncode != 0:
        return []

    paths = []
    for line in result.stdout.splitlines():
        if len(line) < 4:
            continue
        path = line[3:]
        # Renames are reported as "old -> new"; the destination is what matters.
        if " -> " in path:
            path = path.split(" -> ", 1)[1]
        paths.append(path.strip().strip('"'))
    return paths


def load_projects(ground_truth_dir: Path) -> list[dict]:
    documents = []
    for path in sorted(ground_truth_dir.glob("*.json")):
        documents.append(json.loads(path.read_text(encoding="utf-8")))
    return documents


#: Terminal styling in a version banner. A generator that colours its output
#: writes these whether or not anything is attached to read them, and the escape
#: sequence then travels through the manifest into the published results table,
#: where it renders as literal noise around the version.
ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def tool_version(spec: dict) -> str:
    command = spec.get("version_command")
    if not command:
        return "unknown"
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as exc:
        return f"unavailable ({exc})"
    text = ANSI_ESCAPE.sub("", (result.stdout or result.stderr or "")).strip()
    return text.splitlines()[0] if text else "unknown"


#: Never copied into a scan tree. A generator pointed at build output reports
#: cryptography in compiled artifacts, at paths no ground truth describes.
BUILD_ARTIFACTS = {".git", "node_modules", "target", "dist", "__pycache__", ".venv"}


def copy_project(source: Path, destination: Path) -> str | None:
    """Copy a project that is not in git, excluding build artifacts.

    Holdout variants are generated rather than committed -- publishing them would
    turn the holdout into a second public corpus -- so they cannot be exported
    from HEAD. They are copied instead, with the same exclusions git would have
    given us for free.
    """
    if not source.is_dir():
        return f"no such project directory: {source}"
    if destination.exists():
        shutil.rmtree(destination)

    def ignore(directory, names):
        return [n for n in names if n in BUILD_ARTIFACTS or n.endswith((".o", ".class"))]

    try:
        shutil.copytree(source, destination, ignore=ignore, symlinks=True)
    except OSError as exc:
        return str(exc)
    return None


def export_project(corpus_path: str, destination: Path) -> str | None:
    """Export a corpus project from HEAD into a pristine directory.

    Generators must see the corpus the ground truth describes, not the working
    tree. Building the corpus leaves ``dist/``, ``node_modules/``, ``target/``
    and object files behind, and a generator scanning those reports cryptography
    in compiled output -- real findings, at paths the ground truth says nothing
    about, which then look like false positives.

    Exporting from HEAD also matches how the intended runner behaves: BF-CBOM
    workers ``git clone --depth 1`` and therefore always see a clean tree
    (``common/utils.py:136``).
    """
    tracked = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "ls-files", "--error-unmatch", corpus_path],
        capture_output=True,
        timeout=60,
    )
    if tracked.returncode != 0 or not tracked.stdout.strip():
        # Not in git: a generated holdout variant. Copy it instead.
        return copy_project(REPO_ROOT / corpus_path, destination)

    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)

    archive = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "archive", "HEAD", "--", corpus_path],
        capture_output=True,
        timeout=120,
    )
    if archive.returncode != 0:
        return (archive.stderr or b"").decode("utf-8", "replace").strip()

    extract = subprocess.run(
        ["tar", "-x", "-C", str(destination), "--strip-components", str(len(Path(corpus_path).parts))],
        input=archive.stdout,
        capture_output=True,
        timeout=120,
    )
    if extract.returncode != 0:
        return (extract.stderr or b"").decode("utf-8", "replace").strip()
    return None


def project_snapshot(project: Path) -> set[str]:
    """Relative paths currently in a project, for detecting writes into it."""
    skip = {".git", "node_modules", "target", "dist", "__pycache__", ".venv"}
    found = set()
    for path in project.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(project)
        if any(part in skip for part in relative.parts):
            continue
        found.add(relative.as_posix())
    return found


def run_one(spec: dict, project: Path, workdir: Path, timeout: int) -> dict:
    """The 2026-07-27 run generator against one project. Never raises."""
    output_mode = spec.get("output", "stdout")
    out_file = (workdir / "bom.json").resolve()
    if out_file.exists():
        out_file.unlink()

    argv = [
        part.replace("{project}", str(project)).replace("{out}", str(out_file))
        for part in spec["invocation"]
    ]

    env = os.environ.copy()
    env.update(spec.get("env", {}))

    started = time.monotonic()
    try:
        proc = subprocess.run(
            argv,
            cwd=str(project if spec.get("cwd") == "project" else workdir),
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "timeout",
            "argv": argv,
            "duration_sec": round(time.monotonic() - started, 2),
            "error": f"timed out after {timeout}s",
        }
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            "status": "error",
            "argv": argv,
            "duration_sec": round(time.monotonic() - started, 2),
            "error": str(exc),
        }

    duration = round(time.monotonic() - started, 2)
    stderr_tail = " | ".join((proc.stderr or "").strip().splitlines()[-6:])

    if output_mode == "stdout":
        payload = proc.stdout or ""
    else:
        payload = out_file.read_text(encoding="utf-8", errors="replace") if out_file.exists() else ""

    accepted = proc.returncode in spec.get("accept_exit", [0])
    record = {
        "argv": argv,
        "exit_code": proc.returncode,
        "exit_accepted": accepted,
        "duration_sec": duration,
        "bytes": len(payload.encode("utf-8")),
        "stderr_tail": stderr_tail,
    }

    if not payload.strip():
        record["status"] = "empty"
        record["error"] = "generator produced no document"
        return record
    if not accepted:
        record["status"] = "failed"
        record["error"] = f"exit {proc.returncode} not in accepted set {spec.get('accept_exit', [0])}"
        return record

    try:
        json.loads(payload)
    except json.JSONDecodeError as exc:
        record["status"] = "invalid-json"
        record["error"] = str(exc)
        record["payload"] = payload
        return record

    record["status"] = "ok"
    record["payload"] = payload
    return record


class UnsetVariable(Exception):
    """A generator config referenced an environment variable that is not set."""


#: ${NAME} in a generator config. Bare $NAME is deliberately not supported: a
#: path may legitimately contain a dollar sign, and requiring braces means an
#: expansion is always visible as one.
_CONFIG_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def expand_config_vars(value, env=None, _where="tools"):
    """Expand ${VAR} through a loaded config, recursively.

    Paths in a generator config are environment-specific -- a build root lives
    on whichever machine has the disk for it -- so the config carries a name and
    the environment supplies the path.

    An unset variable raises. The alternatives are both worse than failing: an
    empty expansion produces a path like "/scan/." that resolves somewhere real
    and scans the wrong tree, and leaving the literal "${VAR}" unexpanded
    produces a not-found error naming a file nobody can search for. Either way a
    run would be attributed to a binary that did not produce it.
    """
    env = os.environ if env is None else env

    if isinstance(value, str):
        missing = [m.group(1) for m in _CONFIG_VAR.finditer(value) if m.group(1) not in env]
        if missing:
            names = ", ".join(sorted(set(missing)))
            raise UnsetVariable(
                f"{_where}: environment variable {names} is referenced by the generator "
                f"config but is not set. Set it to the path it names, or edit the config."
            )
        return _CONFIG_VAR.sub(lambda m: env[m.group(1)], value)

    if isinstance(value, list):
        return [expand_config_vars(v, env, _where) for v in value]
    if isinstance(value, dict):
        return {k: expand_config_vars(v, env, f"{_where}.{k}") for k, v in value.items()}
    return value


def resolve_repo_paths(specs):
    """Resolve repo-relative tool paths against the repository root.

    A tool that lives in this repository -- the cdxgen wrapper, for instance --
    is named relative to the root, so the config carries no machine-specific
    prefix and reads the same on every checkout. Invocations run with the working
    directory set to the project under inspection, so the path has to be made
    absolute here rather than left for the shell.

    A path outside the repository stays as written; that is what ${VAR} is for.
    """
    for spec in specs:
        for key in ("binary",):
            value = spec.get(key)
            if value and not value.startswith("/"):
                spec[key] = str((REPO_ROOT / value).resolve())
        for key in ("invocation", "version_command"):
            parts = spec.get(key)
            if not parts:
                continue
            spec[key] = [
                str((REPO_ROOT / part).resolve())
                if i == 0 and not part.startswith("/") and not part.startswith("{")
                else part
                for i, part in enumerate(parts)
            ]
    return specs


#: A path outside the repository, recorded by filename only. Its identity is
#: fixed by the sha256 recorded beside it, which is what a reviewer checks; the
#: absolute path of the machine that ran a scan is not a property of the run.
_SCRATCH = re.compile(r"^.*/(?=[^/]+$)")


def record_paths_deep(value):
    """Apply record_path through a whole manifest, argv included."""
    if isinstance(value, str):
        return record_path(value) if value.startswith("/") else value
    if isinstance(value, list):
        return [record_paths_deep(v) for v in value]
    if isinstance(value, dict):
        return {k: record_paths_deep(v) for k, v in value.items()}
    return value


def record_path(value):
    """Render a path for the manifest: repo-relative, or <external>/<name>."""
    if not value:
        return value
    try:
        return str(Path(value).resolve().relative_to(REPO_ROOT))
    except ValueError:
        return "<external>/" + Path(value).name


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--config", type=Path, required=True, help="generator definitions")
    parser.add_argument("--out", type=Path, required=True, help="run directory to create")
    parser.add_argument(
        "--ground-truth",
        type=Path,
        default=GROUND_TRUTH,
        help="ground-truth directory naming the projects to run (default: ground-truth/); "
        "pass ground-truth-holdout/ for a holdout run",
    )
    parser.add_argument("--timeout", type=int, default=600, help="per-invocation timeout, seconds")
    parser.add_argument("--tool", action="append", help="limit to named tool(s)")
    parser.add_argument("--project", action="append", help="limit to named project(s)")
    args = parser.parse_args()

    # Absolute, before anything is spawned. Generators run with their working
    # directory set to the project under inspection, so a relative output path
    # would be written inside the corpus and read back from the repository root
    # -- which silently yields an empty document and looks exactly like a
    # generator that found nothing.
    args.out = args.out.resolve()

    config = json.loads(args.config.read_text(encoding="utf-8"))
    try:
        # Expanded here, once, so every later consumer -- version_command,
        # invocation, the manifest's binary and its sha256 -- sees the resolved
        # path and nothing sees a placeholder.
        config["tools"] = expand_config_vars(config["tools"], _where=str(args.config))
    except UnsetVariable as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    specs = resolve_repo_paths(config["tools"])
    if args.tool:
        specs = [s for s in specs if s["name"] in set(args.tool)]

    projects = load_projects(args.ground_truth.resolve())
    if args.project:
        projects = [p for p in projects if p["project"] in set(args.project)]
    if not specs or not projects:
        print("nothing to run", file=sys.stderr)
        return 1

    # Determine publishability BEFORE creating anything. The run directory is
    # itself untracked until the results are committed, so checking afterwards
    # would let this tool's own output mark every run unpublishable.
    try:
        out_relative = args.out.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        out_relative = None

    def _is_run_output(path: str) -> bool:
        if out_relative is None:
            return False
        return path == out_relative or path.startswith(out_relative + "/")

    outstanding = [path for path in git_status_paths() if not _is_run_output(path)]
    dirty = bool(outstanding)

    cboms_dir = args.out / "cboms"
    cboms_dir.mkdir(parents=True, exist_ok=True)
    workdir = args.out / ".work"
    workdir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "run": {
            "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            # Generators scan a pristine export of this commit, not the working
            # tree, so build artifacts cannot enter the scan.
            "scan_tree": "git archive HEAD",
            "ground_truth": str(args.ground_truth),
            "holdout": args.ground_truth.resolve() != GROUND_TRUTH.resolve(),
            "corpus_commit": git("rev-parse", "HEAD"),
            "corpus_commit_short": git("rev-parse", "--short", "HEAD"),
            "corpus_tree_dirty": dirty,
            "uncommitted_paths": outstanding[:20],
            "host_platform": sys.platform,
            "python": sys.version.split()[0],
        },
        "judgement_tables": judgement_table_digest(),
        "tools": {},
        "projects": {p["project"]: {"language": p["language"], "assets": p["asset_count"]} for p in projects},
        "invocations": [],
    }

    if dirty:
        print(
            "warning: corpus tree is dirty; this run is not publishable "
            "(see METHODOLOGY.md §8)",
            file=sys.stderr,
        )

    for spec in specs:
        binary = spec.get("binary")
        manifest["tools"][spec["name"]] = {
            "version": tool_version(spec),
            "binary": record_path(binary),
            "binary_sha256": sha256_file(Path(binary)) if binary and Path(binary).exists() else None,
            "package_version": spec.get("package_version"),
            "accept_exit": spec.get("accept_exit", [0]),
            "notes": spec.get("notes", ""),
        }

    total = len(specs) * len(projects)
    done = 0
    for spec in specs:
        for project in projects:
            done += 1
            label = f"{spec['name']} x {project['project']}"
            print(f"[{done}/{total}] {label} ...", flush=True)

            # Scan a pristine export, never the working tree.
            path = workdir / "scan" / project["project"]
            export_error = export_project(project["corpus_path"], path)
            if export_error:
                print(f"      EXPORT FAILED: {export_error}")
                manifest["invocations"].append(
                    {
                        "tool": spec["name"],
                        "project": project["project"],
                        "language": project["language"],
                        "status": "export-failed",
                        "error": export_error,
                    }
                )
                continue

            before = project_snapshot(path)
            record = run_one(spec, path, workdir, args.timeout)
            payload = record.pop("payload", None)

            # A generator that writes into the corpus is worth recording either
            # way: it may be leaving a bom.json behind, or -- as happened once
            # in development -- the harness may be handing it a relative output
            # path that lands inside the tree under inspection, which reads back
            # as "the generator found nothing".
            written_into_project = sorted(project_snapshot(path) - before)
            if written_into_project:
                # Recorded because it is a real property of the generator. The
                # scan tree is a throwaway export, so nothing needs cleaning up.
                record["wrote_into_scan_tree"] = written_into_project[:20]
                print(
                    f"      note: wrote {len(written_into_project)} file(s) into the scan tree",
                    flush=True,
                )

            if record["status"] == "ok" and payload is not None:
                target = cboms_dir / f"{project['project']}__{spec['name']}.json"
                target.write_text(payload, encoding="utf-8")
                record["written"] = target.name
                print(f"      ok  {record['bytes']} bytes in {record['duration_sec']}s")
            else:
                print(f"      {record['status'].upper()}: {record.get('error', '')}")

            record["tool"] = spec["name"]
            record["project"] = project["project"]
            record["language"] = project["language"]
            manifest["invocations"].append(record)

    manifest["run"]["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    manifest["run"]["succeeded"] = sum(1 for i in manifest["invocations"] if i["status"] == "ok")
    manifest["run"]["attempted"] = len(manifest["invocations"])

    (args.out / "manifest.json").write_text(
        json.dumps(record_paths_deep(manifest), indent=2, sort_keys=False) + "\n", encoding="utf-8"
    )
    shutil.rmtree(workdir, ignore_errors=True)

    print(
        f"\n{manifest['run']['succeeded']}/{manifest['run']['attempted']} invocations produced a document"
    )
    print(f"wrote {args.out / 'manifest.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
