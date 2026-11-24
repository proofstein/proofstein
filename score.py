#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ottenheimer GmbH
"""Score CBOMs against the Proofstein ground-truth corpus.

    ./score.py --cboms path/to/cboms/          # raw CycloneDX directory
    ./score.py --bundle cboms_ab12cd34.zip     # BF-CBOM artifact bundle

Writes results/results.md and results/results.json.

The scorer runs standalone. It needs no runner, no Redis, and no network.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_ROOT))

from proofstein import schema as schema_module  # noqa: E402
from proofstein.cbom import parse_cbom  # noqa: E402
from proofstein.tables import judgement_table_digest  # noqa: E402

#: A run's own directory under runs/. Generators scan an export of the corpus,
#: which never contains runs/, so an uncommitted run directory, this run's or
#: another's, does not make the corpus dirty. runs/generators.json is a run
#: input and is not matched.
RUN_DIRECTORY = re.compile(r"^runs/[^/]+/")


def corpus_dirty(run: dict) -> bool:
    """Whether a run's corpus tree was dirty: an uncommitted path outside the
    run directories, or the recorded flag when no paths were recorded."""
    paths = run.get("uncommitted_paths")
    if paths is None:
        return bool(run.get("corpus_tree_dirty"))
    return any(not RUN_DIRECTORY.match(path) for path in paths)
from proofstein.inputs import discover_bundle, discover_raw_directory  # noqa: E402
from proofstein.matching import DEFAULT_LINE_TOLERANCE  # noqa: E402
from proofstein.report import render_json, render_markdown  # noqa: E402
from proofstein.scoring import Unplanted, score_cbom  # noqa: E402

GROUND_TRUTH_DIR = REPO_ROOT / "ground-truth"
CORPUS_DIR = REPO_ROOT / "corpus"
RESULTS_DIR = REPO_ROOT / "results"

# Cryptographic constructs present in the corpus that carry no ground-truth
# entry. They are excluded from the phantom-algorithm check. A bare string is
# corpus-wide; ``Unplanted(name, project, file)`` applies only in that file.
# Every entry names something present in the corpus.
KNOWN_UNPLANTED: frozenset[str | Unplanted] = frozenset(
    {
        # CSPRNGs. Every project seeds nonces or keys from one:
        # crypto/rand.Read (Go), RAND_bytes (C), randomBytes (JS),
        # SecureRandom (Java), os.urandom (Python), OsRng (Rust).
        "CSPRNG",
        "DRBG",
        "SecureRandom",
        "OsRng",
        "urandom",
        # Encodings, not ciphers, but frequently reported as crypto assets.
        # encoding/hex and base64url appear in the fingerprint and JWKS paths.
        "base64",
        "hex",
        # A mode named on its own, where the planted asset is the full AEAD.
        "GCM",
        # Named in ledger-svc/deploy/jvm.options as disabled algorithms
        # (-Djdk.tls.disabledAlgorithms). Allowed in that file only.
        Unplanted("MD5", "ledger-svc", "deploy/jvm.options"),
        Unplanted("RC4", "ledger-svc", "deploy/jvm.options"),
        Unplanted("DES", "ledger-svc", "deploy/jvm.options"),
        Unplanted("SSLv3", "ledger-svc", "deploy/jvm.options"),
        # Halves of planted composites: SHA-384 from the nginx suite
        # ECDHE-ECDSA-AES256-GCM-SHA384, and X25519 from the JVM group
        # x25519mlkem768.
        "SHA-384",
        "X25519",
        # TLS versions named in several configs.
        "TLS",
    }
)


def load_projects(ground_truth_dir: Path = GROUND_TRUTH_DIR) -> dict[str, dict]:
    """Load every ground-truth document, keyed by project name."""
    if not ground_truth_dir.is_dir():
        raise SystemExit(f"no ground truth at {ground_truth_dir}; run tools/build-corpus.py first")

    projects: dict[str, dict] = {}
    for path in sorted(ground_truth_dir.glob("*.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        projects[document["project"]] = document
    if not projects:
        raise SystemExit(f"no ground-truth files found in {GROUND_TRUTH_DIR}")
    return projects


def _corpus_hint(corpus_path: str) -> str:
    """What to run to produce a corpus that is not there."""
    if corpus_path.split("/", 1)[0] == "corpus":
        return "run tools/build-corpus.py first"
    # A holdout corpus is generated from a seed and not committed.
    return "a holdout corpus is generated, not committed: regenerate it with tools/generate-holdout.py --seed <seed>"


def project_file_index(project: dict) -> frozenset[str]:
    """Every file in a corpus project, as repo-relative POSIX paths.

    Exits with an error when the project directory is missing or holds no files.
    """
    corpus_path = project["corpus_path"]
    root = REPO_ROOT / corpus_path

    if not root.is_dir():
        raise SystemExit(
            f"no corpus directory for project {project['project']!r}: "
            f"{corpus_path} (resolved to {root}); {_corpus_hint(corpus_path)}"
        )

    skip = {".git", "node_modules", "target", "dist", "__pycache__", ".venv"}
    files = set()
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if any(part in skip for part in relative.parts):
            continue
        files.add(relative.as_posix())

    if not files:
        raise SystemExit(
            f"corpus directory for project {project['project']!r} holds no files: "
            f"{corpus_path} (resolved to {root}); {_corpus_hint(corpus_path)}"
        )

    return frozenset(files)


def _display(path: Path) -> str:
    """Show a path relative to the repository when it is inside it."""
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def corpus_version() -> str:
    """Identify the corpus so a result file can be traced to an input."""
    try:
        revision = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if revision.returncode == 0:
            head = revision.stdout.strip()
            dirty = subprocess.run(
                ["git", "-C", str(REPO_ROOT), "status", "--porcelain"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            suffix = "-dirty" if dirty.stdout.strip() else ""
            return f"{head}{suffix}"
    except (OSError, subprocess.SubprocessError):
        pass
    return "unknown"


def scorer_commit() -> str:
    """The last commit that changed score.py or proofstein/, with -dirty when
    either has uncommitted changes."""
    scorer = ["--", "score.py", "proofstein"]
    try:
        log = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "log", "-1", "--format=%h", *scorer],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        commit = log.stdout.strip()
        if log.returncode == 0 and commit:
            dirty = subprocess.run(
                ["git", "-C", str(REPO_ROOT), "status", "--porcelain", "--untracked-files=no", *scorer],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            return commit + ("-dirty" if dirty.stdout.strip() else "")
    except (OSError, subprocess.SubprocessError):
        pass
    return "unknown"


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--cboms", type=Path, help="directory of raw CycloneDX CBOMs")
    source.add_argument("--bundle", type=Path, help="BF-CBOM artifact bundle (zip or directory)")
    parser.add_argument("--out", type=Path, default=RESULTS_DIR, help="output directory")
    parser.add_argument(
        "--line-tolerance",
        type=int,
        default=DEFAULT_LINE_TOLERANCE,
        help=f"lines a report may differ from the plant (default {DEFAULT_LINE_TOLERANCE})",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        help="run manifest from tools/collect-cboms.py; its tool versions, corpus "
        "commit and judgement-table digests are carried into the results",
    )
    parser.add_argument(
        "--ground-truth",
        type=Path,
        default=GROUND_TRUTH_DIR,
        help="ground-truth directory to score against (default: ground-truth/); "
        "pass ground-truth-holdout/ to score a holdout run. Holdout and public "
        "scores are reported separately and never averaged -- see METHODOLOGY.md 6.",
    )
    parser.add_argument("--no-schema", action="store_true", help="skip CycloneDX schema validation")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    if args.line_tolerance < 0:
        raise SystemExit("--line-tolerance must not be negative")
    if args.line_tolerance > DEFAULT_LINE_TOLERANCE:
        # Announced here and recorded in the header of both output files.
        print(
            f"warning: line tolerance {args.line_tolerance} is wider than the default "
            f"{DEFAULT_LINE_TOLERANCE}; results are not comparable with published runs",
            file=sys.stderr,
        )

    projects = load_projects(args.ground_truth.resolve())
    known = set(projects)

    if args.cboms:
        if not args.cboms.is_dir():
            raise SystemExit(f"not a directory: {args.cboms}")
        inputs, problems = discover_raw_directory(args.cboms, known)
    else:
        if not args.bundle.exists():
            raise SystemExit(f"no such bundle: {args.bundle}")
        inputs, problems = discover_bundle(args.bundle, known)

    if not inputs:
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        raise SystemExit("no CBOMs found to score")

    validate_schema = not args.no_schema
    if validate_schema and not schema_module.available():
        print(
            "warning: jsonschema is unavailable, skipping schema validation "
            "(pip install -r requirements.txt)",
            file=sys.stderr,
        )
        validate_schema = False

    file_index = {name: project_file_index(project) for name, project in projects.items()}

    results = []
    for item in inputs:
        project = projects[item.project]
        bom, reported, parse_error = parse_cbom(item.raw)

        result = score_cbom(
            project=item.project,
            language=project["language"],
            tool=item.tool,
            source=item.source,
            ground_truth=project["assets"],
            reported=reported,
            project_files=file_index[item.project],
            known_unplanted=KNOWN_UNPLANTED,
            line_tolerance=args.line_tolerance,
        )
        result.parse_error = parse_error

        if validate_schema:
            if parse_error:
                result.schema_valid = False
                result.schema_errors = [parse_error]
            else:
                valid, errors = schema_module.validate(bom)
                result.schema_valid = valid
                result.schema_errors = errors

        results.append(result)

    scored_pairs = {(r.project, r.tool) for r in results}
    tools = sorted({r.tool for r in results})
    # A pair absent from the input is excluded, not scored as zero.
    unscored = sum(
        1 for name in projects for tool in tools if (name, tool) not in scored_pairs
    )

    # When a manifest is supplied, its provenance is used instead of the
    # working tree's.
    run_manifest = None
    if args.manifest:
        run_manifest = json.loads(args.manifest.read_text(encoding="utf-8"))

    meta = {
        "corpus_version": (
            run_manifest["run"].get("corpus_commit_short") or corpus_version()
            if run_manifest
            else corpus_version()
        ),
        "line_tolerance": args.line_tolerance,
        "scorer_commit": scorer_commit(),
        "corpus": "holdout" if args.ground_truth.resolve() != GROUND_TRUTH_DIR.resolve() else "public",
        "schema_validated": validate_schema,
        "cboms_scored": len(results),
        "projects": sorted(projects),
        "tools": tools,
        "unscored_pairs": unscored,
        "problems": problems,
    }

    if run_manifest:
        meta["run"] = {
            "manifest": str(args.manifest),
            "started_utc": run_manifest["run"].get("started_utc"),
            "corpus_commit": run_manifest["run"].get("corpus_commit"),
            "corpus_tree_dirty": corpus_dirty(run_manifest["run"]),
            "attempted": run_manifest["run"].get("attempted"),
            "succeeded": run_manifest["run"].get("succeeded"),
            "tool_versions": {
                name: spec.get("version") for name, spec in run_manifest.get("tools", {}).items()
            },
            # The tables this scoring used, and the ones the run was collected
            # under when those differ.
            "judgement_tables": judgement_table_digest(KNOWN_UNPLANTED),
            "judgement_tables_collected": (
                run_manifest.get("judgement_tables")
                if run_manifest.get("judgement_tables") != judgement_table_digest(KNOWN_UNPLANTED)
                else None
            ),
            # Invocations that produced no document.
            "failed_invocations": [
                {
                    "tool": entry["tool"],
                    "project": entry["project"],
                    "status": entry["status"],
                    "error": entry.get("error", ""),
                    "stderr_tail": entry.get("stderr_tail", ""),
                }
                for entry in run_manifest.get("invocations", [])
                if entry.get("status") != "ok"
            ],
        }

    args.out.mkdir(parents=True, exist_ok=True)
    markdown_path = args.out / "results.md"
    json_path = args.out / "results.json"
    markdown_path.write_text(render_markdown(results, meta), encoding="utf-8")
    json_path.write_text(
        json.dumps(render_json(results, meta), indent=2, sort_keys=False) + "\n", encoding="utf-8"
    )

    if not args.quiet:
        print(f"scored {len(results)} CBOM(s) across {len(tools)} tool(s)")
        for tool in tools:
            subset = [r for r in results if r.tool == tool]
            detected = sum(r.detected for r in subset)
            total = sum(r.total for r in subset)
            rate = f"{100 * detected / total:.0f}%" if total else "--"
            fps = sum(r.false_positives for r in subset)
            print(f"  {tool:<20} {rate:>5} ({detected}/{total})  false positives: {fps}")
        if unscored:
            print(f"  {unscored} (project, tool) pair(s) not present in input; excluded, not zeroed")
        for problem in problems:
            print(f"  warning: {problem}", file=sys.stderr)
        print(f"\nwrote {_display(markdown_path)} and {_display(json_path)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
