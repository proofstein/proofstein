# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ottenheimer GmbH
"""Scoring must not proceed against a corpus that is not there.

``project_file_index`` used to return an empty set when a project's
``corpus_path`` did not resolve, and scoring carried on. The result was not a
visible error: an empty file list resolves no reported path, so every component
becomes a phantom location and the run reports 0/108 with a full sheet of false
positives. A missing corpus and a generator that found nothing while fabricating
everything produced the same numbers.

That is not hypothetical. Re-scoring the 2026-07-28 run's holdout against a ground truth
whose corpus was not on disk produced exactly that, and it was diagnosed from the
shape of the result rather than from any message
(``docs/pending-review.md`` entry 8, residual).

Run with: python3 -m unittest discover -s tests
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from score import load_projects, project_file_index  # noqa: E402

SCORE = REPO_ROOT / "score.py"


def ground_truth_document(corpus_path: str, project: str = "phantom-project") -> dict:
    return {
        "project": project,
        "language": "go",
        "corpus_path": corpus_path,
        "asset_count": 1,
        "assets": [
            {
                "id": "x-l1-aes",
                "file": "src/seal.go",
                "line": 10,
                "algorithm": "AES-256-GCM",
                "layer": 1,
                "cyclonedx_asset_type": "algorithm",
            }
        ],
    }


def cbom_document() -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [
            {
                "type": "cryptographic-asset",
                "name": "AES-256-GCM",
                "cryptoProperties": {"assetType": "algorithm"},
                "evidence": {"occurrences": [{"location": "src/seal.go", "line": 10}]},
            }
        ],
    }


class TestProjectFileIndexFailsLoud(unittest.TestCase):
    def test_missing_corpus_path_names_the_path(self):
        project = ground_truth_document("corpus/go/does-not-exist")
        with self.assertRaises(SystemExit) as caught:
            project_file_index(project)
        message = str(caught.exception)
        self.assertIn("corpus/go/does-not-exist", message)
        self.assertIn("phantom-project", message)

    def test_empty_corpus_directory_is_also_a_failure(self):
        """A directory that exists but holds nothing yields the same empty index."""
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            relative = Path(temporary).relative_to(REPO_ROOT).as_posix()
            with self.assertRaises(SystemExit) as caught:
                project_file_index(ground_truth_document(relative))
            self.assertIn(relative, str(caught.exception))

    def test_a_directory_holding_only_skipped_paths_is_a_failure(self):
        """Everything filtered out leaves an empty index, which is still empty."""
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            (Path(temporary) / "node_modules").mkdir()
            (Path(temporary) / "node_modules" / "left-pad.js").write_text("", encoding="utf-8")
            relative = Path(temporary).relative_to(REPO_ROOT).as_posix()
            with self.assertRaises(SystemExit):
                project_file_index(ground_truth_document(relative))

    def test_the_hint_matches_the_corpus_it_names(self):
        """A missing holdout is regenerated from a seed, not built."""
        with self.assertRaises(SystemExit) as public:
            project_file_index(ground_truth_document("corpus/go/nope"))
        self.assertIn("tools/build-corpus.py", str(public.exception))

        with self.assertRaises(SystemExit) as holdout:
            project_file_index(ground_truth_document("holdout/go/nope"))
        self.assertIn("tools/generate-holdout.py", str(holdout.exception))

    def test_the_shipped_corpus_still_indexes(self):
        """The committed corpus must not trip any of the above."""
        projects = load_projects()
        self.assertGreater(len(projects), 0)
        for name, project in sorted(projects.items()):
            with self.subTest(project=name):
                files = project_file_index(project)
                self.assertGreater(len(files), 0, f"{name} indexed no files")


class TestScoreExitsNonZero(unittest.TestCase):
    """End to end, because the requirement is an exit status, not an exception."""

    def run_score(self, cboms: Path, ground_truth: Path, out: Path):
        return subprocess.run(
            [
                sys.executable,
                str(SCORE),
                "--cboms",
                str(cboms),
                "--ground-truth",
                str(ground_truth),
                "--out",
                str(out),
                "--no-schema",
            ],
            capture_output=True,
            text=True,
            timeout=300,
            cwd=REPO_ROOT,
        )

    def test_unresolvable_corpus_path_exits_nonzero_with_the_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            gt = root / "ground-truth"
            cboms = root / "cboms"
            gt.mkdir()
            cboms.mkdir()
            (gt / "phantom-project.json").write_text(
                json.dumps(ground_truth_document("corpus/go/does-not-exist")), encoding="utf-8"
            )
            (cboms / "phantom-project__a-tool.json").write_text(
                json.dumps(cbom_document()), encoding="utf-8"
            )

            completed = self.run_score(cboms, gt, root / "out")

            self.assertNotEqual(completed.returncode, 0, "scoring a missing corpus succeeded")
            self.assertIn("corpus/go/does-not-exist", completed.stderr)
            # The failure must not look like a score.
            self.assertNotIn("0/1", completed.stdout)
            self.assertFalse(
                (root / "out" / "results.md").exists(),
                "a results file was written for a run that could not be scored",
            )

    def test_the_shipped_samples_still_score(self):
        """The existing path must be untouched: same command, same success."""
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary) / "out"
            completed = self.run_score(REPO_ROOT / "samples" / "cboms", REPO_ROOT / "ground-truth", out)

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue((out / "results.md").exists())
            self.assertIn("scored", completed.stdout)


if __name__ == "__main__":
    unittest.main()
