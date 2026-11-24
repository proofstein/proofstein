# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ottenheimer GmbH
"""What the JSON results publish about each plant, public and holdout."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from proofstein.report import render_json, render_markdown  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_scoring import crypto, make_bom, run  # noqa: E402


def assets(corpus: str) -> list[dict]:
    result = run(make_bom([crypto("AES-256-GCM", "src/seal.go", 10)]))
    return render_json([result], {"corpus": corpus})["results"][0]["assets"]


class TestHoldoutResultsNameNoLocation(unittest.TestCase):
    def test_public_results_carry_file_and_line(self):
        entry = assets("public")[0]
        self.assertEqual((entry["file"], entry["line"]), ("src/seal.go", 10))

    def test_holdout_results_name_each_plant_by_id_alone(self):
        for entry in assets("holdout"):
            self.assertNotIn("file", entry)
            self.assertNotIn("line", entry)

    def test_holdout_keeps_every_verdict(self):
        public, holdout = assets("public"), assets("holdout")
        for p, h in zip(public, holdout):
            self.assertEqual({k: v for k, v in p.items() if k not in ("file", "line")}, h)
        self.assertTrue(holdout[0]["detected"])



class TestJudgementTablesAtCollection(unittest.TestCase):
    def test_a_table_added_since_collection_is_said_to_be_new(self):
        result = run(make_bom([crypto("AES-256-GCM", "src/seal.go", 10)]))
        meta = {
            "corpus": "public", "corpus_version": "abc1234", "line_tolerance": 2,
            "run": {
                "judgement_tables": {"old": {"entries": 2, "sha256_16": "bbbb"}, "new": {"entries": 1, "sha256_16": "cccc"}},
                "judgement_tables_collected": {"old": {"entries": 1, "sha256_16": "aaaa"}},
            },
        }
        page = render_markdown([result], meta)
        row = next(line for line in page.splitlines() if line.startswith("| new "))
        self.assertIn("did not exist when this run was collected", row)
        self.assertNotIn("?", row)
        self.assertIn("1 entries, aaaa", next(line for line in page.splitlines() if line.startswith("| old ")))


if __name__ == "__main__":
    unittest.main()
