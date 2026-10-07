# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ottenheimer GmbH
"""What the JSON results publish about each plant, public and holdout."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from proofstein.report import render_json  # noqa: E402

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


if __name__ == "__main__":
    unittest.main()
