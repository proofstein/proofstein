# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ottenheimer GmbH
"""Discovery of CBOMs in both supported input layouts.

The bundle layout is BF-CBOM's, reproduced from its writer at
``coordinator/utils.py:551`` and ``misc/cli/cli.py:187``:

    <insp_id>/<worker>/<repo_full_name with "/" -> "_">_<worker>.json
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from proofstein.inputs import discover_bundle, discover_raw_directory  # noqa: E402

PROJECTS = {"beacon-relay", "vaultkeeper", "sealbox"}
BOM = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []})


class TestRawDirectory(unittest.TestCase):
    def test_double_underscore_convention(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "beacon-relay__yourtool.json").write_text(BOM)
            found, problems = discover_raw_directory(root, PROJECTS)
            self.assertEqual(problems, [])
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0].project, "beacon-relay")
            self.assertEqual(found[0].tool, "yourtool")

    def test_tool_subdirectory_layout(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "yourtool").mkdir()
            (root / "yourtool" / "sealbox.json").write_text(BOM)
            found, problems = discover_raw_directory(root, PROJECTS)
            self.assertEqual(problems, [])
            self.assertEqual((found[0].project, found[0].tool), ("sealbox", "yourtool"))

    def test_hyphenated_tool_name_survives(self):
        """Project and tool names both contain hyphens; only '__' separates."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "beacon-relay__pqprobe-static.json").write_text(BOM)
            found, _ = discover_raw_directory(root, PROJECTS)
            self.assertEqual((found[0].project, found[0].tool), ("beacon-relay", "pqprobe-static"))

    def test_unparseable_name_is_reported_not_guessed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "mystery.json").write_text(BOM)
            found, problems = discover_raw_directory(root, PROJECTS)
            self.assertEqual(found, [])
            self.assertEqual(len(problems), 1)
            self.assertIn("mystery.json", problems[0])

    def test_unknown_project_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "not-a-corpus-project__tool.json").write_text(BOM)
            found, problems = discover_raw_directory(root, PROJECTS)
            self.assertEqual(found, [])
            self.assertTrue(problems)


class TestBfCbomBundle(unittest.TestCase):
    INSP = "ab12cd34-5e6f-7890-abcd-ef1234567890"

    def _bundle(self, root: Path, entries: list[tuple[str, str]]) -> Path:
        path = root / f"cboms_{self.INSP[:8]}.zip"
        with zipfile.ZipFile(path, "w") as archive:
            for worker, repo in entries:
                archive.writestr(f"{self.INSP}/{worker}/{repo}_{worker}.json", BOM)
        return path

    def test_tool_comes_from_the_directory_level(self):
        """The filename is ambiguous; the directory is not."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = self._bundle(root, [("cdxgen", "acme_beacon-relay")])
            found, problems = discover_bundle(bundle, PROJECTS)
            self.assertEqual(problems, [])
            self.assertEqual((found[0].project, found[0].tool), ("beacon-relay", "cdxgen"))

    def test_underscored_owner_and_repo_resolve(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = self._bundle(root, [("cbomkit", "some-org_sealbox")])
            found, _ = discover_bundle(bundle, PROJECTS)
            self.assertEqual(found[0].project, "sealbox")

    def test_tool_name_containing_underscores(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = self._bundle(root, [("my_tool_v2", "org_vaultkeeper")])
            found, _ = discover_bundle(bundle, PROJECTS)
            self.assertEqual((found[0].project, found[0].tool), ("vaultkeeper", "my_tool_v2"))

    def test_extracted_bundle_directory_works(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / self.INSP / "cdxgen"
            target.mkdir(parents=True)
            (target / "acme_sealbox_cdxgen.json").write_text(BOM)
            found, problems = discover_bundle(root, PROJECTS)
            self.assertEqual(problems, [])
            self.assertEqual((found[0].project, found[0].tool), ("sealbox", "cdxgen"))

    def test_unknown_repo_is_reported_not_guessed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = self._bundle(root, [("cdxgen", "acme_some-other-repo")])
            found, problems = discover_bundle(bundle, PROJECTS)
            self.assertEqual(found, [])
            self.assertTrue(problems)

    def test_non_archive_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notazip.zip"
            path.write_text("this is not a zip")
            found, problems = discover_bundle(path, PROJECTS)
            self.assertEqual(found, [])
            self.assertTrue(problems)


if __name__ == "__main__":
    unittest.main()
