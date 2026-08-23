# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ottenheimer GmbH
"""Schema validation must actually reject invalid documents.

A validator that silently degrades into approving everything is worse than no
validator, because the results file would carry a column of green ticks that
mean nothing. These tests pin both directions.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from proofstein import schema  # noqa: E402
from proofstein.cbom import parse_cbom  # noqa: E402

INVALID_DIR = REPO_ROOT / "samples" / "invalid"
SAMPLES_DIR = REPO_ROOT / "samples" / "cboms"

VALID_BOM = {
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


@unittest.skipUnless(schema.available(), "jsonschema not installed")
class TestSchemaValidation(unittest.TestCase):
    def test_valid_document_passes(self):
        valid, errors = schema.validate(VALID_BOM)
        self.assertTrue(valid, f"a well-formed CBOM was rejected: {errors}")
        self.assertEqual(errors, [])

    def test_missing_spec_version_fails(self):
        document = dict(VALID_BOM)
        document.pop("specVersion")
        valid, errors = schema.validate(document)
        self.assertFalse(valid)
        self.assertTrue(any("specVersion" in message for message in errors), errors)

    def test_missing_bom_format_fails(self):
        document = dict(VALID_BOM)
        document.pop("bomFormat")
        valid, _ = schema.validate(document)
        self.assertFalse(valid)

    def test_invalid_component_type_fails(self):
        document = json.loads(json.dumps(VALID_BOM))
        document["components"][0]["type"] = "not-a-real-component-type"
        valid, _ = schema.validate(document)
        self.assertFalse(valid)

    def test_invalid_asset_type_fails(self):
        document = json.loads(json.dumps(VALID_BOM))
        document["components"][0]["cryptoProperties"]["assetType"] = "not-an-asset-type"
        valid, _ = schema.validate(document)
        self.assertFalse(valid)

    def test_occurrence_without_location_fails(self):
        """`location` is required by the 1.6 schema."""
        document = json.loads(json.dumps(VALID_BOM))
        document["components"][0]["evidence"]["occurrences"] = [{"line": 10}]
        valid, _ = schema.validate(document)
        self.assertFalse(valid)

    def test_empty_object_fails(self):
        valid, _ = schema.validate({})
        self.assertFalse(valid)

    def test_shipped_invalid_fixtures_are_rejected(self):
        """Every fixture in samples/invalid/ must fail, one way or another."""
        fixtures = sorted(INVALID_DIR.glob("*.json"))
        self.assertGreaterEqual(len(fixtures), 3, "invalid fixtures are missing; run tools/make-sample-cboms.py")

        for path in fixtures:
            with self.subTest(fixture=path.name):
                raw = path.read_text(encoding="utf-8")
                bom, _, parse_error = parse_cbom(raw)
                if parse_error is not None:
                    continue  # rejected before validation, which is a rejection
                valid, errors = schema.validate(bom)
                self.assertFalse(valid, f"{path.name} was accepted but should not be")
                self.assertTrue(errors)

    def test_shipped_sample_cboms_are_valid(self):
        """The samples are the worked example; they must be well formed."""
        fixtures = sorted(SAMPLES_DIR.glob("*.json"))
        self.assertGreater(len(fixtures), 0, "samples are missing; run tools/make-sample-cboms.py")

        for path in fixtures:
            with self.subTest(sample=path.name):
                bom, _, parse_error = parse_cbom(path.read_text(encoding="utf-8"))
                self.assertIsNone(parse_error)
                valid, errors = schema.validate(bom)
                self.assertTrue(valid, f"{path.name} is not schema valid: {errors[:3]}")


class TestSchemaFilesArePresent(unittest.TestCase):
    def test_vendored_schemas_exist(self):
        for name in ("bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json"):
            with self.subTest(schema=name):
                self.assertTrue((REPO_ROOT / "schemas" / name).exists())

    def test_bom_schema_is_the_official_one(self):
        document = json.loads((REPO_ROOT / "schemas" / "bom-1.6.schema.json").read_text())
        self.assertEqual(document.get("$id"), "http://cyclonedx.org/schema/bom-1.6.schema.json")


if __name__ == "__main__":
    unittest.main()
