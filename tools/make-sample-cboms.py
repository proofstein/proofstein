#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ottenheimer GmbH
"""Generate the synthetic sample CBOMs under samples/.

These exist so that a fresh clone can run the scorer end to end without having
to stand up a runner first, and so the tests have fixtures with known answers.

**They are not tool output.** The generator names are deliberately fictional
(`demo-precise`, `demo-srcfile`, `demo-noisy`) because attaching a real
vendor's name to numbers nobody measured would misrepresent that vendor. Each
one models an *evidence style* observed in real CBOMs:

* ``demo-precise``  -- spec-shaped ``evidence.occurrences`` with file and line.
* ``demo-srcfile``  -- file path in ``properties[].SrcFile``, no line at all,
  the shape cdxgen emits (``tests/bisq_cdxgen.json`` in BF-CBOM).
* ``demo-noisy``    -- a mix, plus phantom files and phantom algorithms, to
  exercise the false-positive paths.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GROUND_TRUTH = REPO_ROOT / "ground-truth"
SAMPLES = REPO_ROOT / "samples" / "cboms"
INVALID = REPO_ROOT / "samples" / "invalid"

BOM_HEADER = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "version": 1,
}


def bom(components: list[dict], tool_name: str) -> dict:
    document = dict(BOM_HEADER)
    document["metadata"] = {
        "tools": {"components": [{"type": "application", "name": tool_name, "version": "0.0.0-demo"}]}
    }
    document["components"] = components
    return document


def occurrence_component(asset: dict, *, with_line: bool = True) -> dict:
    occurrence: dict = {"location": asset["file"]}
    if with_line:
        occurrence["line"] = asset["line"]
    return {
        "type": "cryptographic-asset",
        "bom-ref": f"crypto/{asset['id']}",
        "name": asset["algorithm"],
        "cryptoProperties": {"assetType": asset["cyclonedx_asset_type"]},
        "evidence": {"occurrences": [occurrence]},
    }


def srcfile_component(asset: dict) -> dict:
    """The cdxgen shape: path in properties, no line number."""
    return {
        "type": "cryptographic-asset",
        "bom-ref": f"crypto/{asset['id']}",
        "name": asset["algorithm"],
        "cryptoProperties": {"assetType": asset["cyclonedx_asset_type"]},
        "properties": [{"name": "SrcFile", "value": asset["file"]}],
    }


def build_precise(assets: list[dict]) -> list[dict]:
    """Finds direct call sites and files; weaker on indirection."""
    out = []
    for asset in assets:
        if asset["layer"] in (1, 2, 6):
            out.append(occurrence_component(asset))
        elif asset["layer"] == 4 and asset["cyclonedx_asset_type"] == "algorithm":
            out.append(occurrence_component(asset))
    return out


def build_srcfile(assets: list[dict]) -> list[dict]:
    """Finds plenty, but supplies no line numbers -- so nothing is checkable."""
    return [srcfile_component(asset) for asset in assets if asset["layer"] in (1, 2, 4, 6)]


def build_noisy(assets: list[dict], project: str) -> list[dict]:
    """Some real detections, plus phantoms of both kinds."""
    out = []
    for index, asset in enumerate(assets):
        if asset["layer"] in (1, 3) and index % 2 == 0:
            out.append(occurrence_component(asset))

    # Phantom location: a file that is not in the project.
    out.append(
        {
            "type": "cryptographic-asset",
            "bom-ref": f"crypto/phantom-file/{project}",
            "name": "AES-256-GCM",
            "cryptoProperties": {"assetType": "algorithm"},
            "evidence": {"occurrences": [{"location": "src/does-not-exist.go", "line": 12}]},
        }
    )
    # Phantom algorithm: a family that appears nowhere in the corpus project.
    out.append(
        {
            "type": "cryptographic-asset",
            "bom-ref": f"crypto/phantom-algorithm/{project}",
            "name": "Blowfish-448",
            "cryptoProperties": {"assetType": "algorithm"},
            "evidence": {"occurrences": [{"location": assets[0]["file"], "line": assets[0]["line"]}]},
        }
    )
    return out


BUILDERS = {
    "demo-precise": lambda assets, project: build_precise(assets),
    "demo-srcfile": lambda assets, project: build_srcfile(assets),
    "demo-noisy": build_noisy,
}


def main() -> int:
    if not GROUND_TRUTH.is_dir():
        print(f"no ground truth at {GROUND_TRUTH}; run tools/build-corpus.py first", file=sys.stderr)
        return 1

    SAMPLES.mkdir(parents=True, exist_ok=True)
    INVALID.mkdir(parents=True, exist_ok=True)

    written = 0
    for path in sorted(GROUND_TRUTH.glob("*.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        project = document["project"]
        assets = document["assets"]

        for tool, builder in BUILDERS.items():
            components = builder(assets, project)
            out_path = SAMPLES / f"{project}__{tool}.json"
            out_path.write_text(
                json.dumps(bom(components, tool), indent=2) + "\n", encoding="utf-8"
            )
            written += 1

    # A document that must fail schema validation: specVersion is required by
    # the schema and components[].type has a closed enum.
    broken = {
        "bomFormat": "CycloneDX",
        "components": [{"type": "not-a-valid-component-type", "name": "AES-256-GCM"}],
    }
    (INVALID / "malformed.cdx.json").write_text(json.dumps(broken, indent=2) + "\n", encoding="utf-8")

    # A document that is valid JSON but not a BOM at all.
    (INVALID / "not-a-bom.json").write_text(json.dumps({"hello": "world"}, indent=2) + "\n", encoding="utf-8")

    # A document that is not JSON.
    (INVALID / "truncated.json").write_text('{"bomFormat": "CycloneDX", "comp', encoding="utf-8")

    print(f"wrote {written} sample CBOM(s) to {SAMPLES.relative_to(REPO_ROOT)}")
    print(f"wrote 3 invalid fixture(s) to {INVALID.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
