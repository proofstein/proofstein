# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ottenheimer GmbH
"""Layer-5 dependency components.

CycloneDX models a library a project depends on as a ``library`` component with
no ``cryptoProperties``. Before this behaviour existed the scorer discarded such
a component before matching, so a generator that answered a layer-5 plant
correctly scored zero for it, and a generator that mislabelled the same
dependency as a ``cryptographic-asset`` scored one. The scorer was measuring
vocabulary compliance rather than detection, and it rewarded the wrong answer.

The defect surfaced because a scored vendor's own trace contradicted its score:
pqprobe-static emitted library components for dependencies it had genuinely
found, and layer 5 read 0/7 anyway.

Both fixtures describe the same real dependency at the same real line of
ledger-svc's pom.xml. They differ only in how the component is labelled.
"""

from __future__ import annotations

import json
from pathlib import Path

from proofstein.cbom import parse_cbom
from proofstein.matching import DEFAULT_LINE_TOLERANCE
from proofstein.scoring import score_cbom

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"
GROUND_TRUTH = REPO_ROOT / "ground-truth" / "ledger-svc.json"


def _score(fixture: str, tool: str):
    project = json.loads(GROUND_TRUTH.read_text())
    _, assets, error = parse_cbom((FIXTURES / fixture).read_text())
    assert error is None, error
    files = frozenset(entry["file"] for entry in project["assets"])
    return score_cbom(
        project=project["project"],
        language=project.get("language", ""),
        tool=tool,
        source=fixture,
        ground_truth=project["assets"],
        reported=assets,
        project_files=files,
        known_unplanted=frozenset(),
        line_tolerance=DEFAULT_LINE_TOLERANCE,
    )


def _layer5(result):
    return result.by_layer().get(5, (0, 0))


def test_library_component_satisfies_layer_five():
    """A dependency reported the way CycloneDX says to report it counts."""
    detected, total = _layer5(_score("dependency_as_library.json", "correct-labelling"))
    assert total == 1
    assert detected == 1, (
        "a library component at the planted manifest line did not satisfy the "
        "layer-5 plant; the scorer is measuring vocabulary, not detection"
    )


def test_library_component_is_not_a_crypto_claim():
    """No credit and no punishment: a dependency is outside crypto precision.

    An SBOM listing eighty ordinary packages must not acquire eighty crypto
    claims, and must not be charged eighty phantom algorithms for naming things
    that appear in no ground truth.
    """
    result = _score("dependency_as_library.json", "correct-labelling")
    assert result.evidence.crypto_components == 0
    assert result.credited_claims == 0
    assert result.phantom_algorithm == 0
    assert result.phantom_location == 0


def test_costume_buys_no_extra_detection():
    """Mislabelling a dependency as a cryptographic asset gains nothing.

    This is the loophole the old behaviour created: dressing a library up as a
    ``cryptographic-asset`` was the only way to score. Layer-5 credit must now be
    identical either way, so there is no longer an incentive to misdescribe.
    """
    correct = _layer5(_score("dependency_as_library.json", "correct-labelling"))
    costume = _layer5(_score("dependency_as_costumed_crypto_asset.json", "costumed"))
    assert correct == costume, (
        f"labelling changed the layer-5 result: correct={correct} costume={costume}"
    )


def test_costume_cannot_escape_the_claim_denominator():
    """A component carrying cryptoProperties is a crypto claim, whatever its type.

    The exemption is for components that make no cryptographic assertion. A
    generator that asserts one takes on the precision exposure that goes with it;
    it cannot relabel its way into the exempt bucket.
    """
    costumed = _score("dependency_as_costumed_crypto_asset.json", "costumed")
    assert costumed.evidence.crypto_components == 1, (
        "a component with invented cryptoProperties was treated as exempt; "
        "declaring a crypto claim must carry the cost of one"
    )
