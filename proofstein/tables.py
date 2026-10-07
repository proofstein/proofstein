# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ottenheimer GmbH
"""Digests of the tables that encode judgement rather than fact.

METHODOLOGY.md §9.1 requires table changes to be attributable. A digest per
table, recorded when a run is collected and again when it is scored, lets a
reader tell whether a score moved because a generator changed or because the
tables did.
"""

from __future__ import annotations

import hashlib
import json

from proofstein.cbom import LINE_PROPERTY_NAMES, LOCATION_PROPERTY_NAMES, OID_ALGORITHMS
from proofstein.matching import _FAMILY_MARKERS, _TOKEN_ALIASES, _WHOLE_TOKEN_ONLY


def _digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=list).encode("utf-8")).hexdigest()[:16]


def judgement_table_digest(known_unplanted) -> dict:
    """Entries and a 16-hex-digit digest for each judgement table."""
    return {
        "oid_algorithms": {"entries": len(OID_ALGORITHMS), "sha256_16": _digest(OID_ALGORITHMS)},
        "location_property_names": {
            "entries": len(LOCATION_PROPERTY_NAMES),
            "sha256_16": _digest(sorted(LOCATION_PROPERTY_NAMES)),
        },
        "line_property_names": {
            "entries": len(LINE_PROPERTY_NAMES),
            "sha256_16": _digest(sorted(LINE_PROPERTY_NAMES)),
        },
        "token_aliases": {"entries": len(_TOKEN_ALIASES), "sha256_16": _digest(_TOKEN_ALIASES)},
        "family_markers": {
            "entries": len(_FAMILY_MARKERS),
            "sha256_16": _digest([list(pair) for pair in _FAMILY_MARKERS]),
        },
        "whole_token_only": {
            "entries": len(_WHOLE_TOKEN_ONLY),
            "sha256_16": _digest(sorted(_WHOLE_TOKEN_ONLY)),
        },
        # Which fabricated algorithm names are forgiven, and where. Moving an
        # entry from a scoped to a corpus-wide form silently lowers every tool's
        # false-positive count, so the digest travels with the run.
        "known_unplanted": {
            "entries": len(known_unplanted),
            "sha256_16": _digest(
                sorted(str(tuple(entry)) if isinstance(entry, tuple) else str(entry) for entry in known_unplanted)
            ),
        },
    }
