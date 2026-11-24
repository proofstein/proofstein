# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ottenheimer GmbH
"""Digests of the judgement tables (METHODOLOGY.md §9.1).

A digest per table is recorded when a run is collected and when it is scored.
"""

from __future__ import annotations

import hashlib
import json

from proofstein.cbom import LINE_PROPERTY_NAMES, LOCATION_PROPERTY_NAMES, OID_ALGORITHMS
from proofstein.matching import (
    _FAMILY_MARKERS,
    _HYBRID_GROUPS,
    _JOSE_NAMES,
    _TOKEN_ALIASES,
    _WHOLE_TOKEN_ONLY,
)


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
        "jose_names": {"entries": len(_JOSE_NAMES), "sha256_16": _digest(_JOSE_NAMES)},
        "hybrid_groups": {
            "entries": len(_HYBRID_GROUPS),
            "sha256_16": _digest({key: list(value) for key, value in _HYBRID_GROUPS.items()}),
        },
        "whole_token_only": {
            "entries": len(_WHOLE_TOKEN_ONLY),
            "sha256_16": _digest(sorted(_WHOLE_TOKEN_ONLY)),
        },
        # Entries are digested with their project and file scope.
        "known_unplanted": {
            "entries": len(known_unplanted),
            "sha256_16": _digest(
                sorted(str(tuple(entry)) if isinstance(entry, tuple) else str(entry) for entry in known_unplanted)
            ),
        },
    }
