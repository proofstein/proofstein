# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ottenheimer GmbH
"""Validation against the official CycloneDX 1.6 JSON schema.

The schema files under ``schemas/`` are the upstream ones, unmodified, vendored
so that validation does not depend on network access at scoring time. They are
draft-07 and reference ``spdx.schema.json`` and ``jsf-0.82.schema.json``, both
of which are vendored alongside and resolved locally.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schemas"
BOM_SCHEMA = SCHEMA_DIR / "bom-1.6.schema.json"

#: Errors beyond this are truncated; a document that fails this hard is not
#: made more informative by another thousand messages.
MAX_REPORTED_ERRORS = 12


class SchemaUnavailable(RuntimeError):
    """Raised when validation cannot run at all."""


@lru_cache(maxsize=1)
def _validator():
    try:
        import jsonschema
    except ImportError as exc:  # pragma: no cover - depends on environment
        raise SchemaUnavailable(
            "jsonschema is not installed; install it with 'pip install -r requirements.txt'"
        ) from exc

    if not BOM_SCHEMA.exists():
        raise SchemaUnavailable(f"missing vendored schema: {BOM_SCHEMA}")

    schema = json.loads(BOM_SCHEMA.read_text(encoding="utf-8"))

    store = {}
    for path in SCHEMA_DIR.glob("*.json"):
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        identifier = document.get("$id")
        if identifier:
            store[identifier] = document
        store[path.name] = document

    # jsonschema 4.18+ prefers a referencing Registry; RefResolver still works
    # and is used when the newer API is unavailable.
    try:
        from referencing import Registry, Resource

        registry = Registry()
        for identifier, document in store.items():
            registry = registry.with_resource(
                identifier, Resource.from_contents(document, default_specification=_spec())
            )
        return jsonschema.Draft7Validator(schema, registry=registry)
    except ImportError:  # pragma: no cover - older jsonschema
        resolver = jsonschema.RefResolver(base_uri=schema.get("$id", ""), referrer=schema, store=store)
        return jsonschema.Draft7Validator(schema, resolver=resolver)


def _spec():
    from referencing.jsonschema import DRAFT7

    return DRAFT7


def validate(document: dict) -> tuple[bool, list[str]]:
    """Validate a parsed BOM. Returns ``(is_valid, error_messages)``."""
    validator = _validator()
    errors = []
    for error in validator.iter_errors(document):
        path = "/".join(str(part) for part in error.absolute_path) or "<root>"
        errors.append(f"{path}: {error.message}")
        if len(errors) >= MAX_REPORTED_ERRORS:
            errors.append("... further errors suppressed")
            break
    return (not errors), errors


def available() -> bool:
    """Report whether schema validation can run."""
    try:
        _validator()
    except SchemaUnavailable:
        return False
    return True
