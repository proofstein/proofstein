# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ottenheimer GmbH
"""Parsing CycloneDX CBOMs into a tool-neutral shape.

Every rule in this module is applied to every tool identically. There is no
branch anywhere on which tool produced a document, and adding one would defeat
the point of the benchmark -- see ``tests/test_no_tool_specific_logic.py``,
which fails the build if a vendor name appears in the scoring path.

Two observations from real generator output drive the design:

* ``cdxgen`` records the source file in ``properties[]`` under the name
  ``SrcFile`` and emits no line number at all.
* ``cbomkit`` uses the spec-blessed ``evidence.occurrences[]`` with both
  ``location`` and ``line``, but frequently leaves ``name`` as an opaque
  ``key@<uuid>`` and identifies the algorithm only by ``cryptoProperties.oid``.

Reading only ``evidence.occurrences`` would score the first tool at zero for a
reason that has nothing to do with whether it found the asset, and reading only
``name`` would score the second at zero for the same kind of reason. So the
parser accepts a fixed, documented set of shapes for both location and
identity, and applies the whole set to everyone.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Location extraction
# ---------------------------------------------------------------------------

# Property names that carry a source file path. Case-insensitive.
LOCATION_PROPERTY_NAMES = frozenset(
    {
        "srcfile",
        "sourcefile",
        "source_file",
        "location",
        "filepath",
        "file_path",
        "file",
        "path",
    }
)

# Property names that carry a line number. Case-insensitive.
LINE_PROPERTY_NAMES = frozenset({"line", "linenumber", "line_number", "startline", "start_line"})

# ---------------------------------------------------------------------------
# Algorithm identity
# ---------------------------------------------------------------------------

# OID -> canonical algorithm name. A generator that identifies an algorithm only
# by OID (cbomkit does this routinely) is otherwise unidentifiable, so this
# table is part of making the comparison fair rather than a courtesy to one tool.
OID_ALGORITHMS: dict[str, str] = {
    "1.2.840.113549.1.1.1": "RSA",
    "1.2.840.113549.1.1.5": "SHA1withRSA",
    "1.2.840.113549.1.1.8": "MGF1",
    "1.2.840.113549.1.1.10": "RSASSA-PSS",
    "1.2.840.113549.1.1.11": "SHA256withRSA",
    "1.2.840.113549.3.7": "3DES",
    "1.2.840.10045.2.1": "EC",
    "1.2.840.10045.3.1.7": "ECDSA-P256",
    "1.2.840.10045.4.3.2": "SHA256withECDSA",
    "1.3.101.110": "X25519",
    "1.3.101.112": "Ed25519",
    "1.3.132.0.34": "ECDSA-P384",
    "2.16.840.1.101.3.4.1.2": "AES-128-CBC",
    "2.16.840.1.101.3.4.1.6": "AES-128-GCM",
    "2.16.840.1.101.3.4.1.22": "AES-192-CBC",
    "2.16.840.1.101.3.4.1.26": "AES-192-GCM",
    "2.16.840.1.101.3.4.1.42": "AES-256-CBC",
    "2.16.840.1.101.3.4.1.46": "AES-256-GCM",
    "2.16.840.1.101.3.4.2.1": "SHA-256",
    "2.16.840.1.101.3.4.2.2": "SHA-384",
    "2.16.840.1.101.3.4.2.3": "SHA-512",
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
    "2.16.840.1.101.3.4.4.1": "ML-KEM-512",
    "2.16.840.1.101.3.4.4.2": "ML-KEM-768",
    "2.16.840.1.101.3.4.4.3": "ML-KEM-1024",
}

CRYPTO_COMPONENT_TYPE = "cryptographic-asset"

#: Component types that describe a dependency rather than a cryptographic
#: construct. CycloneDX models a library a project depends on as a ``library``
#: (or ``framework``) component with no ``cryptoProperties``, which is the
#: correct answer for a layer-5 dependency asset and was previously discarded
#: before matching. They are ingested as dependency-kind: eligible to satisfy a
#: layer-5 plant, and excluded from the crypto-claim accounting in both
#: directions, so an SBOM listing eighty packages is neither credited with
#: eighty crypto claims nor charged for them.
DEPENDENCY_COMPONENT_TYPES = frozenset({"library", "framework"})


@dataclass
class Occurrence:
    """One reported evidence location."""

    file: str | None
    line: int | None
    #: Which documented shape this came from; recorded for evidence-quality
    #: reporting, never for scoring.
    source: str = "evidence.occurrences"


@dataclass
class ReportedAsset:
    """One cryptographic asset as a generator reported it."""

    names: list[str] = field(default_factory=list)
    asset_type: str | None = None
    oid: str | None = None
    occurrences: list[Occurrence] = field(default_factory=list)
    index: int = -1

    #: True for a component describing a dependency rather than a cryptographic
    #: construct. Such an asset may satisfy a layer-5 plant and takes no part in
    #: crypto-claim precision. A component carrying ``cryptoProperties`` is never
    #: dependency-kind, whatever its declared type, so labelling a library as a
    #: cryptographic asset cannot buy it out of this classification.
    is_dependency: bool = False

    @property
    def has_location(self) -> bool:
        return any(o.file for o in self.occurrences)

    @property
    def has_line(self) -> bool:
        return any(o.file and o.line is not None for o in self.occurrences)

    @property
    def uses_spec_evidence(self) -> bool:
        return any(o.source == "evidence.occurrences" for o in self.occurrences)


def unwrap_bom(document: Any) -> dict:
    """Return the BOM object from the shapes generators and runners produce.

    BF-CBOM's bundle writer strips a ``{"bom": {...}}`` wrapper before writing
    (``coordinator/utils.py:545``), but a raw CBOM directory may still carry it,
    and cbomkit's own output has been seen wrapped in a single-element list.
    """
    seen = 0
    while seen < 8:
        seen += 1
        if isinstance(document, list):
            if not document:
                return {}
            document = document[0]
            continue
        if isinstance(document, dict) and isinstance(document.get("bom"), dict):
            document = document["bom"]
            continue
        break
    return document if isinstance(document, dict) else {}


def iter_components(bom: dict):
    """Yield every component in a BOM, including nested sub-components."""
    stack = list(bom.get("components") or [])
    while stack:
        component = stack.pop()
        if not isinstance(component, dict):
            continue
        yield component
        nested = component.get("components")
        if isinstance(nested, list):
            stack.extend(nested)


def _coerce_line(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value > 0 else None
    if isinstance(value, str):
        try:
            parsed = int(value.strip())
        except ValueError:
            return None
        return parsed if parsed > 0 else None
    return None


def _properties_occurrence(component: dict) -> Occurrence | None:
    """Build an occurrence from ``properties[]`` name/value pairs."""
    properties = component.get("properties")
    if not isinstance(properties, list):
        return None

    file_value: str | None = None
    line_value: int | None = None

    for prop in properties:
        if not isinstance(prop, dict):
            continue
        name = str(prop.get("name", "")).strip().lower()
        # Generators namespace these, e.g. "cdx:cbom:SrcFile".
        leaf = name.rsplit(":", 1)[-1]
        value = prop.get("value")
        if leaf in LOCATION_PROPERTY_NAMES and isinstance(value, str) and value.strip():
            if file_value is None:
                file_value = value.strip()
        elif leaf in LINE_PROPERTY_NAMES and line_value is None:
            line_value = _coerce_line(value)

    if file_value is None and line_value is None:
        return None
    return Occurrence(file=file_value, line=line_value, source="properties")


def extract_occurrences(component: dict) -> list[Occurrence]:
    """Return every reported location for a component, from all known shapes."""
    found: list[Occurrence] = []

    evidence = component.get("evidence")
    if isinstance(evidence, dict):
        occurrences = evidence.get("occurrences")
        if isinstance(occurrences, list):
            for entry in occurrences:
                if not isinstance(entry, dict):
                    continue
                location = entry.get("location")
                file_value = location.strip() if isinstance(location, str) and location.strip() else None
                line_value = _coerce_line(entry.get("line"))
                if file_value or line_value is not None:
                    found.append(
                        Occurrence(file=file_value, line=line_value, source="evidence.occurrences")
                    )

    from_properties = _properties_occurrence(component)
    if from_properties is not None:
        found.append(from_properties)

    return found


def extract_names(component: dict) -> list[str]:
    """Return every string that could identify the algorithm.

    Includes the component name, the OID's canonical name, the parameter set
    identifier, and the related-crypto-material type. Generators disagree about
    where the algorithm name belongs, so all documented places are read.
    """
    names: list[str] = []

    name = component.get("name")
    if isinstance(name, str) and name.strip():
        names.append(name.strip())

    crypto = component.get("cryptoProperties")
    if isinstance(crypto, dict):
        oid = crypto.get("oid")
        if isinstance(oid, str):
            mapped = OID_ALGORITHMS.get(oid.strip())
            if mapped:
                names.append(mapped)

        algorithm = crypto.get("algorithmProperties")
        if isinstance(algorithm, dict):
            for key in ("parameterSetIdentifier", "primitive", "curve"):
                value = algorithm.get(key)
                if isinstance(value, str) and value.strip():
                    names.append(value.strip())

        material = crypto.get("relatedCryptoMaterialProperties")
        if isinstance(material, dict):
            value = material.get("type")
            if isinstance(value, str) and value.strip():
                names.append(value.strip())

        protocol = crypto.get("protocolProperties")
        if isinstance(protocol, dict):
            for key in ("type", "version"):
                value = protocol.get(key)
                if isinstance(value, str) and value.strip():
                    names.append(value.strip())

    version = component.get("version")
    if isinstance(version, str) and version.strip() and len(version.strip()) < 24:
        names.append(version.strip())

    return names


def is_crypto_component(component: dict) -> bool:
    """Report whether a component is a cryptographic asset.

    ``type == "cryptographic-asset"`` is the spec answer; the presence of
    ``cryptoProperties`` is accepted too, because a generator that populates
    the crypto block but mislabels the component type has still found the asset.
    """
    if component.get("type") == CRYPTO_COMPONENT_TYPE:
        return True
    return isinstance(component.get("cryptoProperties"), dict)


def is_dependency_component(component: dict) -> bool:
    """Report whether a component describes a dependency.

    A ``library`` or ``framework`` component with no ``cryptoProperties``. The
    ``cryptoProperties`` exclusion matters: a generator that dresses a library up
    as a cryptographic asset is treated as having made a crypto claim, and is
    scored on it, rather than being quietly reclassified into the exempt bucket.
    """
    if isinstance(component.get("cryptoProperties"), dict):
        return False
    return component.get("type") in DEPENDENCY_COMPONENT_TYPES


def parse_cbom(raw: str | bytes | dict) -> tuple[dict, list[ReportedAsset], str | None]:
    """Parse a CBOM document.

    Returns ``(bom, assets, parse_error)``. A parse error yields an empty BOM
    and no assets rather than raising, so that one broken file does not abort a
    whole scoring run.
    """
    if isinstance(raw, (str, bytes)):
        try:
            document = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            return {}, [], f"invalid JSON: {exc}"
    else:
        document = raw

    bom = unwrap_bom(document)
    if not bom:
        return {}, [], "document contains no BOM object"

    assets: list[ReportedAsset] = []
    for index, component in enumerate(iter_components(bom)):
        dependency = is_dependency_component(component)
        if not dependency and not is_crypto_component(component):
            continue
        crypto = component.get("cryptoProperties")
        asset_type = None
        oid = None
        if isinstance(crypto, dict):
            raw_type = crypto.get("assetType")
            if isinstance(raw_type, str):
                asset_type = raw_type.strip()
            raw_oid = crypto.get("oid")
            if isinstance(raw_oid, str):
                oid = raw_oid.strip()
        assets.append(
            ReportedAsset(
                names=extract_names(component),
                asset_type=asset_type,
                oid=oid,
                occurrences=extract_occurrences(component),
                index=index,
                is_dependency=dependency,
            )
        )

    return bom, assets, None
