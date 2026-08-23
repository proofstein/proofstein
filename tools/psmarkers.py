# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ottenheimer GmbH
"""Shared parsing for Proofstein corpus annotations.

Corpus templates under ``corpus-src/`` carry *trailing* annotations that name the
cryptographic asset planted on that line::

    block, err := aes.NewCipher(key) //@PS aes-gcm-seal|AES-256-GCM|1|algorithm

Annotations are always trailing, never on their own line, so that stripping them
cannot shift any line number.  The corpus that tools actually see is emitted by
``tools/build-corpus.py`` with every annotation removed, which keeps hints out of
reach of tools that read comments (an LLM-based generator would otherwise be
handed the answer key).

Field order is ``id|algorithm|layer|asset_type[|note]``.

A line may instead carry ``//@PS +<id>``, which registers an *additional*
accepted evidence location for an asset declared elsewhere. Tools legitimately
differ over which line they attribute an asset to -- the aliased import or the
aliased call, the wrapper body or the wrapper's caller -- and scoring a tool
down for a defensible choice would measure convention rather than detection.
Every accepted location is applied identically to every tool.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

MARKER = "@PS"

# CycloneDX 1.6 cryptoProperties.assetType enumeration.
ASSET_TYPES = frozenset({"algorithm", "certificate", "protocol", "related-crypto-material"})

LAYERS: dict[int, str] = {
    1: "direct crypto API call site",
    2: "aliased import",
    3: "wrapper function",
    4: "config-driven selection",
    5: "declared dependency, not called",
    6: "key, certificate or keystore file",
}

# Comment syntaxes that may introduce a trailing annotation. Each entry maps a
# file suffix to the (open, close) delimiters; close is "" for line comments.
_LINE = ("//", "")
_HASH = ("#", "")
_BLOCK = ("/*", "*/")
_XML = ("<!--", "-->")

# A suffix may permit more than one comment syntax; each is tried in order.
_COMMENT_STYLES: list[tuple[tuple[str, ...], tuple[tuple[str, str], ...]]] = [
    ((".c", ".h", ".java", ".rs", ".go", ".js", ".ts", ".mjs", ".cjs"), (_LINE, _BLOCK)),
    ((".mod", ".json"), (_LINE,)),
    (
        (
            ".py",
            ".yaml",
            ".yml",
            ".conf",
            ".toml",
            ".sh",
            ".properties",
            ".cfg",
            ".txt",
            ".in",
            ".options",
            ".env",
            ".ini",
        ),
        (_HASH,),
    ),
    ((".xml", ".pom", ".html"), (_XML,)),
]

# Files that carry no extension but still need a comment style.
_BY_NAME: dict[str, tuple[tuple[str, str], ...]] = {
    "dockerfile": (_HASH,),
    "makefile": (_HASH,),
    "gemfile": (_HASH,),
}


def comment_styles(filename: str) -> tuple[tuple[str, str], ...]:
    """Return the (open, close) comment delimiters valid for a filename."""
    lowered = filename.lower()
    if lowered in _BY_NAME:
        return _BY_NAME[lowered]
    for suffixes, styles in _COMMENT_STYLES:
        if lowered.endswith(suffixes):
            return styles
    return ()


@dataclass(frozen=True)
class Annotation:
    """One planted cryptographic asset."""

    id: str
    algorithm: str
    layer: int
    asset_type: str
    note: str = ""
    file: str = ""
    line: int = 0
    accept_locations: list = field(default_factory=list)

    def to_ground_truth(self) -> dict:
        entry = {
            "id": self.id,
            "file": self.file,
            "line": self.line,
            "algorithm": self.algorithm,
            "layer": self.layer,
            "layer_name": LAYERS[self.layer],
            "cyclonedx_asset_type": self.asset_type,
        }
        if self.accept_locations:
            entry["accept_locations"] = [
                {"file": f, "line": ln} for f, ln in sorted(self.accept_locations)
            ]
        if self.note:
            entry["note"] = self.note
        return entry


@dataclass(frozen=True)
class AliasLocation:
    """An additional accepted evidence location for an asset declared elsewhere."""

    target_id: str
    file: str = ""
    line: int = 0


class AnnotationError(ValueError):
    """Raised when a template annotation is malformed."""


def _marker_regex(open_delim: str, close_delim: str) -> re.Pattern[str]:
    body = r"\s*" + re.escape(MARKER) + r"\s+(?P<body>.*?)\s*"
    if close_delim:
        return re.compile(re.escape(open_delim) + body + re.escape(close_delim) + r"\s*$")
    return re.compile(re.escape(open_delim) + body + r"$")


def parse_line(text: str, filename: str) -> tuple[str, Annotation | None]:
    """Split one template line into (stripped_line, annotation_or_None).

    ``stripped_line`` is the line as it will appear in the emitted corpus, with
    the annotation and any whitespace that preceded it removed.
    """
    styles = comment_styles(filename)
    if not styles or MARKER not in text:
        return text, None

    match = None
    for style in styles:
        match = _marker_regex(*style).search(text)
        if match is not None:
            break
    if match is None:
        raise AnnotationError(f"{filename}: line contains {MARKER} but is not a well-formed trailing annotation: {text!r}")

    stripped = text[: match.start()].rstrip()
    body = match.group("body").strip()

    if body.startswith("+"):
        target = body[1:].strip()
        if not target:
            raise AnnotationError(f"{filename}: '+' alias annotation needs a target id")
        if "|" in target:
            raise AnnotationError(f"{filename}: '+' alias annotation takes only an id, got {body!r}")
        return stripped, AliasLocation(target_id=target)

    fields = [part.strip() for part in body.split("|")]
    if len(fields) not in (4, 5):
        raise AnnotationError(f"{filename}: annotation needs 4 or 5 fields, got {len(fields)}: {match.group('body')!r}")

    ident, algorithm, raw_layer, asset_type = fields[:4]
    note = fields[4] if len(fields) == 5 else ""

    if not ident:
        raise AnnotationError(f"{filename}: annotation id must not be empty")
    try:
        layer = int(raw_layer)
    except ValueError as exc:
        raise AnnotationError(f"{filename}: layer must be an integer, got {raw_layer!r}") from exc
    if layer not in LAYERS:
        raise AnnotationError(f"{filename}: layer must be one of {sorted(LAYERS)}, got {layer}")
    if asset_type not in ASSET_TYPES:
        raise AnnotationError(f"{filename}: asset_type must be one of {sorted(ASSET_TYPES)}, got {asset_type!r}")
    if not algorithm:
        raise AnnotationError(f"{filename}: algorithm must not be empty (id={ident})")

    return stripped, Annotation(id=ident, algorithm=algorithm, layer=layer, asset_type=asset_type, note=note)


def parse_text(
    text: str, filename: str, relpath: str
) -> tuple[str, list[Annotation], list[AliasLocation]]:
    """Strip annotations from a whole file.

    Returns ``(clean_text, annotations, alias_locations)``.
    """
    lines = text.split("\n")
    out: list[str] = []
    found: list[Annotation] = []
    aliases: list[AliasLocation] = []

    for number, line in enumerate(lines, start=1):
        clean, parsed = parse_line(line, filename)
        out.append(clean)
        if parsed is None:
            continue
        if isinstance(parsed, AliasLocation):
            aliases.append(AliasLocation(target_id=parsed.target_id, file=relpath, line=number))
        else:
            found.append(
                Annotation(
                    id=parsed.id,
                    algorithm=parsed.algorithm,
                    layer=parsed.layer,
                    asset_type=parsed.asset_type,
                    note=parsed.note,
                    file=relpath,
                    line=number,
                )
            )
    return "\n".join(out), found, aliases
