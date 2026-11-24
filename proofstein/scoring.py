# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ottenheimer GmbH
"""Scoring a CBOM against ground truth."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import NamedTuple

from .cbom import ReportedAsset
from .matching import (
    PathResolver,
    algorithms_compatible,
    families,
    hybrid_halves,
    location_matches,
    normalize_tokens,
)


class Unplanted(NamedTuple):
    """A cryptographic construct that exists in the corpus without being planted.

    Reporting one is excluded from the phantom-algorithm check. ``project`` and
    ``file`` limit the allowance to where the construct is; both ``None`` means
    corpus-wide.
    """

    algorithm: str
    project: str | None = None
    file: str | None = None

    def applies_to(self, project: str, resolved_files: set[str], has_location: bool) -> bool:
        if self.project is not None and self.project != project:
            return False
        if self.file is None:
            return True
        if self.file in resolved_files:
            return True
        # A report with no location keeps the allowance.
        return not has_location


def _as_unplanted(entry: str | Unplanted) -> Unplanted:
    return entry if isinstance(entry, Unplanted) else Unplanted(entry)


@dataclass
class AssetVerdict:
    """How one planted asset fared against one CBOM."""

    id: str
    file: str
    line: int
    algorithm: str
    layer: int
    asset_type: str

    #: File, algorithm and layer agree. The headline metric.
    detected: bool = False
    #: File agrees and the line is within the tolerance, whatever the algorithm
    #: was called. Reported, not scored.
    located: bool = False
    #: File agrees, whatever the algorithm was called. Reported, not scored.
    file_only: bool = False
    #: The algorithm name appears somewhere in the document. Not a detection.
    name_only: bool = False

    matched_component: int | None = None


@dataclass
class EvidenceQuality:
    """How well a generator backs its claims."""

    crypto_components: int = 0
    with_location: int = 0
    with_line: int = 0
    using_spec_evidence: int = 0
    using_properties_only: int = 0
    total_occurrences: int = 0
    #: Distinct (component, file, line) claims: the denominator of claim
    #: precision.
    distinct_claims: int = 0
    resolvable_locations: int = 0
    unresolvable_locations: int = 0

    def as_dict(self) -> dict:
        def ratio(part: int) -> float:
            return round(part / self.crypto_components, 4) if self.crypto_components else 0.0

        return {
            "crypto_components": self.crypto_components,
            "total_occurrences": self.total_occurrences,
            "distinct_claims": self.distinct_claims,
            "with_location": self.with_location,
            "with_location_pct": ratio(self.with_location),
            "with_line": self.with_line,
            "with_line_pct": ratio(self.with_line),
            "using_spec_evidence": self.using_spec_evidence,
            "using_properties_only": self.using_properties_only,
            "resolvable_locations": self.resolvable_locations,
            "unresolvable_locations": self.unresolvable_locations,
            "occurrences_per_component": (
                round(self.total_occurrences / self.crypto_components, 3)
                if self.crypto_components
                else 0.0
            ),
        }


@dataclass
class ScoreResult:
    """The full verdict for one (project, tool) pair."""

    project: str
    language: str
    tool: str
    source: str

    verdicts: list[AssetVerdict] = field(default_factory=list)
    evidence: EvidenceQuality = field(default_factory=EvidenceQuality)

    schema_valid: bool | None = None
    schema_errors: list[str] = field(default_factory=list)
    parse_error: str | None = None

    #: Reported at a location that is not a file in the project.
    phantom_location: int = 0
    #: Algorithm family present nowhere in the project and not declared as an
    #: unplanted-but-real construct.
    phantom_algorithm: int = 0
    #: Reported at a real location with no planted asset there. Counted, not
    #: charged.
    unmatched_reports: int = 0

    @property
    def false_positives(self) -> int:
        return self.phantom_location + self.phantom_algorithm

    def by_layer(self) -> dict[int, tuple[int, int]]:
        """Return ``{layer: (detected, total)}``."""
        counts: dict[int, list[int]] = {}
        for verdict in self.verdicts:
            entry = counts.setdefault(verdict.layer, [0, 0])
            entry[1] += 1
            if verdict.detected:
                entry[0] += 1
        return {layer: (hit, total) for layer, (hit, total) in sorted(counts.items())}

    @property
    def detected(self) -> int:
        return sum(1 for v in self.verdicts if v.detected)

    @property
    def total(self) -> int:
        return len(self.verdicts)

    @property
    def detection_rate(self) -> float:
        return round(self.detected / self.total, 4) if self.total else 0.0

    #: Reported crypto components that were credited with a planted asset.
    matched_components: int = 0
    #: Distinct (component, file) pairs that were credited.
    credited_claims: int = 0

    @property
    def precision(self) -> float:
        """Credited components over reported components."""
        reported = self.evidence.crypto_components
        return round(self.matched_components / reported, 4) if reported else 0.0

    @property
    def claim_precision(self) -> float:
        """Credited (component, file) pairs over distinct (component, file, line) claims."""
        claims = self.evidence.distinct_claims
        return round(self.credited_claims / claims, 4) if claims else 0.0


def score_cbom(
    *,
    project: str,
    language: str,
    tool: str,
    source: str,
    ground_truth: list[dict],
    reported: list[ReportedAsset],
    project_files: frozenset[str],
    known_unplanted: frozenset[str] | tuple[str | Unplanted, ...],
    line_tolerance: int,
) -> ScoreResult:
    """Score one CBOM against one project's ground truth."""
    result = ScoreResult(project=project, language=language, tool=tool, source=source)
    resolver = PathResolver(project_files=project_files)

    # Resolve every reported occurrence once.
    resolved: list[tuple[ReportedAsset, list[tuple[str | None, int | None]]]] = []
    for asset in reported:
        locations: list[tuple[str | None, int | None]] = []
        for occurrence in asset.occurrences:
            resolved_file = resolver.resolve(occurrence.file) if occurrence.file else None
            locations.append((resolved_file, occurrence.line))
        resolved.append((asset, locations))

    _measure_evidence(result, resolved)

    # The halves of a planted hybrid count as planted algorithms of the project.
    planted_algorithms = {entry["algorithm"] for entry in ground_truth}
    for algorithm in list(planted_algorithms):
        planted_algorithms.update(hybrid_halves(algorithm) or ())
    matched_components: set[int] = set()
    credited_claims: set[tuple[int, str, int]] = set()

    for entry in ground_truth:
        verdict = AssetVerdict(
            id=entry["id"],
            file=entry["file"],
            line=int(entry["line"]),
            algorithm=entry["algorithm"],
            layer=int(entry["layer"]),
            asset_type=entry["cyclonedx_asset_type"],
        )

        # Locations that count as this asset: the plant plus any declared
        # alternative. Applied identically to every tool.
        accepted = [(entry["file"], int(entry["line"]))]
        for alternative in entry.get("accept_locations", []) or []:
            accepted.append((alternative["file"], int(alternative["line"])))

        for asset, locations in resolved:
            # A dependency component may satisfy a layer-5 plant and nothing else.
            if asset.is_dependency and verdict.layer != 5:
                continue

            algorithm_ok = any(algorithms_compatible(verdict.algorithm, name) for name in asset.names)

            if algorithm_ok:
                verdict.name_only = True

            for resolved_file, line in locations:
                if resolved_file is None:
                    continue
                for accepted_file, accepted_line in accepted:
                    if resolved_file != accepted_file:
                        continue
                    verdict.file_only = True

                    # Detection is file + algorithm + layer; the line is not
                    # scored. The layer condition is the is_dependency gate above.
                    if algorithm_ok and not asset.is_dependency:
                        # Every (component, file) pair that lands on a plant is
                        # credited, including a plant already found by another
                        # component. Dependency components are neither credited
                        # nor counted in the claim denominator.
                        credited_claims.add((asset.index, resolved_file))
                    if algorithm_ok and not verdict.detected:
                        verdict.detected = True
                        verdict.matched_component = asset.index
                        if not asset.is_dependency:
                            matched_components.add(asset.index)

                    # Reported, not scored: whether the line is within the tolerance.
                    if location_matches(
                        accepted_file,
                        accepted_line,
                        resolved_file,
                        line,
                        line_tolerance=line_tolerance,
                    ):
                        verdict.located = True

        halves = hybrid_halves(verdict.algorithm)
        if halves and not verdict.detected:
            _credit_hybrid_halves(verdict, halves, accepted, resolved, credited_claims, matched_components)

        result.verdicts.append(verdict)

    result.matched_components = len(matched_components)
    result.credited_claims = len(credited_claims)

    _count_false_positives(
        result,
        resolved,
        matched_components=matched_components,
        planted_algorithms=planted_algorithms,
        known_unplanted=known_unplanted,
        ground_truth=ground_truth,
        line_tolerance=line_tolerance,
    )
    return result


def _credit_hybrid_halves(
    verdict: AssetVerdict,
    halves: tuple[str, str],
    accepted: list[tuple[str, int]],
    resolved: list[tuple[ReportedAsset, list[tuple[str | None, int | None]]]],
    credited_claims: set[tuple[int, str]],
    matched_components: set[int],
) -> None:
    """Credit a hybrid plant whose two halves are named in its file.

    Both halves must be named in the file, as one component or two, and each
    half must agree on its own parameters. One half alone does not detect it.
    """
    for accepted_file, _ in accepted:
        found: list[list[int]] = [[], []]
        for asset, locations in resolved:
            if asset.is_dependency:
                continue
            if not any(resolved_file == accepted_file for resolved_file, _ in locations):
                continue
            for side, half in enumerate(halves):
                if any(algorithms_compatible(half, name) for name in asset.names):
                    found[side].append(asset.index)
        if found[0] and found[1]:
            verdict.detected = True
            verdict.name_only = True
            verdict.matched_component = found[0][0]
            for index in found[0] + found[1]:
                credited_claims.add((index, accepted_file))
                matched_components.add(index)
            return


def _measure_evidence(
    result: ScoreResult,
    resolved: list[tuple[ReportedAsset, list[tuple[str | None, int | None]]]],
) -> None:
    quality = result.evidence
    # Dependency components are not counted as crypto claims.
    crypto_only = [(a, loc) for a, loc in resolved if not a.is_dependency]
    quality.crypto_components = len(crypto_only)
    seen_claims: set[tuple[int, str | None, int | None]] = set()
    for asset, locations in crypto_only:
        quality.total_occurrences += len(asset.occurrences)
        for resolved_file, line in locations:
            seen_claims.add((asset.index, resolved_file, line))
        if asset.has_location:
            quality.with_location += 1
        if asset.has_line:
            quality.with_line += 1
        if asset.uses_spec_evidence:
            quality.using_spec_evidence += 1
        elif asset.occurrences:
            quality.using_properties_only += 1
        for occurrence, (resolved_file, _) in zip(asset.occurrences, locations, strict=False):
            if not occurrence.file:
                continue
            if resolved_file is None:
                quality.unresolvable_locations += 1
            else:
                quality.resolvable_locations += 1
    quality.distinct_claims = len(seen_claims)
    result.evidence = quality


def _count_false_positives(
    result: ScoreResult,
    resolved: list[tuple[ReportedAsset, list[tuple[str | None, int | None]]]],
    *,
    matched_components: set[int],
    planted_algorithms: set[str],
    known_unplanted: frozenset[str] | tuple[str | Unplanted, ...],
    ground_truth: list[dict],
    line_tolerance: int,
) -> None:
    """Classify reported assets that matched no planted asset.

    Two categories are charged as false positives:

    * **phantom location** -- evidence points at a file that is not in the
      project at all.
    * **phantom algorithm** -- the algorithm family appears nowhere in the
      project's ground truth and is not covered by an :class:`Unplanted`
      allowance that reaches this project and file.

    Everything else is reported as ``unmatched_reports`` and left uncharged.
    """
    allowances = [_as_unplanted(entry) for entry in known_unplanted]
    planted_locations = set()
    for entry in ground_truth:
        planted_locations.add((entry["file"], int(entry["line"])))
        for alternative in entry.get("accept_locations", []) or []:
            planted_locations.add((alternative["file"], int(alternative["line"])))

    planted_files = {entry["file"] for entry in ground_truth}
    for entry in ground_truth:
        for alternative in entry.get("accept_locations", []) or []:
            planted_files.add(alternative["file"])

    for asset, locations in resolved:
        if asset.index in matched_components:
            continue

        # A dependency component is never charged.
        if asset.is_dependency:
            continue

        # Only a component whose name carries an algorithm family token can be
        # charged a phantom algorithm.
        claims_a_family = any(families(normalize_tokens(name)) for name in asset.names)

        if claims_a_family:
            resolved_files = {
                resolved_file for resolved_file, _ in locations if resolved_file is not None
            }
            has_location = any(occurrence.file for occurrence in asset.occurrences)
            credible = any(
                algorithms_compatible(planted, name)
                for planted in planted_algorithms
                for name in asset.names
            ) or any(
                unplanted.applies_to(result.project, resolved_files, has_location)
                and algorithms_compatible(unplanted.algorithm, name)
                for unplanted in allowances
                for name in asset.names
            )
            # Checked before location: a family that exists nowhere in the
            # project is charged wherever it is reported.
            if not credible:
                result.phantom_algorithm += 1
                continue

        # A component in a file that holds a planted asset is not a phantom
        # location.
        on_a_planted_file = any(
            resolved_file in planted_files for resolved_file, _ in locations if resolved_file
        )
        has_any_location = any(occurrence.file for occurrence in asset.occurrences)
        every_location_unresolvable = has_any_location and all(
            resolved_file is None for resolved_file, _ in locations
        )
        if every_location_unresolvable and not on_a_planted_file:
            result.phantom_location += 1
            continue

        # A report in a file holding a planted asset is not counted as unmatched.
        near_a_plant = any(
            resolved_file is not None
            and any(
                resolved_file == planted_file
                for planted_file, _planted_line in planted_locations
            )
            for resolved_file, line in locations
        )
        if not near_a_plant:
            result.unmatched_reports += 1
