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
    location_matches,
    normalize_tokens,
)


class Unplanted(NamedTuple):
    """A cryptographic construct that exists in the corpus without being planted.

    Reporting one is not an error, so it is excluded from the phantom-algorithm
    check. The exclusion is only sound where the construct actually is, though:
    ``DES`` appears in the corpus exactly once, in one project's JVM options,
    named as a *disabled* algorithm. Allowed corpus-wide it forgives the same
    name reported anywhere, which is what let five fabricated DES findings
    through the 2026-07-28 run's precision column uncharged.

    ``project`` and ``file`` narrow the allowance to where the justification
    holds. Both ``None`` means corpus-wide, for constructs such as CSPRNGs that
    every project really does contain.
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
        # A report with no resolvable location has not claimed to have read the
        # wrong file; it has failed to say which file, which the evidence table
        # already reports. Charging it here would price the same shortcoming
        # twice, so a location-less report keeps the allowance.
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

    #: The headline metric: file and line agree AND the algorithm is credible.
    detected: bool = False
    #: File and line agree, whatever the algorithm was called. Diagnostic only.
    located: bool = False
    #: File agrees, line not required. Diagnostic only -- reported separately so
    #: a generator that omits line numbers is visibly distinguished from one
    #: that missed the asset entirely.
    file_only: bool = False
    #: The algorithm name appears somewhere in the document. NOT a detection:
    #: reported only to show what an algorithm-name-only metric would claim.
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
    #: Occurrences deduplicated per component. Repeating one site three times is
    #: redundancy, not three guesses, so this -- not the raw count -- is the
    #: denominator for claim precision.
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
    #: Reported at a real location with no planted asset there. Counted and
    #: shown, never charged against the tool -- see METHODOLOGY.md.
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
    #: Distinct evidence claims -- (component, file, line) -- that were credited.
    credited_claims: int = 0

    @property
    def precision(self) -> float:
        """Credited components over reported components."""
        reported = self.evidence.crypto_components
        return round(self.matched_components / reported, 4) if reported else 0.0

    @property
    def claim_precision(self) -> float:
        """Credited evidence claims over all evidence claims made.

        This, not :attr:`precision`, is the check on guessing.

        Component-level precision can be defeated by putting the guesses inside
        a small number of components: ten components, each carrying an
        occurrence for every line of every file, reach full recall at 80%
        component precision and zero false positives, because each of those ten
        components does match something. Counting the individual claims instead
        prices every guess -- that same document credits 19 claims out of 7670.

        An honest generator makes roughly one claim per site it found, so its
        two precision figures stay close together. A large gap between them is
        the signature of the attack.
        """
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

    planted_algorithms = {entry["algorithm"] for entry in ground_truth}
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
            # A dependency component answers a dependency question. It may
            # satisfy a layer-5 plant and nothing else: a library named
            # "openssl" is not a detection of an AES call site.
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

                    # Detection is file + algorithm + layer. The line is
                    # recorded and reported, never scored.
                    #
                    # An import and the call site it enables assert the same
                    # inventory fact: this algorithm is used in this file. A
                    # generator reporting the import has answered the question
                    # the inventory asks. See docs/pending-review.md entry 2,
                    # which this rule resolves.
                    #
                    # The layer half of the rule is the is_dependency gate
                    # above: a dependency component may satisfy a layer-5 plant
                    # and nothing else.
                    if algorithm_ok and not asset.is_dependency:
                        # Every claim that lands on a plant is credited, even
                        # when the plant was already found by another claim --
                        # otherwise duplicated evidence would look like wasted
                        # guessing rather than repetition.
                        #
                        # Keyed on (component, file), not (component, file,
                        # line), because the file is the unit of correctness
                        # once the line is no longer scored. The denominator in
                        # claim_precision stays line-granular, so a generator
                        # naming one algorithm at forty lines of one file is
                        # credited with the one claim it got right and charged
                        # for the thirty-nine guesses. That is what keeps claim
                        # precision able to price a shotgun after this change.
                        #
                        # Dependency components are excluded in both directions:
                        # they are not counted in the claim denominator, so
                        # crediting them here would inflate precision above 100%.
                        credited_claims.add((asset.index, resolved_file))
                    if algorithm_ok and not verdict.detected:
                        verdict.detected = True
                        verdict.matched_component = asset.index
                        if not asset.is_dependency:
                            matched_components.add(asset.index)

                    # Reported, not scored: how close the claim landed.
                    if location_matches(
                        accepted_file,
                        accepted_line,
                        resolved_file,
                        line,
                        line_tolerance=line_tolerance,
                    ):
                        verdict.located = True

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


def _measure_evidence(
    result: ScoreResult,
    resolved: list[tuple[ReportedAsset, list[tuple[str | None, int | None]]]],
) -> None:
    quality = result.evidence
    # Dependency components are not crypto claims. Counting them here would put
    # an SBOM's whole package list into the precision denominator, which is the
    # punishment half of the exclusion.
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

    The corpus ground truth is complete for *planted* assets, not exhaustive of
    every cryptographic construct in the tree -- a CSPRNG call or an encoding
    helper is real crypto that carries no ground-truth entry. Charging those as
    false positives would penalise a correct finding, so only two categories are
    charged, and both are unambiguous:

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

        # A dependency component makes no cryptographic claim, so it cannot make
        # a false one. This is the other half of the exclusion: an SBOM listing
        # eighty ordinary packages would otherwise be charged eighty phantom
        # algorithms for naming things like "lodash" that appear in no ground
        # truth. No credit, no punishment.
        if asset.is_dependency:
            continue

        # Only a component that actually names an algorithm family can be
        # charged with naming the wrong one. A name carrying no family token --
        # "relay-key.pem", "key@<uuid>" -- makes no algorithm claim at all. It
        # is uninformative, which the evidence-quality table already reports,
        # not false. cdxgen names key-file components after the file, which is
        # a reasonable thing to report for key material whose algorithm cannot
        # be known without parsing it; charging that would invent an error the
        # generator did not make.
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
            # A family that exists nowhere in the project is a fabrication
            # wherever it is reported, so this is checked before location.
            if not credible:
                result.phantom_algorithm += 1
                continue

        # A component landing in a file that holds a planted asset is not a
        # phantom location even if it named nothing useful: the generator found
        # a real crypto-bearing file.
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

        # A report that lands on a file holding a planted asset is not a stray
        # claim, even when it carries no line number: the generator found the
        # right place and merely failed to say where in it. Those are already
        # visible as a zero in the "with line" column of the evidence table, and
        # counting them here too would report the same shortcoming twice.
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
