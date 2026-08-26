"""Deterministic trial-level clue attribution and three-trial aggregation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Iterable, Literal, Mapping, Sequence

from hardening_game.attribution.clue_registry import BaselineRuleClues
from hardening_game.attribution.registry import RelatedCveRegistry
from hardening_game.predicates import (
    normalize_evidence_text,
    predicate_coverage_spans,
    predicate_spans,
    resolve_predicate_ids,
)

if TYPE_CHECKING:
    from hardening_game.mutations.attacker_trials import AttackerTrial


AttributionLabel = Literal["exact", "close", "non_close", "unreviewed", "failed"]
ClueEffectLabel = Literal[
    "major_disruption", "secondary_disruption", "unsupported", "unmeasured"
]
OutcomeLabel = Literal[
    "no_effective_obscurity",
    "major_obscurity",
    "weak_obscurity",
    "unsupported_attribution_miss",
    "unmeasured",
]
AggregateLabel = Literal[
    "durable_major",
    "probable_major",
    "durable_weak",
    "unsupported_miss",
    "no_effective_obscurity",
    "unstable",
    "unmeasured",
]


@dataclass(frozen=True)
class EvidenceMapping:
    predicate_ids: tuple[str, ...]
    measured: bool
    reason: str | None


@dataclass(frozen=True)
class TrialClueScore:
    candidate_id: str
    trial_index: int
    attribution_label: AttributionLabel
    clue_effect_label: ClueEffectLabel
    outcome_label: OutcomeLabel


@dataclass(frozen=True)
class CandidateClueSummary:
    aggregate_label: AggregateLabel
    configured_trial_count: int
    observed_trial_count: int
    attribution_labels: tuple[AttributionLabel, ...]
    clue_effect_labels: tuple[ClueEffectLabel, ...]
    outcome_labels: tuple[OutcomeLabel, ...]
    attribution_rates: dict[str, float]
    clue_effect_rates: dict[str, float]
    outcome_rates: dict[str, float]


def map_attacker_evidence(
    evidence: Iterable[str],
    *,
    visible_rule: str,
    rule_predicates: Mapping[str, Mapping[str, object]],
) -> EvidenceMapping:
    """Map exact, uniquely located evidence spans to overlapped predicates."""
    evidence = tuple(evidence)
    if not evidence:
        return EvidenceMapping((), False, "missing_evidence")
    normalized_rule, positions = _normalized_with_positions(visible_rule)
    spans = predicate_spans(rule_predicates)
    coverage_spans = predicate_coverage_spans(rule_predicates)
    predicates: set[str] = set()
    for snippet in evidence:
        normalized = normalize_evidence_text(snippet)
        if not normalized:
            return EvidenceMapping((), False, "unmapped_evidence")
        locations: list[int] = []
        offset = 0
        while True:
            location = normalized_rule.find(normalized, offset)
            if location < 0:
                break
            locations.append(location)
            offset = location + 1
        if not locations:
            return EvidenceMapping((), False, "unmapped_evidence")
        if len(locations) != 1:
            return EvidenceMapping((), False, "ambiguous_evidence")
        location = locations[0]
        source_positions = positions[location : location + len(normalized)]
        mapped = {
            predicate_id
            for predicate_id, start, end in spans
            if any(start <= position < end for position in source_positions)
        }
        if not mapped:
            return EvidenceMapping((), False, "unmapped_evidence")
        if any(
            not any(start <= position < end for start, end in coverage_spans)
            for position in source_positions
        ):
            return EvidenceMapping((), False, "unmapped_evidence")
        predicates.update(mapped)
    return EvidenceMapping(tuple(sorted(predicates)), True, None)


def _normalized_with_positions(text: str) -> tuple[str, tuple[int, ...]]:
    output: list[str] = []
    positions: list[int] = []
    quoted = escaped = False
    for index, character in enumerate(text):
        if quoted and escaped:
            output.append(character)
            positions.append(index)
            escaped = False
        elif quoted and character == "\\":
            output.append(character)
            positions.append(index)
            escaped = True
        elif character == '"':
            output.append(character)
            positions.append(index)
            quoted = not quoted
        elif not quoted and character.isspace():
            continue
        else:
            output.append(character)
            positions.append(index)
    return "".join(output), tuple(positions)


def _structured_evidence(trial: AttackerTrial) -> list[str] | None:
    if not isinstance(trial.exchange, dict):
        return None
    parsed = trial.exchange.get("parsed_response")
    if not isinstance(parsed, dict):
        return None
    clues = parsed.get("clues")
    if not isinstance(clues, list) or not clues:
        return None
    evidence: list[str] = []
    for clue in clues:
        if not isinstance(clue, dict):
            return None
        snippets = clue.get("rule_evidence")
        if (
            not isinstance(snippets, list)
            or not snippets
            or any(not isinstance(item, str) or not item for item in snippets)
        ):
            return None
        evidence.extend(snippets)
    return evidence


def _attacker_visible_rule(trial: AttackerTrial) -> str | None:
    if not isinstance(trial.exchange, dict):
        return None
    prompt = trial.exchange.get("prompt")
    marker = "\nRule:\n"
    if not isinstance(prompt, str) or marker not in prompt:
        return None
    return prompt.split(marker, 1)[1].strip()


def _attribution_label(
    trial: AttackerTrial,
    *,
    target_cve: str,
    registry: RelatedCveRegistry,
) -> AttributionLabel:
    if trial.status != "succeeded" or trial.prediction is None:
        return "failed"
    if trial.prediction == target_cve:
        return "exact"
    tier = next(
        (
            entry.tier
            for entry in registry.entries
            if entry.target_cve == target_cve
            and entry.predicted_cve == trial.prediction
        ),
        None,
    )
    if tier == "closely_related":
        return "close"
    if tier in {"same_ecosystem", "meaningfully_distinct"}:
        return "non_close"
    return "unreviewed"


def _clue_effect(
    *,
    rule_clues: BaselineRuleClues,
    touched_predicate_ids: Iterable[str],
    mapping: EvidenceMapping,
    known_predicate_ids: Iterable[str],
) -> ClueEffectLabel:
    if not mapping.measured:
        return "unmeasured"
    known_source = (
        known_predicate_ids
        if isinstance(known_predicate_ids, Mapping)
        else tuple(known_predicate_ids)
    )
    known = set(known_predicate_ids)
    touched = set(
        resolve_predicate_ids(
            touched_predicate_ids, known_predicate_ids=known_source
        )
    )
    present = set(mapping.predicate_ids)
    clue_predicates = {
        clue.clue_id: set(
            resolve_predicate_ids(
                clue.predicate_ids, known_predicate_ids=known_source
            )
        )
        for clue in rule_clues.clues
    }
    targeted = [
        clue for clue in rule_clues.clues if touched.intersection(clue_predicates[clue.clue_id])
    ]
    if not targeted:
        return "unsupported"
    # A canonical clue is identified only when the evidence union contains ALL
    # predicates linked to it. Partial evidence is a clue disruption when the
    # candidate explicitly touched at least one of those linked predicates.
    missing_targeted_major = any(
        clue.rank is not None
        and not clue_predicates[clue.clue_id].issubset(present)
        for clue in targeted
    )
    if missing_targeted_major:
        return "major_disruption"
    missing_targeted_secondary = any(
        clue.rank is None
        and not clue_predicates[clue.clue_id].issubset(present)
        for clue in targeted
    )
    all_majors_present = all(
        clue_predicates[clue.clue_id].issubset(present)
        for clue in rule_clues.clues
        if clue.rank is not None
    )
    if missing_targeted_secondary and all_majors_present:
        return "secondary_disruption"
    return "unsupported"


def score_trial(
    trial: AttackerTrial,
    *,
    target_cve: str,
    related_cve_registry: RelatedCveRegistry,
    rule_clues: BaselineRuleClues,
    touched_predicate_ids: Iterable[str],
    rule_predicates: Mapping[str, Mapping[str, object]],
) -> TrialClueScore:
    """Score one persisted trial without inference or text similarity."""
    canonical_touched_predicate_ids = resolve_predicate_ids(
        touched_predicate_ids, known_predicate_ids=rule_predicates
    )
    attribution = _attribution_label(
        trial, target_cve=target_cve, registry=related_cve_registry
    )
    if attribution in {"failed", "unreviewed"}:
        clue_effect: ClueEffectLabel = "unmeasured"
    else:
        evidence = _structured_evidence(trial)
        visible_rule = _attacker_visible_rule(trial)
        mapping = (
            EvidenceMapping((), False, "legacy_or_missing_structured_evidence")
            if evidence is None or visible_rule is None
            else map_attacker_evidence(
                evidence,
                visible_rule=visible_rule,
                rule_predicates=rule_predicates,
            )
        )
        clue_effect = _clue_effect(
            rule_clues=rule_clues,
            touched_predicate_ids=canonical_touched_predicate_ids,
            mapping=mapping,
            known_predicate_ids=rule_predicates,
        )
    if attribution in {"exact", "close"}:
        outcome: OutcomeLabel = "no_effective_obscurity"
    elif attribution in {"failed", "unreviewed"} or clue_effect == "unmeasured":
        outcome = "unmeasured"
    elif clue_effect == "major_disruption":
        outcome = "major_obscurity"
    elif clue_effect == "secondary_disruption":
        outcome = "weak_obscurity"
    else:
        outcome = "unsupported_attribution_miss"
    return TrialClueScore(
        candidate_id=trial.candidate_id,
        trial_index=trial.trial_index,
        attribution_label=attribution,
        clue_effect_label=clue_effect,
        outcome_label=outcome,
    )


def aggregate_candidate_trials(
    outcomes: Iterable[str],
    *,
    configured_trial_count: int,
    trial_indexes: Iterable[int] | None = None,
) -> AggregateLabel:
    """Reduce a complete configured trial set without dropping mixed patterns."""
    values = tuple(outcomes)
    indexes = tuple(trial_indexes) if trial_indexes is not None else None
    if (
        configured_trial_count != 3
        or len(values) != configured_trial_count
        or (indexes is not None and indexes != (0, 1, 2))
    ):
        return "unmeasured"
    if any(value == "unmeasured" for value in values):
        return "unmeasured"
    major = values.count("major_obscurity")
    if major == 3:
        return "durable_major"
    if major == 2 and "no_effective_obscurity" not in values:
        return "probable_major"
    if values.count("weak_obscurity") == 3:
        return "durable_weak"
    if values.count("unsupported_attribution_miss") == 3:
        return "unsupported_miss"
    if values.count("no_effective_obscurity") == 3:
        return "no_effective_obscurity"
    return "unstable"


def _rates(values: Sequence[str]) -> dict[str, float]:
    if not values:
        return {}
    return {
        label: values.count(label) / len(values)
        for label in sorted(set(values))
    }


def summarize_candidate_trials(
    trials: Iterable[TrialClueScore], *, configured_trial_count: int
) -> CandidateClueSummary:
    """Preserve ordered raw labels and their rates with the aggregate."""
    ordered = sorted(trials, key=lambda trial: trial.trial_index)
    attribution = tuple(trial.attribution_label for trial in ordered)
    clue_effect = tuple(trial.clue_effect_label for trial in ordered)
    outcomes = tuple(trial.outcome_label for trial in ordered)
    return CandidateClueSummary(
        aggregate_label=aggregate_candidate_trials(
            outcomes,
            configured_trial_count=configured_trial_count,
            trial_indexes=(trial.trial_index for trial in ordered),
        ),
        configured_trial_count=configured_trial_count,
        observed_trial_count=len(ordered),
        attribution_labels=attribution,
        clue_effect_labels=clue_effect,
        outcome_labels=outcomes,
        attribution_rates=_rates(attribution),
        clue_effect_rates=_rates(clue_effect),
        outcome_rates=_rates(outcomes),
    )
