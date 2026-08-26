"""Attribution registries, classification, and deterministic clue scoring."""

from hardening_game.attribution.classifier import classify_cve_attribution
from hardening_game.attribution.clue_registry import (
    BaselineClue,
    BaselineClueRegistry,
    BaselineRuleClues,
    load_baseline_clue_registry,
    registry_sha256,
    validate_completed_rule,
)
from hardening_game.attribution.clue_scoring import (
    CandidateClueSummary,
    EvidenceMapping,
    TrialClueScore,
    aggregate_candidate_trials,
    map_attacker_evidence,
    score_trial,
    summarize_candidate_trials,
)
from hardening_game.attribution.registry import (
    AttributionResult,
    RelatedCveEntry,
    RelatedCveRegistry,
    load_related_cve_registry,
)

__all__ = [
    "AttributionResult",
    "BaselineClue",
    "BaselineClueRegistry",
    "BaselineRuleClues",
    "CandidateClueSummary",
    "EvidenceMapping",
    "RelatedCveEntry",
    "RelatedCveRegistry",
    "TrialClueScore",
    "aggregate_candidate_trials",
    "classify_cve_attribution",
    "load_baseline_clue_registry",
    "load_related_cve_registry",
    "map_attacker_evidence",
    "registry_sha256",
    "score_trial",
    "summarize_candidate_trials",
    "validate_completed_rule",
]
