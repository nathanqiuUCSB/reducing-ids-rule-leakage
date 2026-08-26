"""Capture-level and relevant-flow-level benign evaluation metrics."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from hardening_game.benign.registry import CoverageTier


@dataclass(frozen=True)
class BenignCaptureResult:
    source_id: str
    coverage_tier: CoverageTier
    capture_name: str
    fired: bool
    total_alerts: int
    relevant_flow_count: int | None
    alerting_relevant_flow_count: int | None
    alerts_per_relevant_flow: float | None
    error: str | None


@dataclass(frozen=True)
class BenignAggregateMetrics:
    corpus_available: bool
    captures_requested: int
    captures_evaluated: int
    captures_missing: int
    capture_firing_rate: float | None
    alerting_flow_rate: float | None
    total_alert_count: int
    coverage_tiers_present: dict[str, int]
    cache_errors: tuple[str, ...]


def aggregate_benign_metrics(
    results: Sequence[BenignCaptureResult],
    *,
    requested: int,
    cache_errors: Sequence[str],
) -> BenignAggregateMetrics:
    """Aggregate available captures without converting unavailable data to zeros."""
    evaluated = [result for result in results if result.error is None]
    measurable = [
        result
        for result in evaluated
        if result.relevant_flow_count is not None
        and result.alerting_relevant_flow_count is not None
    ]
    total_relevant_flows = sum(
        result.relevant_flow_count or 0 for result in measurable
    )
    total_alerting_flows = sum(
        result.alerting_relevant_flow_count or 0 for result in measurable
    )
    coverage_tiers: dict[str, int] = {}
    for result in evaluated:
        coverage_tiers[result.coverage_tier] = (
            coverage_tiers.get(result.coverage_tier, 0) + 1
        )

    return BenignAggregateMetrics(
        corpus_available=bool(evaluated),
        captures_requested=requested,
        captures_evaluated=len(evaluated),
        captures_missing=max(0, requested - len(evaluated)),
        capture_firing_rate=(
            sum(result.fired for result in evaluated) / len(evaluated)
            if evaluated
            else None
        ),
        alerting_flow_rate=(
            total_alerting_flows / total_relevant_flows
            if total_relevant_flows
            else None
        ),
        total_alert_count=sum(result.total_alerts for result in evaluated),
        coverage_tiers_present=coverage_tiers,
        cache_errors=tuple(cache_errors),
    )
