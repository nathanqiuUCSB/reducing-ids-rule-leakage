"""Classify attacker CVE predictions against experiment targets."""

from __future__ import annotations

from hardening_game.attribution.registry import (
    AttributionResult,
    AttributionTier,
    RelatedCveRegistry,
)


def classify_cve_attribution(
    *,
    target_cve: str,
    predicted_cve: str,
    registry: RelatedCveRegistry,
) -> AttributionResult:
    """Return relationship tier and meaningful-obscurity for one prediction."""
    if target_cve == predicted_cve:
        return AttributionResult(
            relationship_tier="exact_match",
            meaningful_obscurity=False,
        )

    lookup = {
        (entry.target_cve, entry.predicted_cve): entry.tier
        for entry in registry.entries
    }
    tier = lookup.get((target_cve, predicted_cve))
    if tier is None:
        return AttributionResult(
            relationship_tier="unclassified",
            meaningful_obscurity=None,
        )

    relationship_tier: AttributionTier = tier
    if tier == "closely_related":
        meaningful_obscurity = False
    else:
        meaningful_obscurity = True

    return AttributionResult(
        relationship_tier=relationship_tier,
        meaningful_obscurity=meaningful_obscurity,
    )
