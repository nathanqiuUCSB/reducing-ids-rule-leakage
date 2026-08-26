import json
from pathlib import Path

import pytest

from hardening_game.attribution.classifier import classify_cve_attribution
from hardening_game.attribution.registry import load_related_cve_registry


PROJECT_ROOT = Path(__file__).parents[1]
REGISTRY_PATH = PROJECT_ROOT / "fixtures/related_cve_registry.json"


@pytest.fixture
def committed_registry():
    return load_related_cve_registry(REGISTRY_PATH)


def test_registry_is_directional(committed_registry):
    forward = classify_cve_attribution(
        target_cve="CVE-2025-0108",
        predicted_cve="CVE-2024-0012",
        registry=committed_registry,
    )
    reverse = classify_cve_attribution(
        target_cve="CVE-2024-0012",
        predicted_cve="CVE-2025-0108",
        registry=committed_registry,
    )
    assert forward.relationship_tier == "closely_related"
    assert forward.meaningful_obscurity is False
    assert reverse.relationship_tier == "unclassified"
    assert reverse.meaningful_obscurity is None


def test_same_ecosystem_is_not_close(committed_registry):
    result = classify_cve_attribution(
        target_cve="CVE-2025-1094",
        predicted_cve="CVE-2024-1597",
        registry=committed_registry,
    )
    assert result.relationship_tier == "same_ecosystem"
    assert result.meaningful_obscurity is True


def test_exact_match(committed_registry):
    result = classify_cve_attribution(
        target_cve="CVE-2025-0108",
        predicted_cve="CVE-2025-0108",
        registry=committed_registry,
    )
    assert result.relationship_tier == "exact_match"
    assert result.meaningful_obscurity is False


def test_closely_related_confluence_pair(committed_registry):
    result = classify_cve_attribution(
        target_cve="CVE-2023-22527",
        predicted_cve="CVE-2021-26084",
        registry=committed_registry,
    )
    assert result.relationship_tier == "closely_related"
    assert result.meaningful_obscurity is False


def test_unclassified_pair(committed_registry):
    result = classify_cve_attribution(
        target_cve="CVE-2025-0108",
        predicted_cve="CVE-1999-0001",
        registry=committed_registry,
    )
    assert result.relationship_tier == "unclassified"
    assert result.meaningful_obscurity is None


def _write_registry(tmp_path: Path, payload: dict[str, object]) -> Path:
    path = tmp_path / "registry.json"
    path.write_text(json.dumps(payload))
    return path


def _entry(**overrides: object) -> dict[str, object]:
    entry = {
        "target_cve": "CVE-2025-0108",
        "predicted_cve": "CVE-2024-0012",
        "tier": "closely_related",
        "vendor": "Palo Alto Networks",
        "product": "PAN-OS management interface",
        "rationale": "Both are authentication bypasses in the PAN-OS management interface.",
        "provenance": "Manual review of experiment target and attacker prediction",
    }
    entry.update(overrides)
    return entry


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ({"version": 2, "entries": [_entry()]}, "unsupported registry version"),
        ({"version": 1, "entries": [_entry(), _entry()]}, "duplicate directional pair"),
        ({"version": 1, "entries": [_entry(tier="unknown_tier")]}, "unsupported tier"),
        ({"version": 1, "entries": [_entry(target_cve="not-a-cve")]}, "malformed CVE"),
        ({"version": 1, "entries": [_entry(rationale="")]}, "empty rationale"),
        ({"version": 1, "entries": [_entry(provenance="")]}, "empty provenance"),
        ({"version": 1, "entries": [_entry(vendor="")]}, "empty vendor"),
        ({"version": 1, "entries": [_entry(vendor="   ")]}, "empty vendor"),
        ({"version": 1, "entries": [_entry(product="")]}, "empty product"),
        (
            {"version": 1, "entries": [_entry(vendor=None)]},
            "vendor must be a nonempty string",
        ),
        (
            {"version": 1, "entries": [_entry(product=["PAN-OS"])]},
            "product must be a nonempty string",
        ),
    ],
)
def test_registry_rejects_invalid_entries(
    tmp_path: Path, payload: dict[str, object], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        load_related_cve_registry(_write_registry(tmp_path, payload))


def test_committed_registry_is_valid() -> None:
    registry = load_related_cve_registry(REGISTRY_PATH)
    assert registry.version == 1
    for entry in registry.entries:
        assert entry.vendor.strip()
        assert entry.product.strip()
    # The three originally hand-seeded pairs survived the reviewed rewrite.
    tiers = {
        (entry.target_cve, entry.predicted_cve): entry.tier
        for entry in registry.entries
    }
    assert tiers[("CVE-2023-22527", "CVE-2021-26084")] == "closely_related"
    assert tiers[("CVE-2025-0108", "CVE-2024-0012")] == "closely_related"
    assert tiers[("CVE-2025-1094", "CVE-2024-1597")] == "same_ecosystem"
