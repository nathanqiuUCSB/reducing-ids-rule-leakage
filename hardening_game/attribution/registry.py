"""Load and validate the directional related-CVE registry."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Literal, cast


RelationshipTier = Literal[
    "closely_related", "same_ecosystem", "meaningfully_distinct"
]
AttributionTier = Literal[
    "exact_match",
    "closely_related",
    "same_ecosystem",
    "meaningfully_distinct",
    "unclassified",
]

_SUPPORTED_VERSION = 1
_RELATIONSHIP_TIERS = frozenset(
    {"closely_related", "same_ecosystem", "meaningfully_distinct"}
)
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


@dataclass(frozen=True)
class RelatedCveEntry:
    target_cve: str
    predicted_cve: str
    tier: RelationshipTier
    vendor: str
    product: str
    rationale: str
    provenance: str


@dataclass(frozen=True)
class AttributionResult:
    relationship_tier: AttributionTier
    meaningful_obscurity: bool | None


@dataclass(frozen=True)
class RelatedCveRegistry:
    version: int
    entries: tuple[RelatedCveEntry, ...]


def _validated_cve(value: str, *, field: str) -> str:
    if not _CVE_RE.fullmatch(value):
        raise ValueError(f"malformed CVE: {field}={value!r}")
    return value


def _validated_text(value: object, *, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a nonempty string, not {value!r}")
    if not value.strip():
        raise ValueError(f"empty {field}")
    return value


_MIN_RATIONALE_LENGTH = 100
# Unfilled-text markers only. Words such as "placeholder" occur legitimately in
# technical prose (SQL placeholders), so each marker is matched as a phrase.
_PLACEHOLDER_RE = re.compile(
    r"\b(todo|tbd|fixme|xxx|n/?a|see above|as above|same as above|fill in|"
    r"placeholder text|to be written)\b"
)
# A directional judgement about an unpublished identifier says the same thing
# whatever the target is, so this one rationale may legitimately be shared
# across targets. Every other shared rationale must describe a single target.
_TARGET_INDEPENDENT_PHRASE = "no published CVE record"
_TOKEN_RE = re.compile(r"[^a-z0-9]+")


def _substantive_tokens(value: str) -> set[str]:
    return {token for token in _TOKEN_RE.split(value.lower()) if len(token) >= 4}


def _validate_reviewed_rationale(entry: RelatedCveEntry) -> None:
    label = f"{entry.target_cve} -> {entry.predicted_cve}"
    rationale = entry.rationale.strip()
    if len(rationale) < _MIN_RATIONALE_LENGTH:
        raise ValueError(
            f"{label}: rationale must be at least {_MIN_RATIONALE_LENGTH} "
            f"characters, got {len(rationale)}"
        )
    if not rationale.endswith("."):
        raise ValueError(f"{label}: rationale must end in a full stop")
    unfilled = _PLACEHOLDER_RE.search(rationale.lower())
    if unfilled:
        raise ValueError(
            f"{label}: rationale contains placeholder {unfilled.group(0)!r}"
        )
    if rationale == entry.provenance.strip():
        raise ValueError(f"{label}: rationale merely repeats the provenance")
    subject_tokens = _substantive_tokens(entry.vendor) | _substantive_tokens(
        entry.product
    )
    if not subject_tokens & _substantive_tokens(rationale):
        raise ValueError(
            f"{label}: rationale names neither the vendor nor the product it judges"
        )


def validate_reviewed_related_registry(registry: RelatedCveRegistry) -> None:
    """Enforce reviewed-quality rationales on a directional pair registry.

    Directional entries may legitimately share one rationale across a group of
    predictions made against the same target, so uniqueness is scoped rather
    than global: a shared rationale must belong to a single target, and the
    tightest tier, ``closely_related``, must justify every pair individually
    because that is the tier which grants attribution credit.
    """
    targets_by_rationale: dict[str, set[str]] = {}
    close_rationales: dict[str, str] = {}
    for entry in registry.entries:
        _validate_reviewed_rationale(entry)
        rationale = entry.rationale.strip()
        targets_by_rationale.setdefault(rationale, set()).add(entry.target_cve)
        if entry.tier != "closely_related":
            continue
        label = f"{entry.target_cve} -> {entry.predicted_cve}"
        if rationale in close_rationales:
            raise ValueError(
                f"{label}: closely_related rationale is reused from "
                f"{close_rationales[rationale]}; each close pair needs its own "
                "factual justification"
            )
        close_rationales[rationale] = label

    for rationale, targets in targets_by_rationale.items():
        if len(targets) == 1 or _TARGET_INDEPENDENT_PHRASE in rationale:
            continue
        raise ValueError(
            "one rationale is shared across unrelated targets "
            f"{sorted(targets)}: {rationale[:80]!r}"
        )


def load_related_cve_registry(path: Path) -> RelatedCveRegistry:
    """Load and validate a JSON related-CVE registry."""
    data = json.loads(path.read_text())
    version = data["version"]
    if version != _SUPPORTED_VERSION:
        raise ValueError(f"unsupported registry version: {version}")

    entries: list[RelatedCveEntry] = []
    seen: set[tuple[str, str]] = set()
    for record in data["entries"]:
        target_cve = _validated_cve(record["target_cve"], field="target_cve")
        predicted_cve = _validated_cve(record["predicted_cve"], field="predicted_cve")
        pair = (target_cve, predicted_cve)
        if pair in seen:
            raise ValueError(
                f"duplicate directional pair: {target_cve} -> {predicted_cve}"
            )
        seen.add(pair)

        tier = record["tier"]
        if tier not in _RELATIONSHIP_TIERS:
            raise ValueError(f"unsupported tier: {tier!r}")

        entries.append(
            RelatedCveEntry(
                target_cve=target_cve,
                predicted_cve=predicted_cve,
                tier=cast(RelationshipTier, tier),
                vendor=_validated_text(record.get("vendor"), field="vendor"),
                product=_validated_text(record.get("product"), field="product"),
                rationale=_validated_text(
                    record.get("rationale"), field="rationale"
                ),
                provenance=_validated_text(
                    record.get("provenance"), field="provenance"
                ),
            )
        )

    return RelatedCveRegistry(version=version, entries=tuple(entries))
