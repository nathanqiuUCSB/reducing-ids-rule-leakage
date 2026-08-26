"""Serializable accepted and rejected mutation specifications."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from hardening_game.mutations.engine import MutationCandidate


# Canonical predicate/clue annotations describe an edit, they do not define it.
# They are excluded from the identity digest so that annotating an existing
# mutation never renumbers the candidate and rejection IDs recorded in a
# completed run.
IDENTITY_EXCLUDED_PARAM_KEYS = frozenset(
    {"predicate_id", "predicate_ids", "clue_ids", "recipe_id", "rationale"}
)


def identity_params(params: dict[str, object]) -> dict[str, object]:
    """Return the semantic parameters that define one edit's identity."""
    return {
        key: value
        for key, value in params.items()
        if key not in IDENTITY_EXCLUDED_PARAM_KEYS
    }


@dataclass(frozen=True)
class MutationSpec:
    """One accepted single-semantic-component edit rendered as full rule text."""

    component: str
    operator: str
    params: dict[str, object]
    description: str
    rule: str


@dataclass(frozen=True)
class RejectedSpec:
    id: str
    component: str
    operator: str
    params: dict[str, object]
    reason: Literal["structural", "unsupported", "suricata_preflight"]
    diagnostic: str


@dataclass(frozen=True)
class CandidateSet:
    accepted: tuple["MutationCandidate", ...]
    rejected: tuple[RejectedSpec, ...]


def rejected_spec(
    *,
    fixture_name: str,
    component: str,
    operator: str,
    params: dict[str, object],
    reason: Literal["structural", "unsupported", "suricata_preflight"],
    diagnostic: str,
) -> RejectedSpec:
    identity = json.dumps(
        {
            "component": component,
            "operator": operator,
            "params": identity_params(params),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(identity.encode()).hexdigest()[:12]
    return RejectedSpec(
        id=f"{fixture_name}-{component}-{operator}-{digest}",
        component=component,
        operator=operator,
        params=params,
        reason=reason,
        diagnostic=diagnostic,
    )
