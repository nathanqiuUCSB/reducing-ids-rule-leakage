"""Clue-targeted edits for flowbits state that leaks a rule's exploit chain.

A `flowbits:set` (or `unset`/`toggle`) option records cross-rule state when the
rule fires; it never gates whether the rule fires.  Both operators here are
therefore recall-preserving for the rule under evaluation even though removing
the bit would break any companion rule that reads it.  `isset`/`isnotset` do
gate matching, and `noalert` changes whether an alert is emitted at all, so
neither is edited by this model.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Mapping

from hardening_game.mutations.families import (
    canonical_option,
    leading_whitespace,
    remove_spans,
    replace_span,
)
from hardening_game.mutations.specifications import (
    MutationSpec,
    RejectedSpec,
    rejected_spec,
)
from hardening_game.suricata.rule_model import ParsedRule, RuleOption


GATING_ACTIONS = frozenset({"isset", "isnotset"})
STATE_ACTIONS = frozenset({"set", "unset", "toggle"})
_NEUTRAL_NAME = re.compile(r"^bit[0-9]+$")


@dataclass(frozen=True)
class _StateBit:
    option: RuleOption
    action: str
    name: str
    diagnostic: str | None


def _resolve(rule: ParsedRule, params: Mapping[str, object]) -> _StateBit:
    predicate_id = params.get("predicate_id")
    if not isinstance(predicate_id, str):
        raise ValueError("flowbits operators require a predicate_id")
    option = canonical_option(rule, predicate_id)
    if option.name != "flowbits":
        raise ValueError(f"{predicate_id} is not a flowbits option")
    parts = [part.strip() for part in (option.value or "").split(",")]
    if len(parts) != 2 or not parts[1]:
        return _StateBit(
            option,
            "",
            "",
            f"flowbits option {option.value!r} is not the action,name form this "
            "model edits",
        )
    action, name = parts[0].casefold(), parts[1]
    if action in GATING_ACTIONS:
        return _StateBit(
            option,
            action,
            name,
            f"flowbits {action},{name} gates whether this rule matches, so it "
            "cannot be treated as a state-only annotation",
        )
    if action not in STATE_ACTIONS:
        return _StateBit(
            option,
            action,
            name,
            f"flowbits action {action!r} is outside the modelled state actions",
        )
    return _StateBit(option, action, name, None)


def _reject(
    *,
    fixture_name: str,
    operator: str,
    params: dict[str, object],
    diagnostic: str,
    reason: str = "structural",
) -> RejectedSpec:
    return rejected_spec(
        fixture_name=fixture_name,
        component="flowbits",
        operator=operator,
        params=params,
        reason=reason,
        diagnostic=diagnostic,
    )


def remove_state_set(
    rule: ParsedRule, params: Mapping[str, object], *, fixture_name: str
) -> MutationSpec | RejectedSpec:
    """Drop a state-only flowbits option, leaving this rule's matching intact."""
    bit = _resolve(rule, params)
    identity: dict[str, object] = {
        "option_index": bit.option.option_index,
        "operation": "remove_state_set",
        "predicate_id": params.get("predicate_id"),
    }
    if bit.diagnostic is not None:
        return _reject(
            fixture_name=fixture_name,
            operator="remove_state_set",
            params=identity,
            diagnostic=bit.diagnostic,
        )
    return MutationSpec(
        component="flowbits",
        operator="remove_state_set",
        params={
            **identity,
            "flowbits_action": bit.action,
            "flowbits_name": bit.name,
        },
        description=(
            f"Remove the state-only flowbits {bit.action} that names {bit.name!r}."
        ),
        rule=remove_spans(rule.source, (bit.option.span,)),
    )


def anonymize_name(
    rule: ParsedRule, params: Mapping[str, object], *, fixture_name: str
) -> MutationSpec | RejectedSpec:
    """Keep the flowbits mechanism but replace its descriptive bit name."""
    bit = _resolve(rule, params)
    replacement = params.get("name")
    if not isinstance(replacement, str) or not _NEUTRAL_NAME.fullmatch(replacement):
        raise ValueError(
            "flowbits/anonymize_name requires a neutral bit name such as 'bit1'"
        )
    identity: dict[str, object] = {
        "option_index": bit.option.option_index,
        "operation": "anonymize_name",
        "to": replacement,
        "predicate_id": params.get("predicate_id"),
    }
    if bit.diagnostic is not None:
        return _reject(
            fixture_name=fixture_name,
            operator="anonymize_name",
            params=identity,
            diagnostic=bit.diagnostic,
        )
    if replacement == bit.name:
        return _reject(
            fixture_name=fixture_name,
            operator="anonymize_name",
            params=identity,
            reason="unsupported",
            diagnostic=f"flowbits name {bit.name!r} is already the replacement",
        )
    return MutationSpec(
        component="flowbits",
        operator="anonymize_name",
        params={**identity, "flowbits_action": bit.action, "from": bit.name},
        description=(
            f"Rename the flowbits {bit.action} bit from {bit.name!r} to "
            f"{replacement!r}."
        ),
        rule=replace_span(
            rule.source,
            bit.option.span,
            leading_whitespace(rule.source, bit.option.span)
            + f"flowbits:{bit.action},{replacement};",
        ),
    )


TARGETED_OPERATORS = {
    "flowbits/remove_state_set": remove_state_set,
    "flowbits/anonymize_name": anonymize_name,
}
