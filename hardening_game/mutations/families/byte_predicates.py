"""Negated content removal and byte_test removal or threshold widening."""

from __future__ import annotations

from hardening_game.mutations.dependencies import (
    content_dependency_group,
    downstream_endpoint_consumers,
)
from typing import Mapping

from hardening_game.mutations.families import (
    canonical_option,
    leading_whitespace,
    predicate_tags,
    remove_spans,
    replace_span,
)
from hardening_game.mutations.specifications import (
    MutationSpec,
    RejectedSpec,
    rejected_spec,
)
from hardening_game.predicates import predicate_ids_for_option
from hardening_game.suricata.rule_model import ParsedRule


THRESHOLD_OPERATORS = {">", "<", ">=", "<="}
# These keywords publish offsets or extracted variables that later options can
# consume, so this model neither edits nor removes them.
UNMODELLED_BYTE_OPTIONS = ("byte_jump", "byte_extract", "byte_math", "isdataat")


def _parse_number(text: str) -> tuple[int, bool] | None:
    try:
        if text.casefold().startswith("0x"):
            return int(text, 16), True
        return int(text, 10), False
    except ValueError:
        return None


def _negated_content_specifications(
    rule: ParsedRule, *, fixture_name: str
) -> list[MutationSpec | RejectedSpec]:
    specifications: list[MutationSpec | RejectedSpec] = []
    for group in rule.sticky_groups:
        for predicate in group.predicates:
            if not predicate.negated:
                continue
            consumers = predicate.relative_consumers + downstream_endpoint_consumers(
                rule, predicate.predicate_id
            )
            params = {**predicate_tags(predicate), "operation": "remove"}
            if consumers:
                specifications.append(
                    rejected_spec(
                        fixture_name=fixture_name,
                        component="negated_content",
                        operator="remove",
                        params=params,
                        reason="structural",
                        diagnostic=(
                            "downstream consumers prevent negated content removal: "
                            + ", ".join(consumer.name for consumer in consumers)
                        ),
                    )
                )
                continue
            dependency = content_dependency_group(rule, predicate.predicate_id)
            specifications.append(
                MutationSpec(
                    component="negated_content",
                    operator="remove",
                    params=params,
                    description="Remove one negated content requirement.",
                    rule=remove_spans(rule.source, dependency.spans),
                )
            )
    return specifications


def _byte_test_specifications(
    rule: ParsedRule, *, fixture_name: str
) -> list[MutationSpec | RejectedSpec]:
    specifications: list[MutationSpec | RejectedSpec] = []
    for option in rule.options:
        if option.name != "byte_test":
            continue
        predicate_id = predicate_ids_for_option(rule, option.option_index)[0]
        params = {
            "option_index": option.option_index,
            "operation": "widen",
            "predicate_id": predicate_id,
        }
        fields = [field.strip() for field in (option.value or "").split(",")]
        number = _parse_number(fields[2]) if len(fields) >= 4 else None
        if len(fields) < 4 or fields[1] not in THRESHOLD_OPERATORS or number is None:
            specifications.append(
                rejected_spec(
                    fixture_name=fixture_name,
                    component="byte_test",
                    operator="widen",
                    params=params,
                    reason="unsupported",
                    diagnostic=(
                        f"byte_test {option.value!r} is not a numeric threshold "
                        "comparison that can be widened in one direction"
                    ),
                )
            )
        else:
            value, is_hex = number
            widened = max(0, value // 2) if fields[1].startswith(">") else value * 2
            widened_fields = list(fields)
            widened_fields[2] = f"0x{widened:x}" if is_hex else str(widened)
            specifications.append(
                MutationSpec(
                    component="byte_test",
                    operator="widen",
                    params={**params, "from": fields[2], "to": widened_fields[2]},
                    description="Widen one numeric byte_test threshold.",
                    rule=replace_span(
                        rule.source,
                        option.span,
                        leading_whitespace(rule.source, option.span)
                        + f"byte_test:{','.join(widened_fields)};",
                    ),
                )
            )
        specifications.append(
            MutationSpec(
                component="byte_test",
                operator="remove",
                params={
                    "option_index": option.option_index,
                    "operation": "remove",
                    "predicate_id": predicate_id,
                },
                description="Remove one byte_test predicate.",
                rule=remove_spans(rule.source, (option.span,)),
            )
        )
    return specifications


def _unmodelled_byte_option_rejections(
    rule: ParsedRule, *, fixture_name: str
) -> list[RejectedSpec]:
    return [
        rejected_spec(
            fixture_name=fixture_name,
            component=option.name,
            operator="remove",
            params={"option_index": option.option_index, "operation": "remove"},
            reason="unsupported",
            diagnostic=(
                f"{option.name} publishes offsets or variables that later options "
                "may consume, so this model does not edit it"
            ),
        )
        for option in rule.options
        if option.name in UNMODELLED_BYTE_OPTIONS
    ]


def generate(
    rule: ParsedRule, *, fixture_name: str
) -> tuple[MutationSpec | RejectedSpec, ...]:
    """Emit negated-content and byte_test edits, rejecting unmodelled keywords."""
    return tuple(
        _negated_content_specifications(rule, fixture_name=fixture_name)
        + _byte_test_specifications(rule, fixture_name=fixture_name)
        + _unmodelled_byte_option_rejections(rule, fixture_name=fixture_name)
    )


def remove_window(
    rule: ParsedRule, params: Mapping[str, object], *, fixture_name: str
) -> MutationSpec | RejectedSpec:
    """Remove the byte tests that jointly bound one value, not just one side.

    Widening or deleting a single `byte_test` leaves the opposite bound in
    place, so the "this field is checked against a narrow numeric window" clue
    survives.  Removing the paired tests together is the edit that actually
    targets that clue.  `byte_test` never advances the match pointer, so no
    later option needs compensating.
    """
    predicate_ids = params.get("predicate_ids")
    if (
        not isinstance(predicate_ids, (list, tuple))
        or len(predicate_ids) < 2
        or any(not isinstance(item, str) for item in predicate_ids)
    ):
        raise ValueError(
            "byte_test/remove_window requires at least two byte_test predicate IDs"
        )
    options = [canonical_option(rule, str(item)) for item in predicate_ids]
    identity: dict[str, object] = {
        "option_indexes": sorted(option.option_index for option in options),
        "operation": "remove_window",
        "predicate_ids": list(predicate_ids),
    }
    unsupported = sorted(
        {option.name for option in options if option.name != "byte_test"}
    )
    if unsupported:
        return rejected_spec(
            fixture_name=fixture_name,
            component="byte_test",
            operator="remove_window",
            params=identity,
            reason="unsupported",
            diagnostic=(
                "a byte_test window may only contain byte_test options, not: "
                + ", ".join(unsupported)
            ),
        )
    return MutationSpec(
        component="byte_test",
        operator="remove_window",
        params=identity,
        description=(
            f"Remove the {len(options)} byte tests that jointly bound one field."
        ),
        rule=remove_spans(rule.source, tuple(option.span for option in options)),
    )


TARGETED_OPERATORS = {
    "byte_test/remove_window": remove_window,
}
