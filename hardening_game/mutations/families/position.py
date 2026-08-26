"""Monotonic positional widening and removal for relative constraints and bsize.

Suricata evaluates a content's positional window as
``[start + lower_bound, start + lower_bound + upper_bound]``: ``depth`` counts
from ``offset`` and ``within`` counts from the previous match end plus
``distance``.  Lowering or removing a lower bound therefore also pulls the upper
bound in, which would silently drop matches the baseline rule accepted.  Every
lower-bound edit here compensates its paired upper bound by the same amount so
the mutated window is always a superset of the original one.
"""

from __future__ import annotations

import re
from typing import Mapping

from hardening_game.mutations.families import (
    Edit,
    apply_edits,
    canonical_option,
    leading_whitespace,
    option_index_of,
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
from hardening_game.suricata.rule_model import Modifier, ParsedRule


LOWER_BOUND_PARTNERS = {"offset": "depth", "distance": "within"}
UPPER_BOUNDS = frozenset(LOWER_BOUND_PARTNERS.values())
# Measured against Suricata 7.0.3: offset and depth are uint16, and distance and
# within are capped at DETECT_CONTENT_VALUE_MAX rather than at the int32 range,
# so 1048577 is rejected with "invalid value for within".
MAXIMUM_BOUND = {
    "offset": 65535,
    "depth": 65535,
    "distance": 1048576,
    "within": 1048576,
}
RELATIVE_CONSTRAINTS = tuple(MAXIMUM_BOUND)
_SIGNED_OPERAND = re.compile(r"^[+-]\d+$")
_BSIZE_RANGE = re.compile(r"^(?P<low>\d+)\s*<>\s*(?P<high>\d+)$")
_BSIZE_COMPARISON = re.compile(r"^(?P<operator>>=|<=|>|<)\s*(?P<value>\d+)$")
_BSIZE_EXACT = re.compile(r"^(?P<value>\d+)$")
_BSIZE_MARGIN = 3


def _widened_values(name: str, number: int) -> tuple[int, ...]:
    """Return the widening levels for one constraint, clamped to Suricata's range."""
    if name in UPPER_BOUNDS:
        maximum = MAXIMUM_BOUND[name]
        levels = (min(number * 2, maximum), min(number * 4, maximum))
    else:
        levels = (number // 2, 0)
    seen: list[int] = []
    for level in levels:
        if level != number and level not in seen:
            seen.append(level)
    return tuple(seen)


def _render(rule: ParsedRule, modifier: Modifier, value: int) -> Edit:
    return (
        modifier.span.start,
        modifier.span.end,
        leading_whitespace(rule.source, modifier.span) + f"{modifier.name}:{value};",
    )


def _compensate(
    rule: ParsedRule,
    modifier: Modifier,
    number: int,
    target: int | None,
    partner: Modifier | None,
) -> tuple[list[Edit], dict[str, object] | None] | str:
    """Return the partner edits keeping the window's upper bound, or a diagnostic."""
    if partner is None:
        return [], None
    if partner.value is None or not partner.value.isdecimal():
        return (
            f"cannot compensate {partner.name}:{partner.value} for a lowered "
            f"{modifier.name}, so the positional window cannot be preserved"
        )
    partner_value = int(partner.value)
    compensated = partner_value + (number - (0 if target is None else target))
    maximum = MAXIMUM_BOUND[partner.name]
    if compensated > maximum:
        return (
            f"compensating {partner.name} to {compensated} exceeds the Suricata "
            f"maximum {maximum}, so the original window cannot be preserved"
        )
    record = {
        "constraint": partner.name,
        "option_index": option_index_of(rule, partner.span),
        "predicate_id": predicate_ids_for_option(
            rule, option_index_of(rule, partner.span)
        )[0],
        "from": partner_value,
        "to": compensated,
    }
    if compensated == partner_value:
        return [], record
    return [_render(rule, partner, compensated)], record


def _unsupported_operand(modifier: Modifier) -> str:
    """Explain why an operand this model cannot widen or remove was refused."""
    if modifier.value is not None and _SIGNED_OPERAND.fullmatch(modifier.value):
        # Suricata accepts a negative distance, which lets a match start before
        # the previous match ended. Halving or dropping it raises the lower
        # bound towards zero, so the usual widening moves are narrowings here.
        return (
            f"{modifier.name}:{modifier.value} is a signed operand, and lowering "
            "or removing it would raise the lower bound rather than widen it"
        )
    return (
        f"{modifier.name}:{modifier.value} is a variable or non-decimal operand "
        "this model cannot widen or safely remove"
    )


def _constraint_specifications(
    rule: ParsedRule,
    modifier: Modifier,
    tags: dict[str, object],
    partner: Modifier | None,
    *,
    fixture_name: str,
) -> list[MutationSpec | RejectedSpec]:
    if modifier.value is None or not modifier.value.isdecimal():
        return [
            rejected_spec(
                fixture_name=fixture_name,
                component="relative_constraint",
                operator=operator,
                params={**tags, "operation": operator},
                reason="unsupported",
                diagnostic=_unsupported_operand(modifier),
            )
            for operator in ("widen", "remove")
        ]

    number = int(modifier.value)
    specifications: list[MutationSpec | RejectedSpec] = []
    targets: list[tuple[str, int | None]] = [
        ("widen", value) for value in _widened_values(modifier.name, number)
    ]
    targets.append(("remove", None))
    for operator, target in targets:
        params = {
            **tags,
            "operation": operator,
            "from": number,
            "to": target,
            "direction": "broadening",
        }
        edits: list[Edit] = [
            (modifier.span.start, modifier.span.end, "")
            if target is None
            else _render(rule, modifier, target)
        ]
        compensation: dict[str, object] | None = None
        if modifier.name not in UPPER_BOUNDS:
            outcome = _compensate(rule, modifier, number, target, partner)
            if isinstance(outcome, str):
                specifications.append(
                    rejected_spec(
                        fixture_name=fixture_name,
                        component="relative_constraint",
                        operator=operator,
                        params=params,
                        reason="unsupported",
                        diagnostic=outcome,
                    )
                )
                continue
            partner_edits, compensation = outcome
            edits.extend(partner_edits)
        specifications.append(
            MutationSpec(
                component="relative_constraint",
                operator=operator,
                params={**params, "compensation": compensation},
                description=(
                    f"{operator.title()} this {modifier.name} lower bound and "
                    "compensate its positional window."
                    if compensation is not None
                    else f"{operator.title()} only this {modifier.name} constraint."
                ),
                rule=apply_edits(rule.source, edits),
            )
        )
    return specifications


def _relative_constraint_specifications(
    rule: ParsedRule, *, fixture_name: str
) -> list[MutationSpec | RejectedSpec]:
    specifications: list[MutationSpec | RejectedSpec] = []
    for group in rule.sticky_groups:
        for predicate in group.predicates:
            positional: dict[str, list[Modifier]] = {}
            for modifier in predicate.modifiers:
                if modifier.name in MAXIMUM_BOUND:
                    positional.setdefault(modifier.name, []).append(modifier)
            occurrences: dict[str, int] = {}
            for modifier in predicate.modifiers:
                if modifier.name not in MAXIMUM_BOUND:
                    continue
                occurrence = occurrences.get(modifier.name, 0)
                occurrences[modifier.name] = occurrence + 1
                option_index = option_index_of(rule, modifier.span)
                partner_name = LOWER_BOUND_PARTNERS.get(modifier.name)
                partners = positional.get(partner_name, []) if partner_name else []
                partner = partners[occurrence] if occurrence < len(partners) else None
                specifications.extend(
                    _constraint_specifications(
                        rule,
                        modifier,
                        {
                            **predicate_tags(predicate),
                            "predicate_id": predicate_ids_for_option(
                                rule, option_index
                            )[0],
                            "option_index": option_index,
                            "constraint": modifier.name,
                        },
                        partner,
                        fixture_name=fixture_name,
                    )
                )
    return specifications


def _widened_bsize(value: str) -> str | None:
    """Widen a recognized bsize comparison so the original size still matches."""
    condensed = value.strip()
    match = _BSIZE_RANGE.fullmatch(condensed)
    if match is not None:
        low = max(0, int(match.group("low")) - _BSIZE_MARGIN)
        return f"{low}<>{int(match.group('high')) + _BSIZE_MARGIN}"
    match = _BSIZE_COMPARISON.fullmatch(condensed)
    if match is not None:
        operator = match.group("operator")
        number = int(match.group("value"))
        widened = (
            max(0, number - _BSIZE_MARGIN)
            if operator.startswith(">")
            else number + _BSIZE_MARGIN
        )
        return f"{operator}{widened}"
    match = _BSIZE_EXACT.fullmatch(condensed)
    if match is not None:
        # `A<>B` excludes both endpoints, so the bounds sit one past the margin.
        # Below the margin there is no non-negative lower bound that still
        # includes the original size, so fall back to an upper bound alone.
        number = int(match.group("value"))
        if number > _BSIZE_MARGIN:
            return f"{number - _BSIZE_MARGIN - 1}<>{number + _BSIZE_MARGIN + 1}"
        return f"<{number + _BSIZE_MARGIN + 1}"
    return None


def _buffer_size_specifications(
    rule: ParsedRule, *, fixture_name: str
) -> list[MutationSpec | RejectedSpec]:
    specifications: list[MutationSpec | RejectedSpec] = []
    for group in rule.sticky_groups:
        for constraint in group.buffer_constraints:
            if constraint.name != "bsize":
                continue
            original = (constraint.value or "").strip()
            params = {
                "buffer": group.buffer,
                "option_index": constraint.option_index,
                "predicate_id": predicate_ids_for_option(
                    rule, constraint.option_index
                )[0],
                "operation": "widen",
                "direction": "broadening",
            }
            widened = _widened_bsize(original)
            if widened is None or widened == original:
                specifications.append(
                    rejected_spec(
                        fixture_name=fixture_name,
                        component="buffer_size",
                        operator="widen",
                        params=params,
                        reason="unsupported",
                        diagnostic=(
                            f"bsize value {constraint.value!r} uses a comparison "
                            "grammar this model does not recognize"
                            if widened is None
                            else f"bsize value {constraint.value!r} is already at its "
                            "widest recognized bound"
                        ),
                    )
                )
            else:
                specifications.append(
                    MutationSpec(
                        component="buffer_size",
                        operator="widen",
                        params={**params, "from": original, "to": widened},
                        description=f"Widen the {group.buffer} buffer size constraint.",
                        rule=replace_span(
                            rule.source,
                            constraint.span,
                            leading_whitespace(rule.source, constraint.span)
                            + f"bsize:{widened};",
                        ),
                    )
                )
            specifications.append(
                MutationSpec(
                    component="buffer_size",
                    operator="remove",
                    params={**params, "operation": "remove", "from": original},
                    description=f"Remove the {group.buffer} buffer size constraint.",
                    rule=remove_spans(rule.source, (constraint.span,)),
                )
            )
    return specifications


def generate(
    rule: ParsedRule, *, fixture_name: str
) -> tuple[MutationSpec | RejectedSpec, ...]:
    """Widen or remove one positional window while preserving its content."""
    return (
        *_relative_constraint_specifications(rule, fixture_name=fixture_name),
        *_buffer_size_specifications(rule, fixture_name=fixture_name),
    )


def _admits(bound: str, size: int) -> bool | None:
    """Return whether a bsize expression admits one exact buffer size."""
    condensed = bound.strip()
    match = _BSIZE_RANGE.fullmatch(condensed)
    if match is not None:
        return int(match.group("low")) < size < int(match.group("high"))
    match = _BSIZE_COMPARISON.fullmatch(condensed)
    if match is not None:
        operator, number = match.group("operator"), int(match.group("value"))
        return {
            ">": size > number,
            ">=": size >= number,
            "<": size < number,
            "<=": size <= number,
        }[operator]
    match = _BSIZE_EXACT.fullmatch(condensed)
    if match is not None:
        return size == int(match.group("value"))
    return None


def relax_to_bound(
    rule: ParsedRule, params: Mapping[str, object], *, fixture_name: str
) -> MutationSpec | RejectedSpec:
    """Replace an exact buffer size with a reviewed, strictly wider bound.

    The generic family only nudges `bsize` by a fixed margin or deletes it.  A
    rule whose `bsize` equals the length of its own URI literal publishes that
    layout fact, and the interesting middle ground is a bound loose enough to
    stop naming the length while still constraining the buffer.
    """
    predicate_id = params.get("predicate_id")
    bound = params.get("bound")
    if not isinstance(predicate_id, str) or not isinstance(bound, str):
        raise ValueError("buffer_size/relax_to_bound requires a predicate_id and bound")
    constraint = canonical_option(rule, predicate_id)
    if constraint.name != "bsize":
        raise ValueError(f"{predicate_id} is not a bsize option")
    original = (constraint.value or "").strip()
    identity: dict[str, object] = {
        "option_index": constraint.option_index,
        "predicate_id": predicate_id,
        "operation": "relax_to_bound",
        "direction": "broadening",
        "from": original,
        "to": bound,
    }
    exact = _BSIZE_EXACT.fullmatch(original)
    admits = _admits(bound, int(exact.group("value"))) if exact is not None else None
    if exact is None:
        return rejected_spec(
            fixture_name=fixture_name,
            component="buffer_size",
            operator="relax_to_bound",
            params=identity,
            reason="unsupported",
            diagnostic=(
                f"bsize value {original!r} is not an exact size, so containment of "
                "the original constraint cannot be established from the rule text"
            ),
        )
    if admits is None:
        return rejected_spec(
            fixture_name=fixture_name,
            component="buffer_size",
            operator="relax_to_bound",
            params=identity,
            reason="unsupported",
            diagnostic=(
                f"replacement bound {bound!r} uses a comparison grammar this model "
                "does not recognize"
            ),
        )
    if not admits or bound == original:
        return rejected_spec(
            fixture_name=fixture_name,
            component="buffer_size",
            operator="relax_to_bound",
            params=identity,
            reason="unsupported",
            diagnostic=(
                f"replacement bound {bound!r} does not admit the original exact "
                f"size {original}"
            ),
        )
    return MutationSpec(
        component="buffer_size",
        operator="relax_to_bound",
        params=identity,
        description=f"Relax the exact bsize {original} to the wider bound {bound}.",
        rule=replace_span(
            rule.source,
            constraint.span,
            leading_whitespace(rule.source, constraint.span) + f"bsize:{bound};",
        ),
    )


TARGETED_OPERATORS = {
    "buffer_size/relax_to_bound": relax_to_bound,
}
