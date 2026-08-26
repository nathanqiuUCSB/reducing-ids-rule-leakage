"""Individual removal of non-positional content modifiers."""

from __future__ import annotations

from typing import Mapping

from hardening_game.mutations.families import (
    canonical_modifier,
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
from hardening_game.suricata.rule_model import ParsedRule


# Removing nocase makes matching case sensitive, so it is the one modelled
# narrowing edit. fast_pattern selects the prefilter pattern only, so removing
# it changes matching performance rather than which payloads the rule matches.
REMOVABLE_MODIFIERS = {
    "nocase": "narrowing",
    "startswith": "broadening",
    "endswith": "broadening",
    "fast_pattern": "performance_only",
}


def generate(
    rule: ParsedRule, *, fixture_name: str
) -> tuple[MutationSpec | RejectedSpec, ...]:
    """Remove one recognized content modifier at a time."""
    specifications: list[MutationSpec | RejectedSpec] = []
    for group in rule.sticky_groups:
        for predicate in group.predicates:
            for modifier in predicate.modifiers:
                direction = REMOVABLE_MODIFIERS.get(modifier.name)
                if direction is None:
                    continue
                option_index = option_index_of(rule, modifier.span)
                specifications.append(
                    MutationSpec(
                        component="content_modifier",
                        operator=f"remove_{modifier.name}",
                        params={
                            **predicate_tags(predicate),
                            "predicate_id": predicate_ids_for_option(
                                rule, option_index
                            )[0],
                            "option_index": option_index,
                            "modifier": modifier.name,
                            "operation": "remove",
                            "direction": direction,
                        },
                        description=f"Remove only the {modifier.name} modifier.",
                        rule=remove_spans(rule.source, (modifier.span,)),
                    )
                )
    return tuple(specifications)


def relax_startswith_to_depth(
    rule: ParsedRule, params: Mapping[str, object], *, fixture_name: str
) -> MutationSpec | RejectedSpec:
    """Trade a buffer-start anchor for a wider leading window.

    `startswith` requires the content at offset zero.  `depth:N` with
    `N >= len(content)` requires it to end within the first N bytes, which is a
    strict superset, so the baseline traffic still matches while the attacker
    loses the "this is the request root" statement.
    """
    predicate_id = params.get("predicate_id")
    if not isinstance(predicate_id, str):
        raise ValueError("content_modifier operators require a predicate_id")
    predicate, modifier = canonical_modifier(rule, predicate_id)
    if modifier.name != "startswith":
        raise ValueError(f"{predicate_id} is not a startswith modifier")
    depth = params.get("depth")
    if not isinstance(depth, int) or isinstance(depth, bool) or depth < 1:
        raise ValueError(
            "content_modifier/relax_startswith_to_depth requires a positive depth"
        )
    option_index = option_index_of(rule, modifier.span)
    identity: dict[str, object] = {
        **predicate_tags(predicate),
        "predicate_id": predicate_ids_for_option(rule, option_index)[0],
        "option_index": option_index,
        "modifier": modifier.name,
        "operation": "relax_startswith_to_depth",
        "direction": "broadening",
        "to": depth,
    }
    length = len(predicate.value) if predicate.value is not None else None
    conflicting = sorted(
        other.name
        for other in predicate.modifiers
        if other.name in {"offset", "depth", "endswith"}
    )
    if length is None or depth < length:
        return rejected_spec(
            fixture_name=fixture_name,
            component="content_modifier",
            operator="relax_startswith_to_depth",
            params=identity,
            reason="unsupported",
            diagnostic=(
                f"depth {depth} cannot admit the {length} content bytes the "
                "startswith anchor already accepted"
                if length is not None
                else "content bytes are undecodable, so no depth preserves the match"
            ),
        )
    if conflicting:
        return rejected_spec(
            fixture_name=fixture_name,
            component="content_modifier",
            operator="relax_startswith_to_depth",
            params=identity,
            reason="structural",
            diagnostic=(
                "this content already carries a competing positional modifier: "
                + ", ".join(conflicting)
            ),
        )
    return MutationSpec(
        component="content_modifier",
        operator="relax_startswith_to_depth",
        params=identity,
        description=(
            f"Replace the startswith anchor with depth:{depth} so the content may "
            "appear anywhere in the leading window."
        ),
        rule=replace_span(
            rule.source,
            modifier.span,
            leading_whitespace(rule.source, modifier.span) + f"depth:{depth};",
        ),
    )


TARGETED_OPERATORS = {
    "content_modifier/relax_startswith_to_depth": relax_startswith_to_depth,
}
