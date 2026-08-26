"""Dependency groups for safe source-span mutations."""

from __future__ import annotations

from dataclasses import dataclass

from hardening_game.suricata.rule_model import Modifier, ParsedRule, Span


@dataclass(frozen=True)
class DependencyGroup:
    predicate_id: str
    buffer: str
    spans: tuple[Span, ...]
    remove_sticky_buffer: bool


def content_dependency_group(
    rule: ParsedRule, predicate_id: str
) -> DependencyGroup:
    """Return the semantic component removed with a content predicate."""
    for group in rule.sticky_groups:
        for predicate in group.predicates:
            if predicate.predicate_id != predicate_id:
                continue
            remove_sticky = (
                group.declaration is not None
                and len(group.predicates) == 1
                and not group.buffer_constraints
                and not group.scoped_options
            )
            spans = (
                ((group.declaration.span,) if remove_sticky else ())
                + (predicate.span,)
                + tuple(modifier.span for modifier in predicate.modifiers)
            )
            return DependencyGroup(
                predicate_id=predicate_id,
                buffer=group.buffer,
                spans=spans,
                remove_sticky_buffer=remove_sticky,
            )
    raise KeyError(f"unknown content predicate: {predicate_id}")


def downstream_endpoint_consumers(
    rule: ParsedRule, predicate_id: str
) -> tuple[Modifier, ...]:
    """Return following-content distance/within modifiers anchored to this match."""
    for group in rule.sticky_groups:
        for index, predicate in enumerate(group.predicates):
            if predicate.predicate_id != predicate_id:
                continue
            if index + 1 == len(group.predicates):
                return ()
            return tuple(
                modifier
                for modifier in group.predicates[index + 1].modifiers
                if modifier.name in {"distance", "within"}
            )
    raise KeyError(f"unknown content predicate: {predicate_id}")
