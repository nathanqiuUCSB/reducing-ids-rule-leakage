"""Deterministic mutation analysis categories from component metadata."""

from __future__ import annotations

import re
from typing import Literal


AnalysisCategory = Literal["semantic", "representation", "performance"]

_COMBINATION_OPERATOR = re.compile(r"blocks_[2-8]")

# The analysis taxonomy is exactly these three mutually exclusive categories.
# Reporting that needs the mix of a combination's blocks groups them by this
# same order rather than inventing a fourth category.
ANALYSIS_CATEGORIES: tuple[AnalysisCategory, ...] = (
    "semantic",
    "representation",
    "performance",
)

# A combination is as strong as its strongest block: one semantic edit changes
# what the rule matches no matter what the other blocks do, and a representation
# edit outranks a purely performance-oriented one on the same reasoning.
_COMBINATION_PRECEDENCE: tuple[AnalysisCategory, ...] = ANALYSIS_CATEGORIES

_REPRESENTATION: frozenset[tuple[str, str]] = frozenset(
    {
        ("content", "literal_as_hex"),
        ("content", "hex_as_literal"),
        ("content", "split_adjacent"),
        # Clue-targeted representation edits: the matched bytes are identical,
        # only how the rule spells them changes.
        ("content", "partial_hex"),
        ("content", "split_at_token"),
        ("flowbits", "anonymize_name"),
        ("a_anchor", "split_a"),
        ("b_anchor", "split_b"),
        ("header", "split_4_4_4"),
    }
)

_PERFORMANCE: frozenset[tuple[str, str]] = frozenset(
    {
        ("content_modifier", "remove_fast_pattern"),
    }
)

_SEMANTIC: frozenset[tuple[str, str]] = frozenset(
    {
        ("baseline", "original"),
        ("content", "remove"),
        ("content", "shorten_prefix"),
        ("content", "shorten_suffix"),
        ("content", "retain_middle"),
        ("content", "retain_alternating"),
        # Clue-targeted semantic edits.
        ("content", "retain_boundary_prefix"),
        ("content", "retain_boundary_suffix"),
        ("content", "remove_with_relative_release"),
        ("content_modifier", "relax_startswith_to_depth"),
        ("destination_port", "broaden_group_members"),
        ("destination_port", "broaden_to_any"),
        ("flowbits", "remove_state_set"),
        ("pcre", "generalize_literal_run"),
        ("pcre", "widen_quantifier"),
        ("pcre", "broaden_character_class"),
        ("pcre", "remove_with_relative_release"),
        ("buffer_size", "relax_to_bound"),
        ("byte_test", "remove_window"),
        ("content_modifier", "remove_nocase"),
        ("content_modifier", "remove_startswith"),
        ("content_modifier", "remove_endswith"),
        ("destination_port", "small_list"),
        ("destination_port", "narrow_range"),
        ("destination_port", "broad_range"),
        ("destination_port", "any"),
        ("flow", "remove_established"),
        ("flow", "remove_direction"),
        ("flow", "remove"),
        ("sticky_buffer", "remove"),
        ("relative_constraint", "widen"),
        ("relative_constraint", "remove"),
        ("buffer_size", "widen"),
        ("buffer_size", "remove"),
        ("pcre", "remove"),
        ("pcre", "relax_start_anchor"),
        ("pcre", "relax_end_anchor"),
        ("negated_content", "remove"),
        ("byte_test", "widen"),
        ("byte_test", "remove"),
        ("byte_jump", "remove"),
        ("byte_extract", "remove"),
        ("byte_math", "remove"),
        ("isdataat", "remove"),
        ("a_anchor", "remove"),
        ("a_anchor", "truncate"),
        ("b_anchor", "remove"),
        ("b_anchor", "truncate"),
        ("flow", "established"),
        ("flow", "to_server"),
        ("header", "retain_first_8"),
        ("header", "retain_last_4"),
        ("port", "any"),
        ("port", "range"),
        ("position_window", "a_distance"),
    }
)


def classify_mutation_category(
    *,
    component: str,
    operator: str,
    params: dict[str, object],
) -> AnalysisCategory:
    """Return the analysis category for one mutation component/operator pair."""
    key = (component, operator)
    if key in _REPRESENTATION:
        return "representation"
    if key in _PERFORMANCE:
        direction = params.get("direction")
        if direction == "performance_only":
            return "performance"
        raise ValueError(
            f"unknown component/operator pair: {component}/{operator}"
        )
    if key in _SEMANTIC:
        return "semantic"
    if component == "combination" and _COMBINATION_OPERATOR.fullmatch(operator):
        return _combination_category(
            component=component, operator=operator, params=params
        )
    raise ValueError(f"unknown component/operator pair: {component}/{operator}")


def _combination_category(
    *,
    component: str,
    operator: str,
    params: dict[str, object],
) -> AnalysisCategory:
    categories = params.get("source_categories")
    if not isinstance(categories, list) or not categories:
        raise ValueError(
            f"{component}/{operator} requires a non-empty source_categories list "
            "in params"
        )
    unknown = [
        category for category in categories if category not in _COMBINATION_PRECEDENCE
    ]
    if unknown:
        raise ValueError(
            f"{component}/{operator} has unknown source_categories entries: "
            + ", ".join(repr(category) for category in unknown)
        )
    for category in _COMBINATION_PRECEDENCE:
        if category in categories:
            return category
    raise AssertionError("unreachable: every category is in the precedence order")
