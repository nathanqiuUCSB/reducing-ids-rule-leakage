from typing import get_args

import pytest

from hardening_game.mutations.taxonomy import (
    AnalysisCategory,
    classify_mutation_category,
)


def test_categories_are_exactly_the_three_analysis_categories() -> None:
    assert get_args(AnalysisCategory) == ("semantic", "representation", "performance")


@pytest.mark.parametrize(
    ("component", "operator", "params", "expected"),
    [
        ("content", "literal_as_hex", {}, "representation"),
        ("content", "hex_as_literal", {}, "representation"),
        ("content", "split_adjacent", {}, "representation"),
        (
            "content_modifier",
            "remove_fast_pattern",
            {"direction": "performance_only"},
            "performance",
        ),
        ("destination_port", "any", {}, "semantic"),
        ("content", "remove", {}, "semantic"),
        ("pcre", "relax_start_anchor", {}, "semantic"),
        ("baseline", "original", {}, "semantic"),
        (
            "combination",
            "blocks_2",
            {"source_categories": ["representation", "semantic"]},
            "semantic",
        ),
        (
            "combination",
            "blocks_2",
            {"source_categories": ["performance", "representation"]},
            "representation",
        ),
        (
            "combination",
            "blocks_2",
            {"source_categories": ["performance", "performance"]},
            "performance",
        ),
        (
            "combination",
            "blocks_8",
            {
                "source_categories": [
                    "performance",
                    "representation",
                    "semantic",
                    "semantic",
                    "representation",
                    "performance",
                    "semantic",
                    "representation",
                ]
            },
            "semantic",
        ),
    ],
)
def test_taxonomy(component, operator, params, expected):
    assert (
        classify_mutation_category(
            component=component, operator=operator, params=params
        )
        == expected
    )


def test_unknown_pair_raises() -> None:
    with pytest.raises(ValueError, match="unknown component/operator pair"):
        classify_mutation_category(
            component="unknown_component",
            operator="unknown_operator",
            params={},
        )


def test_out_of_range_combination_block_count_raises() -> None:
    with pytest.raises(ValueError, match="unknown component/operator pair"):
        classify_mutation_category(
            component="combination",
            operator="blocks_9",
            params={"source_categories": ["semantic"]},
        )


@pytest.mark.parametrize(
    "params",
    [
        {},
        {"source_categories": []},
        {"source_categories": "semantic"},
        {"source_categories": ["semantic", "combination"]},
        {"source_categories": ["semantic", None]},
    ],
)
def test_combination_without_usable_source_categories_raises(params) -> None:
    with pytest.raises(ValueError, match="source_categories"):
        classify_mutation_category(
            component="combination", operator="blocks_2", params=params
        )
