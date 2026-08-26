from pathlib import Path

import pytest

from hardening_game.mutations.engine import generate_generic_candidates
from hardening_game.mutations.families import byte_predicates as byte_family
from hardening_game.mutations.families import content as content_family
from hardening_game.mutations.families import flowbits as flowbits_family
from hardening_game.mutations.families import modifiers as modifier_family
from hardening_game.mutations.families import pcre as pcre_family
from hardening_game.mutations.families import ports as port_family
from hardening_game.mutations.families import position as position_family
from hardening_game.mutations.specifications import (
    CandidateSet,
    MutationSpec,
    RejectedSpec,
)
from hardening_game.suricata.rule_model import parse_suricata_rule
from hardening_game.suricata.validate import replay_rule, syntax_check_rule


CONTENT_RULE = 'alert tcp any any -> any any (content:"abcdefgh"; sid:1; rev:1;)'
SMART_INSTALL_RULE = (
    'alert tcp any any -> $HOME_NET 4786 (flow:established,to_server; '
    'content:"|00 00 00 01 00 00 00 01 00 00 00 07|"; depth:12; '
    'content:"' + "A" * 36 + '"; distance:12; within:36; '
    'content:"' + "B" * 44 + '"; distance:4; within:44; '
    "sid:2025472; rev:1;)"
)


def _generate(rule: str, *, fixture_name: str = "family") -> CandidateSet:
    return generate_generic_candidates(rule, revision=1, fixture_name=fixture_name)


def _rules_by_operator(generated: CandidateSet, component: str) -> dict[str, str]:
    return {
        candidate.operator: candidate.rule
        for candidate in generated.accepted
        if candidate.component == component
    }


def _operators(generated: CandidateSet, component: str) -> set[str]:
    return {
        candidate.operator
        for candidate in generated.accepted
        if candidate.component == component
    }


def test_numeric_port_generates_controlled_broadening_levels() -> None:
    rule = (
        "alert tcp any any -> $HOME_NET 873 "
        '(flow:established,to_server; content:"@RSYNCD:"; sid:1; rev:1;)'
    )
    generated = generate_generic_candidates(rule, revision=1, fixture_name="rsync")
    rules = {
        candidate.operator: candidate.rule
        for candidate in generated.accepted
        if candidate.component == "destination_port"
    }
    assert "-> $HOME_NET [873,874] (" in rules["small_list"]
    assert "-> $HOME_NET 871:875 (" in rules["narrow_range"]
    assert "-> $HOME_NET 865:881 (" in rules["broad_range"]
    assert "-> $HOME_NET any (" in rules["any"]


def test_low_numeric_port_broadening_clamps_to_port_zero() -> None:
    generated = _generate('alert tcp any any -> $HOME_NET 1 (content:"a"; sid:1; rev:1;)')

    rules = _rules_by_operator(generated, "destination_port")

    assert "-> $HOME_NET 0:3 (" in rules["narrow_range"]
    assert "-> $HOME_NET 0:9 (" in rules["broad_range"]


def test_port_zero_broadening_preserves_the_baseline_port() -> None:
    generated = _generate('alert tcp any any -> $HOME_NET 0 (content:"a"; sid:1; rev:1;)')

    rules = _rules_by_operator(generated, "destination_port")

    assert "-> $HOME_NET [0,1] (" in rules["small_list"]
    assert "-> $HOME_NET 0:2 (" in rules["narrow_range"]
    assert "-> $HOME_NET 0:8 (" in rules["broad_range"]


def test_range_and_variable_destination_ports_are_rejected_rather_than_skipped() -> None:
    for port in ("873:875", "$HTTP_PORTS", "!80"):
        generated = _generate(
            f'alert tcp any any -> $HOME_NET {port} (content:"a"; sid:1; rev:1;)'
        )

        assert not _operators(generated, "destination_port"), port
        rejection = next(
            rejection
            for rejection in generated.rejected
            if rejection.component == "destination_port"
        )
        assert rejection.reason == "unsupported"
        assert port in rejection.diagnostic


def test_any_destination_port_yields_no_broadening_and_no_rejection() -> None:
    generated = _generate('alert tcp any any -> $HOME_NET any (content:"a"; sid:1; rev:1;)')

    assert not _operators(generated, "destination_port")
    assert not any(
        rejection.component == "destination_port" for rejection in generated.rejected
    )


def test_non_numeric_destination_port_is_rejected_rather_than_guessed() -> None:
    generated = _generate(
        'alert tcp any any -> $HOME_NET [$HTTP_PORTS,5432] (content:"a"; sid:1; rev:1;)'
    )

    assert not _operators(generated, "destination_port")
    rejection = next(
        rejection
        for rejection in generated.rejected
        if rejection.component == "destination_port"
    )
    assert rejection.reason == "unsupported"
    assert "[$HTTP_PORTS,5432]" in rejection.diagnostic


def test_content_retention_covers_prefix_suffix_middle_and_alternating() -> None:
    generated = generate_generic_candidates(
        'alert tcp any any -> any any (content:"abcdefgh"; sid:1; rev:1;)',
        revision=1,
        fixture_name="content-example",
    )
    operators = {
        candidate.operator
        for candidate in generated.accepted
        if candidate.component == "content"
    }
    assert {
        "shorten_prefix",
        "shorten_suffix",
        "retain_middle",
        "retain_alternating",
    } <= operators


def test_prefix_suffix_and_middle_retention_render_exact_fractions() -> None:
    generated = _generate(CONTENT_RULE)
    rendered = {
        (candidate.operator, candidate.params["retained_fraction"]): candidate.rule
        for candidate in generated.accepted
        if candidate.component == "content"
        and candidate.operator in {"shorten_prefix", "shorten_suffix", "retain_middle"}
    }

    assert 'content:"abcdef";' in rendered[("shorten_prefix", 0.75)]
    assert 'content:"abcd";' in rendered[("shorten_prefix", 0.5)]
    assert 'content:"cdefgh";' in rendered[("shorten_suffix", 0.75)]
    assert 'content:"gh";' in rendered[("shorten_suffix", 0.25)]
    assert 'content:"bcdefg";' in rendered[("retain_middle", 0.75)]
    assert 'content:"de";' in rendered[("retain_middle", 0.25)]


def test_alternating_retention_keeps_absolute_positions_with_distances() -> None:
    generated = _generate(CONTENT_RULE)
    rendered = {
        candidate.params["retained_fraction"]: candidate.rule
        for candidate in generated.accepted
        if candidate.operator == "retain_alternating"
    }

    assert 'content:"abc"; content:"efg"; distance:1; within:3;' in rendered[0.75]
    assert 'content:"ab"; content:"ef"; distance:2; within:2;' in rendered[0.5]
    assert 'content:"a"; content:"e"; distance:3; within:1;' in rendered[0.25]


def test_adjacent_split_preserves_byte_order_and_adjacency() -> None:
    generated = _generate(CONTENT_RULE)

    split = next(
        candidate
        for candidate in generated.accepted
        if candidate.operator == "split_adjacent"
    )

    assert 'content:"abcd"; content:"efgh"; distance:0; within:4;' in split.rule


def test_adjacent_split_propagates_nocase_to_the_trailing_fragment() -> None:
    generated = _generate(
        'alert http any any -> any any (http.uri; content:"abcd"; nocase; sid:1; rev:1;)'
    )

    split = next(
        candidate
        for candidate in generated.accepted
        if candidate.operator == "split_adjacent"
    )

    assert (
        'content:"ab"; nocase; content:"cd"; distance:0; within:2; nocase;' in split.rule
    )


def test_adjacent_split_of_endswith_content_is_rejected() -> None:
    generated = _generate(
        'alert http any any -> any any (http.uri; content:"abcd"; endswith; sid:1; rev:1;)'
    )

    assert not any(
        candidate.operator == "split_adjacent" for candidate in generated.accepted
    )
    assert any(
        rejection.component == "content"
        and rejection.operator == "split_adjacent"
        and rejection.reason == "structural"
        for rejection in generated.rejected
    )


def test_printable_pure_hex_content_converts_to_an_equivalent_literal() -> None:
    generated = _generate('alert tcp any any -> any any (content:"|41 42 43|"; sid:1; rev:1;)')

    converted = next(
        candidate
        for candidate in generated.accepted
        if candidate.operator == "hex_as_literal"
    )

    assert 'content:"ABC";' in converted.rule


def test_unprintable_hex_content_is_not_converted_to_a_literal() -> None:
    generated = _generate('alert tcp any any -> any any (content:"|00 ff|"; sid:1; rev:1;)')

    assert not any(
        candidate.operator == "hex_as_literal" for candidate in generated.accepted
    )


def test_literal_content_converts_to_equivalent_hex() -> None:
    generated = _generate('alert tcp any any -> any any (content:"ABC"; sid:1; rev:1;)')

    converted = next(
        candidate
        for candidate in generated.accepted
        if candidate.operator == "literal_as_hex"
    )

    assert 'content:"|41 42 43|";' in converted.rule


def test_negated_content_representation_change_preserves_the_negation() -> None:
    generated = _generate(
        'alert http any any -> any any (http.header_names; '
        'content:!"Referer|0d 0a|"; sid:1; rev:1;)'
    )

    converted = next(
        candidate
        for candidate in generated.accepted
        if candidate.operator == "literal_as_hex"
    )

    assert 'content:!"|52 65 66 65 72 65 72 0d 0a|";' in converted.rule


def test_negated_content_retention_is_rejected_as_unsupported() -> None:
    generated = _generate(
        'alert http any any -> any any (http.header_names; '
        'content:!"Referer|0d 0a|"; sid:1; rev:1;)'
    )

    assert not any(
        candidate.operator
        in {"shorten_prefix", "shorten_suffix", "retain_middle", "retain_alternating", "split_adjacent"}
        for candidate in generated.accepted
    )
    assert any(
        rejection.component == "content"
        and rejection.operator == "shorten_prefix"
        and rejection.reason == "unsupported"
        and "negated" in rejection.diagnostic
        for rejection in generated.rejected
    )


def test_negated_content_removal_is_its_own_family_operation() -> None:
    generated = _generate(
        'alert http any any -> any any (http.header_names; '
        'content:!"Referer|0d 0a|"; sid:1; rev:1;)'
    )

    removed = next(
        candidate
        for candidate in generated.accepted
        if candidate.component == "negated_content" and candidate.operator == "remove"
    )

    assert "content:!" not in removed.rule
    assert not any(
        candidate.component == "content" and candidate.operator == "remove"
        for candidate in generated.accepted
    )


def test_modifier_removal_covers_nocase_startswith_and_fast_pattern() -> None:
    generated = _generate(
        'alert http any any -> any any (http.uri; content:"/abc"; nocase; '
        "startswith; fast_pattern; sid:1; rev:1;)"
    )
    rules = _rules_by_operator(generated, "content_modifier")

    assert "nocase;" not in rules["remove_nocase"]
    assert "startswith;" in rules["remove_nocase"]
    assert "startswith;" not in rules["remove_startswith"]
    assert "fast_pattern;" not in rules["remove_fast_pattern"]
    assert 'content:"/abc";' in rules["remove_fast_pattern"]


def test_endswith_modifier_removal_is_generated() -> None:
    generated = _generate(
        'alert http any any -> any any (http.uri; content:"/abc"; endswith; sid:1; rev:1;)'
    )
    rules = _rules_by_operator(generated, "content_modifier")

    assert "endswith;" not in rules["remove_endswith"]


def test_modifier_removal_records_its_semantic_direction() -> None:
    generated = _generate(
        'alert http any any -> any any (http.uri; content:"/abc"; nocase; '
        "startswith; fast_pattern; sid:1; rev:1;)"
    )
    directions = {
        candidate.operator: candidate.params["direction"]
        for candidate in generated.accepted
        if candidate.component == "content_modifier"
    }

    assert directions == {
        "remove_nocase": "narrowing",
        "remove_startswith": "broadening",
        "remove_fast_pattern": "performance_only",
    }


def test_endswith_modifier_removal_is_labelled_broadening() -> None:
    generated = _generate(
        'alert http any any -> any any (http.uri; content:"/abc"; endswith; sid:1; rev:1;)'
    )

    candidate = next(
        candidate
        for candidate in generated.accepted
        if candidate.operator == "remove_endswith"
    )

    assert candidate.params["direction"] == "broadening"


def test_bsize_widening_and_removal_are_generated() -> None:
    generated = _generate(
        'alert http any any -> any any (http.uri; bsize:11; content:"/hedwig.cgi"; '
        "sid:1; rev:1;)"
    )
    rules = _rules_by_operator(generated, "buffer_size")

    assert "bsize:7<>15;" in rules["widen"]
    assert "bsize:" not in rules["remove"]
    assert 'content:"/hedwig.cgi";' in rules["remove"]


def test_every_bsize_position_spec_uses_its_physical_canonical_predicate_id() -> None:
    parsed = parse_suricata_rule(
        'alert http any any -> any any (http.uri; bsize:11; content:"/one"; '
        'http.request_body; bsize:mylen; content:"two"; sid:1; rev:1;)'
    )

    specifications = [
        specification
        for specification in position_family.generate(parsed, fixture_name="bsize-ids")
        if specification.component == "buffer_size"
    ]

    assert specifications
    expected_by_option = {1: "bsize-0", 4: "bsize-1"}
    assert all(
        specification.params["predicate_id"]
        == expected_by_option[specification.params["option_index"]]
        for specification in specifications
    )
    assert any(isinstance(item, MutationSpec) for item in specifications)
    assert any(isinstance(item, RejectedSpec) for item in specifications)


def test_exact_bsize_zero_widening_still_matches_an_empty_buffer() -> None:
    generated = _generate(
        'alert http any any -> any any (http.uri; bsize:0; content:"/x"; sid:1; rev:1;)'
    )

    assert "bsize:<4;" in _rules_by_operator(generated, "buffer_size")["widen"]


def test_buffer_size_variants_are_labelled_broadening() -> None:
    generated = _generate(
        'alert http any any -> any any (http.uri; bsize:11; content:"/x"; sid:1; rev:1;)'
    )

    assert {
        candidate.params["direction"]
        for candidate in generated.accepted
        if candidate.component == "buffer_size"
    } == {"broadening"}


def test_bounded_bsize_comparison_widens_in_the_same_direction() -> None:
    generated = _generate(
        'alert http any any -> any any (http.uri; bsize:>10; content:"/x"; sid:1; rev:1;)'
    )

    assert "bsize:>7;" in _rules_by_operator(generated, "buffer_size")["widen"]


def test_unrecognized_bsize_grammar_is_rejected_but_removal_survives() -> None:
    generated = _generate(
        'alert http any any -> any any (http.uri; bsize:mylen; content:"/x"; sid:1; rev:1;)'
    )

    assert "widen" not in _operators(generated, "buffer_size")
    assert "remove" in _operators(generated, "buffer_size")
    assert any(
        rejection.component == "buffer_size"
        and rejection.operator == "widen"
        and rejection.reason == "unsupported"
        for rejection in generated.rejected
    )


def test_upper_bound_positional_constraints_widen_and_remove_without_touching_content() -> None:
    generated = _generate(
        'alert tcp any any -> any any (content:"ab"; content:"cd"; distance:12; '
        "within:20; sid:1; rev:1;)"
    )
    widened = {
        (candidate.params["constraint"], candidate.params["to"]): candidate.rule
        for candidate in generated.accepted
        if candidate.component == "relative_constraint"
        and candidate.operator == "widen"
    }

    assert "within:40;" in widened[("within", 40)]
    assert "within:80;" in widened[("within", 80)]
    assert all('content:"cd";' in rule for rule in widened.values())


def test_repeated_modifier_and_constraint_specs_use_occurrence_predicate_ids() -> None:
    parsed = parse_suricata_rule(
        'alert tcp any any -> any any (content:"a"; content:"b"; '
        "distance:1; within:10; distance:2; within:20; "
        "nocase; nocase; sid:1; rev:1;)"
    )
    position_specs = [
        item
        for item in position_family.generate(parsed, fixture_name="repeated-position")
        if item.component == "relative_constraint"
    ]
    modifier_specs = [
        item
        for item in modifier_family.generate(parsed, fixture_name="repeated-modifier")
        if item.component == "content_modifier"
    ]

    expected_position_ids = {
        2: "content-1-distance",
        3: "content-1-within",
        4: "content-1-distance-1",
        5: "content-1-within-1",
    }
    assert {
        (item.params["option_index"], item.params["predicate_id"])
        for item in position_specs
    } == set(expected_position_ids.items())
    assert {
        (
            item.params["option_index"],
            item.params["compensation"]["predicate_id"],
        )
        for item in position_specs
        if item.params["constraint"] == "distance"
        and item.params["compensation"] is not None
    } == {
        (2, "content-1-within"),
        (4, "content-1-within-1"),
    }
    assert {
        (item.params["option_index"], item.params["predicate_id"])
        for item in modifier_specs
    } == {
        (6, "content-1-nocase"),
        (7, "content-1-nocase-1"),
    }


def test_lowering_distance_compensates_within_to_keep_the_original_window() -> None:
    generated = _generate(
        'alert tcp any any -> any any (content:"ab"; content:"cd"; distance:12; '
        "within:20; sid:1; rev:1;)"
    )
    widened = {
        candidate.params["to"]: candidate
        for candidate in generated.accepted
        if candidate.component == "relative_constraint"
        and candidate.operator == "widen"
        and candidate.params["constraint"] == "distance"
    }

    assert "distance:6; within:26;" in widened[6].rule
    assert "distance:0; within:32;" in widened[0].rule
    assert widened[6].params["compensation"] == {
        "constraint": "within",
        "option_index": 3,
        "predicate_id": "content-1-within",
        "from": 20,
        "to": 26,
    }


def test_removing_distance_compensates_within_to_keep_the_original_window() -> None:
    generated = _generate(
        'alert tcp any any -> any any (content:"ab"; content:"cd"; distance:12; '
        "within:20; sid:1; rev:1;)"
    )

    removed = next(
        candidate
        for candidate in generated.accepted
        if candidate.component == "relative_constraint"
        and candidate.operator == "remove"
        and candidate.params["constraint"] == "distance"
    )

    assert "distance:" not in removed.rule
    assert "within:32;" in removed.rule
    assert removed.params["compensation"]["to"] == 32


def test_lowering_offset_compensates_depth_to_keep_the_original_window() -> None:
    generated = _generate(
        'alert tcp any any -> any any (content:"ab"; offset:4; depth:10; sid:1; rev:1;)'
    )
    widened = {
        candidate.params["to"]: candidate.rule
        for candidate in generated.accepted
        if candidate.component == "relative_constraint"
        and candidate.operator == "widen"
        and candidate.params["constraint"] == "offset"
    }

    assert "offset:2; depth:12;" in widened[2]
    assert "offset:0; depth:14;" in widened[0]


def test_removing_offset_compensates_depth_to_keep_the_original_window() -> None:
    generated = _generate(
        'alert tcp any any -> any any (content:"ab"; offset:4; depth:10; sid:1; rev:1;)'
    )

    removed = next(
        candidate
        for candidate in generated.accepted
        if candidate.component == "relative_constraint"
        and candidate.operator == "remove"
        and candidate.params["constraint"] == "offset"
    )

    assert "offset:" not in removed.rule
    assert "depth:14;" in removed.rule


def test_lower_bound_without_a_paired_upper_bound_needs_no_compensation() -> None:
    generated = _generate(
        'alert tcp any any -> any any (content:"ab"; offset:4; sid:1; rev:1;)'
    )

    removed = next(
        candidate
        for candidate in generated.accepted
        if candidate.params.get("constraint") == "offset"
        and candidate.operator == "remove"
    )

    assert removed.params["compensation"] is None
    assert "offset:" not in removed.rule


def test_positional_variants_are_labelled_broadening() -> None:
    generated = _generate(
        'alert tcp any any -> any any (content:"ab"; offset:4; depth:10; sid:1; rev:1;)'
    )

    assert {
        candidate.params["direction"]
        for candidate in generated.accepted
        if candidate.component == "relative_constraint"
    } == {"broadening"}


def test_upper_bound_widening_clamps_to_the_suricata_maximum() -> None:
    generated = _generate(
        'alert tcp any any -> any any (content:"ab"; depth:40000; sid:1; rev:1;)'
    )
    widened = [
        candidate
        for candidate in generated.accepted
        if candidate.operator == "widen" and candidate.params["constraint"] == "depth"
    ]

    assert [candidate.params["to"] for candidate in widened] == [65535]
    assert "depth:65535;" in widened[0].rule


def test_uncompensatable_lower_bound_edit_is_rejected_rather_than_widened() -> None:
    generated = _generate(
        'alert tcp any any -> any any (content:"ab"; offset:4; depth:65534; sid:1; rev:1;)'
    )

    assert not any(
        candidate.params.get("constraint") == "offset"
        for candidate in generated.accepted
    )
    rejections = [
        rejection
        for rejection in generated.rejected
        if rejection.component == "relative_constraint"
        and rejection.params["constraint"] == "offset"
    ]
    assert {rejection.operator for rejection in rejections} == {"widen", "remove"}
    assert all(rejection.reason == "unsupported" for rejection in rejections)
    assert all("65535" in rejection.diagnostic for rejection in rejections)


def test_within_widening_clamps_to_the_suricata_maximum() -> None:
    generated = _generate(
        'alert tcp any any -> any any (content:"ab"; content:"cd"; '
        "within:600000; sid:1; rev:1;)"
    )
    widened = [
        candidate
        for candidate in generated.accepted
        if candidate.operator == "widen" and candidate.params["constraint"] == "within"
    ]

    assert [candidate.params["to"] for candidate in widened] == [1048576]
    assert "within:1048576;" in widened[0].rule
    assert syntax_check_rule(widened[0].rule).valid


def test_compensation_beyond_the_within_maximum_is_rejected() -> None:
    generated = _generate(
        'alert tcp any any -> any any (content:"ab"; content:"cd"; '
        "distance:1000000; within:100000; sid:1; rev:1;)"
    )
    accepted = [
        candidate
        for candidate in generated.accepted
        if candidate.params.get("constraint") == "distance"
    ]
    rejected = [
        rejection
        for rejection in generated.rejected
        if rejection.params.get("constraint") == "distance"
    ]

    assert [candidate.params["to"] for candidate in accepted] == [500000]
    assert "distance:500000; within:600000;" in accepted[0].rule
    assert syntax_check_rule(accepted[0].rule).valid
    assert [(rejection.operator, rejection.params["to"]) for rejection in rejected] == [
        ("widen", 0),
        ("remove", None),
    ]
    assert all("1048576" in rejection.diagnostic for rejection in rejected)


def test_every_accepted_positional_edge_candidate_passes_syntax() -> None:
    for rule in (
        'alert tcp any any -> any any (content:"ab"; content:"cd"; '
        "within:600000; sid:1; rev:1;)",
        'alert tcp any any -> any any (content:"ab"; content:"cd"; '
        "distance:1000000; within:100000; sid:1; rev:1;)",
        'alert tcp any any -> any any (content:"ab"; offset:65000; depth:400; '
        "sid:1; rev:1;)",
    ):
        generated = _generate(rule)
        for candidate in generated.accepted:
            assert syntax_check_rule(candidate.rule).valid, candidate.rule


def test_negative_distance_is_rejected_as_a_signed_operand() -> None:
    generated = _generate(
        'alert tcp any any -> any any (content:"ab"; content:"cd"; '
        "distance:-5; sid:1; rev:1;)"
    )

    rejections = [
        rejection
        for rejection in generated.rejected
        if rejection.component == "relative_constraint"
    ]

    assert {rejection.operator for rejection in rejections} == {"widen", "remove"}
    assert all("signed" in rejection.diagnostic for rejection in rejections)
    assert all("variable" not in rejection.diagnostic for rejection in rejections)


def test_non_decimal_positional_operand_is_rejected_rather_than_skipped() -> None:
    generated = _generate(
        'alert tcp any any -> any any (content:"ab"; content:"cd"; '
        "distance:mylen; sid:1; rev:1;)"
    )

    rejections = [
        rejection
        for rejection in generated.rejected
        if rejection.component == "relative_constraint"
    ]

    assert {rejection.operator for rejection in rejections} == {"widen", "remove"}
    assert all(rejection.reason == "unsupported" for rejection in rejections)
    assert all("mylen" in rejection.diagnostic for rejection in rejections)


def test_non_decimal_partner_blocks_only_the_lower_bound_edit() -> None:
    generated = _generate(
        'alert tcp any any -> any any (content:"ab"; content:"cd"; distance:12; '
        "within:mylen; sid:1; rev:1;)"
    )

    blocked = [
        rejection
        for rejection in generated.rejected
        if rejection.component == "relative_constraint"
        and rejection.params["constraint"] == "distance"
    ]

    assert {rejection.operator for rejection in blocked} == {"widen", "remove"}
    assert all("within" in rejection.diagnostic for rejection in blocked)


def test_pcre_removal_is_generated_when_nothing_depends_on_it() -> None:
    generated = _generate(
        'alert http any any -> any any (http.uri; content:"/x"; pcre:"/^abc/R"; '
        "sid:1; rev:1;)"
    )

    removed = next(
        candidate
        for candidate in generated.accepted
        if candidate.component == "pcre" and candidate.operator == "remove"
    )

    assert "pcre:" not in removed.rule
    assert 'content:"/x";' in removed.rule


def test_pcre_removal_is_rejected_when_a_following_content_is_relative() -> None:
    generated = _generate(
        'alert http any any -> any any (http.uri; content:"/x"; pcre:"/^abc/R"; '
        'content:"y"; distance:0; sid:1; rev:1;)'
    )

    assert not any(
        candidate.component == "pcre" and candidate.operator == "remove"
        for candidate in generated.accepted
    )
    assert any(
        rejection.component == "pcre"
        and rejection.operator == "remove"
        and rejection.reason == "structural"
        and "distance" in rejection.diagnostic
        for rejection in generated.rejected
    )


def test_pcre_start_and_end_anchors_relax_independently() -> None:
    generated = _generate(
        'alert http any any -> any any (http.uri; content:"/x"; pcre:"/^abc$/Ui"; '
        "sid:1; rev:1;)"
    )
    rules = _rules_by_operator(generated, "pcre")

    assert 'pcre:"/abc$/Ui";' in rules["relax_start_anchor"]
    assert 'pcre:"/^abc/Ui";' in rules["relax_end_anchor"]


def test_unrecognized_pcre_grammar_rejects_anchor_relaxation() -> None:
    generated = _generate(
        'alert http any any -> any any (http.uri; content:"/x"; pcre:!"/abc/"; '
        "sid:1; rev:1;)"
    )

    assert "relax_start_anchor" not in _operators(generated, "pcre")
    assert any(
        rejection.component == "pcre"
        and rejection.operator == "relax_anchor"
        and rejection.reason == "unsupported"
        for rejection in generated.rejected
    )


def test_byte_test_removal_and_threshold_widening_are_generated() -> None:
    generated = _generate(
        'alert tcp any any -> any any (content:"|00|"; '
        "byte_test:4,>,16,9,relative,little; byte_test:4,<,65,9,relative,little; "
        "sid:1; rev:1;)"
    )
    widened = [
        candidate.rule
        for candidate in generated.accepted
        if candidate.component == "byte_test" and candidate.operator == "widen"
    ]
    removed = [
        candidate.rule
        for candidate in generated.accepted
        if candidate.component == "byte_test" and candidate.operator == "remove"
    ]

    assert any("byte_test:4,>,8,9,relative,little;" in rule for rule in widened)
    assert any("byte_test:4,<,130,9,relative,little;" in rule for rule in widened)
    assert len(removed) == 2
    assert any(
        "byte_test:4,>,16,9,relative,little;" not in rule
        and "byte_test:4,<,65,9,relative,little;" in rule
        for rule in removed
    )


def test_bitmask_byte_test_widening_is_rejected_but_removal_survives() -> None:
    generated = _generate(
        'alert tcp any any -> any any (content:"|00|"; '
        "byte_test:1,&,0x80,0,relative; sid:1; rev:1;)"
    )

    assert "widen" not in _operators(generated, "byte_test")
    assert "remove" in _operators(generated, "byte_test")
    assert any(
        rejection.component == "byte_test"
        and rejection.operator == "widen"
        and rejection.reason == "unsupported"
        for rejection in generated.rejected
    )


def test_unmodelled_byte_options_are_recorded_as_rejections() -> None:
    generated = _generate(
        'alert tcp any any -> any any (content:"|00|"; '
        "byte_jump:4,0,relative,little; sid:1; rev:1;)"
    )

    rejection = next(
        rejection
        for rejection in generated.rejected
        if rejection.component == "byte_jump"
    )

    assert rejection.reason == "unsupported"


def test_compensated_lower_bound_edits_still_match_the_baseline_capture() -> None:
    pcap = Path(__file__).resolve().parents[1] / "pcap" / "smart_install" / "P0-baseline.pcap"
    generated = _generate(SMART_INSTALL_RULE, fixture_name="smart-install")
    candidates = [
        candidate
        for candidate in generated.accepted
        if candidate.component == "relative_constraint"
        and candidate.params["constraint"] == "distance"
    ]

    assert len(candidates) == 6
    for candidate in candidates:
        result = replay_rule(candidate.rule, pcap, expected_sid=2025472)
        assert result.error is None, candidate.id
        assert result.fired, f"{candidate.id} lost the baseline match: {candidate.rule}"


def test_uncompensated_lower_bound_edit_would_lose_the_baseline_capture() -> None:
    pcap = Path(__file__).resolve().parents[1] / "pcap" / "smart_install" / "P0-baseline.pcap"
    uncompensated = SMART_INSTALL_RULE.replace("distance:12;", "distance:6;")

    result = replay_rule(uncompensated, pcap, expected_sid=2025472)

    assert result.error is None
    assert result.fired is False


def test_family_candidates_and_rejections_are_deterministic() -> None:
    rule = (
        'alert http any any -> $HOME_NET 8080 (flow:established,to_server; '
        'http.uri; bsize:11; content:"/hedwig.cgi"; nocase; fast_pattern; '
        'pcre:"/^abc$/U"; sid:1; rev:1;)'
    )

    first = _generate(rule)
    second = _generate(rule)

    assert [candidate.id for candidate in first.accepted] == [
        candidate.id for candidate in second.accepted
    ]
    assert [rejection.id for rejection in first.rejected] == [
        rejection.id for rejection in second.rejected
    ]
    assert len({candidate.fingerprint for candidate in first.accepted}) == len(
        first.accepted
    )


def test_every_family_component_is_reachable_from_one_rule() -> None:
    rule = (
        'alert tcp any any -> $HOME_NET 873 (flow:established,to_server; '
        'content:"abcdefgh"; nocase; content:"|41 42 43 44|"; distance:12; '
        "within:20; byte_test:4,>,16,9,relative,little; sid:1; rev:1;)"
    )

    generated = _generate(rule)

    assert {
        "destination_port",
        "content",
        "content_modifier",
        "relative_constraint",
        "byte_test",
    } <= {candidate.component for candidate in generated.accepted}


# --- clue-targeted operators ------------------------------------------------
#
# The generic matrix above edits every predicate it can reach with a fixed
# schedule.  The operators below are invoked by name from a reviewed recipe and
# take the boundary, token or bound that the review chose, so each one is
# exercised here directly on a small rule rather than through the matrix.

TARGETED_RULE = (
    "alert http any any -> $HOME_NET 8080 (flow:established,to_server; "
    'http.uri; content:"/api/vendor/reset"; startswith; content:"token"; '
    'distance:0; within:20; pcre:"/id=[1-6]{1,4}/"; '
    "flowbits:set,ET.Exploit.Vendor.Reset; bsize:17; sid:1; rev:1;)"
)


FREE_CONTENT_RULE = (
    "alert http any any -> $HOME_NET 8080 (flow:established,to_server; "
    'http.uri; content:"/api/vendor/reset"; sid:1; rev:1;)'
)


def _targeted(
    operator, rule: str = TARGETED_RULE, **params
) -> MutationSpec | RejectedSpec:
    return operator(parse_suricata_rule(rule), params, fixture_name="targeted")


def _contents(rule: str) -> tuple:
    parsed = parse_suricata_rule(rule)
    return tuple(
        predicate for group in parsed.sticky_groups for predicate in group.predicates
    )


def test_state_only_flowbits_is_removed_and_gating_flowbits_is_rejected() -> None:
    removed = _targeted(flowbits_family.remove_state_set, predicate_id="flowbits-0")

    assert isinstance(removed, MutationSpec)
    assert "flowbits" not in removed.rule
    assert 'content:"/api/vendor/reset"' in removed.rule

    gating = _targeted(
        flowbits_family.remove_state_set,
        rule=TARGETED_RULE.replace(
            "flowbits:set,ET.Exploit.Vendor.Reset",
            "flowbits:isset,ET.Exploit.Vendor.Stage1",
        ),
        predicate_id="flowbits-0",
    )

    assert isinstance(gating, RejectedSpec)
    assert gating.reason == "structural"
    assert "gates whether this rule matches" in gating.diagnostic


def test_flowbits_anonymization_keeps_the_mechanism_and_drops_the_label() -> None:
    spec = _targeted(
        flowbits_family.anonymize_name, predicate_id="flowbits-0", name="bit1"
    )

    assert isinstance(spec, MutationSpec)
    assert "flowbits:set,bit1;" in spec.rule
    assert "ET.Exploit.Vendor.Reset" not in spec.rule


def test_flowbits_anonymization_refuses_a_descriptive_replacement() -> None:
    with pytest.raises(ValueError, match="neutral bit name"):
        _targeted(
            flowbits_family.anonymize_name,
            predicate_id="flowbits-0",
            name="ET.Exploit.Other",
        )


def test_destination_port_group_broadening_widens_every_numeric_member() -> None:
    rule = (
        "alert http any any -> $HOME_NET [80,8080] "
        '(flow:established,to_server; content:"/x"; sid:1; rev:1;)'
    )

    spec = _targeted(
        port_family.broaden_group_members,
        rule=rule,
        predicate_id="header-dst-port",
        margin=8,
    )

    assert isinstance(spec, MutationSpec)
    assert "-> $HOME_NET [72:88,8072:8088] (" in spec.rule


def test_destination_port_group_broadening_needs_a_bracketed_group() -> None:
    rule = (
        "alert http any any -> $HOME_NET $HTTP_PORTS "
        '(flow:established,to_server; content:"/x"; sid:1; rev:1;)'
    )

    rejected = _targeted(
        port_family.broaden_group_members,
        rule=rule,
        predicate_id="header-dst-port",
        margin=8,
    )

    assert isinstance(rejected, RejectedSpec)
    assert "not a bracketed group" in rejected.diagnostic


def test_destination_port_any_broadening_covers_a_variable_header() -> None:
    rule = (
        "alert http any any -> $HOME_NET $HTTP_PORTS "
        '(flow:established,to_server; content:"/x"; sid:1; rev:1;)'
    )

    spec = _targeted(
        port_family.broaden_to_any, rule=rule, predicate_id="header-dst-port"
    )

    assert isinstance(spec, MutationSpec)
    assert "-> $HOME_NET any (" in spec.rule


def test_boundary_prefix_retention_cuts_at_the_reviewed_token() -> None:
    spec = _targeted(
        content_family.retain_boundary_prefix,
        rule=FREE_CONTENT_RULE,
        predicate_id="content-0",
        boundary="/api/",
    )

    assert isinstance(spec, MutationSpec)
    assert 'content:"/api/"' in spec.rule
    assert "vendor" not in spec.rule


def test_boundary_suffix_retention_cuts_at_the_reviewed_token() -> None:
    spec = _targeted(
        content_family.retain_boundary_suffix,
        rule=FREE_CONTENT_RULE,
        predicate_id="content-0",
        boundary="/reset",
    )

    assert isinstance(spec, MutationSpec)
    assert 'content:"/reset"' in spec.rule
    assert "vendor" not in spec.rule


def test_boundary_retention_is_rejected_when_a_dependent_needs_the_endpoint() -> None:
    rejected = _targeted(
        content_family.retain_boundary_prefix,
        predicate_id="content-0",
        boundary="/api/",
    )

    assert isinstance(rejected, RejectedSpec)
    assert rejected.reason == "structural"
    assert "endpoint" in rejected.diagnostic


def test_boundary_suffix_retention_is_rejected_under_a_startswith_anchor() -> None:
    rejected = _targeted(
        content_family.retain_boundary_suffix,
        rule=FREE_CONTENT_RULE.replace(
            'content:"/api/vendor/reset";', 'content:"/api/vendor/reset"; startswith;'
        ),
        predicate_id="content-0",
        boundary="/reset",
    )

    assert isinstance(rejected, RejectedSpec)
    assert "startswith" in rejected.diagnostic


def test_boundary_retention_refuses_a_token_that_is_not_at_that_end() -> None:
    with pytest.raises(ValueError, match="is not a proper prefix"):
        _targeted(
            content_family.retain_boundary_prefix,
            rule=FREE_CONTENT_RULE,
            predicate_id="content-0",
            boundary="vendor",
        )


def test_partial_hex_preserves_the_matched_bytes_of_the_content() -> None:
    spec = _targeted(
        content_family.partial_hex, predicate_id="content-0", hex_token="vendor"
    )

    assert isinstance(spec, MutationSpec)
    assert 'content:"/api/|76 65 6e 64 6f 72|/reset"' in spec.rule
    assert "vendor" not in spec.rule
    assert _contents(spec.rule)[0].value == b"/api/vendor/reset"


def test_partial_hex_refuses_a_token_that_is_not_unique() -> None:
    rule = TARGETED_RULE.replace("/api/vendor/reset", "/api/api/reset")

    with pytest.raises(ValueError, match="occurs 2 times"):
        _targeted(
            content_family.partial_hex,
            rule=rule,
            predicate_id="content-0",
            hex_token="api",
        )


def test_split_at_token_keeps_the_bytes_adjacent_and_ordered() -> None:
    spec = _targeted(
        content_family.split_at_token,
        rule=FREE_CONTENT_RULE,
        predicate_id="content-0",
        boundary="/api/",
    )

    assert isinstance(spec, MutationSpec)
    contents = _contents(spec.rule)
    assert [content.value for content in contents[:2]] == [b"/api/", b"vendor/reset"]
    assert {"distance", "within"} <= {
        modifier.name for modifier in contents[1].modifiers
    }


def test_startswith_relaxation_replaces_the_anchor_with_a_depth_window() -> None:
    spec = _targeted(
        modifier_family.relax_startswith_to_depth,
        predicate_id="content-0-startswith",
        depth=64,
    )

    assert isinstance(spec, MutationSpec)
    assert "startswith" not in spec.rule
    assert "depth:64;" in spec.rule


def test_startswith_relaxation_refuses_a_depth_shorter_than_the_content() -> None:
    rejected = _targeted(
        modifier_family.relax_startswith_to_depth,
        predicate_id="content-0-startswith",
        depth=4,
    )

    assert isinstance(rejected, RejectedSpec)
    assert "cannot admit the 17 content bytes" in rejected.diagnostic


def test_pcre_literal_generalization_keeps_the_matched_length() -> None:
    spec = _targeted(
        pcre_family.generalize_literal_run, predicate_id="pcre-0", literal="id"
    )

    assert isinstance(spec, MutationSpec)
    assert 'pcre:"/.{2}=[1-6]{1,4}/"' in spec.rule


def test_pcre_character_class_broadening_must_be_a_superset() -> None:
    spec = _targeted(
        pcre_family.broaden_character_class,
        predicate_id="pcre-0",
        character_class="[1-6]",
        replacement="[0-9]",
    )

    assert isinstance(spec, MutationSpec)
    assert 'pcre:"/id=[0-9]{1,4}/"' in spec.rule

    rejected = _targeted(
        pcre_family.broaden_character_class,
        predicate_id="pcre-0",
        character_class="[1-6]",
        replacement="[1-3]",
    )

    assert isinstance(rejected, RejectedSpec)
    assert "superset" in rejected.diagnostic


def test_pcre_quantifier_widening_only_grows_the_window() -> None:
    spec = _targeted(
        pcre_family.widen_quantifier,
        predicate_id="pcre-0",
        quantifier="{1,4}",
        upper=64,
    )

    assert isinstance(spec, MutationSpec)
    assert 'pcre:"/id=[1-6]{1,64}/"' in spec.rule

    rejected = _targeted(
        pcre_family.widen_quantifier,
        predicate_id="pcre-0",
        quantifier="{1,4}",
        upper=2,
    )

    assert isinstance(rejected, RejectedSpec)
    assert "does not widen" in rejected.diagnostic


def test_pcre_removal_releases_the_following_relative_constraint() -> None:
    rule = (
        "alert http any any -> any any (flow:established,to_server; http.uri; "
        'content:"/api"; pcre:"/id=[0-9]+/"; content:"token"; distance:0; '
        "within:20; sid:1; rev:1;)"
    )

    spec = _targeted(
        pcre_family.remove_with_relative_release, rule=rule, predicate_id="pcre-0"
    )

    assert isinstance(spec, MutationSpec)
    assert "pcre" not in spec.rule
    assert "distance" not in spec.rule and "within" not in spec.rule
    assert 'content:"token"' in spec.rule
    released = {record["predicate_id"] for record in spec.params["compensation"]}
    assert released == {"content-1-distance", "content-1-within"}


def test_content_removal_releases_the_dependents_it_anchored() -> None:
    spec = _targeted(
        content_family.remove_with_relative_release, predicate_id="content-0"
    )

    assert isinstance(spec, MutationSpec)
    assert "/api/vendor/reset" not in spec.rule
    assert 'content:"token"' in spec.rule
    assert "distance" not in spec.rule and "within" not in spec.rule


def test_relative_release_is_rejected_without_a_dependent_to_free() -> None:
    rejected = _targeted(
        content_family.remove_with_relative_release, predicate_id="content-1"
    )

    assert isinstance(rejected, RejectedSpec)
    assert rejected.reason == "unsupported"
    assert "no relative dependent" in rejected.diagnostic


def test_buffer_size_relaxation_must_still_admit_the_original_size() -> None:
    spec = _targeted(position_family.relax_to_bound, predicate_id="bsize-0", bound="<64")

    assert isinstance(spec, MutationSpec)
    assert "bsize:<64;" in spec.rule

    rejected = _targeted(
        position_family.relax_to_bound, predicate_id="bsize-0", bound="<8"
    )

    assert isinstance(rejected, RejectedSpec)
    assert "17" in rejected.diagnostic


def test_byte_test_window_removal_drops_every_named_test() -> None:
    rule = (
        "alert tcp any any -> $HOME_NET 873 (flow:established,to_server; "
        'content:"@RSYNCD:"; byte_test:1,>,47,0,relative; '
        "byte_test:1,<,58,0,relative; sid:1; rev:1;)"
    )

    spec = _targeted(
        byte_family.remove_window,
        rule=rule,
        predicate_ids=["byte_test-0", "byte_test-1"],
    )

    assert isinstance(spec, MutationSpec)
    assert "byte_test" not in spec.rule
    assert 'content:"@RSYNCD:"' in spec.rule


def test_byte_test_window_removal_needs_more_than_one_test() -> None:
    rule = (
        "alert tcp any any -> $HOME_NET 873 (flow:established,to_server; "
        'content:"@RSYNCD:"; byte_test:1,>,47,0,relative; sid:1; rev:1;)'
    )

    with pytest.raises(ValueError, match="two"):
        _targeted(
            byte_family.remove_window, rule=rule, predicate_ids=["byte_test-0"]
        )


# --- targeted operator hardening --------------------------------------------

MICROS_PCRE = (
    "alert http any any -> any any (http.uri; content:\"/x\"; "
    'pcre:"/^[a-zA-Z]\\x3a\\x5cMICROS\\x5c/R"; sid:1; rev:1;)'
)
PAN_PCRE = (
    "alert http any any -> any any (http.uri; content:\"/x\"; "
    'pcre:"/^\\x2funauth\\x2f[^\\x25]*?(?:\\x252e){2}.*?\\x2fPAN_help\\x2f'
    '.*?\\x2e(?:css|js|html|htm)$/Ui"; sid:1; rev:1;)'
)


def test_literal_generalization_accepts_the_reviewed_pattern_literals() -> None:
    micros = _targeted(
        pcre_family.generalize_literal_run,
        rule=MICROS_PCRE,
        predicate_id="pcre-0",
        literal="MICROS",
    )
    assert isinstance(micros, MutationSpec)
    assert r'pcre:"/^[a-zA-Z]\x3a\x5c.{6}\x5c/R"' in micros.rule

    for literal, width in (("PAN_help", 8), ("unauth", 6)):
        spec = _targeted(
            pcre_family.generalize_literal_run,
            rule=PAN_PCRE,
            predicate_id="pcre-0",
            literal=literal,
        )
        assert isinstance(spec, MutationSpec)
        assert f".{{{width}}}" in spec.rule
        assert literal not in spec.rule.split("pcre:")[1]


def test_literal_generalization_refuses_a_run_inside_a_character_class() -> None:
    rule = (
        'alert http any any -> any any (http.uri; content:"/x"; '
        'pcre:"/id=[abc]+/R"; sid:1; rev:1;)'
    )

    rejected = _targeted(
        pcre_family.generalize_literal_run,
        rule=rule,
        predicate_id="pcre-0",
        literal="abc",
    )

    assert isinstance(rejected, RejectedSpec)
    assert "character class" in rejected.diagnostic


def test_literal_generalization_refuses_a_run_overlapping_an_escape() -> None:
    rule = (
        'alert http any any -> any any (http.uri; content:"/x"; '
        'pcre:"/\\x2fabc/R"; sid:1; rev:1;)'
    )

    for literal in ("x2f", "fabc", "x2fabc"):
        rejected = _targeted(
            pcre_family.generalize_literal_run,
            rule=rule,
            predicate_id="pcre-0",
            literal=literal,
        )
        assert isinstance(rejected, RejectedSpec), literal
        assert "escape" in rejected.diagnostic, literal


def test_literal_generalization_still_accepts_the_plain_run_after_an_escape() -> None:
    rule = (
        'alert http any any -> any any (http.uri; content:"/x"; '
        'pcre:"/\\x2fabc/R"; sid:1; rev:1;)'
    )

    spec = _targeted(
        pcre_family.generalize_literal_run,
        rule=rule,
        predicate_id="pcre-0",
        literal="abc",
    )

    assert isinstance(spec, MutationSpec)
    assert r'pcre:"/\x2f.{3}/R"' in spec.rule


def test_boundary_token_must_be_spelled_the_way_the_source_spells_it() -> None:
    rule = (
        "alert http any any -> $HOME_NET 8080 (flow:established,to_server; "
        'http.uri; content:"|2f|api/vendor/reset"; sid:1; rev:1;)'
    )

    spec = _targeted(
        content_family.retain_boundary_prefix,
        rule=rule,
        predicate_id="content-0",
        boundary="|2f|api/",
    )
    assert isinstance(spec, MutationSpec)
    assert 'content:"|2f|api/"' in spec.rule

    with pytest.raises(ValueError, match="source spells"):
        _targeted(
            content_family.retain_boundary_prefix,
            rule=rule,
            predicate_id="content-0",
            boundary="/api/",
        )


def test_partial_hex_token_must_be_spelled_the_way_the_source_spells_it() -> None:
    rule = (
        "alert http any any -> $HOME_NET 8080 (flow:established,to_server; "
        'http.uri; content:"/api|2f|vendor/reset"; sid:1; rev:1;)'
    )

    with pytest.raises(ValueError, match="source spells"):
        _targeted(
            content_family.partial_hex,
            rule=rule,
            predicate_id="content-0",
            hex_token="/vendor",
        )


def test_every_targeted_operator_records_its_own_name_as_the_operation() -> None:
    from hardening_game.mutations.clue_targets import TARGETED_OPERATORS

    seen: dict[str, str] = {}
    for name, operator in TARGETED_OPERATORS.items():
        _component, _, expected = name.partition("/")
        seen[name] = expected
    assert len(seen) == 16

    checks = (
        (flowbits_family.remove_state_set, {"predicate_id": "flowbits-0"}, TARGETED_RULE),
        (
            flowbits_family.anonymize_name,
            {"predicate_id": "flowbits-0", "name": "bit1"},
            TARGETED_RULE,
        ),
        (
            port_family.broaden_group_members,
            {"predicate_id": "header-dst-port", "margin": 8},
            "alert http any any -> $HOME_NET [80,8080] "
            '(flow:established,to_server; content:"/x"; sid:1; rev:1;)',
        ),
        (
            port_family.broaden_to_any,
            {"predicate_id": "header-dst-port"},
            TARGETED_RULE,
        ),
    )
    for operator, params, rule in checks:
        spec = _targeted(operator, rule=rule, **params)
        assert isinstance(spec, MutationSpec)
        assert spec.params["operation"] == spec.operator


def test_literal_generalization_refuses_a_run_inside_a_quoted_literal_region() -> None:
    r"""`\Q...\E` turns metacharacters into literals, so `.{n}` cannot go there."""
    rule = (
        'alert http any any -> any any (http.uri; content:"/x"; '
        'pcre:"/id=\\Qabc.def\\E/R"; sid:1; rev:1;)'
    )

    rejected = _targeted(
        pcre_family.generalize_literal_run,
        rule=rule,
        predicate_id="pcre-0",
        literal="abc",
    )

    assert isinstance(rejected, RejectedSpec)
    assert "quoted literal" in rejected.diagnostic


def test_literal_generalization_still_accepts_a_run_outside_a_quoted_region() -> None:
    rule = (
        'alert http any any -> any any (http.uri; content:"/x"; '
        'pcre:"/xyz\\Qa.b\\E/R"; sid:1; rev:1;)'
    )

    spec = _targeted(
        pcre_family.generalize_literal_run,
        rule=rule,
        predicate_id="pcre-0",
        literal="xyz",
    )

    assert isinstance(spec, MutationSpec)
    assert r".{3}\Qa.b\E" in spec.rule
