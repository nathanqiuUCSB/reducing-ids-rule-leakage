import pytest

from hardening_game.suricata.semantics import (
    canonical_rule_fingerprint_input,
    exactly_one_transformation_problem,
    semantic_rule_problem,
)


ORIGINAL = (
    'alert tcp any any -> $HOME_NET 4786 ('
    'flow:established,to_server; '
    'content:"|00 00 00 01 00 00 00 01 00 00 00 07|"; depth:12; '
    'content:"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; distance:12; within:36; '
    'content:"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"; distance:4; within:44; '
    'pcre:"/C{8}/"; sid:2025472; rev:1;)'
)


def hardened(options: str) -> str:
    return f"alert tcp any any -> $HOME_NET 4786 ({options}; sid:2025472; rev:2;)"


def test_canonical_rule_normalizes_revision_whitespace_integers_flow_and_content_bytes() -> None:
    textual = (
        'alert tcp any any -> any 80 (flow: established, to_server; '
        'content:"B"; distance:00; within:01; sid:0001; rev:2;)'
    )
    hexadecimal = (
        'alert   tcp any any -> any 80 ( flow:to_server,established;'
        'content: "|42|";distance: 0;within:1;sid:1;rev:999; )'
    )

    assert canonical_rule_fingerprint_input(textual) == canonical_rule_fingerprint_input(
        hexadecimal
    )


def test_canonical_rule_does_not_reinterpret_hex_decoded_backslash_as_an_escape() -> None:
    literal_byte = 'alert tcp any any -> any 80 (content:"B"; sid:1; rev:1;)'
    backslash_then_text = (
        'alert tcp any any -> any 80 (content:"|5c|x42"; sid:1; rev:2;)'
    )

    assert canonical_rule_fingerprint_input(
        literal_byte
    ) != canonical_rule_fingerprint_input(backslash_then_text)


def test_canonical_rule_normalizes_negated_content_bytes_but_preserves_negation() -> None:
    textual = 'alert tcp any any -> any 80 (content:!"B"; sid:1; rev:1;)'
    hexadecimal = 'alert tcp any any -> any 80 (content:!"|42|"; sid:1; rev:2;)'
    positive = 'alert tcp any any -> any 80 (content:"B"; sid:1; rev:3;)'

    assert canonical_rule_fingerprint_input(textual) == canonical_rule_fingerprint_input(
        hexadecimal
    )
    assert canonical_rule_fingerprint_input(
        textual
    ) != canonical_rule_fingerprint_input(positive)


def test_semantic_rule_rejects_negation_or_negated_material_changes() -> None:
    oracle = 'alert tcp any any -> any 80 (content:!"AB"; sid:1; rev:1;)'

    negation_problem = semantic_rule_problem(
        oracle,
        'alert tcp any any -> any 80 (content:"AB"; sid:1; rev:2;)',
    )
    material_problem = semantic_rule_problem(
        oracle,
        'alert tcp any any -> any 80 (content:!"AC"; sid:1; rev:2;)',
    )

    assert negation_problem is not None
    assert material_problem is not None


def test_exactly_one_transformation_rejects_nocase_on_negated_content() -> None:
    oracle = 'alert tcp any any -> any 80 (content:!"B"; sid:1; rev:1;)'
    candidate = (
        'alert tcp any any -> any 80 (content:!"|42|"; nocase; sid:1; rev:2;)'
    )

    problem = exactly_one_transformation_problem(oracle, oracle, candidate)

    assert problem is not None
    assert "nocase" in problem


def test_negated_content_cannot_be_split_into_conjoined_negations() -> None:
    oracle = 'alert tcp any any -> any 80 (content:!"AB"; sid:1; rev:1;)'
    split = (
        'alert tcp any any -> any 80 ('
        'content:!"A"; content:!"B"; distance:0; within:1; sid:1; rev:2;)'
    )

    semantic_problem = semantic_rule_problem(oracle, split)
    transformation_problem = exactly_one_transformation_problem(
        oracle, oracle, split
    )

    assert semantic_problem is not None
    assert "negated content" in semantic_problem
    assert transformation_problem is not None


def test_negated_content_encoding_only_change_remains_semantically_equivalent() -> None:
    oracle = 'alert tcp any any -> any 80 (content:!"B"; sid:1; rev:1;)'
    encoded = 'alert tcp any any -> any 80 (content:!"|42|"; sid:1; rev:2;)'

    assert semantic_rule_problem(oracle, encoded) is None
    assert canonical_rule_fingerprint_input(oracle) == canonical_rule_fingerprint_input(
        encoded
    )


def test_exactly_one_transformation_rejects_encoding_only_change() -> None:
    oracle = 'alert tcp any any -> any 80 (content:"B"; sid:1; rev:1;)'
    candidate = 'alert tcp any any -> any 80 (content:"|42|"; sid:1; rev:2;)'

    problem = exactly_one_transformation_problem(oracle, oracle, candidate)

    assert problem is not None
    assert "zero" in problem


def test_exactly_one_transformation_rejects_changes_to_multiple_oracle_groups() -> None:
    oracle = (
        'alert tcp any any -> any 80 ('
        'content:"AAAA"; content:"BBBB"; sid:1; rev:1;)'
    )
    candidate = (
        'alert tcp any any -> any 80 ('
        'content:"AA"; content:"AA"; distance:0; within:2; '
        'content:"BB"; content:"BB"; distance:0; within:2; sid:1; rev:2;)'
    )

    problem = exactly_one_transformation_problem(oracle, oracle, candidate)

    assert problem is not None
    assert "multiple oracle content" in problem


def test_exactly_one_transformation_accepts_repartition_of_one_oracle_group() -> None:
    forty_four = "B" * 44
    oracle = (
        'alert tcp any any -> any 80 ('
        f'content:"{forty_four}"; distance:4; within:44; sid:1; rev:1;)'
    )
    current = (
        'alert tcp any any -> any 80 ('
        f'content:"{"B" * 43}"; distance:4; within:43; '
        'content:"B"; distance:0; within:1; sid:1; rev:2;)'
    )
    candidate = (
        'alert tcp any any -> any 80 ('
        f'content:"{"B" * 42}"; distance:4; within:42; '
        'content:"BB"; distance:0; within:2; sid:1; rev:3;)'
    )

    assert exactly_one_transformation_problem(oracle, current, candidate) is None


def test_exactly_one_transformation_counts_modifier_changes_per_content_match() -> None:
    oracle = (
        'alert tcp any any -> any 80 ('
        'content:"A"; content:"B"; sid:1; rev:1;)'
    )
    current = (
        'alert tcp any any -> any 80 ('
        'content:"A"; content:"B"; sid:1; rev:2;)'
    )
    candidate = (
        'alert tcp any any -> any 80 ('
        'content:"A"; fast_pattern; content:"B"; fast_pattern; sid:1; rev:3;)'
    )

    problem = exactly_one_transformation_problem(oracle, current, candidate)

    assert problem is not None
    assert "exactly one" in problem


def test_exactly_one_transformation_counts_allowed_modifier_movement_within_group() -> None:
    oracle = 'alert tcp any any -> any 80 (content:"AB"; sid:1; rev:1;)'
    current = (
        'alert tcp any any -> any 80 ('
        'content:"A"; fast_pattern; '
        'content:"B"; distance:0; within:1; sid:1; rev:2;)'
    )
    candidate = (
        'alert tcp any any -> any 80 ('
        'content:"A"; '
        'content:"B"; fast_pattern; distance:0; within:1; sid:1; rev:3;)'
    )

    problem = exactly_one_transformation_problem(oracle, current, candidate)

    assert problem is not None
    assert "exactly one" in problem


def test_exactly_one_transformation_rejects_disallowed_modifier_movement_within_group() -> None:
    oracle = 'alert tcp any any -> any 80 (content:"AB"; sid:1; rev:1;)'
    current = (
        'alert tcp any any -> any 80 ('
        'content:"A"; startswith; '
        'content:"B"; distance:0; within:1; sid:1; rev:2;)'
    )
    candidate = (
        'alert tcp any any -> any 80 ('
        'content:"A"; fast_pattern; '
        'content:"B"; startswith; distance:0; within:1; sid:1; rev:3;)'
    )

    problem = exactly_one_transformation_problem(oracle, current, candidate)

    assert problem is not None
    assert "not an allowed hardening option" in problem
    assert "startswith" in problem


@pytest.mark.parametrize(
    "associated_option",
    [
        "isdataat:1,relative",
        "byte_test:1,=,0,0,relative",
        "future_cursor_guard:1",
    ],
)
def test_exactly_one_transformation_tracks_any_cursor_option_by_fragment(
    associated_option: str,
) -> None:
    oracle = 'alert tcp any any -> any 80 (content:"AB"; sid:1; rev:1;)'
    current = (
        'alert tcp any any -> any 80 ('
        f'content:"A"; {associated_option}; '
        'content:"B"; distance:0; within:1; sid:1; rev:2;)'
    )
    candidate = (
        'alert tcp any any -> any 80 ('
        'content:"A"; fast_pattern; '
        f'content:"B"; distance:0; within:1; {associated_option}; sid:1; rev:3;)'
    )

    problem = exactly_one_transformation_problem(oracle, current, candidate)

    assert problem is not None
    assert "not an allowed hardening option" in problem
    assert associated_option.split(":", 1)[0] in problem


def test_exactly_one_transformation_tracks_relative_pcre_by_fragment() -> None:
    oracle = 'alert tcp any any -> any 80 (content:"AB"; sid:1; rev:1;)'
    current = (
        'alert tcp any any -> any 80 ('
        'content:"A"; pcre:"/marker/R"; '
        'content:"B"; distance:0; within:1; sid:1; rev:2;)'
    )
    candidate = (
        'alert tcp any any -> any 80 ('
        'content:"A"; fast_pattern; '
        'content:"B"; distance:0; within:1; pcre:"/marker/R"; sid:1; rev:3;)'
    )

    problem = exactly_one_transformation_problem(oracle, current, candidate)

    assert problem is not None
    assert "not an allowed hardening option" in problem
    assert "pcre" in problem


def test_exactly_one_transformation_keeps_non_relative_pcre_global() -> None:
    oracle = 'alert tcp any any -> any 80 (content:"AB"; sid:1; rev:1;)'
    current = (
        'alert tcp any any -> any 80 ('
        'content:"A"; pcre:"/marker/i"; '
        'content:"B"; distance:0; within:1; sid:1; rev:2;)'
    )
    candidate = (
        'alert tcp any any -> any 80 ('
        'content:"A"; fast_pattern; '
        'content:"B"; distance:0; within:1; pcre:"/marker/i"; sid:1; rev:3;)'
    )

    assert exactly_one_transformation_problem(oracle, current, candidate) is None


def test_pcre_sticky_buffer_movement_cannot_hide_beside_another_change() -> None:
    oracle = (
        'alert http any any -> any any ('
        'http.uri; content:"A"; pcre:"/marker/i"; '
        'http.header; content:"B"; sid:1; rev:1;)'
    )
    candidate = (
        'alert http any any -> any any ('
        'http.uri; content:"A"; fast_pattern; '
        'http.header; content:"B"; pcre:"/marker/i"; sid:1; rev:2;)'
    )

    semantic_problem = semantic_rule_problem(oracle, candidate)
    transformation_problem = exactly_one_transformation_problem(
        oracle, oracle, candidate
    )

    assert semantic_problem is not None
    assert "pcre" in semantic_problem
    assert transformation_problem is not None
    assert "pcre" in transformation_problem


@pytest.mark.parametrize(
    "administrative_change",
    [
        "gid:2",
        'metadata:former_category MALWARE',
        "reference:url,example.invalid",
    ],
)
def test_exactly_one_transformation_rejects_administrative_option_changes(
    administrative_change: str,
) -> None:
    oracle = 'alert tcp any any -> any 80 (content:"A"; sid:1; rev:1;)'
    candidate = (
        'alert tcp any any -> any 80 ('
        f'content:"A"; {administrative_change}; sid:1; rev:2;)'
    )

    problem = exactly_one_transformation_problem(oracle, oracle, candidate)

    assert problem is not None
    assert "not an allowed hardening option" in problem


def test_exactly_one_transformation_allows_fast_pattern() -> None:
    oracle = 'alert tcp any any -> any 80 (content:"A"; sid:1; rev:1;)'
    candidate = (
        'alert tcp any any -> any 80 ('
        'content:"A"; fast_pattern; sid:1; rev:2;)'
    )

    assert exactly_one_transformation_problem(oracle, oracle, candidate) is None


def test_adding_nocase_is_rejected_as_lowercase_broadening() -> None:
    oracle = 'alert tcp any any -> any 80 (content:"ADMIN"; sid:1; rev:1;)'
    candidate = (
        'alert tcp any any -> any 80 ('
        'content:"ADMIN"; nocase; sid:1; rev:2;)'
    )

    semantic_problem = semantic_rule_problem(oracle, candidate)
    transformation_problem = exactly_one_transformation_problem(
        oracle, oracle, candidate
    )

    assert semantic_problem is not None
    assert "nocase" in semantic_problem
    assert transformation_problem is not None
    assert "nocase" in transformation_problem


def test_exactly_one_transformation_rejects_multiple_allowed_option_changes() -> None:
    oracle = 'alert tcp any any -> any 80 (content:"A"; sid:1; rev:1;)'
    candidate = (
        'alert tcp any any -> any 80 ('
        'content:"A"; nocase; fast_pattern; sid:1; rev:2;)'
    )

    problem = exactly_one_transformation_problem(oracle, oracle, candidate)

    assert problem is not None
    assert "nocase" in problem


def test_rejects_split_with_relative_modifiers_on_later_fragment() -> None:
    misplaced_modifier_split = hardened(
        'flow:established,to_server; '
        'content:"|00 00 00 01 00 00 00 01|"; depth:8; '
        'content:"|00 00 00 07|"; distance:0; within:4; '
        'content:"AAAAAAAAAA"; '
        'content:"AAAAAAAAAAAAAAAAAAAAAAAAAA"; distance:12; within:36; '
        'content:"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"; distance:4; within:44; '
        'pcre:"/C{8}/"'
    )

    problem = semantic_rule_problem(ORIGINAL, misplaced_modifier_split)

    assert problem is not None
    assert "distance" in problem


def test_rejects_split_that_keeps_original_within_on_shorter_first_fragment() -> None:
    broadened_split = hardened(
        'flow:established,to_server; '
        'content:"|00 00 00 01 00 00 00 01|"; depth:8; '
        'content:"|00 00 00 07|"; distance:0; within:4; '
        'content:"AAAAAAAAAA"; distance:12; within:36; '
        'content:"AAAAAAAAAAAAAAAAAAAAAAAAAA"; distance:0; within:26; '
        'content:"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"; distance:4; within:44; '
        'pcre:"/C{8}/"'
    )

    problem = semantic_rule_problem(ORIGINAL, broadened_split)

    assert problem is not None
    assert "expected first fragment within 10" in problem
    assert "got 36" in problem


def test_accepts_split_refactor_with_recomputed_fragment_windows() -> None:
    split_with_recomputed_windows = hardened(
        'flow:established,to_server; '
        'content:"|00 00 00 01 00 00 00 01|"; depth:8; '
        'content:"|00 00 00 07|"; distance:0; within:4; '
        'content:"AAAAAAAAAAAAAAAA"; distance:12; within:16; '
        'content:"AAAAAAAAAAAAAAAAAAAA"; distance:0; within:20; '
        'content:"BBBBBBBBBBBBBBBBBBBB"; distance:4; within:20; '
        'content:"BBBBBBBBBBBBBBBBBBBBBBBB"; distance:0; within:24; '
        'pcre:"/C{8}/"'
    )

    assert semantic_rule_problem(ORIGINAL, split_with_recomputed_windows) is None


def test_rejects_merging_an_original_relative_content_boundary() -> None:
    original = (
        'alert tcp any any -> any 80 ('
        'content:"A"; content:"B"; distance:0; within:1; sid:1; rev:1;)'
    )
    candidate = 'alert tcp any any -> any 80 (content:"AB"; sid:1; rev:2;)'

    problem = semantic_rule_problem(original, candidate)

    assert problem is not None
    assert "distance" in problem


def test_rejects_merging_a_constrained_literal_as_candidate_prefix() -> None:
    original = (
        'alert tcp any any -> any 80 ('
        'content:"A"; content:"B"; distance:0; within:1; content:"C"; sid:1; rev:1;)'
    )
    candidate = 'alert tcp any any -> any 80 (content:"A"; content:"BC"; sid:1; rev:2;)'

    problem = semantic_rule_problem(original, candidate)

    assert problem is not None
    assert "distance" in problem


@pytest.mark.parametrize(
    "candidate",
    [
        'alert tcp any any -> any 80 (content:"marker"; sid:1; rev:2;)',
        'alert tcp any any -> any 80 (content:"marker"; offset:1; depth:6; sid:1; rev:2;)',
    ],
)
def test_rejects_removed_or_changed_offset_depth_on_unsplit_content(candidate: str) -> None:
    original = (
        'alert tcp any any -> any 80 ('
        'content:"marker"; offset:0; depth:7; sid:1; rev:1;)'
    )

    problem = semantic_rule_problem(original, candidate)

    assert problem is not None
    assert "offset" in problem or "depth" in problem


def test_rejects_split_that_drops_an_original_absolute_constraint() -> None:
    original = (
        'alert tcp any any -> any 80 ('
        'content:"marker"; offset:0; depth:7; sid:1; rev:1;)'
    )
    candidate = (
        'alert tcp any any -> any 80 ('
        'content:"mar"; content:"ker"; sid:1; rev:2;)'
    )

    problem = semantic_rule_problem(original, candidate)

    assert problem is not None
    assert "offset" in problem or "depth" in problem


def test_accepts_split_that_retains_original_absolute_constraint() -> None:
    original = (
        'alert tcp any any -> any 80 ('
        'content:"marker"; offset:0; depth:7; sid:1; rev:1;)'
    )
    candidate = (
        'alert tcp any any -> any 80 ('
        'content:"mar"; offset:0; depth:4; '
        'content:"ker"; distance:0; within:3; sid:1; rev:2;)'
    )

    assert semantic_rule_problem(original, candidate) is None


def test_rejects_split_that_keeps_original_depth_on_shorter_first_fragment() -> None:
    original = (
        'alert tcp any any -> any 80 ('
        'content:"marker"; depth:6; sid:1; rev:1;)'
    )
    candidate = (
        'alert tcp any any -> any 80 ('
        'content:"mar"; depth:6; '
        'content:"ker"; distance:0; within:3; sid:1; rev:2;)'
    )

    problem = semantic_rule_problem(original, candidate)

    assert problem is not None
    assert "expected first fragment depth 3" in problem
    assert "got 6" in problem


def test_rejects_content_moved_between_sticky_buffers() -> None:
    original = (
        'alert http any any -> any any ('
        'http.uri; content:"marker"; http.header; content:"host"; sid:1; rev:1;)'
    )
    candidate = (
        'alert http any any -> any any ('
        'http.header; content:"marker"; content:"host"; sid:1; rev:2;)'
    )

    problem = semantic_rule_problem(original, candidate)

    assert problem is not None
    assert "buffer" in problem


def test_rejects_cross_buffer_content_merge() -> None:
    original = (
        'alert http any any -> any any ('
        'http.uri; content:"A"; http.header; content:"B"; sid:1; rev:1;)'
    )
    candidate = (
        'alert http any any -> any any ('
        'http.uri; content:"AB"; sid:1; rev:2;)'
    )

    problem = semantic_rule_problem(original, candidate)

    assert problem is not None
    assert "buffer" in problem


def test_rejects_default_buffer_content_merged_into_sticky_buffer() -> None:
    original = (
        'alert http any any -> any any ('
        'content:"A"; http.header; content:"B"; sid:1; rev:1;)'
    )
    candidate = (
        'alert http any any -> any any ('
        'http.header; content:"AB"; sid:1; rev:2;)'
    )

    problem = semantic_rule_problem(original, candidate)

    assert problem is not None
    assert "buffer" in problem


@pytest.mark.parametrize(
    ("original_options", "candidate_options"),
    [
        ('content:"AB"', 'content:"A"; content:"B"; distance:0; within:1'),
        (
            'http.header; content:"AB"',
            'http.header; content:"A"; content:"B"; distance:0; within:1',
        ),
    ],
)
def test_accepts_content_splits_within_the_same_buffer(
    original_options: str, candidate_options: str
) -> None:
    original = (
        f"alert http any any -> any any ({original_options}; sid:1; rev:1;)"
    )
    candidate = (
        f"alert http any any -> any any ({candidate_options}; sid:1; rev:2;)"
    )

    assert semantic_rule_problem(original, candidate) is None


def test_rejects_content_split_without_exact_fragment_adjacency() -> None:
    original = 'alert tcp any any -> any 80 (content:"AB"; sid:1; rev:1;)'
    candidate = (
        'alert tcp any any -> any 80 ('
        'content:"A"; content:"B"; sid:1; rev:2;)'
    )

    problem = semantic_rule_problem(original, candidate)

    assert problem is not None
    assert "following split fragment" in problem


def test_rejects_content_moved_between_http_request_body_and_uri_buffers() -> None:
    original = (
        'alert http any any -> any any ('
        'http.request_body; content:"marker"; sid:1; rev:1;)'
    )
    candidate = (
        'alert http any any -> any any ('
        'http.uri; content:"marker"; sid:1; rev:2;)'
    )

    problem = semantic_rule_problem(original, candidate)

    assert problem is not None
    assert "buffer" in problem


def test_rejects_content_moved_between_http_accept_and_uri_buffers() -> None:
    original = (
        'alert http any any -> any any ('
        'http.accept; content:"marker"; sid:1; rev:1;)'
    )
    candidate = (
        'alert http any any -> any any ('
        'http.uri; content:"marker"; sid:1; rev:2;)'
    )

    problem = semantic_rule_problem(original, candidate)

    assert problem is not None
    assert "buffer" in problem


def test_does_not_treat_nocase_as_a_sticky_buffer() -> None:
    original = (
        'alert http any any -> any any ('
        'http.uri; content:"marker"; sid:1; rev:1;)'
    )
    candidate = (
        'alert http any any -> any any ('
        'http.uri; nocase; content:"marker"; sid:1; rev:2;)'
    )

    assert semantic_rule_problem(original, candidate) is None


def test_does_not_treat_content_modifiers_as_sticky_buffers() -> None:
    original = (
        'alert http any any -> any any ('
        'http.uri; content:"marker"; offset:0; depth:6; sid:1; rev:1;)'
    )
    candidate = (
        'alert http any any -> any any ('
        'http.uri; content:"mar"; offset:0; depth:3; '
        'content:"ker"; distance:0; within:3; sid:1; rev:2;)'
    )

    assert semantic_rule_problem(original, candidate) is None


@pytest.mark.parametrize(
    ("original", "candidate"),
    [
        (
            'alert tcp any any -> any 80 (content:"one"; sid:1; rev:1;)',
            'drop tcp any any -> any 80 (content:"one"; sid:1; rev:2;)',
        ),
        (
            'alert tcp any any -> any 80 (content:"one"; sid:1; rev:1;)',
            'alert udp any any -> any 80 (content:"one"; sid:1; rev:2;)',
        ),
        (
            'alert tcp $HOME_NET any -> any 80 (content:"one"; sid:1; rev:1;)',
            'alert tcp any any -> any 80 (content:"one"; sid:1; rev:2;)',
        ),
        (
            'alert tcp any any -> any 80 (content:"one"; sid:1; rev:1;)',
            'alert tcp any any <- any 80 (content:"one"; sid:1; rev:2;)',
        ),
    ],
)
def test_rejects_immutable_header_changes(original: str, candidate: str) -> None:
    assert semantic_rule_problem(original, candidate) is not None


def test_allows_case_changes_only_for_header_action_protocol_and_direction() -> None:
    original = 'alert tcp $HOME_NET HTTP_PORT -> $EXTERNAL_NET 4786 (content:"one"; sid:1; rev:1;)'
    candidate = 'ALERT TCP $HOME_NET HTTP_PORT -> $EXTERNAL_NET 4786 (content:"one"; sid:1; rev:2;)'

    assert semantic_rule_problem(original, candidate) is None


@pytest.mark.parametrize(
    "candidate",
    [
        'alert tcp $home_net HTTP_PORT -> $EXTERNAL_NET 4786 (content:"one"; sid:1; rev:2;)',
        'alert tcp $HOME_NET http_port -> $EXTERNAL_NET 4786 (content:"one"; sid:1; rev:2;)',
        'alert tcp $HOME_NET HTTP_PORT -> $external_net 4786 (content:"one"; sid:1; rev:2;)',
    ],
)
def test_rejects_header_address_or_port_case_changes(candidate: str) -> None:
    original = 'alert tcp $HOME_NET HTTP_PORT -> $EXTERNAL_NET 4786 (content:"one"; sid:1; rev:1;)'

    assert semantic_rule_problem(original, candidate) is not None


def test_allows_reordered_flow_flags() -> None:
    original = (
        'alert tcp any any -> any 80 (flow:established,to_server; '
        'content:"one"; sid:1; rev:1;)'
    )
    candidate = (
        'alert tcp any any -> any 80 (flow:to_server,established; '
        'content:"one"; sid:1; rev:2;)'
    )

    assert semantic_rule_problem(original, candidate) is None


@pytest.mark.parametrize(
    "candidate_flow",
    ["established", "established,to_server,only_stream"],
)
def test_rejects_added_or_removed_flow_flags(candidate_flow: str) -> None:
    original = (
        'alert tcp any any -> any 80 (flow:established,to_server; '
        'content:"one"; sid:1; rev:1;)'
    )
    candidate = (
        f'alert tcp any any -> any 80 (flow:{candidate_flow}; '
        'content:"one"; sid:1; rev:2;)'
    )

    assert semantic_rule_problem(original, candidate) is not None


@pytest.mark.parametrize(
    "candidate_options",
    [
        'content:"first"; content:"third"; pcre:"/C{8}/"',
        'content:"second"; content:"first"; content:"third"; pcre:"/C{8}/"',
        'content:"first"; content:"second"; content:"third"; pcre:"/D{8}/"',
        'content:"first"; content:"second"; content:"third"; pcre:"/C{8}/"',
    ],
)
def test_rejects_removed_reordered_or_changed_match_requirements(candidate_options: str) -> None:
    original = (
        'alert tcp any any -> any 80 (flow:established,to_server; '
        'content:"first"; content:"second"; content:"third"; pcre:"/C{8}/"; sid:1; rev:1;)'
    )
    candidate = hardened(candidate_options).replace(
        "-> $HOME_NET 4786", "-> any 80"
    )

    assert semantic_rule_problem(original, candidate) is not None
