from hardening_game.mutations.dependencies import content_dependency_group
from hardening_game.mutations.engine import generate_generic_candidates
from hardening_game.suricata.rule_model import parse_suricata_rule


def test_content_dependency_group_includes_modifiers_and_empty_sticky_buffer() -> None:
    rule = (
        'alert http any any -> any any (http.uri; content:"/x"; '
        "fast_pattern; startswith; sid:1; rev:1;)"
    )
    parsed = parse_suricata_rule(rule)
    predicate = parsed.sticky_groups[0].predicates[0]

    group = content_dependency_group(parsed, predicate.predicate_id)

    assert group.remove_sticky_buffer is True
    assert [span for span in group.spans] == [
        parsed.sticky_groups[0].declaration.span,
        predicate.span,
        *(modifier.span for modifier in predicate.modifiers),
    ]


def test_removing_uri_content_co_removes_dependent_modifiers() -> None:
    rule = (
        'alert http any any -> any any (http.uri; content:"/x"; '
        "fast_pattern; startswith; sid:1; rev:1;)"
    )

    candidate_set = generate_generic_candidates(rule, revision=1, fixture_name="example")
    removed = next(
        candidate
        for candidate in candidate_set.accepted
        if candidate.component == "content"
        and candidate.operator == "remove"
        and candidate.params["buffer"] == "http.uri"
    )

    assert 'content:"/x"' not in removed.rule
    assert "startswith;" not in removed.rule
    assert "fast_pattern;" not in removed.rule
    assert "http.uri;" not in removed.rule


def test_removing_one_of_two_buffer_contents_keeps_buffer_and_unrelated_predicate() -> None:
    rule = (
        'alert http any any -> any any (http.uri; content:"/x"; nocase; '
        'content:"/y"; endswith; sid:1; rev:1;)'
    )

    candidate_set = generate_generic_candidates(rule, revision=1, fixture_name="example")
    removed = next(
        candidate
        for candidate in candidate_set.accepted
        if candidate.component == "content"
        and candidate.operator == "remove"
        and candidate.params["content_index"] == 0
    )

    assert "http.uri;" in removed.rule
    assert 'content:"/x"' not in removed.rule
    assert "nocase;" not in removed.rule
    assert 'content:"/y"; endswith;' in removed.rule


def test_escaped_content_is_rejected_instead_of_re_rendered_unsafely() -> None:
    rule = (
        'alert http any any -> any any (http.header; '
        'content:"\\"quoted\\""; sid:1; rev:1;)'
    )

    candidate_set = generate_generic_candidates(rule, revision=1, fixture_name="example")

    assert not any(
        candidate.operator == "shorten_prefix" for candidate in candidate_set.accepted
    )
    assert any(
        rejection.component == "content" and rejection.reason == "unsupported"
        for rejection in candidate_set.rejected
    )


def test_mixed_literal_hex_content_renders_as_exact_pure_hex() -> None:
    rule = (
        'alert http any any -> any any (http.header; '
        'content:"|22|quoted|22|"; sid:1; rev:1;)'
    )

    candidate_set = generate_generic_candidates(rule, revision=1, fixture_name="example")

    rendered = next(
        candidate
        for candidate in candidate_set.accepted
        if candidate.operator == "literal_as_hex"
    )

    assert 'content:"|22 71 75 6f 74 65 64 22|";' in rendered.rule
    assert any(candidate.operator == "shorten_prefix" for candidate in candidate_set.accepted)


def test_surviving_non_relative_pcre_keeps_sole_sticky_declaration() -> None:
    rule = (
        'alert http any any -> any any (http.uri; content:"/x"; '
        'pcre:"/other/"; sid:1; rev:1;)'
    )

    candidate_set = generate_generic_candidates(rule, revision=1, fixture_name="example")
    removed = next(
        candidate
        for candidate in candidate_set.accepted
        if candidate.component == "content" and candidate.operator == "remove"
    )

    assert "http.uri;" in removed.rule
    assert 'content:"/x";' not in removed.rule
    assert 'pcre:"/other/";' in removed.rule
