import pytest

from hardening_game.mutations import families
from hardening_game.suricata import rule_model
from hardening_game.suricata.rule_model import (
    CONTENT_MODIFIERS,
    CONTENT_OPTION,
    RELATIVE_CONSUMER_NAMES,
    RuleOption,
    Span,
    decode_content,
    is_relative_consumer,
    parse_suricata_rule,
    pcre_is_relative,
)


def test_content_modifiers_attach_to_preceding_content() -> None:
    parsed = parse_suricata_rule(
        'alert http any any -> any any (http.uri; content:"/x"; '
        "nocase; fast_pattern; startswith; sid:1; rev:1;)"
    )

    predicate = parsed.sticky_groups[0].predicates[0]

    assert predicate.buffer == "http.uri"
    assert [modifier.name for modifier in predicate.modifiers] == [
        "nocase",
        "fast_pattern",
        "startswith",
    ]


def test_parser_preserves_supported_content_and_rule_context() -> None:
    parsed = parse_suricata_rule(
        'alert tcp any [80,443] -> $HOME_NET 8080 '
        '(flow:established,to_server; content:!"a|20 41|"; offset:1; depth:2; '
        'pcre:"/x/R"; byte_test:1,=,1,0; bsize:>3; '
        'content:"b"; distance:0; within:4; sid:1; rev:1;)'
    )

    first, second = parsed.sticky_groups[0].predicates

    assert parsed.header.direction == "->"
    assert parsed.header.source_port == "[80,443]"
    assert parsed.header.destination_port == "8080"
    assert (
        parsed.source[
            parsed.header.destination_port_span.start : parsed.header.destination_port_span.end
        ]
        == "8080"
    )
    assert parsed.flow == "established,to_server"
    assert first.negated is True
    assert first.representation == "mixed"
    assert first.value == b"a A"
    assert [modifier.name for modifier in first.modifiers] == ["offset", "depth"]
    assert [modifier.name for modifier in second.modifiers] == ["distance", "within"]
    assert parsed.sticky_groups[0].buffer_constraints[0].name == "bsize"
    assert [option.name for option in parsed.other_options] == [
        "pcre",
        "byte_test",
        "bsize",
        "sid",
        "rev",
    ]


def test_rawbytes_is_a_content_modifier_not_a_sticky_buffer() -> None:
    parsed = parse_suricata_rule(
        'alert tcp any any -> any any (content:"x"; rawbytes; sid:1; rev:1;)'
    )

    assert [group.buffer for group in parsed.sticky_groups] == ["payload"]
    assert [modifier.name for modifier in parsed.sticky_groups[0].predicates[0].modifiers] == [
        "rawbytes"
    ]


def test_relative_consumers_attach_to_the_preceding_content_only() -> None:
    parsed = parse_suricata_rule(
        'alert tcp any any -> any any (content:"a"; byte_test:1,=,1,0,relative; '
        'http.uri; content:"b"; pcre:"/b/R"; isdataat:1,relative; sid:1; rev:1;)'
    )
    first_group, second_group = parsed.sticky_groups

    assert [option.name for option in first_group.predicates[0].relative_consumers] == [
        "byte_test"
    ]
    assert [option.name for option in second_group.predicates[0].relative_consumers] == [
        "pcre",
        "isdataat",
    ]


def _option(name: str, value: str | None) -> RuleOption:
    return RuleOption(name=name, value=value, span=Span(0, 0), option_index=0)


def test_mutation_families_reuse_the_parser_domain_definitions() -> None:
    assert families.RELATIVE_CONSUMER_NAMES is RELATIVE_CONSUMER_NAMES
    assert families.STICKY_BUFFER_NAMES is rule_model.STICKY_BUFFER_NAMES
    assert families.is_sticky_declaration is rule_model.is_sticky_declaration


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ('"/x/R"', True),
        ('"/x/Ri"', True),
        ('"/x/iR"', True),
        ('"/x/R" ', True),
        ("'/x/R'", True),
        ('"/x/i"', False),
        ('"/R/i"', False),
        ('"/x/"', False),
    ],
)
def test_pcre_relative_detection_has_one_whitespace_behavior(
    value: str, expected: bool
) -> None:
    assert pcre_is_relative(value) is expected
    assert is_relative_consumer(_option("pcre", value)) is expected
    assert families.depends_on_previous_match(_option("pcre", value)) is expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("1,=,1,0,relative", True),
        ("1,=,1,0, relative", True),
        ("1,=,1,0,RELATIVE", True),
        ("1,=,1,0", False),
    ],
)
def test_relative_keyword_detection_tolerates_separator_whitespace(
    value: str, expected: bool
) -> None:
    assert is_relative_consumer(_option("byte_test", value)) is expected
    assert families.depends_on_previous_match(_option("byte_test", value)) is expected


def test_relative_detection_ignores_options_that_cannot_be_relative() -> None:
    assert is_relative_consumer(_option("content", "relative")) is False
    assert is_relative_consumer(_option("byte_test", None)) is False


def test_public_content_definitions_expose_parser_truth() -> None:
    match = CONTENT_OPTION.fullmatch('content:!"a|41|";')
    assert match is not None
    assert match.group("negated") == "!"
    assert match.group("value") == "a|41|"
    assert "fast_pattern" in CONTENT_MODIFIERS
    assert "content" not in CONTENT_MODIFIERS


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("|41 42|", (b"AB", "hex")),
        ("a|20|b", (b"a b", "mixed")),
        ("abc", (b"abc", "literal")),
        ("|zz|", (None, "mixed")),
        ("a\\;b", (None, "mixed")),
    ],
)
def test_decode_content_is_public_parser_truth(
    value: str, expected: tuple[bytes | None, str]
) -> None:
    assert decode_content(value) == expected
