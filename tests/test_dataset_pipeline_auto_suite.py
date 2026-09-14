from pathlib import Path

import pytest

from hardening_game.dataset_pipeline.auto_suite import (
    blocking_options,
    buffer_bytes,
    generate_auto_suite,
)
from hardening_game.suricata.rule_model import parse_suricata_rule


HTTP_METHOD_URI = (
    'alert http any any -> $HOME_NET any (flow:established,to_server; '
    'http.method; content:"POST"; http.uri; content:"/acme/lic/accept?bundle="; '
    'startswith; sid:9000001; rev:1;)'
)

HTTP_WITH_BODY = (
    'alert http any any -> $HOME_NET any (flow:established,to_server; '
    'http.method; content:"POST"; http.uri; content:"/cgi-bin/handler"; '
    'http.request_body; content:"operation=write"; content:"country=|24 28|"; '
    'sid:9000002; rev:1;)'
)

RAW_TCP = (
    'alert tcp any any -> $HOME_NET 4786 (flow:established,to_server; '
    'content:"|00 00 00 01|"; content:"ACMEPAYLOAD"; distance:4; '
    'sid:9000003; rev:1;)'
)

PCRE_GATED = (
    'alert http any any -> $HOME_NET any (flow:established,to_server; '
    'http.uri; content:"/acme/"; pcre:"/^[a-z]{3}\\x2f/R"; sid:9000004; rev:1;)'
)

BYTE_TEST_GATED = (
    'alert tcp any any -> $HOME_NET 873 (flow:established,to_server; '
    'content:"|40|ACME|3a|"; byte_test:4,>,16,9,relative,little; '
    'sid:9000005; rev:1;)'
)


def test_buffer_bytes_packs_literals_and_honours_distance() -> None:
    parsed = parse_suricata_rule(RAW_TCP)
    payload = buffer_bytes(parsed.sticky_groups[0])

    assert payload.startswith(b"\x00\x00\x00\x01")
    assert payload.endswith(b"ACMEPAYLOAD")
    # four filler bytes for `distance:4` between the two literals
    assert payload == b"\x00\x00\x00\x01" + b"AAAA" + b"ACMEPAYLOAD"


def test_buffer_bytes_honours_offset() -> None:
    rule = (
        'alert tcp any any -> any 9999 (content:"ACME"; offset:6; sid:1; rev:1;)'
    )
    parsed = parse_suricata_rule(rule)

    assert buffer_bytes(parsed.sticky_groups[0]) == b"AAAAAA" + b"ACME"


@pytest.mark.parametrize(
    ("rule", "expected"),
    [
        (PCRE_GATED, "pcre"),
        (BYTE_TEST_GATED, "byte_test"),
    ],
)
def test_blocking_options_names_the_offending_option(rule: str, expected: str) -> None:
    assert expected in blocking_options(parse_suricata_rule(rule))


def test_flowbits_set_is_not_blocking_but_isset_is() -> None:
    setter = (
        'alert http any any -> any 80 (flowbits:set,acme.step1; http.uri; '
        'content:"/a"; sid:1; rev:1;)'
    )
    gate = (
        'alert http any any -> any 80 (flowbits:isset,acme.step1; http.uri; '
        'content:"/a"; sid:1; rev:1;)'
    )

    assert blocking_options(parse_suricata_rule(setter)) == ()
    assert blocking_options(parse_suricata_rule(gate)) == ("flowbits:isset",)


@pytest.mark.parametrize(
    ("rule", "reason_fragment"),
    [
        (PCRE_GATED, "pcre"),
        (BYTE_TEST_GATED, "byte_test"),
    ],
)
def test_a_gated_rule_is_reported_as_needing_a_manual_pcap(
    tmp_path: Path, rule: str, reason_fragment: str
) -> None:
    result = generate_auto_suite(
        rule, rule_name="r", sid=9000004, output_dir=tmp_path, project_root=tmp_path
    )

    assert result.status == "needs_manual_pcap"
    assert reason_fragment in result.reason
    assert reason_fragment in result.blocking_predicates
    assert result.cases == ()


def test_negated_content_is_refused_by_predicate_name(tmp_path: Path) -> None:
    rule = (
        'alert http any any -> any 80 (http.uri; content:"/a"; '
        'http.header_names; content:!"Referer|0d 0a|"; sid:1; rev:1;)'
    )

    result = generate_auto_suite(
        rule, rule_name="r", sid=1, output_dir=tmp_path, project_root=tmp_path
    )

    assert result.status == "needs_manual_pcap"
    assert "negated content" in result.reason


def test_an_unsupported_buffer_is_refused_by_name(tmp_path: Path) -> None:
    rule = (
        'alert http any any -> any 80 (http.header_names; '
        'content:"|0d 0a|X-Token|0d 0a|"; sid:1; rev:1;)'
    )

    result = generate_auto_suite(
        rule, rule_name="r", sid=1, output_dir=tmp_path, project_root=tmp_path
    )

    assert result.status == "needs_manual_pcap"
    assert "http.header_names" in result.reason


def test_a_non_tcp_protocol_is_refused(tmp_path: Path) -> None:
    rule = 'alert dns any any -> any any (dns.query; content:"acme"; sid:1; rev:1;)'

    result = generate_auto_suite(
        rule, rule_name="r", sid=1, output_dir=tmp_path, project_root=tmp_path
    )

    assert result.status == "needs_manual_pcap"
    assert "dns" in result.reason


@pytest.mark.integration
@pytest.mark.parametrize(
    ("rule", "sid", "kind"),
    [
        (HTTP_METHOD_URI, 9000001, "auto_http"),
        (HTTP_WITH_BODY, 9000002, "auto_http"),
        (RAW_TCP, 9000003, "auto_raw_tcp"),
    ],
)
def test_supported_shapes_generate_a_suricata_validated_suite(
    tmp_path: Path, rule: str, sid: int, kind: str
) -> None:
    result = generate_auto_suite(
        rule, rule_name="r", sid=sid, output_dir=tmp_path, project_root=tmp_path
    )

    assert result.status == "generated", result.reason
    assert result.kind == kind
    assert [case.expected_alert for case in result.cases] == [True, False]
    assert all(case.pcap_path.is_file() for case in result.cases)


@pytest.mark.integration
def test_a_rule_whose_synthesized_traffic_does_not_fire_is_refused_not_written(
    tmp_path: Path,
) -> None:
    """`endswith` on a non-final content can't hold under tight packing. The
    suite must be refused on the real replay result, not written out anyway."""
    rule = (
        'alert http any any -> $HOME_NET any (flow:established,to_server; '
        'http.uri; content:"/first"; endswith; content:"/second"; '
        'sid:9000009; rev:1;)'
    )

    result = generate_auto_suite(
        rule, rule_name="r", sid=9000009, output_dir=tmp_path, project_root=tmp_path
    )

    assert result.status == "needs_manual_pcap"
    assert "did not behave as required" in result.reason
    assert not list(tmp_path.glob("*.pcap"))
