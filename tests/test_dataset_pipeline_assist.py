from pathlib import Path

import pytest

from hardening_game.dataset_pipeline.assist import (
    blocking_predicate_anchor,
    complete_manual_pcap,
    describe_byte_test,
    explain_rule,
)
from hardening_game.dataset_pipeline.manifest import DatasetRecord
from hardening_game.suricata.rule_model import parse_suricata_rule


PCRE_GATED = (
    'alert http any any -> $HOME_NET any (flow:established,to_server; '
    'http.uri; content:"/acme/"; pcre:"/^[a-z]{3}\\x2f/R"; sid:9000004; rev:1;)'
)

BYTE_TEST_GATED = (
    'alert tcp any any -> $HOME_NET 873 (flow:established,to_server; '
    'content:"|40|ACME|3a|"; byte_test:4,<,16,9,relative; sid:9000005; rev:1;)'
)

PLAIN = (
    'alert http any any -> $HOME_NET any (flow:established,to_server; '
    'http.uri; content:"/acme/plain"; sid:9000006; rev:1;)'
)


def _record(rule: str, *, name: str = "acme-rule-009", sid: int = 9000004) -> DatasetRecord:
    return DatasetRecord(
        name=name,
        sid=sid,
        cve="CVE-2025-12345",
        rule=rule,
        status="suite_needs_manual_pcap",
    )


def test_byte_test_is_translated_into_a_sentence() -> None:
    described = describe_byte_test("4,>,16,9,relative,little")

    assert "4 bytes at offset 9" in described
    assert "after the end of the previous match" in described
    assert "little-endian" in described
    assert "greater than 16" in described


def test_an_unrecognised_byte_test_is_echoed_rather_than_mistranslated() -> None:
    assert describe_byte_test("4,>") == "byte_test:4,>"


@pytest.mark.parametrize(
    ("rule", "expected_buffer"),
    [
        (PCRE_GATED, "http.uri"),
        (BYTE_TEST_GATED, "payload"),
    ],
)
def test_the_anchor_is_the_content_the_blocking_option_is_relative_to(
    rule: str, expected_buffer: str
) -> None:
    anchor = blocking_predicate_anchor(parse_suricata_rule(rule))

    assert anchor is not None
    buffer, predicate_id = anchor
    assert buffer == expected_buffer
    assert predicate_id in {
        predicate.predicate_id
        for group in parse_suricata_rule(rule).sticky_groups
        for predicate in group.predicates
    }


def test_explain_names_the_blocking_option_and_what_is_already_derived() -> None:
    explained = explain_rule(_record(PCRE_GATED))

    assert "pcre" in explained
    assert "/^[a-z]{3}\\x2f/R" in explained  # the exact pattern, not a paraphrase
    assert "/acme/" in explained  # the literal already placed for the user
    assert "http.uri" in explained
    assert "complete-pcap" in explained  # the next command to run


def test_explain_says_so_when_nothing_is_blocking() -> None:
    explained = explain_rule(_record(PLAIN))

    assert "Nothing is blocking automatic synthesis" in explained
    assert "complete-pcap" not in explained


@pytest.mark.integration
def test_a_correct_pcre_fill_produces_a_suricata_validated_suite(tmp_path: Path) -> None:
    result = complete_manual_pcap(
        _record(PCRE_GATED),
        dataset_id="acme",
        fill=b"abc/",  # three lowercase letters then a slash, anchored after /acme/
        project_root=tmp_path,
    )

    assert result.status == "generated", result.reason
    assert [case.expected_alert for case in result.cases] == [True, False]
    assert all(case.pcap_path.is_file() for case in result.cases)
    assert all("manual" in case.pcap_path.name for case in result.cases)


@pytest.mark.integration
def test_a_correct_byte_test_fill_produces_a_suricata_validated_suite(
    tmp_path: Path,
) -> None:
    result = complete_manual_pcap(
        _record(BYTE_TEST_GATED, sid=9000005),
        dataset_id="acme",
        # nine filler bytes, then a big-endian 5 to satisfy `4,<,16,9,relative`
        fill=b"A" * 9 + b"\x00\x00\x00\x05",
        project_root=tmp_path,
    )

    assert result.status == "generated", result.reason
    assert result.kind == "auto_raw_tcp"


@pytest.mark.integration
def test_a_wrong_fill_fails_with_a_reason_naming_the_anchor_and_writes_nothing(
    tmp_path: Path,
) -> None:
    result = complete_manual_pcap(
        _record(PCRE_GATED),
        dataset_id="acme",
        fill=b"999/",  # digits, so `^[a-z]{3}` cannot match
        project_root=tmp_path,
    )

    assert result.status == "needs_manual_pcap"
    assert "did not satisfy the rule under real Suricata" in result.reason
    assert "inserted after" in result.reason
    assert result.cases == ()
    assert not list(tmp_path.rglob("*.pcap"))
