from pathlib import Path

from hardening_game.fixture import (
    ValidationCase,
    build_validation_contract,
    load_fixture,
    sanitize_l5_rule,
)


def test_sanitize_l5_rule_removes_identity_metadata_but_keeps_sid_and_rev() -> None:
    rule = (
        'alert http any any -> $HOME_NET any '
        '(msg:"TP-Link RCE CVE-2025-9961"; '
        'flow:established,to_server; http.method; content:"POST"; '
        'reference:url,example.test/advisory; reference:cve,2025-9961; '
        'classtype:web-application-attack; sid:2065809; rev:1; '
        'metadata:affected_product TPLINK, cve CVE_2025_9961;)'
    )

    sanitized = sanitize_l5_rule(rule)

    assert 'content:"POST"' in sanitized
    assert "sid:2065809;" in sanitized
    assert "rev:1;" in sanitized
    assert "msg:" not in sanitized
    assert "reference:" not in sanitized
    assert "classtype:" not in sanitized
    assert "metadata:" not in sanitized


def test_load_fixture_exposes_hidden_ground_truth_and_sanitized_rule() -> None:
    fixture = load_fixture("tp_link_genieacs")

    assert fixture.sid == 2065809
    assert fixture.cve == "CVE-2025-9961"
    assert fixture.revision == 1
    assert fixture.pcap_path.name == "2065809.pcap"
    assert fixture.pcap_path.is_file()
    assert "sid:2065809;" in fixture.sanitized_rule
    assert "CVE-2025-9961" not in fixture.sanitized_rule


def test_smart_install_fixture_has_a_validated_pcap() -> None:
    fixture = load_fixture("smart_install")

    assert fixture.sid == 2025472
    assert fixture.cve == "CVE-2018-0171"
    assert fixture.pcap_path.name == "2025472.pcap"
    assert fixture.pcap_path.is_file()
    assert "CVE-2018-0171" not in fixture.sanitized_rule
    assert len(fixture.validation_cases) >= 10
    assert any(case.expected_alert for case in fixture.validation_cases)
    assert any(not case.expected_alert for case in fixture.validation_cases)
    assert all(case.pcap_path.is_file() for case in fixture.validation_cases)


def test_tp_link_fixture_keeps_legacy_single_pcap_validation() -> None:
    fixture = load_fixture("tp_link_genieacs")

    assert fixture.validation_cases == ()


def test_build_validation_contract_groups_positive_and_negative_cases() -> None:
    contract = build_validation_contract(
        (
            ValidationCase("P0", Path("positive.pcap"), True, "canonical payload"),
            ValidationCase("N0", Path("negative.pcap"), False, "benign payload"),
        )
    )

    assert "Required signature-positives — must alert on the fixture SID:" in contract
    assert "- P0: canonical payload" in contract
    assert "Required negatives — must remain silent on the fixture SID:" in contract
    assert "- N0: benign payload" in contract
    assert "Every case must meet its expected outcome." in contract


def test_build_validation_contract_describes_legacy_single_pcap() -> None:
    contract = build_validation_contract(())

    assert "Legacy single-PCAP contract" in contract
    assert "must alert on the fixture SID" in contract
