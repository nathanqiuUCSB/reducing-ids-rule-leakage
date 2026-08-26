import pytest

from hardening_game.fixture import load_fixture
from hardening_game.suricata.validate import replay_rule, replay_suite, syntax_check_rule


@pytest.mark.integration
def test_original_fixture_parses_and_alerts_on_its_pcap() -> None:
    fixture = load_fixture("smart_install")

    syntax = syntax_check_rule(fixture.rule)
    replay = replay_rule(fixture.rule, fixture.pcap_path, expected_sid=fixture.sid)

    assert syntax.valid, syntax.error
    assert replay.fired, replay.error


@pytest.mark.integration
def test_original_smart_install_rule_passes_committed_suite() -> None:
    fixture = load_fixture("smart_install")

    assert fixture.validation_cases
    result = replay_suite(
        fixture.rule, fixture.validation_cases, expected_sid=fixture.sid
    )

    assert result.fired, result.error
    assert all(case.passed for case in result.cases)
    assert any(case.expected_alert for case in result.cases)
    assert any(not case.expected_alert for case in result.cases)
