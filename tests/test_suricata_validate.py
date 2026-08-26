import json
from pathlib import Path
import subprocess

from hardening_game.fixture import ValidationCase
from hardening_game.suricata.validate import (
    MINIMAL_CONFIG,
    CaseReplayResult,
    ReplayResult,
    SyntaxResult,
    parse_expected_sid_alert,
    replay_rule,
    replay_suite,
    syntax_check_rule,
)


def test_minimal_config_uses_a_writable_log_directory() -> None:
    assert "default-log-dir: /tmp" in MINIMAL_CONFIG


def test_parse_expected_sid_alert_requires_matching_signature_id(tmp_path: Path) -> None:
    eve = tmp_path / "eve.json"
    eve.write_text(
        "\n".join(
            [
                json.dumps({"event_type": "alert", "alert": {"signature_id": 999}}),
                json.dumps({"event_type": "flow"}),
                json.dumps({"event_type": "alert", "alert": {"signature_id": 2065809}}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    assert parse_expected_sid_alert(eve, 2065809) is True
    assert parse_expected_sid_alert(eve, 1234) is False


def test_syntax_check_runs_suricata_test_mode(tmp_path: Path) -> None:
    calls: list[list[str]] = []

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    result = syntax_check_rule(
        'alert tcp any any -> any any (sid:2065809; rev:2;)',
        runner=runner,
        config_path=tmp_path / "suricata.yaml",
    )

    assert result == SyntaxResult(valid=True, error=None)
    assert "-T" in calls[0]
    assert "-S" in calls[0]


def test_replay_rule_requires_expected_sid_alert(tmp_path: Path) -> None:
    pcap = tmp_path / "fixture.pcap"
    pcap.touch()

    def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        log_dir = Path(command[command.index("-l") + 1])
        log_dir.mkdir(parents=True, exist_ok=True)
        (log_dir / "eve.json").write_text(
            json.dumps({"event_type": "alert", "alert": {"signature_id": 999}}) + "\n",
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    result = replay_rule(
        'alert tcp any any -> any any (sid:2065809; rev:2;)',
        pcap,
        expected_sid=2065809,
        runner=runner,
        config_path=tmp_path / "suricata.yaml",
    )

    assert result.fired is False
    assert result.error is None
    assert result.alerts == [{"event_type": "alert", "alert": {"signature_id": 999}}]


def test_replay_suite_requires_every_case_expectation(tmp_path: Path) -> None:
    positive = tmp_path / "positive.pcap"
    negative = tmp_path / "negative.pcap"
    positive.touch()
    negative.touch()
    cases = (
        ValidationCase(
            name="P0",
            pcap_path=positive,
            expected_alert=True,
            reason="must fire",
        ),
        ValidationCase(
            name="N0",
            pcap_path=negative,
            expected_alert=False,
            reason="must stay silent",
        ),
    )
    calls: list[str] = []

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        pcap = command[command.index("-r") + 1]
        calls.append(Path(pcap).name)
        log_dir = Path(command[command.index("-l") + 1])
        log_dir.mkdir(parents=True, exist_ok=True)
        signature_id = 2025472 if Path(pcap).name == "positive.pcap" else 999
        (log_dir / "eve.json").write_text(
            json.dumps({"event_type": "alert", "alert": {"signature_id": signature_id}})
            + "\n",
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    result = replay_suite(
        'alert tcp any any -> any any (sid:2025472; rev:1;)',
        cases,
        expected_sid=2025472,
        runner=runner,
        config_path=tmp_path / "suricata.yaml",
    )

    assert result.fired is True
    assert result.error is None
    assert calls == ["positive.pcap", "negative.pcap"]
    assert [case.passed for case in result.cases] == [True, True]


def test_replay_suite_reports_positive_miss_and_negative_false_positive(
    tmp_path: Path,
) -> None:
    positive = tmp_path / "positive.pcap"
    negative = tmp_path / "negative.pcap"
    positive.touch()
    negative.touch()
    cases = (
        ValidationCase("P0", positive, True, "must fire"),
        ValidationCase("N0", negative, False, "must stay silent"),
    )

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        pcap = Path(command[command.index("-r") + 1]).name
        log_dir = Path(command[command.index("-l") + 1])
        log_dir.mkdir(parents=True, exist_ok=True)
        # Both fire: positive miss is avoided, negative becomes a false positive.
        signature_id = 2025472
        if pcap == "positive.pcap":
            signature_id = 999
        (log_dir / "eve.json").write_text(
            json.dumps({"event_type": "alert", "alert": {"signature_id": signature_id}})
            + "\n",
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    result = replay_suite(
        'alert tcp any any -> any any (sid:2025472; rev:1;)',
        cases,
        expected_sid=2025472,
        runner=runner,
        config_path=tmp_path / "suricata.yaml",
    )

    assert result.fired is False
    assert result.error is None
    assert [case.name for case in result.cases if not case.passed] == ["P0", "N0"]
    assert [case.passed for case in result.cases] == [False, False]
    assert isinstance(result.cases[0], CaseReplayResult)
