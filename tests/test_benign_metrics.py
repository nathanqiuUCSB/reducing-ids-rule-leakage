import json
from pathlib import Path
import subprocess

from hardening_game.benign.metrics import (
    BenignCaptureResult,
    aggregate_benign_metrics,
)
from hardening_game.suricata.validate import replay_benign_capture


def test_benign_metrics_report_capture_and_flow_rates() -> None:
    aggregate = aggregate_benign_metrics(
        (
            BenignCaptureResult(
                source_id="A",
                coverage_tier="level1",
                capture_name="a.pcap",
                fired=True,
                total_alerts=2,
                relevant_flow_count=4,
                alerting_relevant_flow_count=1,
                alerts_per_relevant_flow=0.5,
                error=None,
            ),
            BenignCaptureResult(
                source_id="B",
                coverage_tier="level2",
                capture_name="b.pcap",
                fired=False,
                total_alerts=0,
                relevant_flow_count=6,
                alerting_relevant_flow_count=0,
                alerts_per_relevant_flow=0.0,
                error=None,
            ),
        ),
        requested=2,
        cache_errors=(),
    )
    assert aggregate.capture_firing_rate == 0.5
    assert aggregate.alerting_flow_rate == 0.1
    assert aggregate.total_alert_count == 2


def test_no_available_benign_data_produces_null_rates() -> None:
    aggregate = aggregate_benign_metrics(
        (), requested=3, cache_errors=("three files missing",)
    )
    assert aggregate.corpus_available is False
    assert aggregate.capture_firing_rate is None
    assert aggregate.alerting_flow_rate is None


def test_unmeasurable_flows_are_excluded_from_flow_rate() -> None:
    result = BenignCaptureResult(
        source_id="A",
        coverage_tier="level1",
        capture_name="a.pcap",
        fired=True,
        total_alerts=1,
        relevant_flow_count=None,
        alerting_relevant_flow_count=None,
        alerts_per_relevant_flow=None,
        error=None,
    )

    aggregate = aggregate_benign_metrics(
        (result,), requested=2, cache_errors=("one capture missing",)
    )

    assert aggregate.corpus_available is True
    assert aggregate.captures_evaluated == 1
    assert aggregate.captures_missing == 1
    assert aggregate.capture_firing_rate == 1.0
    assert aggregate.alerting_flow_rate is None
    assert aggregate.coverage_tiers_present == {"level1": 1}


def test_replay_benign_capture_counts_only_fixture_sid_and_relevant_flows(
    tmp_path: Path,
) -> None:
    pcap = tmp_path / "benign.pcap"
    pcap.touch()

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        log_dir = Path(command[command.index("-l") + 1])
        events = [
            {
                "event_type": "flow",
                "flow_id": 1,
                "proto": "TCP",
                "app_proto": "http",
                "src_ip": "198.51.100.10",
                "dest_ip": "10.0.0.10",
                "src_port": 51000,
                "dest_port": 80,
            },
            {
                "event_type": "flow",
                "flow_id": 2,
                "proto": "TCP",
                "app_proto": "http",
                "src_ip": "198.51.100.11",
                "dest_ip": "10.0.0.10",
                "src_port": 51001,
                "dest_port": 80,
            },
            {
                "event_type": "flow",
                "flow_id": 3,
                "proto": "TCP",
                "app_proto": "http",
                "src_ip": "198.51.100.12",
                "dest_ip": "10.0.0.10",
                "src_port": 51002,
                "dest_port": 443,
            },
            {
                "event_type": "alert",
                "flow_id": 1,
                "alert": {"signature_id": 42},
            },
            {
                "event_type": "alert",
                "flow_id": 1,
                "alert": {"signature_id": 42},
            },
            {
                "event_type": "alert",
                "flow_id": 2,
                "alert": {"signature_id": 999},
            },
        ]
        (log_dir / "eve.json").write_text(
            "".join(json.dumps(event) + "\n" for event in events),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    result = replay_benign_capture(
        'alert http any any -> $HOME_NET 80 (flow:established,to_server; sid:42; rev:1;)',
        pcap,
        expected_sid=42,
        runner=runner,
    )

    assert result.fired is True
    assert result.total_alerts == 2
    assert result.relevant_flow_count == 2
    assert result.alerting_relevant_flow_count == 1
    assert result.alerts_per_relevant_flow == 1.0


def test_replay_benign_capture_has_null_flow_metrics_without_flow_events(
    tmp_path: Path,
) -> None:
    pcap = tmp_path / "benign.pcap"
    pcap.touch()

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        log_dir = Path(command[command.index("-l") + 1])
        (log_dir / "eve.json").write_text(
            json.dumps(
                {"event_type": "alert", "flow_id": 1, "alert": {"signature_id": 42}}
            )
            + "\n",
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    result = replay_benign_capture(
        'alert tcp any any -> $HOME_NET 80 (sid:42; rev:1;)',
        pcap,
        expected_sid=42,
        runner=runner,
    )

    assert result.total_alerts == 1
    assert result.relevant_flow_count is None
    assert result.alerting_relevant_flow_count is None
    assert result.alerts_per_relevant_flow is None


def test_replay_benign_capture_has_null_flow_metrics_with_two_constrained_ports(
    tmp_path: Path,
) -> None:
    pcap = tmp_path / "benign.pcap"
    pcap.touch()

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        log_dir = Path(command[command.index("-l") + 1])
        (log_dir / "eve.json").write_text(
            json.dumps(
                {
                    "event_type": "flow",
                    "flow_id": 1,
                    "proto": "TCP",
                    "src_port": 51000,
                    "dest_port": 80,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    result = replay_benign_capture(
        'alert tcp any 443 -> $HOME_NET 80 (sid:42; rev:1;)',
        pcap,
        expected_sid=42,
        runner=runner,
    )

    assert result.relevant_flow_count is None
    assert result.alerting_relevant_flow_count is None
    assert result.alerts_per_relevant_flow is None


def test_replay_benign_capture_counts_protocol_flows_without_constrained_port(
    tmp_path: Path,
) -> None:
    pcap = tmp_path / "benign.pcap"
    pcap.touch()

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        log_dir = Path(command[command.index("-l") + 1])
        events = [
            {
                "event_type": "flow",
                "flow_id": 1,
                "proto": "TCP",
                "app_proto": "http",
                "src_ip": "198.51.100.10",
                "dest_ip": "10.0.0.10",
                "src_port": 51000,
                "dest_port": 8080,
            },
            {
                "event_type": "flow",
                "flow_id": 2,
                "proto": "TCP",
                "app_proto": "smtp",
                "src_ip": "198.51.100.11",
                "dest_ip": "10.0.0.10",
                "src_port": 51001,
                "dest_port": 25,
            },
        ]
        (log_dir / "eve.json").write_text(
            "".join(json.dumps(event) + "\n" for event in events),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    result = replay_benign_capture(
        'alert http any any -> $HOME_NET any (sid:42; rev:1;)',
        pcap,
        expected_sid=42,
        runner=runner,
    )

    assert result.relevant_flow_count == 1
    assert result.alerting_relevant_flow_count == 0
    assert result.alerts_per_relevant_flow == 0.0


def test_replay_benign_capture_has_no_per_flow_rate_when_no_flow_is_relevant(
    tmp_path: Path,
) -> None:
    pcap = tmp_path / "benign.pcap"
    pcap.touch()

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        log_dir = Path(command[command.index("-l") + 1])
        (log_dir / "eve.json").write_text(
            json.dumps(
                {
                    "event_type": "flow",
                    "flow_id": 1,
                    "proto": "TCP",
                    "src_port": 51000,
                    "dest_port": 443,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    result = replay_benign_capture(
        'alert tcp any any -> $HOME_NET 80 (sid:42; rev:1;)',
        pcap,
        expected_sid=42,
        runner=runner,
    )

    assert result.relevant_flow_count == 0
    assert result.alerting_relevant_flow_count == 0
    assert result.alerts_per_relevant_flow is None


def test_nonzero_replay_without_usable_eve_is_unavailable(tmp_path: Path) -> None:
    pcap = tmp_path / "benign.pcap"
    pcap.touch()

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 1, "", "replay warning")

    result = replay_benign_capture(
        'alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (sid:42; rev:1;)',
        pcap,
        expected_sid=42,
        runner=runner,
    )

    assert result.error == (
        "Suricata replay exited with code 1 without usable Eve events: replay warning"
    )
    assert result.fired is False
    assert result.total_alerts == 0
    assert result.relevant_flow_count is None


def test_nonzero_replay_with_usable_eve_remains_measurable(tmp_path: Path) -> None:
    pcap = tmp_path / "benign.pcap"
    pcap.touch()

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        log_dir = Path(command[command.index("-l") + 1])
        (log_dir / "eve.json").write_text(
            json.dumps(
                {
                    "event_type": "flow",
                    "flow_id": 1,
                    "proto": "TCP",
                    "src_ip": "198.51.100.10",
                    "dest_ip": "10.0.0.10",
                    "src_port": 51000,
                    "dest_port": 80,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 1, "", "replay warning")

    result = replay_benign_capture(
        'alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (sid:42; rev:1;)',
        pcap,
        expected_sid=42,
        runner=runner,
    )

    assert result.error is None
    assert result.relevant_flow_count == 1


def test_relevant_flows_exclude_opposite_address_direction(tmp_path: Path) -> None:
    pcap = tmp_path / "benign.pcap"
    pcap.touch()

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        log_dir = Path(command[command.index("-l") + 1])
        events = [
            {
                "event_type": "flow",
                "flow_id": 1,
                "proto": "TCP",
                "src_ip": "198.51.100.10",
                "dest_ip": "10.0.0.10",
                "src_port": 51000,
                "dest_port": 80,
            },
            {
                "event_type": "flow",
                "flow_id": 2,
                "proto": "TCP",
                "src_ip": "10.0.0.10",
                "dest_ip": "198.51.100.10",
                "src_port": 51001,
                "dest_port": 80,
            },
        ]
        (log_dir / "eve.json").write_text(
            "".join(json.dumps(event) + "\n" for event in events),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    result = replay_benign_capture(
        'alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (sid:42; rev:1;)',
        pcap,
        expected_sid=42,
        runner=runner,
    )

    assert result.relevant_flow_count == 1


def test_ambiguous_address_expression_makes_flow_metrics_unmeasurable(
    tmp_path: Path,
) -> None:
    pcap = tmp_path / "benign.pcap"
    pcap.touch()

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        log_dir = Path(command[command.index("-l") + 1])
        (log_dir / "eve.json").write_text(
            json.dumps(
                {
                    "event_type": "flow",
                    "flow_id": 1,
                    "proto": "TCP",
                    "src_ip": "198.51.100.10",
                    "dest_ip": "10.0.0.10",
                    "src_port": 51000,
                    "dest_port": 80,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    result = replay_benign_capture(
        'alert tcp $UNKNOWN_NET any -> $HOME_NET 80 (sid:42; rev:1;)',
        pcap,
        expected_sid=42,
        runner=runner,
        config_path=tmp_path / "suricata.yaml",
    )

    assert result.relevant_flow_count is None
    assert result.alerting_relevant_flow_count is None
    assert result.alerts_per_relevant_flow is None


def test_relevant_flows_support_concrete_ip_cidrs_and_bracketed_unions(
    tmp_path: Path,
) -> None:
    pcap = tmp_path / "benign.pcap"
    pcap.touch()

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        log_dir = Path(command[command.index("-l") + 1])
        events = [
            {
                "event_type": "flow",
                "flow_id": 1,
                "proto": "TCP",
                "src_ip": "192.0.2.5",
                "dest_ip": "10.0.0.10",
                "src_port": 51000,
                "dest_port": 80,
            },
            {
                "event_type": "flow",
                "flow_id": 2,
                "proto": "TCP",
                "src_ip": "2001:db8::5",
                "dest_ip": "2001:db8:1::10",
                "src_port": 51001,
                "dest_port": 80,
            },
            {
                "event_type": "flow",
                "flow_id": 3,
                "proto": "TCP",
                "src_ip": "203.0.113.5",
                "dest_ip": "10.0.0.10",
                "src_port": 51002,
                "dest_port": 80,
            },
        ]
        (log_dir / "eve.json").write_text(
            "".join(json.dumps(event) + "\n" for event in events),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    result = replay_benign_capture(
        "alert tcp [192.0.2.0/24,2001:db8::/32] any -> "
        "[10.0.0.10,2001:db8:1::/64] 80 (sid:42; rev:1;)",
        pcap,
        expected_sid=42,
        runner=runner,
        config_path=tmp_path / "suricata.yaml",
    )

    assert result.relevant_flow_count == 2


def test_mixed_address_list_requires_positive_and_excludes_negative_matches(
    tmp_path: Path,
) -> None:
    pcap = tmp_path / "benign.pcap"
    pcap.touch()

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        log_dir = Path(command[command.index("-l") + 1])
        events = [
            {
                "event_type": "flow",
                "flow_id": flow_id,
                "proto": "TCP",
                "src_ip": source_ip,
                "dest_ip": "10.0.0.10",
                "src_port": 51000 + flow_id,
                "dest_port": 80,
            }
            for flow_id, source_ip in enumerate(
                ("192.0.2.5", "192.0.2.200", "203.0.113.5"),
                start=1,
            )
        ]
        (log_dir / "eve.json").write_text(
            "".join(json.dumps(event) + "\n" for event in events),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    result = replay_benign_capture(
        "alert tcp [192.0.2.0/24,!192.0.2.128/25] any -> "
        "10.0.0.0/8 80 (sid:42; rev:1;)",
        pcap,
        expected_sid=42,
        runner=runner,
        config_path=tmp_path / "custom.yaml",
    )

    assert result.relevant_flow_count == 1


def test_negative_only_address_list_starts_from_all_addresses(
    tmp_path: Path,
) -> None:
    pcap = tmp_path / "benign.pcap"
    pcap.touch()

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        log_dir = Path(command[command.index("-l") + 1])
        events = [
            {
                "event_type": "flow",
                "flow_id": flow_id,
                "proto": "TCP",
                "src_ip": source_ip,
                "dest_ip": "10.0.0.10",
                "src_port": 51000 + flow_id,
                "dest_port": 80,
            }
            for flow_id, source_ip in enumerate(
                ("192.0.2.5", "198.51.100.5", "203.0.113.5"),
                start=1,
            )
        ]
        (log_dir / "eve.json").write_text(
            "".join(json.dumps(event) + "\n" for event in events),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    result = replay_benign_capture(
        "alert tcp [!192.0.2.0/24,!198.51.100.0/24] any -> "
        "10.0.0.0/8 80 (sid:42; rev:1;)",
        pcap,
        expected_sid=42,
        runner=runner,
        config_path=tmp_path / "custom.yaml",
    )

    assert result.relevant_flow_count == 1


def test_custom_config_address_variable_makes_flow_metrics_unmeasurable(
    tmp_path: Path,
) -> None:
    pcap = tmp_path / "benign.pcap"
    pcap.touch()
    custom_config = tmp_path / "custom.yaml"
    custom_config.write_text("%YAML 1.1\n---\n")

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        log_dir = Path(command[command.index("-l") + 1])
        (log_dir / "eve.json").write_text(
            json.dumps(
                {
                    "event_type": "flow",
                    "flow_id": 1,
                    "proto": "TCP",
                    "src_ip": "198.51.100.10",
                    "dest_ip": "10.0.0.10",
                    "src_port": 51000,
                    "dest_port": 80,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    result = replay_benign_capture(
        'alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (sid:42; rev:1;)',
        pcap,
        expected_sid=42,
        runner=runner,
        config_path=custom_config,
    )

    assert result.relevant_flow_count is None
    assert result.alerting_relevant_flow_count is None
    assert result.alerts_per_relevant_flow is None
