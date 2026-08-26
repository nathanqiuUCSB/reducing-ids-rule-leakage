"""Validate a single hardened Suricata rule before and during PCAP replay."""

from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    ip_address,
    ip_network,
)
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Callable, Sequence

from hardening_game.fixture import ValidationCase


MINIMAL_CONFIG = """\
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "!$HOME_NET"
    HTTP_SERVERS: "$HOME_NET"
    SMTP_SERVERS: "$HOME_NET"
  port-groups:
    HTTP_PORTS: "[80,8080]"
default-log-dir: /tmp
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - flow
pcap-file:
  checksum-checks: no
"""

Runner = Callable[..., subprocess.CompletedProcess[str]]


@dataclass(frozen=True)
class SyntaxResult:
    valid: bool
    error: str | None


@dataclass(frozen=True)
class CaseReplayResult:
    name: str
    expected_alert: bool
    fired: bool
    passed: bool
    reason: str
    error: str | None = None
    alerts: list[dict[str, object]] = field(default_factory=list)


@dataclass(frozen=True)
class ReplayResult:
    fired: bool
    error: str | None
    alerts: list[dict[str, object]]
    cases: list[CaseReplayResult] = field(default_factory=list)


@dataclass(frozen=True)
class BenignReplayResult:
    fired: bool
    total_alerts: int
    relevant_flow_count: int | None
    alerting_relevant_flow_count: int | None
    alerts_per_relevant_flow: float | None
    error: str | None


def parse_expected_sid_alert(eve_path: Path, expected_sid: int) -> bool:
    """Return true only when eve.json contains an alert for the fixture SID."""
    if not eve_path.exists():
        return False
    for line in eve_path.read_text(encoding="utf-8").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        alert = event.get("alert")
        if (
            event.get("event_type") == "alert"
            and isinstance(alert, dict)
            and alert.get("signature_id") == expected_sid
        ):
            return True
    return False


def _find_suricata() -> str | None:
    return shutil.which("suricata")


def _write_rule_and_config(
    directory: Path, rule_text: str, config_path: Path | None
) -> tuple[Path, Path]:
    rule_path = directory / "rule.rules"
    rule_path.write_text(rule_text.rstrip() + "\n", encoding="utf-8")
    if config_path is not None:
        return rule_path, config_path
    generated_config = directory / "suricata.yaml"
    generated_config.write_text(MINIMAL_CONFIG, encoding="utf-8")
    return rule_path, generated_config


def _run(command: list[str], runner: Runner) -> subprocess.CompletedProcess[str]:
    return runner(command, capture_output=True, text=True, timeout=30)


def syntax_check_rule(
    rule_text: str,
    *,
    runner: Runner = subprocess.run,
    suricata_bin: str | None = None,
    config_path: Path | None = None,
) -> SyntaxResult:
    """Run `suricata -T` for a single rule before attempting PCAP replay."""
    binary = suricata_bin or _find_suricata()
    if binary is None:
        return SyntaxResult(valid=False, error="suricata not found on PATH")

    with tempfile.TemporaryDirectory(prefix="hardening_syntax_") as temporary:
        directory = Path(temporary)
        rule_path, config = _write_rule_and_config(directory, rule_text, config_path)
        command = [binary, "-T", "-S", str(rule_path), "-c", str(config)]
        try:
            result = _run(command, runner)
        except subprocess.TimeoutExpired:
            return SyntaxResult(valid=False, error="suricata syntax check timed out")
        except OSError as exc:
            return SyntaxResult(valid=False, error=str(exc))
    if result.returncode == 0:
        return SyntaxResult(valid=True, error=None)
    detail = (result.stderr or result.stdout or f"exit code {result.returncode}").strip()
    return SyntaxResult(valid=False, error=detail[:500])


def _read_alerts(eve_path: Path) -> list[dict[str, object]]:
    if not eve_path.exists():
        return []
    alerts: list[dict[str, object]] = []
    for line in eve_path.read_text(encoding="utf-8").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("event_type") == "alert":
            alerts.append(event)
    return alerts


def _read_events(eve_path: Path) -> list[dict[str, object]]:
    if not eve_path.exists():
        return []
    events: list[dict[str, object]] = []
    for line in eve_path.read_text(encoding="utf-8").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict):
            events.append(event)
    return events


@dataclass(frozen=True)
class _FlowRelevance:
    protocol: str
    source_address: _AddressConstraint
    destination_address: _AddressConstraint
    port_field: str | None
    port: int | None


IPAddress = IPv4Address | IPv6Address
IPNetwork = IPv4Network | IPv6Network


@dataclass(frozen=True)
class _AddressClause:
    networks: tuple[IPNetwork, ...] = ()
    negated: bool = False
    matches_any: bool = False

    def contains(self, address: IPAddress) -> bool:
        if self.matches_any:
            return True
        return any(
            address.version == network.version and address in network
            for network in self.networks
        )


@dataclass(frozen=True)
class _AddressConstraint:
    alternatives: tuple[_AddressClause, ...]

    def matches(self, value: object) -> bool:
        if not isinstance(value, str):
            return False
        try:
            address = ip_address(value)
        except ValueError:
            return False
        positive_clauses = tuple(
            clause for clause in self.alternatives if not clause.negated
        )
        negative_clauses = tuple(
            clause for clause in self.alternatives if clause.negated
        )
        positive_match = not positive_clauses or any(
            clause.contains(address) for clause in positive_clauses
        )
        negative_match = any(
            clause.contains(address) for clause in negative_clauses
        )
        return positive_match and not negative_match


_HOME_NETWORKS: tuple[IPNetwork, ...] = (
    ip_network("192.168.0.0/16"),
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
)
_ADDRESS_GROUPS = {
    "$HOME_NET": _AddressClause(networks=_HOME_NETWORKS),
    "$HTTP_SERVERS": _AddressClause(networks=_HOME_NETWORKS),
    "$EXTERNAL_NET": _AddressClause(networks=_HOME_NETWORKS, negated=True),
}


def _parse_address_clause(
    expression: str, *, allow_minimal_groups: bool
) -> _AddressClause | None:
    negated = expression.startswith("!")
    value = expression[1:] if negated else expression
    if value.casefold() == "any":
        return None if negated else _AddressClause(matches_any=True)
    group = _ADDRESS_GROUPS.get(value) if allow_minimal_groups else None
    if group is not None:
        return _AddressClause(
            networks=group.networks,
            negated=group.negated is not negated,
        )
    try:
        network = ip_network(value, strict=False)
    except ValueError:
        return None
    return _AddressClause(networks=(network,), negated=negated)


def _parse_address_constraint(
    expression: str, *, allow_minimal_groups: bool
) -> _AddressConstraint | None:
    if expression.startswith("[") and expression.endswith("]"):
        members = expression[1:-1].split(",")
        if not members or any(not member for member in members):
            return None
    else:
        members = [expression]
    clauses = tuple(
        _parse_address_clause(
            member,
            allow_minimal_groups=allow_minimal_groups,
        )
        for member in members
    )
    if any(clause is None for clause in clauses):
        return None
    return _AddressConstraint(
        alternatives=tuple(clause for clause in clauses if clause is not None)
    )


_RULE_HEADER = re.compile(
    r"^\s*\S+\s+(?P<protocol>\S+)\s+(?P<src_addr>\S+)\s+"
    r"(?P<src_port>\S+)\s+(?P<direction>->|<-|<>)\s+"
    r"(?P<dest_addr>\S+)\s+(?P<dest_port>\S+)\s*\("
)


def _infer_flow_relevance(
    rule_text: str, *, allow_minimal_groups: bool
) -> _FlowRelevance | None:
    match = _RULE_HEADER.match(rule_text)
    if match is None or match.group("direction") == "<>":
        return None
    source_address = match.group("src_addr")
    destination_address = match.group("dest_addr")
    source_port = match.group("src_port")
    destination_port = match.group("dest_port")
    if match.group("direction") == "<-":
        source_address, destination_address = destination_address, source_address
        source_port, destination_port = destination_port, source_port
    source_constraint = _parse_address_constraint(
        source_address,
        allow_minimal_groups=allow_minimal_groups,
    )
    destination_constraint = _parse_address_constraint(
        destination_address,
        allow_minimal_groups=allow_minimal_groups,
    )
    if source_constraint is None or destination_constraint is None:
        return None
    constrained = [
        (field, int(value))
        for field, value in (
            ("src_port", source_port),
            ("dest_port", destination_port),
        )
        if value.isdigit()
    ]
    if len(constrained) > 1:
        return None
    field, port = constrained[0] if constrained else (None, None)
    return _FlowRelevance(
        protocol=match.group("protocol").casefold(),
        source_address=source_constraint,
        destination_address=destination_constraint,
        port_field=field,
        port=port,
    )


def _flow_is_relevant(event: dict[str, object], relevance: _FlowRelevance) -> bool:
    protocol = relevance.protocol
    if protocol in {"tcp", "udp", "icmp", "ip"}:
        event_protocol = event.get("proto")
        if not isinstance(event_protocol, str) or event_protocol.casefold() != protocol:
            return False
    else:
        application_protocol = event.get("app_proto")
        if (
            not isinstance(application_protocol, str)
            or application_protocol.casefold() != protocol
        ):
            return False
    return (
        relevance.source_address.matches(event.get("src_ip"))
        and relevance.destination_address.matches(event.get("dest_ip"))
        and (
            relevance.port_field is None
            or event.get(relevance.port_field) == relevance.port
        )
    )


def replay_benign_capture(
    rule_text: str,
    pcap_path: Path,
    *,
    expected_sid: int,
    runner: Runner = subprocess.run,
    suricata_bin: str | None = None,
    config_path: Path | None = None,
) -> BenignReplayResult:
    """Replay benign traffic and measure fixture-SID alerts on relevant flows."""
    unavailable = dict(
        fired=False,
        total_alerts=0,
        relevant_flow_count=None,
        alerting_relevant_flow_count=None,
        alerts_per_relevant_flow=None,
    )
    binary = suricata_bin or _find_suricata()
    if binary is None:
        return BenignReplayResult(
            error="suricata not found on PATH",
            **unavailable,
        )
    if not pcap_path.is_file():
        return BenignReplayResult(
            error=f"PCAP not found: {pcap_path}",
            **unavailable,
        )

    with tempfile.TemporaryDirectory(prefix="hardening_benign_") as temporary:
        directory = Path(temporary)
        rule_path, config = _write_rule_and_config(directory, rule_text, config_path)
        command = [
            binary,
            "-r",
            str(pcap_path),
            "-S",
            str(rule_path),
            "-l",
            str(directory),
            "-c",
            str(config),
        ]
        try:
            result = _run(command, runner)
        except subprocess.TimeoutExpired:
            return BenignReplayResult(error="suricata replay timed out", **unavailable)
        except OSError as exc:
            return BenignReplayResult(error=str(exc), **unavailable)
        if result.returncode not in (0, 1):
            detail = (result.stderr or result.stdout or f"exit code {result.returncode}").strip()
            return BenignReplayResult(error=detail[:500], **unavailable)

        events = _read_events(directory / "eve.json")
        usable_events = [
            event
            for event in events
            if event.get("event_type") in {"alert", "flow"}
        ]
        if result.returncode != 0 and not usable_events:
            detail = (result.stderr or result.stdout or "no diagnostic output").strip()
            return BenignReplayResult(
                error=(
                    f"Suricata replay exited with code {result.returncode} "
                    f"without usable Eve events: {detail[:400]}"
                ),
                **unavailable,
            )
        alerts = [
            event
            for event in events
            if event.get("event_type") == "alert"
            and isinstance(event.get("alert"), dict)
            and event["alert"].get("signature_id") == expected_sid
        ]
        relevance = _infer_flow_relevance(
            rule_text,
            allow_minimal_groups=config_path is None,
        )
        flow_events = [event for event in events if event.get("event_type") == "flow"]
        if relevance is None or not flow_events:
            return BenignReplayResult(
                fired=bool(alerts),
                total_alerts=len(alerts),
                relevant_flow_count=None,
                alerting_relevant_flow_count=None,
                alerts_per_relevant_flow=None,
                error=None,
            )
        relevant_flow_ids = {
            event["flow_id"]
            for event in flow_events
            if "flow_id" in event and _flow_is_relevant(event, relevance)
        }
        alerting_flow_ids = {
            event["flow_id"]
            for event in alerts
            if event.get("flow_id") in relevant_flow_ids
        }
        relevant_count = len(relevant_flow_ids)
        return BenignReplayResult(
            fired=bool(alerts),
            total_alerts=len(alerts),
            relevant_flow_count=relevant_count,
            alerting_relevant_flow_count=len(alerting_flow_ids),
            alerts_per_relevant_flow=(
                len(alerts) / relevant_count if relevant_count else None
            ),
            error=None,
        )


def replay_rule(
    rule_text: str,
    pcap_path: Path,
    *,
    expected_sid: int,
    runner: Runner = subprocess.run,
    suricata_bin: str | None = None,
    config_path: Path | None = None,
) -> ReplayResult:
    """Replay a PCAP and accept only an alert whose SID matches expected_sid."""
    binary = suricata_bin or _find_suricata()
    if binary is None:
        return ReplayResult(fired=False, error="suricata not found on PATH", alerts=[])
    if not pcap_path.is_file():
        return ReplayResult(fired=False, error=f"PCAP not found: {pcap_path}", alerts=[])

    with tempfile.TemporaryDirectory(prefix="hardening_replay_") as temporary:
        directory = Path(temporary)
        rule_path, config = _write_rule_and_config(directory, rule_text, config_path)
        command = [
            binary,
            "-r",
            str(pcap_path),
            "-S",
            str(rule_path),
            "-l",
            str(directory),
            "-c",
            str(config),
        ]
        try:
            result = _run(command, runner)
        except subprocess.TimeoutExpired:
            return ReplayResult(fired=False, error="suricata replay timed out", alerts=[])
        except OSError as exc:
            return ReplayResult(fired=False, error=str(exc), alerts=[])

        if result.returncode not in (0, 1):
            detail = (result.stderr or result.stdout or f"exit code {result.returncode}").strip()
            return ReplayResult(fired=False, error=detail[:500], alerts=[])

        alerts = _read_alerts(directory / "eve.json")
        fired = any(
            isinstance(event.get("alert"), dict)
            and event["alert"].get("signature_id") == expected_sid
            for event in alerts
        )
        return ReplayResult(fired=fired, error=None, alerts=alerts)


def replay_suite(
    rule_text: str,
    cases: Sequence[ValidationCase],
    *,
    expected_sid: int,
    runner: Runner = subprocess.run,
    suricata_bin: str | None = None,
    config_path: Path | None = None,
) -> ReplayResult:
    """Replay every suite case and accept only when all expectations hold."""
    if not cases:
        return ReplayResult(fired=False, error="validation suite is empty", alerts=[], cases=[])

    case_results: list[CaseReplayResult] = []
    for case in cases:
        single = replay_rule(
            rule_text,
            case.pcap_path,
            expected_sid=expected_sid,
            runner=runner,
            suricata_bin=suricata_bin,
            config_path=config_path,
        )
        if single.error is not None:
            case_results.append(
                CaseReplayResult(
                    name=case.name,
                    expected_alert=case.expected_alert,
                    fired=single.fired,
                    passed=False,
                    reason=case.reason,
                    error=single.error,
                    alerts=single.alerts,
                )
            )
            return ReplayResult(
                fired=False,
                error=f"{case.name}: {single.error}",
                alerts=single.alerts,
                cases=case_results,
            )
        passed = single.fired is case.expected_alert
        case_results.append(
            CaseReplayResult(
                name=case.name,
                expected_alert=case.expected_alert,
                fired=single.fired,
                passed=passed,
                reason=case.reason,
                error=None,
                alerts=single.alerts,
            )
        )

    failures = [case.name for case in case_results if not case.passed]
    if failures:
        return ReplayResult(
            fired=False,
            error=None,
            alerts=[],
            cases=case_results,
        )
    return ReplayResult(fired=True, error=None, alerts=[], cases=case_results)
