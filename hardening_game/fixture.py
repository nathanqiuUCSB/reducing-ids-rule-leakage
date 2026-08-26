"""Fixture loading and attacker-safe rule sanitization."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
import re


_IDENTITY_OPTION = re.compile(
    r"\s*(?:msg|reference|classtype|metadata)\s*:\s*(?:[^;\\]|\\.)*;\s*",
    re.IGNORECASE,
)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class ValidationCase:
    name: str
    pcap_path: Path
    expected_alert: bool
    reason: str
    predicate_id: str | None = None


@dataclass(frozen=True)
class GameFixture:
    name: str
    sid: int
    revision: int
    cve: str
    pcap_path: Path
    rule: str
    validation_cases: tuple[ValidationCase, ...] = field(default_factory=tuple)

    @property
    def sanitized_rule(self) -> str:
        return sanitize_l5_rule(self.rule)


def sanitize_l5_rule(rule_text: str) -> str:
    """Remove descriptive identifiers while preserving detection logic and SID/revision."""
    return _IDENTITY_OPTION.sub("", rule_text).strip()


def build_validation_contract(cases: tuple[ValidationCase, ...]) -> str:
    """Format fixture expectations as compact defender prompt context."""
    if not cases:
        return (
            "Legacy single-PCAP contract:\n"
            "- The primary fixture PCAP must alert on the fixture SID."
        )

    positives = [case for case in cases if case.expected_alert]
    negatives = [case for case in cases if not case.expected_alert]
    lines = ["Required signature-positives — must alert on the fixture SID:"]
    lines.extend(f"- {case.name}: {case.reason}" for case in positives)
    lines.append("")
    lines.append("Required negatives — must remain silent on the fixture SID:")
    lines.extend(f"- {case.name}: {case.reason}" for case in negatives)
    lines.extend(["", "Every case must meet its expected outcome."])
    return "\n".join(lines)


def _load_validation_cases(
    raw: dict[str, object], *, project_root: Path
) -> tuple[ValidationCase, ...]:
    suite_ref = raw.get("suite")
    if suite_ref is None:
        return ()
    suite_path = project_root / str(suite_ref)
    suite = json.loads(suite_path.read_text(encoding="utf-8"))
    cases: list[ValidationCase] = []
    for entry in suite["cases"]:
        cases.append(
            ValidationCase(
                name=str(entry["name"]),
                pcap_path=project_root / str(entry["pcap"]),
                expected_alert=bool(entry["expected_alert"]),
                reason=str(entry["reason"]),
                predicate_id=(
                    str(entry["predicate_id"])
                    if entry.get("predicate_id") is not None
                    else None
                ),
            )
        )
    return tuple(cases)


def load_fixture_path(
    path: Path, *, project_root: Path | None = None
) -> GameFixture:
    """Load and validate one game fixture JSON file."""
    root = project_root or _PROJECT_ROOT
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("fixture JSON must be an object")
    return GameFixture(
        name=str(raw["name"]),
        sid=int(raw["sid"]),
        revision=int(raw["revision"]),
        cve=str(raw["cve"]).upper(),
        pcap_path=root / str(raw["pcap"]),
        rule=str(raw["rule"]),
        validation_cases=_load_validation_cases(raw, project_root=root),
    )


def load_fixture(name: str, *, project_root: Path | None = None) -> GameFixture:
    """Load a committed game fixture by its short name."""
    root = project_root or _PROJECT_ROOT
    return load_fixture_path(
        root / "fixtures" / f"{name}.json",
        project_root=root,
    )
