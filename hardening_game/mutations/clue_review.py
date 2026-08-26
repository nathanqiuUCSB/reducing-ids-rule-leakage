"""Deterministic evidence packets for baseline clue review."""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
from typing import Iterable

from hardening_game.agents import (
    ATTACKER_PROMPT_VERSION,
    ATTACKER_RESPONSE_SCHEMA_VERSION,
    ATTACKER_RULE_SANITIZER_VERSION,
    sanitize_attacker_rule,
)
from hardening_game.attribution.clue_registry import (
    BaselineClueRegistry,
    validate_completed_rule,
)
from hardening_game.attribution.clue_scoring import map_attacker_evidence
from hardening_game.fixture import GameFixture, load_fixture_path
from hardening_game.mutations.attacker_trials import (
    AttackerTrial,
    load_attacker_trial_history,
    successful_trial_slots,
)
from hardening_game.predicates import canonical_rule_predicates, resolve_predicate_ids
from hardening_game.suricata.rule_model import ParsedRule, parse_suricata_rule


_PACKET_VERSION = 2
_TRIAL_INDEXES = (0, 1, 2)


def _validate_review_packet_version(packet: dict[str, object]) -> None:
    version = packet.get("version")
    if isinstance(version, bool) or version != _PACKET_VERSION:
        raise ValueError(
            "unsupported review packet version: "
            f"expected {_PACKET_VERSION}, got {version!r}"
        )


def _load_jsonl(path: Path) -> list[dict[str, object]]:
    if not path.is_file():
        raise ValueError(f"missing required artifact: {path}")
    records: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"invalid JSONL artifact: {path}: {error}") from error
        if not isinstance(record, dict):
            raise ValueError(f"JSONL record must be an object: {path}")
        records.append(record)
    return records


def _candidate_id(fixture: GameFixture) -> str:
    return f"{fixture.name}-baseline"


def _traffic_result_count(
    records: Iterable[dict[str, object]], *, candidate_id: str
) -> int:
    return sum(
        1
        for record in records
        if record.get("candidate_id") == candidate_id
        and record.get("status") == "traffic_complete"
    )


def _trial_outputs(
    path: Path, *, candidate_id: str
) -> tuple[
    list[dict[str, object]],
    tuple[AttackerTrial, ...],
    int,
    list[dict[str, object]],
    int,
    list[str],
]:
    history = load_attacker_trial_history(path, trial_count=len(_TRIAL_INDEXES))
    trials = history.trials
    attempts = [trial for trial in trials if trial.candidate_id == candidate_id]
    selected = successful_trial_slots(
        trials, candidate_id, trial_count=len(_TRIAL_INDEXES)
    )
    outputs: list[dict[str, object]] = []
    for trial in selected:
        output = asdict(trial)
        exchange = trial.exchange
        output["parsed_response"] = (
            exchange.get("parsed_response")
            if isinstance(exchange, dict) and isinstance(exchange.get("parsed_response"), dict)
            else None
        )
        outputs.append(output)
    failed_attempts = [
        asdict(trial) for trial in attempts if trial.status == "failed"
    ]
    return (
        outputs,
        selected,
        len(attempts),
        failed_attempts,
        history.torn_tail_count,
        list(history.torn_tail_diagnostics),
    )


def _rule_predicates(parsed: ParsedRule) -> dict[str, dict[str, object]]:
    return canonical_rule_predicates(parsed)


def _suite_predicate_evidence(
    fixture: GameFixture, *, known_predicate_ids: Iterable[str]
) -> list[dict[str, object]]:
    evidence: list[dict[str, object]] = []
    for case in fixture.validation_cases:
        if case.predicate_id is None:
            continue
        resolved = resolve_predicate_ids(
            (case.predicate_id,), known_predicate_ids=known_predicate_ids
        )
        evidence.append(
            {
            "case": case.name,
            "expected_alert": case.expected_alert,
            "predicate_id": resolved[0] if len(resolved) == 1 else None,
            "predicate_ids": list(resolved),
            "reason": case.reason,
            }
        )
    return evidence


def _target_prediction_pairs(
    trials: Iterable[AttackerTrial], *, target_cve: str
) -> list[dict[str, object]]:
    counts = Counter(
        trial.prediction.upper()
        for trial in trials
        if trial.status == "succeeded" and trial.prediction is not None
    )
    return [
        {
            "count": count,
            "predicted_cve": prediction,
            "target_cve": target_cve,
        }
        for prediction, count in sorted(counts.items())
    ]


def _qualification(trials: Iterable[AttackerTrial], *, target_cve: str) -> str:
    exact = [
        trial
        for trial in trials
        if trial.status == "succeeded"
        and trial.prediction is not None
        and trial.prediction.upper() == target_cve
    ]
    return (
        "primary_qualified"
        if len(exact) == len(_TRIAL_INDEXES)
        else "control_or_unstable"
    )


def build_review_packet(
    *, project_root: Path, manifest_path: Path, run_root: Path
) -> dict[str, object]:
    """Build a canonical, complete packet from a single three-trial baseline run."""
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or not isinstance(manifest.get("records"), list):
        raise ValueError(f"invalid dataset manifest: {manifest_path}")
    validated = sorted(
        (
            record
            for record in manifest["records"]
            if isinstance(record, dict) and record.get("status") == "validated"
        ),
        key=lambda record: str(record["name"]),
    )
    rules: list[dict[str, object]] = []
    attempt_count = 0
    torn_tail_count = 0
    torn_tail_diagnostics: list[str] = []
    for record in validated:
        fixture_ref = record.get("fixture")
        if not isinstance(fixture_ref, str):
            raise ValueError(f"validated manifest record lacks fixture: {record!r}")
        fixture = load_fixture_path(project_root / fixture_ref, project_root=project_root)
        candidate_id = _candidate_id(fixture)
        fixture_run = run_root / fixture.name
        results = _load_jsonl(fixture_run / "results.jsonl")
        traffic_result_count = _traffic_result_count(results, candidate_id=candidate_id)
        if traffic_result_count != 1:
            raise ValueError(
                f"{candidate_id} must contain exactly one traffic result, "
                f"found {traffic_result_count}"
            )
        (
            outputs,
            trials,
            fixture_attempt_count,
            failed_attempts,
            fixture_torn_tail_count,
            fixture_torn_tail_diagnostics,
        ) = _trial_outputs(
            fixture_run / "attacker_trials.jsonl",
            candidate_id=candidate_id,
        )
        attempt_count += fixture_attempt_count
        torn_tail_count += fixture_torn_tail_count
        torn_tail_diagnostics.extend(fixture_torn_tail_diagnostics)
        target_cve = fixture.cve.upper()
        visible_rule = sanitize_attacker_rule(fixture.sanitized_rule)
        rule_predicates = _rule_predicates(parse_suricata_rule(visible_rule))
        rules.append(
            {
                "attempt_count": fixture_attempt_count,
                "candidate_id": candidate_id,
                "failed_attempts": failed_attempts,
                "fixture": fixture.name,
                "qualification": _qualification(trials, target_cve=target_cve),
                "rule_predicates": rule_predicates,
                "suite_predicate_evidence": _suite_predicate_evidence(
                    fixture, known_predicate_ids=rule_predicates
                ),
                "target_cve": target_cve,
                "target_prediction_pairs": _target_prediction_pairs(
                    trials, target_cve=target_cve
                ),
                "torn_tail_count": fixture_torn_tail_count,
                "torn_tail_diagnostics": fixture_torn_tail_diagnostics,
                "traffic_result_count": traffic_result_count,
                "trial_indexes": [trial.trial_index for trial in trials],
                "trial_outputs": outputs,
            }
        )
    return {
        "attempt_count": attempt_count,
        "run_id": run_root.name,
        "rules": rules,
        "torn_tail_count": torn_tail_count,
        "torn_tail_diagnostics": torn_tail_diagnostics,
        "trial_count": len(_TRIAL_INDEXES),
        "version": _PACKET_VERSION,
    }


def qualification_summary(packet: dict[str, object]) -> dict[str, int]:
    """Return a compact, explicit primary-vs-control baseline summary."""
    _validate_review_packet_version(packet)
    rules = packet.get("rules")
    if not isinstance(rules, list):
        raise ValueError("review packet rules must be an array")
    primary = sum(
        1
        for rule in rules
        if isinstance(rule, dict) and rule.get("qualification") == "primary_qualified"
    )
    return {
        "control_or_unstable_count": len(rules) - primary,
        "primary_qualified_count": primary,
        "total_validated_fixtures": len(rules),
    }


def audit_review_packet_mapping(packet: dict[str, object]) -> dict[str, object]:
    """Dry-map every persisted structured evidence set without scoring clues."""
    _validate_review_packet_version(packet)
    raw_rules = packet.get("rules")
    if not isinstance(raw_rules, list):
        raise ValueError("review packet rules must be an array")
    trial_count = 0
    measurable_count = 0
    ambiguities: list[dict[str, object]] = []
    marker = "\nRule:\n"
    for rule in raw_rules:
        if not isinstance(rule, dict):
            raise ValueError("review packet rule must be an object")
        fixture = rule.get("fixture")
        predicates = rule.get("rule_predicates")
        outputs = rule.get("trial_outputs")
        if (
            not isinstance(fixture, str)
            or not isinstance(predicates, dict)
            or not isinstance(outputs, list)
        ):
            raise ValueError("review packet rule lacks mapping inputs")
        for output in outputs:
            trial_count += 1
            if not isinstance(output, dict):
                raise ValueError("review packet trial must be an object")
            exchange = output.get("exchange")
            parsed = output.get("parsed_response")
            prompt = exchange.get("prompt") if isinstance(exchange, dict) else None
            clues = parsed.get("clues") if isinstance(parsed, dict) else None
            evidence: list[str] = []
            if isinstance(clues, list):
                for clue in clues:
                    snippets = clue.get("rule_evidence") if isinstance(clue, dict) else None
                    if isinstance(snippets, list) and all(
                        isinstance(item, str) and item for item in snippets
                    ):
                        evidence.extend(snippets)
                    else:
                        evidence = []
                        break
            if not isinstance(prompt, str) or marker not in prompt or not evidence:
                reason = "unmapped_evidence"
                mapping_predicates: tuple[str, ...] = ()
            else:
                mapping = map_attacker_evidence(
                    evidence,
                    visible_rule=prompt.split(marker, 1)[1].strip(),
                    rule_predicates=predicates,
                )
                reason = mapping.reason
                mapping_predicates = mapping.predicate_ids
                if mapping.measured:
                    measurable_count += 1
                    continue
            problem_evidence: list[dict[str, str | None]] = []
            if isinstance(prompt, str) and marker in prompt:
                visible_rule = prompt.split(marker, 1)[1].strip()
                for snippet in evidence:
                    snippet_mapping = map_attacker_evidence(
                        (snippet,),
                        visible_rule=visible_rule,
                        rule_predicates=predicates,
                    )
                    if not snippet_mapping.measured:
                        problem_evidence.append(
                            {"reason": snippet_mapping.reason, "snippet": snippet}
                        )
            ambiguities.append(
                {
                    "evidence": evidence,
                    "fixture": fixture,
                    "predicate_ids": list(mapping_predicates),
                    "problem_evidence": problem_evidence,
                    "reason": reason,
                    "trial_index": output.get("trial_index"),
                }
            )
    return {
        "ambiguities": ambiguities,
        "measurable_count": measurable_count,
        "trial_count": trial_count,
        "unmeasured_count": trial_count - measurable_count,
    }


def validate_reviewed_registry(
    registry: BaselineClueRegistry, packet: dict[str, object]
) -> None:
    """Require a complete reviewed registry linked to packet predicates."""
    _validate_review_packet_version(packet)
    raw_rules = packet.get("rules")
    if not isinstance(raw_rules, list):
        raise ValueError("review packet rules must be an array")
    packet_rules: dict[str, dict[str, object]] = {}
    for record in raw_rules:
        if not isinstance(record, dict):
            raise ValueError("review packet rule must be an object")
        fixture = record.get("fixture")
        predicates = record.get("rule_predicates")
        target_cve = record.get("target_cve")
        if (
            not isinstance(fixture, str)
            or not isinstance(predicates, dict)
            or not isinstance(target_cve, str)
        ):
            raise ValueError("review packet rule lacks fixture, target, or predicates")
        packet_rules[fixture] = record
    registry_rules = {rule.rule_id: rule for rule in registry.rules}
    if set(registry_rules) != set(packet_rules):
        missing = sorted(set(packet_rules) - set(registry_rules))
        extra = sorted(set(registry_rules) - set(packet_rules))
        raise ValueError(
            f"registry rules do not match review packet; missing={missing}, extra={extra}"
        )
    for rule_id, rule in registry_rules.items():
        packet_rule = packet_rules[rule_id]
        if rule.target_cve != packet_rule["target_cve"]:
            raise ValueError(f"{rule_id} target_cve does not match review packet")
        validate_completed_rule(rule)
        known_predicates = packet_rule["rule_predicates"]
        for clue in rule.clues:
            try:
                resolve_predicate_ids(
                    clue.predicate_ids, known_predicate_ids=known_predicates
                )
            except ValueError as error:
                raise ValueError(
                    f"{rule_id} clue {clue.clue_id} links unknown rule predicate(s): "
                    + str(error)
                ) from error


def write_review_packet(path: Path, packet: dict[str, object]) -> None:
    """Write stable JSON for human review and hashable downstream evidence."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(packet, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _sanitizer_audit(
    packet: dict[str, object], *, run_root: Path
) -> dict[str, object]:
    _validate_review_packet_version(packet)
    rules = packet.get("rules")
    if not isinstance(rules, list):
        raise ValueError("review packet rules must be an array")
    audited_prompt_count = 0
    for rule in rules:
        if not isinstance(rule, dict) or not isinstance(rule.get("fixture"), str):
            raise ValueError("review packet rule lacks fixture")
        metadata_path = run_root / rule["fixture"] / "run_metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        expected_metadata = {
            "attacker_prompt_version": ATTACKER_PROMPT_VERSION,
            "attacker_response_schema_version": ATTACKER_RESPONSE_SCHEMA_VERSION,
            "attacker_rule_sanitizer_version": ATTACKER_RULE_SANITIZER_VERSION,
            "attacker_trial_count": len(_TRIAL_INDEXES),
            "baseline_only": True,
        }
        for field, expected in expected_metadata.items():
            if not isinstance(metadata, dict) or metadata.get(field) != expected:
                raise ValueError(f"{metadata_path} has incompatible {field}")
        outputs = rule.get("trial_outputs")
        if not isinstance(outputs, list):
            raise ValueError("review packet rule lacks trial outputs")
        for output in outputs:
            exchange = output.get("exchange") if isinstance(output, dict) else None
            prompt = exchange.get("prompt") if isinstance(exchange, dict) else None
            marker = "\nRule:\n"
            if not isinstance(prompt, str) or marker not in prompt:
                raise ValueError(f"{rule['fixture']} trial lacks attacker prompt")
            visible_rule = prompt.split(marker, 1)[1].strip()
            if sanitize_attacker_rule(visible_rule) != visible_rule:
                raise ValueError(
                    f"{rule['fixture']} attacker prompt exposes hidden rule metadata"
                )
            audited_prompt_count += 1
    return {
        "audited_prompt_count": audited_prompt_count,
        "passed": True,
        "sanitizer_version": ATTACKER_RULE_SANITIZER_VERSION,
    }


def write_review_artifacts(
    *, project_root: Path, manifest_path: Path, run_root: Path
) -> dict[str, object]:
    """Write the deterministic packet and post-calibration verification artifacts."""
    packet = build_review_packet(
        project_root=project_root,
        manifest_path=manifest_path,
        run_root=run_root,
    )
    packet_path = run_root / "review_packet.json"
    write_review_packet(packet_path, packet)
    summary = qualification_summary(packet)
    write_review_packet(run_root / "qualification_summary.json", summary)
    rules = packet["rules"]
    if not isinstance(rules, list):
        raise ValueError("review packet rules must be an array")
    successful_slot_count = sum(
        len(rule.get("trial_outputs", []))
        for rule in rules
        if isinstance(rule, dict)
    )
    post_calibration = {
        "attempt_count": packet["attempt_count"],
        "fixture_count": len(rules),
        "packet_sha256": hashlib.sha256(packet_path.read_bytes()).hexdigest(),
        "qualification_summary": summary,
        "sanitizer_audit": _sanitizer_audit(packet, run_root=run_root),
        "successful_slot_count": successful_slot_count,
    }
    write_review_packet(run_root / "post_calibration.json", post_calibration)
    return post_calibration


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate deterministic baseline clue-review artifacts."
    )
    parser.add_argument(
        "--project-root", type=Path, default=Path(__file__).resolve().parents[2]
    )
    parser.add_argument(
        "--manifest", type=Path, default=Path("fixtures/dataset_manifest.json")
    )
    parser.add_argument("--run-root", type=Path, required=True)
    args = parser.parse_args()
    project_root = args.project_root.resolve()
    manifest_path = (
        args.manifest
        if args.manifest.is_absolute()
        else project_root / args.manifest
    )
    run_root = (
        args.run_root
        if args.run_root.is_absolute()
        else project_root / args.run_root
    )
    post_calibration = write_review_artifacts(
        project_root=project_root,
        manifest_path=manifest_path,
        run_root=run_root,
    )
    print(json.dumps(post_calibration, sort_keys=True))


if __name__ == "__main__":
    main()
