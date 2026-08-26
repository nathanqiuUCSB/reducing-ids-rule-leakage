"""Deterministic post-calibration review artifacts for a clue-baseline run.

The generator is read-only with respect to the immutable calibration run: it
reads the frozen review packet, the per-fixture run metadata, and the reviewed
registries, and writes a separate review artifact pair (JSON and Markdown).
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Mapping, Sequence

from hardening_game.attribution.clue_registry import (
    BaselineClueRegistry,
    load_baseline_clue_registry,
    registry_sha256,
)
from hardening_game.attribution.clue_scoring import map_attacker_evidence, score_trial
from hardening_game.attribution.registry import (
    RelatedCveRegistry,
    load_related_cve_registry,
    validate_reviewed_related_registry,
)
from hardening_game.mutations.attacker_trials import load_attacker_trial_history


_ARTIFACT_VERSION = 1
_TIERS = ("closely_related", "same_ecosystem", "meaningfully_distinct")


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def related_registry_sha256(registry: RelatedCveRegistry) -> str:
    """Whitespace-independent content hash of the reviewed pair registry."""
    payload = sorted(
        [
            entry.target_cve,
            entry.predicted_cve,
            entry.tier,
            entry.vendor,
            entry.product,
            entry.rationale,
            entry.provenance,
        ]
        for entry in registry.entries
    )
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _calibration_input_hashes(
    run_root: Path, fixtures: Sequence[str]
) -> dict[str, str]:
    """Registry hashes frozen into the run before calibration started."""
    seen: dict[str, set[str]] = {"clue": set(), "related": set()}
    for fixture in fixtures:
        metadata = json.loads(
            (run_root / fixture / "run_metadata.json").read_text(encoding="utf-8")
        )
        seen["clue"].add(str(metadata["clue_registry_hash"]))
        seen["related"].add(str(metadata["related_cve_registry_hash"]))
    for key, values in seen.items():
        if len(values) != 1:
            raise ValueError(f"run metadata disagrees on {key} registry hash: {values}")
    return {
        "clue_registry_sha256": seen["clue"].pop(),
        "related_cve_registry_file_sha256": seen["related"].pop(),
    }


def _qualification_categories(
    packet: Mapping[str, object],
) -> tuple[dict[str, object], dict[str, list[str]]]:
    rules = packet["rules"]
    assert isinstance(rules, list)
    exact_by_fixture: dict[str, int] = {}
    qualification_by_fixture: dict[str, str] = {}
    for rule in rules:
        fixture = str(rule["fixture"])
        target = str(rule["target_cve"])
        exact_by_fixture[fixture] = sum(
            int(pair["count"])
            for pair in rule["target_prediction_pairs"]
            if pair["predicted_cve"] == target
        )
        qualification_by_fixture[fixture] = str(rule["qualification"])
    buckets: dict[str, list[str]] = {"3/3": [], "2/3": [], "1/3": [], "0/3": []}
    for fixture, exact in sorted(exact_by_fixture.items()):
        buckets[f"{min(exact, 3)}/3"].append(fixture)
    summary = {
        "primary_qualified": sorted(
            fixture
            for fixture, value in qualification_by_fixture.items()
            if value == "primary_qualified"
        ),
        "control_or_unstable": sorted(
            fixture
            for fixture, value in qualification_by_fixture.items()
            if value != "primary_qualified"
        ),
    }
    return summary, buckets


def _pair_rows(
    packet: Mapping[str, object], related_registry: RelatedCveRegistry
) -> list[dict[str, object]]:
    tier_by_pair = {
        (entry.target_cve, entry.predicted_cve): entry.tier
        for entry in related_registry.entries
    }
    rows: list[dict[str, object]] = []
    rules = packet["rules"]
    assert isinstance(rules, list)
    for rule in rules:
        target = str(rule["target_cve"])
        for pair in rule["target_prediction_pairs"]:
            predicted = str(pair["predicted_cve"])
            if predicted == target:
                tier = "exact_match"
            else:
                tier = tier_by_pair.get((target, predicted), "unclassified")
            rows.append(
                {
                    "count": int(pair["count"]),
                    "fixture": str(rule["fixture"]),
                    "predicted_cve": predicted,
                    "target_cve": target,
                    "tier": tier,
                }
            )
    rows.sort(key=lambda row: (row["fixture"], row["predicted_cve"]))
    return rows


def _dry_score(
    packet: Mapping[str, object],
    *,
    run_root: Path,
    clue_registry: BaselineClueRegistry,
    related_registry: RelatedCveRegistry,
) -> dict[str, object]:
    rules_by_id = {rule.rule_id: rule for rule in clue_registry.rules}
    attribution_counts: dict[str, int] = {}
    unmapped: list[dict[str, object]] = []
    scored = 0
    failed_attempts = 0
    packet_rules = packet["rules"]
    assert isinstance(packet_rules, list)
    for packet_rule in packet_rules:
        fixture = str(packet_rule["fixture"])
        predicates = packet_rule["rule_predicates"]
        history = load_attacker_trial_history(
            run_root / fixture / "attacker_trials.jsonl"
        )
        for trial in history.trials:
            if trial.candidate_id != packet_rule["candidate_id"]:
                continue
            if trial.status != "succeeded":
                failed_attempts += 1
                continue
            scored += 1
            score = score_trial(
                trial,
                target_cve=str(packet_rule["target_cve"]),
                related_cve_registry=related_registry,
                rule_clues=rules_by_id[fixture],
                touched_predicate_ids=(),
                rule_predicates=predicates,
            )
            attribution_counts[score.attribution_label] = (
                attribution_counts.get(score.attribution_label, 0) + 1
            )
            exchange = trial.exchange or {}
            parsed = exchange.get("parsed_response") or {}
            evidence = [
                snippet
                for clue in parsed.get("clues", [])
                for snippet in clue.get("rule_evidence", [])
            ]
            visible_rule = str(exchange.get("prompt", "")).split("\nRule:\n", 1)[-1]
            mapping = map_attacker_evidence(
                evidence,
                visible_rule=visible_rule.strip(),
                rule_predicates=predicates,
            )
            if not mapping.measured:
                unmapped.append(
                    {
                        "fixture": fixture,
                        "reason": str(mapping.reason),
                        "trial_index": trial.trial_index,
                    }
                )
    unmapped.sort(key=lambda row: (row["fixture"], row["trial_index"]))
    return {
        "attribution_counts": dict(sorted(attribution_counts.items())),
        "clue_evidence_mapped": scored - len(unmapped),
        "clue_evidence_unmapped": unmapped,
        "failed_attempts": failed_attempts,
        "scored_trials": scored,
    }


def build_post_calibration_review(
    *,
    run_root: Path,
    clue_registry_path: Path,
    related_registry_path: Path,
) -> dict[str, object]:
    """Assemble the deterministic review artifact payload."""
    packet_path = run_root / "review_packet.json"
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    clue_registry = load_baseline_clue_registry(clue_registry_path)
    related_registry = load_related_cve_registry(related_registry_path)
    validate_reviewed_related_registry(related_registry)
    rules = packet["rules"]
    fixtures = [str(rule["fixture"]) for rule in rules]

    qualification, buckets = _qualification_categories(packet)
    pair_rows = _pair_rows(packet, related_registry)
    registry_tier_counts = {
        tier: sum(1 for entry in related_registry.entries if entry.tier == tier)
        for tier in _TIERS
    }
    observed_tier_counts: dict[str, int] = {}
    for row in pair_rows:
        tier = str(row["tier"])
        observed_tier_counts[tier] = observed_tier_counts.get(tier, 0) + int(
            row["count"]
        )

    rankings = []
    for rule in sorted(clue_registry.rules, key=lambda item: item.rule_id):
        majors = sorted(
            (clue for clue in rule.clues if clue.rank is not None),
            key=lambda clue: clue.rank or 0,
        )
        rankings.append(
            {
                "majors": [
                    {
                        "clue_id": clue.clue_id,
                        "description": clue.description,
                        "predicate_ids": list(clue.predicate_ids),
                        "rank": clue.rank,
                        "targetable": clue.targetable,
                    }
                    for clue in majors
                ],
                "rule_id": rule.rule_id,
                "secondary_count": len(rule.clues) - len(majors),
                "target_cve": rule.target_cve,
            }
        )

    return {
        "clue_registry": {
            "canonical_sha256": registry_sha256(clue_registry),
            "clue_count": sum(len(rule.clues) for rule in clue_registry.rules),
            "file_sha256": _file_sha256(clue_registry_path),
            "major_count": sum(
                1
                for rule in clue_registry.rules
                for clue in rule.clues
                if clue.rank is not None
            ),
            "rule_count": len(clue_registry.rules),
        },
        "calibration_input_registry_hashes": _calibration_input_hashes(
            run_root, fixtures
        ),
        "dry_score": _dry_score(
            packet,
            run_root=run_root,
            clue_registry=clue_registry,
            related_registry=related_registry,
        ),
        "exact_prediction_buckets": buckets,
        "observed_pair_tier_counts": dict(sorted(observed_tier_counts.items())),
        "observed_pairs": pair_rows,
        "packet_sha256": _file_sha256(packet_path),
        "qualification": qualification,
        "rankings": rankings,
        "related_cve_registry": {
            "canonical_sha256": related_registry_sha256(related_registry),
            "entry_count": len(related_registry.entries),
            "file_sha256": _file_sha256(related_registry_path),
            "tier_counts": registry_tier_counts,
        },
        "run_id": packet["run_id"],
        "version": _ARTIFACT_VERSION,
    }


def render_markdown(review: Mapping[str, object]) -> str:
    """Render the review artifact as deterministic Markdown."""
    clue = review["clue_registry"]
    related = review["related_cve_registry"]
    inputs = review["calibration_input_registry_hashes"]
    dry = review["dry_score"]
    buckets = review["exact_prediction_buckets"]
    qualification = review["qualification"]
    assert isinstance(clue, dict) and isinstance(related, dict)
    assert isinstance(inputs, dict) and isinstance(dry, dict)
    assert isinstance(buckets, dict) and isinstance(qualification, dict)

    lines: list[str] = []
    lines.append(f"# Post-calibration review: {review['run_id']}")
    lines.append("")
    lines.append(
        "Generated by `hardening_game.mutations.post_calibration_review` from the "
        "frozen calibration packet and the reviewed registries. The calibration "
        "run itself is immutable and is not modified by this artifact."
    )
    lines.append("")

    lines.append("## Hashes")
    lines.append("")
    lines.append(f"- Review packet sha256: `{review['packet_sha256']}`")
    lines.append(
        "- Calibration-input clue registry sha256 (frozen in run metadata): "
        f"`{inputs['clue_registry_sha256']}`"
    )
    lines.append(
        "- Final clue registry canonical sha256: "
        f"`{clue['canonical_sha256']}` (file sha256 `{clue['file_sha256']}`)"
    )
    lines.append(
        "- Calibration-input related-CVE registry file sha256: "
        f"`{inputs['related_cve_registry_file_sha256']}`"
    )
    lines.append(
        "- Final related-CVE registry canonical sha256: "
        f"`{related['canonical_sha256']}` (file sha256 `{related['file_sha256']}`)"
    )
    lines.append("")
    lines.append(
        "The calibration-input hashes differ from the final hashes by design: the "
        "v2 run was launched against the pre-review registries, and this review "
        "replaces them without re-running the calibration."
    )
    lines.append("")

    lines.append("## Qualification")
    lines.append("")
    lines.append(
        f"- Primary qualified (3/3 exact): {len(qualification['primary_qualified'])}"
    )
    lines.append(
        "- Control or unstable: " f"{len(qualification['control_or_unstable'])}"
    )
    lines.append("")
    for bucket in ("3/3", "2/3", "1/3", "0/3"):
        fixtures = buckets[bucket]
        listed = ", ".join(f"`{fixture}`" for fixture in fixtures) or "none"
        lines.append(f"- {bucket} exact predictions ({len(fixtures)}): {listed}")
    lines.append("")

    lines.append("## Registry counts")
    lines.append("")
    lines.append(
        f"- Clue registry: {clue['rule_count']} rules, {clue['clue_count']} clues, "
        f"{clue['major_count']} ranked majors."
    )
    lines.append(f"- Related-CVE registry: {related['entry_count']} reviewed pairs.")
    tier_counts = related["tier_counts"]
    assert isinstance(tier_counts, dict)
    for tier in _TIERS:
        lines.append(f"  - {tier}: {tier_counts[tier]}")
    lines.append("")

    lines.append("## Observed target/prediction pairs in this run")
    lines.append("")
    observed = review["observed_pair_tier_counts"]
    assert isinstance(observed, dict)
    for tier, count in observed.items():
        lines.append(f"- {tier}: {count} trial(s)")
    lines.append("")
    lines.append("| Fixture | Target | Prediction | Trials | Tier |")
    lines.append("| --- | --- | --- | --- | --- |")
    rows = review["observed_pairs"]
    assert isinstance(rows, list)
    for row in rows:
        lines.append(
            f"| `{row['fixture']}` | {row['target_cve']} | {row['predicted_cve']} "
            f"| {row['count']} | {row['tier']} |"
        )
    lines.append("")

    lines.append("## Dry score against the final registries")
    lines.append("")
    lines.append(f"- Scored trials: {dry['scored_trials']}")
    lines.append(
        f"- Persisted attempts skipped as failed retries: {dry['failed_attempts']}"
    )
    counts = dry["attribution_counts"]
    assert isinstance(counts, dict)
    for label, count in counts.items():
        lines.append(f"- Attribution `{label}`: {count}")
    unmapped = dry["clue_evidence_unmapped"]
    assert isinstance(unmapped, list)
    lines.append(
        f"- Clue-evidence mapping audit: {dry['clue_evidence_mapped']}/"
        f"{dry['scored_trials']} trials mapped."
    )
    for row in unmapped:
        lines.append(
            f"  - Unmapped: `{row['fixture']}` trial {row['trial_index']} "
            f"({row['reason']})"
        )
    lines.append("")

    lines.append("## Rankings")
    lines.append("")
    rankings = review["rankings"]
    assert isinstance(rankings, list)
    for rule in rankings:
        lines.append(f"### `{rule['rule_id']}` ({rule['target_cve']})")
        lines.append("")
        for major in rule["majors"]:
            targetable = "targetable" if major["targetable"] else "untargetable"
            predicates = ", ".join(f"`{pid}`" for pid in major["predicate_ids"])
            lines.append(
                f"{major['rank']}. `{major['clue_id']}` — {major['description']} "
                f"[{predicates}; {targetable}]"
            )
        lines.append("")
        lines.append(f"Secondary clues: {rule['secondary_count']}.")
        lines.append("")

    return "\n".join(lines).rstrip("\n") + "\n"


def write_post_calibration_review(
    *,
    run_root: Path,
    clue_registry_path: Path,
    related_registry_path: Path,
    json_path: Path,
    markdown_path: Path,
) -> dict[str, object]:
    """Write both review artifacts and return the JSON payload."""
    review = build_post_calibration_review(
        run_root=run_root,
        clue_registry_path=clue_registry_path,
        related_registry_path=related_registry_path,
    )
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(
        json.dumps(review, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.write_text(render_markdown(review), encoding="utf-8")
    return review


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate deterministic post-calibration review artifacts."
    )
    parser.add_argument(
        "--project-root", type=Path, default=Path(__file__).resolve().parents[2]
    )
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument(
        "--clue-registry",
        type=Path,
        default=Path("fixtures/baseline_clue_registry.json"),
    )
    parser.add_argument(
        "--related-registry",
        type=Path,
        default=Path("fixtures/related_cve_registry.json"),
    )
    parser.add_argument("--json-out", type=Path, required=True)
    parser.add_argument("--markdown-out", type=Path, required=True)
    args = parser.parse_args()
    project_root = args.project_root.resolve()

    def resolve(path: Path) -> Path:
        return path if path.is_absolute() else project_root / path

    review = write_post_calibration_review(
        run_root=resolve(args.run_root),
        clue_registry_path=resolve(args.clue_registry),
        related_registry_path=resolve(args.related_registry),
        json_path=resolve(args.json_out),
        markdown_path=resolve(args.markdown_out),
    )
    print(json.dumps(review["dry_score"], sort_keys=True))


if __name__ == "__main__":
    main()
