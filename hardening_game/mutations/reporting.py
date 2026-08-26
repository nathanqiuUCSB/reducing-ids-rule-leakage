"""Backward-compatible attribution reporting for mutation run trees."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Callable, Iterable, Mapping, Sequence

from hardening_game.attribution import (
    RelatedCveRegistry,
    classify_cve_attribution,
)
from hardening_game.attribution.clue_scoring import (
    TrialClueScore,
    summarize_candidate_trials,
)
from hardening_game.mutations.evaluator import ManifestHashMismatch, latest_records
from hardening_game.mutations.taxonomy import (
    ANALYSIS_CATEGORIES,
    classify_mutation_category,
)


BASELINE_CONTEXT_FILENAME = "baseline_context.json"

# The manifest locks synthetic and benign precision as reported metrics. Both
# are read from an already-persisted false-positive rate, so a record that was
# never measured (no negatives replayed, no benign corpus) must stay out of the
# denominator instead of being counted as a clean zero.
PRECISION_FIELDS: tuple[tuple[str, str], ...] = (
    ("synthetic_precision", "negative_false_positive_rate"),
    ("benign_precision", "benign_false_positive_rate"),
)
_ELIGIBLE_POPULATION = "eligible_records"


def enrich_record(
    record: dict[str, object],
    *,
    target_cve: str,
    registry: RelatedCveRegistry,
) -> dict[str, object]:
    """Return a result record with additive attribution and taxonomy fields."""
    enriched = dict(record)
    prediction = record.get("attacker_prediction")
    if isinstance(prediction, str) and prediction:
        attribution = classify_cve_attribution(
            target_cve=target_cve,
            predicted_cve=prediction,
            registry=registry,
        )
        relationship_tier: str | None = attribution.relationship_tier
        meaningful_obscurity = attribution.meaningful_obscurity
    else:
        relationship_tier = None
        meaningful_obscurity = None

    enriched.update(
        {
            "target_cve": target_cve,
            "relationship_tier": relationship_tier,
            "meaningful_obscurity": meaningful_obscurity,
            "mutation_category": classify_mutation_category(
                component=str(record["component"]),
                operator=str(record["operator"]),
                params=dict(record.get("params", {})),
            ),
        }
    )
    return enriched


def _load_manifest_targets(path: Path) -> dict[str, str]:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    return {
        record["name"]: record["cve"]
        for record in manifest["records"]
        if isinstance(record.get("name"), str)
        and isinstance(record.get("cve"), str)
    }


def read_numbered_jsonl_records(
    path: Path, *, label: str | None = None
) -> tuple[list[tuple[int, dict[str, object]]], list[dict[str, object]]]:
    """Return each whole record with its line number, plus line diagnostics.

    Callers that reject an otherwise well-formed record still owe the reader a
    location, so the line number travels with the record instead of being
    discarded at parse time.
    """
    name = label or str(path)
    records: list[tuple[int, dict[str, object]]] = []
    errors: list[dict[str, object]] = []
    for number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            errors.append(
                {"file": name, "line": number, "error": f"invalid JSON: {error}"}
            )
            continue
        if not isinstance(record, dict):
            errors.append(
                {
                    "file": name,
                    "line": number,
                    "error": (
                        "valid JSON but not an object: "
                        f"{type(record).__name__}"
                    ),
                }
            )
            continue
        records.append((number, record))
    return records, errors


def read_jsonl_records(
    path: Path, *, label: str | None = None
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    """Return whole records plus one diagnostic per line that is not a record.

    An interrupted evaluator can leave a torn trailing line behind, and resume
    already steps over it, so reporting must not abort on the same file. A
    skipped line is still a hole in the data, so every one is returned with its
    file and line number for the caller to publish.
    """
    numbered, errors = read_numbered_jsonl_records(path, label=label)
    return [record for _, record in numbered], errors


def read_baseline_context(
    fixture_dir: Path,
    *,
    fixture: str,
    target_cve: str,
    experiment_manifest_hash: str | None = None,
    source_run: str | None = None,
) -> dict[str, object] | None:
    """Return one fixture's frozen baseline context, or nothing, never a bad one.

    The context decides which records are eligible, so every field a reader
    depends on is checked against what the caller already knows. A stale,
    foreign, or hand-edited file raises instead of quietly changing the answer.
    """
    path = fixture_dir / BASELINE_CONTEXT_FILENAME
    if not path.is_file():
        return None
    try:
        context = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError(f"{path} is not valid JSON: {error}") from error
    if not isinstance(context, dict):
        raise ValueError(f"{path} is not valid JSON: expected a JSON object")

    expected_baseline_id = f"{fixture}-baseline"
    for field, expected in (
        ("fixture", fixture),
        ("baseline_candidate_id", expected_baseline_id),
    ):
        stored = context.get(field)
        if stored != expected:
            raise ValueError(
                f"{path} records {field} {stored!r}, not {expected!r}: this "
                "context belongs to a different fixture"
            )
    stored_target = context.get("target_cve")
    if stored_target != target_cve:
        raise ValueError(
            f"{path} records target CVE {stored_target!r}, not {target_cve!r}"
        )
    if source_run is not None:
        stored_source = context.get("source_run")
        if stored_source != source_run:
            raise ValueError(
                f"{path} records source run {stored_source!r}, not {source_run!r}"
            )
    exact = context.get("baseline_exact")
    if not isinstance(exact, bool):
        raise ValueError(
            f"{path} must record a boolean baseline_exact, not {exact!r}"
        )
    # baseline_exact decides whether a whole rule contributes any records, so it
    # is rederived from the prediction the same file stores rather than trusted.
    prediction = context.get("baseline_attacker_prediction")
    derived = isinstance(prediction, str) and prediction == target_cve
    if exact is not derived:
        raise ValueError(
            f"{path} records baseline_exact {exact!r}, but its stored "
            f"prediction {prediction!r} against target {target_cve!r} implies "
            f"{derived!r}"
        )
    correct = context.get("baseline_attacker_correct")
    if correct is not None:
        if not isinstance(correct, bool):
            raise ValueError(
                f"{path} must record a boolean or absent "
                f"baseline_attacker_correct, not {correct!r}"
            )
        if correct is not derived:
            raise ValueError(
                f"{path} records baseline_attacker_correct {correct!r}, but "
                f"its stored prediction {prediction!r} against target "
                f"{target_cve!r} implies {derived!r}"
            )
    if experiment_manifest_hash is not None:
        stored_hash = context.get("experiment_manifest_hash")
        if stored_hash != experiment_manifest_hash:
            raise ManifestHashMismatch(
                f"{path} belongs to manifest hash {stored_hash!r}, "
                f"not {experiment_manifest_hash!r}"
            )
    return context


def _run_manifest_hash(run_root: Path) -> str | None:
    """Return the run's locked manifest hash when the run tree records one."""
    path = run_root / "run_metadata.json"
    if not path.is_file():
        return None
    try:
        metadata = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError(f"{path} is not valid JSON: {error}") from error
    if not isinstance(metadata, dict):
        raise ValueError(f"{path} is not valid JSON: expected a JSON object")
    stored = metadata.get("experiment_manifest_hash")
    return stored if isinstance(stored, str) else None


def _is_eligible(record: dict[str, object]) -> bool:
    return (
        record.get("component") != "baseline"
        and record.get("status") == "evaluated"
        and record.get("positive_recall") == 1.0
    )


def _empty_counts() -> dict[str, int]:
    return {
        "eligible_record_count": 0,
        "exact_hit_count": 0,
        "exact_miss_count": 0,
        "effective_hit_count": 0,
        "effective_miss_count": 0,
        "closely_related_miss_count": 0,
        "unclassified_miss_count": 0,
    }


def _counts(records: Iterable[Mapping[str, object]]) -> dict[str, int]:
    result = _empty_counts()
    for record in records:
        result["eligible_record_count"] += 1
        tier = record["relationship_tier"]
        exact = tier == "exact_match"
        effective_hit = exact or tier == "closely_related"
        result["exact_hit_count" if exact else "exact_miss_count"] += 1
        result[
            "effective_hit_count" if effective_hit else "effective_miss_count"
        ] += 1
        if tier == "closely_related":
            result["closely_related_miss_count"] += 1
        if tier == "unclassified":
            result["unclassified_miss_count"] += 1
    return result


def _rate(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def summarize_data_quality(
    errors: Iterable[Mapping[str, object]], *, results_files_read: int
) -> dict[str, object]:
    """Report skipped lines as a first-class result, never as silence."""
    entries = sorted(
        (dict(error) for error in errors),
        key=lambda entry: (str(entry["file"]), int(entry["line"])),
    )
    return {
        "results_files_read": results_files_read,
        "files_with_malformed_lines": len({str(entry["file"]) for entry in entries}),
        "malformed_line_count": len(entries),
        "malformed_lines": entries,
    }


def render_data_quality_lines(quality: Mapping[str, object]) -> list[str]:
    lines = [
        f"- Malformed result lines skipped: {quality['malformed_line_count']} "
        f"(in {quality['files_with_malformed_lines']} of "
        f"{quality['results_files_read']} results files)"
    ]
    malformed = quality["malformed_lines"]
    assert isinstance(malformed, list)
    for entry in malformed:
        assert isinstance(entry, dict)
        lines.append(f"- `{entry['file']}:{entry['line']}`: {entry['error']}")
    return lines


def _measured_rate(value: object) -> float | None:
    """Return a persisted false-positive rate, or nothing when unavailable."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def summarize_precision(
    records: Iterable[Mapping[str, object]], *, population: str
) -> dict[str, object]:
    """Summarize the manifest's locked precision metrics over one record set.

    `population` names what the caller counted, so every rate in the result
    carries an explicit denominator instead of an unlabeled fraction.
    """
    records = list(records)
    summary: dict[str, object] = {}
    for metric, field in PRECISION_FIELDS:
        measured = [
            rate
            for rate in (_measured_rate(record.get(field)) for record in records)
            if rate is not None
        ]
        zero_count = sum(1 for rate in measured if rate == 0.0)
        summary[metric] = {
            "denominator": f"{population}_with_a_measured_{field}",
            "measured_record_count": len(measured),
            "unmeasured_record_count": len(records) - len(measured),
            "mean_false_positive_rate": (
                sum(measured) / len(measured) if measured else None
            ),
            "zero_false_positive_count": zero_count,
            "zero_false_positive_rate": _rate(zero_count, len(measured)),
        }
    return summary


def summarize_trial_attribution(
    trials: Iterable[TrialClueScore], *, configured_trial_count: int
) -> dict[str, object]:
    """Report raw trial labels/rates and one exhaustive candidate aggregate."""
    grouped: dict[str, list[TrialClueScore]] = {}
    for trial in trials:
        grouped.setdefault(trial.candidate_id, []).append(trial)
    candidates: dict[str, dict[str, object]] = {}
    aggregate_counts: dict[str, int] = {}
    for candidate_id in sorted(grouped):
        summary = summarize_candidate_trials(
            grouped[candidate_id], configured_trial_count=configured_trial_count
        )
        aggregate_counts[summary.aggregate_label] = (
            aggregate_counts.get(summary.aggregate_label, 0) + 1
        )
        candidates[candidate_id] = {
            "aggregate_label": summary.aggregate_label,
            "configured_trial_count": summary.configured_trial_count,
            "observed_trial_count": summary.observed_trial_count,
            "raw_attribution_labels": list(summary.attribution_labels),
            "raw_clue_effect_labels": list(summary.clue_effect_labels),
            "raw_outcome_labels": list(summary.outcome_labels),
            "attribution_rates": summary.attribution_rates,
            "clue_effect_rates": summary.clue_effect_rates,
            "outcome_rates": summary.outcome_rates,
        }
    return {
        "configured_trial_count": configured_trial_count,
        "candidate_count": len(candidates),
        "aggregate_counts": {
            label: aggregate_counts[label] for label in sorted(aggregate_counts)
        },
        "candidates": candidates,
    }


def _source_categories(record: Mapping[str, object]) -> list[str] | None:
    """Return a combination's persisted block categories, or nothing if unusable."""
    params = record.get("params")
    if not isinstance(params, dict):
        return None
    categories = params.get("source_categories")
    if not isinstance(categories, list) or not categories:
        return None
    if any(category not in ANALYSIS_CATEGORIES for category in categories):
        return None
    return [str(category) for category in categories]


def _mix_key(categories: Sequence[str]) -> str:
    """Return the canonical mix name, ordered by the analysis taxonomy."""
    return "+".join(
        category for category in ANALYSIS_CATEGORIES if category in categories
    )


def summarize_combination_mix(
    records: Iterable[Mapping[str, object]],
    *,
    group_summary: Callable[[list[Mapping[str, object]]], dict[str, object]],
) -> dict[str, object]:
    """Describe what a combination was made of without adding a fourth category.

    A combination keeps its single reduced category, which is by construction
    the strongest block it holds. That hides how mixed it was, so the blocks
    themselves are counted per category and the records are grouped by their
    canonical mix, such as `semantic+performance`.
    """
    records = list(records)
    combinations = [
        record for record in records if record.get("component") == "combination"
    ]
    blocks = dict.fromkeys(ANALYSIS_CATEGORIES, 0)
    grouped: dict[str, list[Mapping[str, object]]] = {}
    unrecorded = 0
    for record in combinations:
        categories = _source_categories(record)
        if categories is None:
            unrecorded += 1
            continue
        for category in categories:
            blocks[category] += 1
        grouped.setdefault(_mix_key(categories), []).append(record)
    total_blocks = sum(blocks.values())
    return {
        "combination_record_count": len(combinations),
        "single_mutation_record_count": len(records) - len(combinations),
        "records_without_source_categories": unrecorded,
        "total_source_category_block_count": total_blocks,
        "source_category_block_denominator": (
            "source_category_blocks_in_combination_records"
        ),
        "source_category_blocks": {
            category: {
                "block_count": count,
                "block_rate": _rate(count, total_blocks),
            }
            for category, count in blocks.items()
        },
        "mix_denominator": "combination_records_with_recorded_source_categories",
        "mix_groups": {key: group_summary(grouped[key]) for key in sorted(grouped)},
    }


def _summarize_rule(
    *,
    target_cve: str,
    records: list[dict[str, object]],
    baseline_context: dict[str, object] | None,
    malformed_line_count: int,
) -> tuple[dict[str, object], list[dict[str, object]]]:
    baseline = next(
        (record for record in records if record.get("component") == "baseline"),
        None,
    )
    if baseline is not None:
        baseline_source = "run_baseline_record"
        baseline_exact = baseline.get("relationship_tier") == "exact_match"
    elif baseline_context is not None:
        # A combination run reuses the locked source run's baseline instead of
        # spending another attacker call to re-measure the same rule.
        baseline_source = "locked_source_run_context"
        baseline_exact = baseline_context.get("baseline_exact") is True
    else:
        baseline_source = "missing"
        baseline_exact = False
    eligible = (
        [record for record in records if _is_eligible(record)]
        if baseline_exact
        else []
    )
    counts = _counts(eligible)
    misses = [
        record for record in eligible if record["relationship_tier"] != "exact_match"
    ]
    pairs = {
        (target_cve, str(record["attacker_prediction"]))
        for record in misses
        if record.get("attacker_prediction")
    }
    denominator = counts["eligible_record_count"]
    summary: dict[str, object] = {
        "independent_unit": "rule",
        "target_cve": target_cve,
        "baseline_exact": baseline_exact,
        "baseline_source": baseline_source,
        **counts,
        "exact_miss_rate": _rate(counts["exact_miss_count"], denominator),
        "effective_miss_rate": _rate(
            counts["effective_miss_count"],
            denominator,
        ),
        "unique_target_prediction_pairs": len(pairs),
        "malformed_line_count": malformed_line_count,
        **summarize_precision(eligible, population=_ELIGIBLE_POPULATION),
    }
    return summary, eligible


def _summarize_pairs(
    records: Iterable[dict[str, object]],
) -> list[dict[str, object]]:
    pairs: dict[tuple[str, str], dict[str, object]] = {}
    for record in records:
        if record["relationship_tier"] == "exact_match":
            continue
        target = str(record["target_cve"])
        prediction = record.get("attacker_prediction")
        if not isinstance(prediction, str) or not prediction:
            continue
        key = (target, prediction)
        if key not in pairs:
            pairs[key] = {
                "target_cve": target,
                "predicted_cve": prediction,
                "relationship_tier": record["relationship_tier"],
                "meaningful_obscurity": record["meaningful_obscurity"],
                "count": 0,
            }
        pairs[key]["count"] = int(pairs[key]["count"]) + 1
    return [pairs[key] for key in sorted(pairs)]


def _summarize_categories(
    records: Iterable[dict[str, object]],
) -> dict[str, dict[str, object]]:
    grouped: dict[str, list[dict[str, object]]] = {}
    for record in records:
        grouped.setdefault(str(record["mutation_category"]), []).append(record)
    return {
        category: _eligible_group_summary(grouped[category])
        for category in sorted(grouped)
    }


def _eligible_group_summary(
    records: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    return {
        "record_count": len(records),
        **_counts(records),
        **summarize_precision(records, population=_ELIGIBLE_POPULATION),
    }


def _per_rule_zero_fp_rates(
    rule_summaries: Mapping[str, Mapping[str, object]], metric: str
) -> list[dict[str, object]]:
    rates: list[dict[str, object]] = []
    for name, summary in rule_summaries.items():
        block = summary[metric]
        assert isinstance(block, dict)
        rates.append({"rule_id": name, "rate": block["zero_false_positive_rate"]})
    return rates


def reanalyze_run_tree(
    run_root: Path,
    *,
    registry: RelatedCveRegistry,
    dataset_manifest: Path,
    trial_scores: Iterable[TrialClueScore] | None = None,
    configured_trial_count: int = 3,
) -> dict[str, object]:
    """Analyze legacy or enriched rule result files and write reports."""
    targets = _load_manifest_targets(dataset_manifest)
    run_manifest_hash = _run_manifest_hash(run_root)
    rule_summaries: dict[str, dict[str, object]] = {}
    all_eligible: list[dict[str, object]] = []
    malformed: list[dict[str, object]] = []
    results_files = 0

    for results_path in sorted(run_root.glob("*/results.jsonl")):
        fixture_name = results_path.parent.name
        if fixture_name not in targets:
            raise ValueError(f"fixture missing from dataset manifest: {fixture_name}")
        results_files += 1
        raw_records, read_errors = read_jsonl_records(
            results_path, label=f"{fixture_name}/results.jsonl"
        )
        malformed.extend(read_errors)
        # Append-only logs can hold a retried candidate more than once, and a
        # rerun without --resume can duplicate an evaluated row outright; only
        # the latest record per candidate is a measurement.
        records = [
            enrich_record(record, target_cve=targets[fixture_name], registry=registry)
            for record in latest_records(raw_records)
        ]
        summary, eligible = _summarize_rule(
            target_cve=targets[fixture_name],
            records=records,
            baseline_context=read_baseline_context(
                results_path.parent,
                fixture=fixture_name,
                target_cve=targets[fixture_name],
                experiment_manifest_hash=run_manifest_hash,
            ),
            malformed_line_count=len(read_errors),
        )
        rule_summaries[fixture_name] = summary
        all_eligible.extend(eligible)

    totals = _counts(all_eligible)
    contributing_rules = {
        name: summary
        for name, summary in rule_summaries.items()
        if summary["eligible_record_count"] > 0
    }
    report: dict[str, object] = {
        "independent_unit": "rule",
        "rules": rule_summaries,
        "totals": {
            "analyzed_rule_count": len(rule_summaries),
            "contributing_rule_count": len(contributing_rules),
            **totals,
            **summarize_precision(all_eligible, population=_ELIGIBLE_POPULATION),
        },
        "cross_rule": {
            "contributing_rule_count": len(contributing_rules),
            "per_rule_exact_miss_rates": [
                {
                    "rule_id": name,
                    "rate": summary["exact_miss_rate"],
                }
                for name, summary in contributing_rules.items()
            ],
            "per_rule_effective_miss_rates": [
                {
                    "rule_id": name,
                    "rate": summary["effective_miss_rate"],
                }
                for name, summary in contributing_rules.items()
            ],
            "per_rule_synthetic_zero_false_positive_rates": _per_rule_zero_fp_rates(
                contributing_rules, "synthetic_precision"
            ),
            "per_rule_benign_zero_false_positive_rates": _per_rule_zero_fp_rates(
                contributing_rules, "benign_precision"
            ),
        },
        "unique_target_prediction_pairs": _summarize_pairs(all_eligible),
        "by_mutation_category": _summarize_categories(all_eligible),
        "combination_mix": summarize_combination_mix(
            all_eligible, group_summary=_eligible_group_summary
        ),
        "data_quality": summarize_data_quality(
            malformed, results_files_read=results_files
        ),
    }
    if trial_scores is not None:
        report["trial_attribution"] = summarize_trial_attribution(
            trial_scores, configured_trial_count=configured_trial_count
        )
    _atomic_write(
        run_root / "attribution_report.json",
        json.dumps(report, indent=2, sort_keys=True) + "\n",
    )
    _atomic_write(run_root / "attribution_report.md", _render_markdown(report))
    return report


def format_rate(value: object) -> str:
    """Render a rate without letting an unavailable one look like a zero."""
    if value is None:
        return "n/a"
    assert isinstance(value, (int, float))
    return f"{float(value):.4f}"


def render_precision_lines(summary: Mapping[str, object]) -> list[str]:
    """Render both locked precision metrics with explicit denominators."""
    labels = {
        "synthetic_precision": "Synthetic precision",
        "benign_precision": "Benign precision",
    }
    lines: list[str] = []
    for metric, _field in PRECISION_FIELDS:
        block = summary[metric]
        assert isinstance(block, dict)
        lines.append(
            f"- {labels[metric]}: measured={block['measured_record_count']} "
            f"(denominator: {block['denominator']}), "
            f"unmeasured={block['unmeasured_record_count']}, "
            "mean false-positive rate="
            f"{format_rate(block['mean_false_positive_rate'])}, "
            f"zero-FP records={block['zero_false_positive_count']} "
            f"({format_rate(block['zero_false_positive_rate'])})"
        )
    return lines


def render_source_category_lines(mix: Mapping[str, object]) -> list[str]:
    blocks = mix["source_category_blocks"]
    assert isinstance(blocks, dict)
    lines = [
        f"- Combination records: {mix['combination_record_count']} "
        f"(single-mutation records: {mix['single_mutation_record_count']}, "
        "without recorded source categories: "
        f"{mix['records_without_source_categories']})",
        f"- Source-category blocks: {mix['total_source_category_block_count']} "
        f"(denominator: {mix['source_category_block_denominator']})",
    ]
    for category, block in blocks.items():
        assert isinstance(block, dict)
        lines.append(
            f"- `{category}` blocks: {block['block_count']} "
            f"({format_rate(block['block_rate'])})"
        )
    return lines


def render_mix_group_lines(mix: Mapping[str, object]) -> list[str]:
    groups = mix["mix_groups"]
    assert isinstance(groups, dict)
    lines = [f"- Mix group denominator: {mix['mix_denominator']}"]
    for key, group in groups.items():
        assert isinstance(group, dict)
        details = ", ".join(
            f"{label}={group[field]}"
            for label, field in (
                ("evaluated", "evaluated"),
                ("exact_misses", "exact_miss_count"),
                ("effective_misses", "effective_miss_count"),
                ("closely_related", "closely_related_miss_count"),
                ("exact_attributions", "attacker_correct"),
            )
            if field in group
        )
        line = f"- `{key}`: records={group['record_count']}"
        lines.append(f"{line}, {details}" if details else line)
    return lines


def _render_markdown(report: dict[str, object]) -> str:
    totals = report["totals"]
    assert isinstance(totals, dict)
    rules = report["rules"]
    assert isinstance(rules, dict)
    quality = report["data_quality"]
    assert isinstance(quality, dict)
    lines = [
        "# Mutation attribution report",
        "",
        "- Independent unit: rule",
        f"- Rules analyzed: {totals['analyzed_rule_count']}",
        f"- Contributing rules: {totals['contributing_rule_count']}",
        f"- Eligible non-baseline full-recall records: {totals['eligible_record_count']}",
        f"- Exact emergent misses: {totals['exact_miss_count']}",
        f"- Effective emergent misses: {totals['effective_miss_count']}",
        f"- Closely related predictions discounted: {totals['closely_related_miss_count']}",
        f"- Unclassified emergent misses: {totals['unclassified_miss_count']}",
        "",
        "## Precision",
        "",
        *render_precision_lines(totals),
        "",
        "## Data quality",
        "",
        *render_data_quality_lines(quality),
    ]
    lines.extend(["", "## Rules (fixture IDs)", ""])
    for name, value in rules.items():
        assert isinstance(value, dict)
        lines.append(
            f"- `{name}`: eligible={value['eligible_record_count']}, "
            f"exact_misses={value['exact_miss_count']}, "
            f"effective_misses={value['effective_miss_count']}, "
            f"closely_related={value['closely_related_miss_count']}, "
            f"baseline={value['baseline_source']}, "
            f"malformed_lines={value['malformed_line_count']}"
        )
    categories = report["by_mutation_category"]
    assert isinstance(categories, dict)
    lines.extend(["", "## Mutation categories", ""])
    for name, value in categories.items():
        assert isinstance(value, dict)
        lines.append(
            f"- `{name}`: eligible={value['eligible_record_count']}, "
            f"exact_misses={value['exact_miss_count']}, "
            f"effective_misses={value['effective_miss_count']}, "
            f"closely_related={value['closely_related_miss_count']}"
        )
    lines.extend(["", "## Precision by mutation category", ""])
    for name, value in categories.items():
        assert isinstance(value, dict)
        synthetic = value["synthetic_precision"]
        benign = value["benign_precision"]
        assert isinstance(synthetic, dict) and isinstance(benign, dict)
        lines.append(
            f"- `{name}`: synthetic zero-FP="
            f"{format_rate(synthetic['zero_false_positive_rate'])} over "
            f"{synthetic['measured_record_count']} measured, benign zero-FP="
            f"{format_rate(benign['zero_false_positive_rate'])} over "
            f"{benign['measured_record_count']} measured"
        )
    mix = report["combination_mix"]
    assert isinstance(mix, dict)
    if mix["combination_record_count"]:
        lines.extend(
            [
                "",
                "## Combination source categories",
                "",
                *render_source_category_lines(mix),
                "",
                "## Combination mixes",
                "",
                *render_mix_group_lines(mix),
            ]
        )
    trial_attribution = report.get("trial_attribution")
    if isinstance(trial_attribution, dict):
        candidates = trial_attribution["candidates"]
        assert isinstance(candidates, dict)
        lines.extend(
            [
                "",
                "## Trial-aware clue attribution",
                "",
                f"- Configured trials: {trial_attribution['configured_trial_count']}",
                f"- Candidates: {trial_attribution['candidate_count']}",
            ]
        )
        for candidate_id, candidate in candidates.items():
            assert isinstance(candidate, dict)
            lines.append(
                f"- `{candidate_id}`: aggregate={candidate['aggregate_label']}, "
                f"attribution={candidate['raw_attribution_labels']}, "
                f"clue_effect={candidate['raw_clue_effect_labels']}, "
                f"outcomes={candidate['raw_outcome_labels']}, "
                f"outcome_rates={candidate['outcome_rates']}"
            )
    lines.append("")
    return "\n".join(lines)


def _atomic_write(path: Path, contents: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(contents, encoding="utf-8")
    os.replace(temporary, path)
