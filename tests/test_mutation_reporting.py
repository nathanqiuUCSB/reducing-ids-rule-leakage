import json
import shutil
from pathlib import Path

import pytest

from hardening_game.attribution import RelatedCveEntry, RelatedCveRegistry
from hardening_game.attribution.clue_scoring import TrialClueScore
from hardening_game.attribution.registry import load_related_cve_registry
from hardening_game.mutations.evaluator import ManifestHashMismatch
from hardening_game.mutations.reporting import (
    enrich_record,
    reanalyze_run_tree,
    summarize_trial_attribution,
)


TARGET = "CVE-2025-0108"
CLOSE = "CVE-2024-0012"
PROJECT_ROOT = Path(__file__).parents[1]
V2_RUN = PROJECT_ROOT / "runs/mutations/dataset-component-mutations-v2"
COMBINATION_RUN = PROJECT_ROOT / "runs/mutations/combination-hybrid-v1-fake-smoke-v3"


def _registry() -> RelatedCveRegistry:
    return RelatedCveRegistry(
        version=1,
        entries=(
            RelatedCveEntry(
                target_cve=TARGET,
                predicted_cve=CLOSE,
                tier="closely_related",
                vendor="Palo Alto Networks",
                product="PAN-OS",
                rationale="Closely related management-interface vulnerabilities.",
                provenance="Test registry.",
            ),
        ),
    )


def _record(
    candidate_id: str,
    *,
    component: str,
    prediction: str | None,
    status: str = "evaluated",
    positive_recall: float | None = 1.0,
    **overrides: object,
) -> dict[str, object]:
    record: dict[str, object] = {
        "candidate_id": candidate_id,
        "component": component,
        "operator": "original" if component == "baseline" else "remove",
        "params": {},
        "status": status,
        "positive_recall": positive_recall,
        "attacker_prediction": prediction,
        "attacker_correct": prediction == TARGET if prediction else None,
    }
    record.update(overrides)
    return record


def test_enrich_record_derives_fields_for_old_style_records() -> None:
    record = _record("fixture-flow-remove", component="flow", prediction=CLOSE)
    record["attacker_correct"] = True
    enriched = enrich_record(
        record,
        target_cve=TARGET,
        registry=_registry(),
    )

    assert enriched["attacker_correct"] is True
    assert enriched["target_cve"] == TARGET
    assert enriched["relationship_tier"] == "closely_related"
    assert enriched["meaningful_obscurity"] is False
    assert enriched["mutation_category"] == "semantic"


def test_enrich_record_keeps_unknown_pairs_unclassified() -> None:
    enriched = enrich_record(
        _record(
            "fixture-flow-remove",
            component="flow",
            prediction="CVE-2099-9999",
        ),
        target_cve=TARGET,
        registry=_registry(),
    )

    assert enriched["relationship_tier"] == "unclassified"
    assert enriched["meaningful_obscurity"] is None


def test_trial_attribution_report_keeps_raw_labels_rates_and_aggregate() -> None:
    trials = [
        TrialClueScore(
            candidate_id="candidate-a",
            trial_index=index,
            attribution_label="non_close",
            clue_effect_label=effect,
            outcome_label=outcome,
        )
        for index, (effect, outcome) in enumerate(
            [
                ("major_disruption", "major_obscurity"),
                ("major_disruption", "major_obscurity"),
                ("unsupported", "unsupported_attribution_miss"),
            ]
        )
    ]
    summary = summarize_trial_attribution(trials, configured_trial_count=3)

    assert summary["aggregate_counts"] == {"probable_major": 1}
    candidate = summary["candidates"]["candidate-a"]
    assert candidate["aggregate_label"] == "probable_major"
    assert candidate["raw_attribution_labels"] == ["non_close"] * 3
    assert candidate["raw_clue_effect_labels"] == [
        "major_disruption",
        "major_disruption",
        "unsupported",
    ]
    assert candidate["raw_outcome_labels"] == [
        "major_obscurity",
        "major_obscurity",
        "unsupported_attribution_miss",
    ]
    assert candidate["outcome_rates"] == {
        "major_obscurity": 2 / 3,
        "unsupported_attribution_miss": 1 / 3,
    }


def test_reanalysis_uses_rule_baseline_and_emergent_miss_eligibility(
    tmp_path: Path,
) -> None:
    run_root = tmp_path / "run"
    fixture_dir = run_root / "fixture-a"
    fixture_dir.mkdir(parents=True)
    records = [
        _record("fixture-a-baseline", component="baseline", prediction=TARGET),
        _record("fixture-a-flow", component="flow", prediction=CLOSE),
        _record(
            "fixture-a-content",
            component="content",
            prediction="CVE-2099-9999",
        ),
        _record("fixture-a-pcre", component="pcre", prediction=TARGET),
        _record(
            "fixture-a-skipped",
            component="flow",
            prediction="CVE-2099-9998",
            status="positive_recall_failed",
            positive_recall=0.5,
        ),
    ]
    (fixture_dir / "results.jsonl").write_text(
        "".join(json.dumps(record) + "\n" for record in records)
    )
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "records": [
                    {
                        "name": "fixture-a",
                        "cve": TARGET,
                        "status": "validated",
                    }
                ]
            }
        )
    )

    report = reanalyze_run_tree(
        run_root,
        registry=_registry(),
        dataset_manifest=manifest,
    )

    summary = report["rules"]["fixture-a"]
    assert summary["independent_unit"] == "rule"
    assert summary["eligible_record_count"] == 3
    assert summary["exact_miss_count"] == 2
    assert summary["effective_miss_count"] == 1
    assert summary["unique_target_prediction_pairs"] == 2
    assert summary["closely_related_miss_count"] == 1
    assert report["cross_rule"]["contributing_rule_count"] == 1
    assert len(report["cross_rule"]["per_rule_exact_miss_rates"]) == 1
    assert report["totals"]["analyzed_rule_count"] == 1
    assert len(report["unique_target_prediction_pairs"]) == 2
    assert report["by_mutation_category"]["semantic"]["exact_miss_count"] == 2
    assert json.loads((run_root / "attribution_report.json").read_text()) == report
    assert "# Mutation attribution report" in (
        run_root / "attribution_report.md"
    ).read_text()
    assert "- Independent unit: rule" in (
        run_root / "attribution_report.md"
    ).read_text()


def _combination_record(
    candidate_id: str,
    *,
    prediction: str | None,
    source_categories: list[str],
    status: str = "evaluated",
    **overrides: object,
) -> dict[str, object]:
    record: dict[str, object] = {
        "candidate_id": candidate_id,
        "component": "combination",
        "operator": f"blocks_{len(source_categories)}",
        "params": {"source_categories": source_categories},
        "block_count": len(source_categories),
        "status": status,
        "positive_recall": 1.0,
        "attacker_prediction": prediction,
        "attacker_correct": prediction == TARGET if prediction else None,
    }
    record.update(overrides)
    return record


MANIFEST_HASH = "0" * 64


def _combination_tree(
    tmp_path: Path,
    *,
    records: list[dict[str, object]],
    baseline_exact: object = True,
    fixture: str = "fixture-a",
    context_overrides: dict[str, object] | None = None,
    run_metadata_hash: str | None = None,
) -> tuple[Path, Path]:
    run_root = tmp_path / "run"
    fixture_dir = run_root / fixture
    fixture_dir.mkdir(parents=True)
    (fixture_dir / "results.jsonl").write_text(
        "".join(json.dumps(record) + "\n" for record in records)
    )
    context: dict[str, object] = {
        "fixture": fixture,
        "source_run": "runs/mutations/dataset-component-mutations-v2",
        "baseline_candidate_id": f"{fixture}-baseline",
        "target_cve": TARGET,
        "baseline_attacker_prediction": TARGET if baseline_exact else CLOSE,
        "baseline_attacker_correct": baseline_exact,
        "baseline_exact": baseline_exact,
        "experiment_manifest_hash": MANIFEST_HASH,
    }
    context.update(context_overrides or {})
    (fixture_dir / "baseline_context.json").write_text(json.dumps(context))
    if run_metadata_hash is not None:
        (run_root / "run_metadata.json").write_text(
            json.dumps({"experiment_manifest_hash": run_metadata_hash})
        )
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"records": [{"name": fixture, "cve": TARGET}]}))
    return run_root, manifest


def test_reanalysis_adds_trial_section_only_for_trial_aware_input(
    tmp_path: Path,
) -> None:
    run_root, manifest = _combination_tree(tmp_path, records=[])
    trial_scores = [
        TrialClueScore(
            candidate_id="candidate-a",
            trial_index=index,
            attribution_label="exact",
            clue_effect_label="unsupported",
            outcome_label="no_effective_obscurity",
        )
        for index in range(3)
    ]
    report = reanalyze_run_tree(
        run_root,
        registry=_registry(),
        dataset_manifest=manifest,
        trial_scores=trial_scores,
        configured_trial_count=3,
    )
    assert report["trial_attribution"]["candidates"]["candidate-a"][
        "aggregate_label"
    ] == "no_effective_obscurity"
    assert "## Trial-aware clue attribution" in (
        run_root / "attribution_report.md"
    ).read_text()


def test_reanalysis_uses_the_persisted_baseline_context_without_a_baseline_row(
    tmp_path: Path,
) -> None:
    run_root, manifest = _combination_tree(
        tmp_path,
        records=[
            _combination_record(
                "fixture-a-combination-2-aaa",
                prediction=CLOSE,
                source_categories=["semantic", "representation"],
            ),
            _combination_record(
                "fixture-a-combination-2-bbb",
                prediction="CVE-2099-9999",
                source_categories=["representation", "performance"],
            ),
            _combination_record(
                "fixture-a-combination-3-ccc",
                prediction=TARGET,
                source_categories=["performance", "performance", "performance"],
            ),
        ],
    )

    report = reanalyze_run_tree(
        run_root, registry=_registry(), dataset_manifest=manifest
    )

    summary = report["rules"]["fixture-a"]
    assert summary["baseline_exact"] is True
    assert summary["baseline_source"] == "locked_source_run_context"
    assert summary["eligible_record_count"] == 3
    assert summary["exact_miss_count"] == 2
    assert summary["effective_miss_count"] == 1
    assert report["totals"]["contributing_rule_count"] == 1
    assert set(report["by_mutation_category"]) == {
        "semantic",
        "representation",
        "performance",
    }
    assert report["by_mutation_category"]["semantic"]["eligible_record_count"] == 1
    assert (
        report["by_mutation_category"]["representation"]["eligible_record_count"] == 1
    )
    assert report["by_mutation_category"]["performance"]["exact_hit_count"] == 1

    markdown = (run_root / "attribution_report.md").read_text()
    assert "## Mutation categories" in markdown
    assert "- `semantic`: eligible=1" in markdown
    assert "baseline=locked_source_run_context" in markdown


def test_reanalysis_excludes_a_rule_whose_source_baseline_context_is_not_exact(
    tmp_path: Path,
) -> None:
    run_root, manifest = _combination_tree(
        tmp_path,
        baseline_exact=False,
        records=[
            _combination_record(
                "fixture-a-combination-2-aaa",
                prediction=CLOSE,
                source_categories=["semantic", "semantic"],
            )
        ],
    )

    report = reanalyze_run_tree(
        run_root, registry=_registry(), dataset_manifest=manifest
    )

    summary = report["rules"]["fixture-a"]
    assert summary["baseline_exact"] is False
    assert summary["baseline_source"] == "locked_source_run_context"
    assert summary["eligible_record_count"] == 0


def test_a_persisted_baseline_row_outranks_the_source_run_context(
    tmp_path: Path,
) -> None:
    run_root, manifest = _combination_tree(
        tmp_path,
        baseline_exact=True,
        records=[
            _record("fixture-a-baseline", component="baseline", prediction=CLOSE),
            _combination_record(
                "fixture-a-combination-2-aaa",
                prediction=CLOSE,
                source_categories=["semantic", "semantic"],
            ),
        ],
    )

    report = reanalyze_run_tree(
        run_root, registry=_registry(), dataset_manifest=manifest
    )

    summary = report["rules"]["fixture-a"]
    assert summary["baseline_source"] == "run_baseline_record"
    assert summary["baseline_exact"] is False
    assert summary["eligible_record_count"] == 0


def test_reanalysis_counts_only_the_latest_record_per_candidate(
    tmp_path: Path,
) -> None:
    run_root, manifest = _combination_tree(
        tmp_path,
        records=[
            _combination_record(
                "fixture-a-combination-2-aaa",
                prediction=TARGET,
                source_categories=["semantic", "semantic"],
            ),
            _combination_record(
                "fixture-a-combination-2-aaa",
                prediction=CLOSE,
                source_categories=["semantic", "semantic"],
            ),
        ],
    )

    report = reanalyze_run_tree(
        run_root, registry=_registry(), dataset_manifest=manifest
    )

    summary = report["rules"]["fixture-a"]
    assert summary["eligible_record_count"] == 1
    assert summary["exact_miss_count"] == 1
    assert summary["closely_related_miss_count"] == 1


def _one_eligible_combination() -> list[dict[str, object]]:
    return [
        _combination_record(
            "fixture-a-combination-2-aaa",
            prediction=CLOSE,
            source_categories=["semantic", "semantic"],
        )
    ]


def test_reanalysis_refuses_a_baseline_context_for_the_wrong_target_cve(
    tmp_path: Path,
) -> None:
    run_root, manifest = _combination_tree(
        tmp_path,
        records=_one_eligible_combination(),
        context_overrides={"target_cve": "CVE-2099-9999"},
    )

    with pytest.raises(ValueError, match="target CVE"):
        reanalyze_run_tree(
            run_root, registry=_registry(), dataset_manifest=manifest
        )


def test_reanalysis_refuses_a_baseline_context_from_another_manifest(
    tmp_path: Path,
) -> None:
    run_root, manifest = _combination_tree(
        tmp_path,
        records=_one_eligible_combination(),
        run_metadata_hash="f" * 64,
    )

    with pytest.raises(ManifestHashMismatch, match="manifest hash"):
        reanalyze_run_tree(
            run_root, registry=_registry(), dataset_manifest=manifest
        )


def test_reanalysis_accepts_a_baseline_context_matching_the_run_manifest_hash(
    tmp_path: Path,
) -> None:
    run_root, manifest = _combination_tree(
        tmp_path,
        records=_one_eligible_combination(),
        run_metadata_hash=MANIFEST_HASH,
    )

    report = reanalyze_run_tree(
        run_root, registry=_registry(), dataset_manifest=manifest
    )

    assert report["rules"]["fixture-a"]["eligible_record_count"] == 1


@pytest.mark.parametrize("value", ["true", 1, None])
def test_reanalysis_refuses_a_non_boolean_baseline_exact(
    tmp_path: Path, value
) -> None:
    run_root, manifest = _combination_tree(
        tmp_path,
        records=_one_eligible_combination(),
        context_overrides={"baseline_exact": value},
    )

    with pytest.raises(ValueError, match="baseline_exact"):
        reanalyze_run_tree(
            run_root, registry=_registry(), dataset_manifest=manifest
        )


def test_reanalysis_refuses_a_baseline_context_naming_another_fixture(
    tmp_path: Path,
) -> None:
    run_root, manifest = _combination_tree(
        tmp_path,
        records=_one_eligible_combination(),
        context_overrides={"fixture": "fixture-b"},
    )

    with pytest.raises(ValueError, match="fixture"):
        reanalyze_run_tree(
            run_root, registry=_registry(), dataset_manifest=manifest
        )


def test_reanalysis_excludes_rule_when_baseline_is_not_exact(
    tmp_path: Path,
) -> None:
    run_root = tmp_path / "run"
    fixture_dir = run_root / "fixture-a"
    fixture_dir.mkdir(parents=True)
    records = [
        _record("fixture-a-baseline", component="baseline", prediction=CLOSE),
        _record(
            "fixture-a-flow",
            component="flow",
            prediction="CVE-2099-9999",
        ),
    ]
    (fixture_dir / "results.jsonl").write_text(
        "".join(json.dumps(record) + "\n" for record in records)
    )
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps({"records": [{"name": "fixture-a", "cve": TARGET}]})
    )

    report = reanalyze_run_tree(
        run_root,
        registry=_registry(),
        dataset_manifest=manifest,
    )

    summary = report["rules"]["fixture-a"]
    assert summary["baseline_exact"] is False
    assert summary["eligible_record_count"] == 0
    assert summary["exact_miss_count"] == 0
    assert summary["effective_miss_count"] == 0
    assert report["cross_rule"]["contributing_rule_count"] == 0
    assert report["cross_rule"]["per_rule_exact_miss_rates"] == []


def _tree_from_lines(
    tmp_path: Path, lines: list[str], *, fixture: str = "fixture-a"
) -> tuple[Path, Path]:
    """Write a results file verbatim so a test can tear or corrupt a line."""
    run_root = tmp_path / "run"
    fixture_dir = run_root / fixture
    fixture_dir.mkdir(parents=True)
    (fixture_dir / "results.jsonl").write_text("".join(lines), encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"records": [{"name": fixture, "cve": TARGET}]}))
    return run_root, manifest


def test_reanalysis_survives_a_torn_trailing_line_and_reports_it(
    tmp_path: Path,
) -> None:
    whole = [
        _record("fixture-a-baseline", component="baseline", prediction=TARGET),
        _record("fixture-a-flow", component="flow", prediction=CLOSE),
    ]
    torn = json.dumps(
        _record("fixture-a-pcre", component="pcre", prediction=TARGET)
    )[:37]
    run_root, manifest = _tree_from_lines(
        tmp_path,
        [*(json.dumps(record) + "\n" for record in whole), torn],
    )

    report = reanalyze_run_tree(
        run_root, registry=_registry(), dataset_manifest=manifest
    )

    summary = report["rules"]["fixture-a"]
    assert summary["eligible_record_count"] == 1
    assert summary["exact_miss_count"] == 1
    assert summary["malformed_line_count"] == 1
    quality = report["data_quality"]
    assert quality["results_files_read"] == 1
    assert quality["files_with_malformed_lines"] == 1
    assert quality["malformed_line_count"] == 1
    assert quality["malformed_lines"] == [
        {
            "file": "fixture-a/results.jsonl",
            "line": 3,
            "error": quality["malformed_lines"][0]["error"],
        }
    ]
    assert "invalid JSON" in quality["malformed_lines"][0]["error"]

    markdown = (run_root / "attribution_report.md").read_text()
    assert "## Data quality" in markdown
    assert "- Malformed result lines skipped: 1" in markdown
    assert "`fixture-a/results.jsonl:3`" in markdown


def test_reanalysis_skips_a_malformed_interior_line_and_keeps_latest_records(
    tmp_path: Path,
) -> None:
    run_root, manifest = _tree_from_lines(
        tmp_path,
        [
            json.dumps(
                _record("fixture-a-baseline", component="baseline", prediction=TARGET)
            )
            + "\n",
            '{"candidate_id": "fixture-a-flow", "component":\n',
            json.dumps(
                _record("fixture-a-flow", component="flow", prediction=TARGET)
            )
            + "\n",
            json.dumps(
                _record("fixture-a-flow", component="flow", prediction=CLOSE)
            )
            + "\n",
            json.dumps(["fixture-a-pcre", "not", "an", "object"]) + "\n",
        ],
    )

    report = reanalyze_run_tree(
        run_root, registry=_registry(), dataset_manifest=manifest
    )

    summary = report["rules"]["fixture-a"]
    assert summary["eligible_record_count"] == 1
    assert summary["exact_miss_count"] == 1
    assert summary["closely_related_miss_count"] == 1
    assert summary["malformed_line_count"] == 2
    quality = report["data_quality"]
    assert quality["malformed_line_count"] == 2
    assert [entry["line"] for entry in quality["malformed_lines"]] == [2, 5]
    assert "not an object" in quality["malformed_lines"][1]["error"]

    markdown = (run_root / "attribution_report.md").read_text()
    assert "- Malformed result lines skipped: 2" in markdown
    assert "`fixture-a/results.jsonl:5`" in markdown


def test_clean_run_reports_zero_malformed_lines(tmp_path: Path) -> None:
    run_root, manifest = _combination_tree(
        tmp_path, records=_one_eligible_combination()
    )

    report = reanalyze_run_tree(
        run_root, registry=_registry(), dataset_manifest=manifest
    )

    assert report["data_quality"] == {
        "results_files_read": 1,
        "files_with_malformed_lines": 0,
        "malformed_line_count": 0,
        "malformed_lines": [],
    }
    assert report["rules"]["fixture-a"]["malformed_line_count"] == 0
    assert "- Malformed result lines skipped: 0" in (
        run_root / "attribution_report.md"
    ).read_text()


def test_precision_metrics_exclude_unmeasured_rates_from_denominators(
    tmp_path: Path,
) -> None:
    run_root, manifest = _combination_tree(
        tmp_path,
        records=[
            _combination_record(
                "fixture-a-combination-2-aaa",
                prediction=TARGET,
                source_categories=["semantic", "semantic"],
                negative_false_positive_rate=0.0,
                benign_false_positive_rate=0.0,
            ),
            _combination_record(
                "fixture-a-combination-2-bbb",
                prediction=CLOSE,
                source_categories=["semantic", "semantic"],
                negative_false_positive_rate=0.5,
                benign_false_positive_rate=None,
            ),
            _combination_record(
                "fixture-a-combination-2-ccc",
                prediction="CVE-2099-9999",
                source_categories=["semantic", "semantic"],
                negative_false_positive_rate=None,
                benign_false_positive_rate=0.25,
            ),
        ],
    )

    report = reanalyze_run_tree(
        run_root, registry=_registry(), dataset_manifest=manifest
    )

    synthetic = report["totals"]["synthetic_precision"]
    assert synthetic == {
        "denominator": (
            "eligible_records_with_a_measured_negative_false_positive_rate"
        ),
        "measured_record_count": 2,
        "unmeasured_record_count": 1,
        "mean_false_positive_rate": 0.25,
        "zero_false_positive_count": 1,
        "zero_false_positive_rate": 0.5,
    }
    benign = report["totals"]["benign_precision"]
    assert benign == {
        "denominator": "eligible_records_with_a_measured_benign_false_positive_rate",
        "measured_record_count": 2,
        "unmeasured_record_count": 1,
        "mean_false_positive_rate": 0.125,
        "zero_false_positive_count": 1,
        "zero_false_positive_rate": 0.5,
    }
    assert report["rules"]["fixture-a"]["synthetic_precision"] == synthetic
    assert report["by_mutation_category"]["semantic"]["benign_precision"] == benign
    assert report["cross_rule"]["per_rule_synthetic_zero_false_positive_rates"] == [
        {"rule_id": "fixture-a", "rate": 0.5}
    ]
    assert report["cross_rule"]["per_rule_benign_zero_false_positive_rates"] == [
        {"rule_id": "fixture-a", "rate": 0.5}
    ]

    markdown = (run_root / "attribution_report.md").read_text()
    assert "## Precision" in markdown
    assert (
        "- Synthetic precision: measured=2 (denominator: "
        "eligible_records_with_a_measured_negative_false_positive_rate)" in markdown
    )
    assert "zero-FP records=1 (0.5000)" in markdown


def test_precision_metrics_stay_none_when_nothing_was_measured(
    tmp_path: Path,
) -> None:
    run_root, manifest = _combination_tree(
        tmp_path, records=_one_eligible_combination()
    )

    report = reanalyze_run_tree(
        run_root, registry=_registry(), dataset_manifest=manifest
    )

    for key in ("synthetic_precision", "benign_precision"):
        block = report["totals"][key]
        assert block["measured_record_count"] == 0
        assert block["unmeasured_record_count"] == 1
        assert block["mean_false_positive_rate"] is None
        assert block["zero_false_positive_rate"] is None
        assert block["zero_false_positive_count"] == 0
    assert "mean false-positive rate=n/a" in (
        run_root / "attribution_report.md"
    ).read_text()


def test_combination_mix_reports_blocks_and_canonical_groups(
    tmp_path: Path,
) -> None:
    run_root, manifest = _combination_tree(
        tmp_path,
        records=[
            _combination_record(
                "fixture-a-combination-2-aaa",
                prediction=CLOSE,
                source_categories=["semantic", "performance"],
            ),
            _combination_record(
                "fixture-a-combination-3-bbb",
                prediction=TARGET,
                source_categories=["performance", "semantic", "semantic"],
            ),
            _combination_record(
                "fixture-a-combination-2-ccc",
                prediction="CVE-2099-9999",
                source_categories=["representation", "representation"],
            ),
        ],
    )

    report = reanalyze_run_tree(
        run_root, registry=_registry(), dataset_manifest=manifest
    )

    # The reduced analysis taxonomy stays exactly three mutually exclusive
    # categories; the mix is reported alongside it, not as a fourth category.
    assert set(report["by_mutation_category"]) == {"semantic", "representation"}
    mix = report["combination_mix"]
    assert mix["combination_record_count"] == 3
    assert mix["single_mutation_record_count"] == 0
    assert mix["records_without_source_categories"] == 0
    assert mix["total_source_category_block_count"] == 7
    assert mix["source_category_blocks"] == {
        "semantic": {"block_count": 3, "block_rate": 3 / 7},
        "representation": {"block_count": 2, "block_rate": 2 / 7},
        "performance": {"block_count": 2, "block_rate": 2 / 7},
    }
    assert set(mix["mix_groups"]) == {"semantic+performance", "representation"}
    group = mix["mix_groups"]["semantic+performance"]
    assert group["record_count"] == 2
    assert group["eligible_record_count"] == 2
    assert group["exact_miss_count"] == 1
    assert group["closely_related_miss_count"] == 1
    assert mix["mix_groups"]["representation"]["unclassified_miss_count"] == 1

    markdown = (run_root / "attribution_report.md").read_text()
    assert "## Combination source categories" in markdown
    assert "- `semantic` blocks: 3 (0.4286)" in markdown
    assert "## Combination mixes" in markdown
    assert "- `semantic+performance`: records=2" in markdown


def test_single_mutation_report_keeps_an_empty_combination_mix(
    tmp_path: Path,
) -> None:
    run_root = tmp_path / "run"
    fixture_dir = run_root / "fixture-a"
    fixture_dir.mkdir(parents=True)
    records = [
        _record("fixture-a-baseline", component="baseline", prediction=TARGET),
        _record("fixture-a-flow", component="flow", prediction=CLOSE),
    ]
    (fixture_dir / "results.jsonl").write_text(
        "".join(json.dumps(record) + "\n" for record in records)
    )
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"records": [{"name": "fixture-a", "cve": TARGET}]}))

    report = reanalyze_run_tree(
        run_root, registry=_registry(), dataset_manifest=manifest
    )

    mix = report["combination_mix"]
    assert mix["combination_record_count"] == 0
    assert mix["single_mutation_record_count"] == 1
    assert mix["mix_groups"] == {}
    assert mix["total_source_category_block_count"] == 0
    assert mix["source_category_blocks"]["semantic"] == {
        "block_count": 0,
        "block_rate": None,
    }
    assert report["rules"]["fixture-a"]["eligible_record_count"] == 1

    markdown = (run_root / "attribution_report.md").read_text()
    assert "## Combination mixes" not in markdown
    assert "## Mutation categories" in markdown


def test_reanalysis_refuses_a_baseline_exact_that_contradicts_the_prediction(
    tmp_path: Path,
) -> None:
    run_root, manifest = _combination_tree(
        tmp_path,
        records=_one_eligible_combination(),
        context_overrides={
            "baseline_attacker_prediction": CLOSE,
            "baseline_attacker_correct": True,
        },
    )

    with pytest.raises(ValueError, match="baseline_exact"):
        reanalyze_run_tree(
            run_root, registry=_registry(), dataset_manifest=manifest
        )


def test_reanalysis_refuses_a_baseline_correct_flag_that_contradicts_exactness(
    tmp_path: Path,
) -> None:
    run_root, manifest = _combination_tree(
        tmp_path,
        records=_one_eligible_combination(),
        context_overrides={"baseline_attacker_correct": False},
    )

    with pytest.raises(ValueError, match="baseline_attacker_correct"):
        reanalyze_run_tree(
            run_root, registry=_registry(), dataset_manifest=manifest
        )


def _copy_run_tree(source: Path, tmp_path: Path) -> Path:
    destination = tmp_path / source.name
    shutil.copytree(source, destination)
    for stale in ("attribution_report.json", "attribution_report.md"):
        (destination / stale).unlink(missing_ok=True)
    return destination


@pytest.mark.skipif(not V2_RUN.is_dir(), reason="locked v2 run tree is absent")
def test_locked_v2_run_keeps_its_core_counts_and_gains_precision_metrics(
    tmp_path: Path,
) -> None:
    run_root = _copy_run_tree(V2_RUN, tmp_path)

    report = reanalyze_run_tree(
        run_root,
        registry=load_related_cve_registry(
            PROJECT_ROOT / "fixtures/related_cve_registry.json"
        ),
        dataset_manifest=PROJECT_ROOT / "fixtures/dataset_manifest.json",
    )

    totals = report["totals"]
    assert totals["eligible_record_count"] == 565
    assert totals["exact_miss_count"] == 79
    assert totals["effective_miss_count"] == 54
    assert totals["closely_related_miss_count"] == 25
    assert report["data_quality"]["malformed_line_count"] == 0
    synthetic = totals["synthetic_precision"]
    benign = totals["benign_precision"]
    assert (
        synthetic["measured_record_count"] + synthetic["unmeasured_record_count"]
        == 565
    )
    assert benign["measured_record_count"] + benign["unmeasured_record_count"] == 565
    assert 0.0 <= synthetic["zero_false_positive_rate"] <= 1.0
    assert report["combination_mix"]["combination_record_count"] == 0
    assert set(report["by_mutation_category"]) == {
        "semantic",
        "representation",
        "performance",
    }


@pytest.mark.skipif(
    not COMBINATION_RUN.is_dir(), reason="combination run tree is absent"
)
def test_existing_combination_run_reports_mix_groups(tmp_path: Path) -> None:
    run_root = _copy_run_tree(COMBINATION_RUN, tmp_path)

    report = reanalyze_run_tree(
        run_root,
        registry=load_related_cve_registry(
            PROJECT_ROOT / "fixtures/related_cve_registry.json"
        ),
        dataset_manifest=PROJECT_ROOT / "fixtures/dataset_manifest.json",
    )

    mix = report["combination_mix"]
    assert mix["combination_record_count"] > 0
    assert mix["records_without_source_categories"] == 0
    assert mix["mix_groups"]
    assert all("+" in key or key in {"semantic", "representation", "performance"}
               for key in mix["mix_groups"])
    assert set(report["by_mutation_category"]) <= {
        "semantic",
        "representation",
        "performance",
    }
    assert report["totals"]["synthetic_precision"]["measured_record_count"] > 0
