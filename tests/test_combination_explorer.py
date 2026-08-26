import json
from pathlib import Path

import pytest

from hardening_game.attribution.registry import load_related_cve_registry
from hardening_game.mutations.combination_manifest import manifest_hash
from hardening_game.mutations.combination_explorer import (
    build_combination_detail_extensions,
    build_combination_index_extensions,
    classify_obscurity_comparison,
    classify_precision_change,
    load_source_records,
    resolve_combination_provenance,
)
from hardening_game.mutations.evaluator import ManifestHashMismatch


def _measured(tier: str, **overrides: object) -> dict[str, object]:
    record: dict[str, object] = {
        "status": "evaluated",
        "positive_recall": 1.0,
        "attacker_prediction": "CVE-2099-0001",
        "attacker_error": None,
        "relationship_tier": tier,
        "negative_false_positive_rate": 0.0,
        "benign_false_positive_rate": 0.0,
    }
    record.update(overrides)
    return record


@pytest.mark.parametrize(
    ("measure", "combination_tier", "constituent_tiers", "expected"),
    [
        ("exact", "unclassified", ["exact_match", "exact_match"], "improved_obscurity"),
        (
            "effective",
            "unclassified",
            ["closely_related", "exact_match"],
            "improved_obscurity",
        ),
        (
            "exact",
            "unclassified",
            ["closely_related", "exact_match"],
            "reinforced_obscurity",
        ),
        (
            "effective",
            "same_ecosystem",
            ["unclassified", "exact_match"],
            "reinforced_obscurity",
        ),
        ("exact", "exact_match", ["unclassified"], "lost_obscurity"),
        ("effective", "closely_related", ["same_ecosystem"], "lost_obscurity"),
        ("exact", "exact_match", ["exact_match"], "no_obscurity_change"),
        (
            "effective",
            "closely_related",
            ["closely_related"],
            "no_obscurity_change",
        ),
    ],
)
def test_classifies_exact_and_effective_obscurity_separately(
    measure: str,
    combination_tier: str,
    constituent_tiers: list[str],
    expected: str,
) -> None:
    assert classify_obscurity_comparison(
        measure=measure,
        combination=_measured(combination_tier),
        constituents=[_measured(tier) for tier in constituent_tiers],
    ) == expected


@pytest.mark.parametrize(
    "bad_record",
    [
        _measured("exact_match", status="attacker_provider_failed"),
        _measured("exact_match", attacker_prediction=None),
        _measured("exact_match", positive_recall=0.5),
        _measured("exact_match", status="positive_recall_failed"),
        _measured("exact_match", attacker_error="provider failed"),
    ],
)
def test_obscurity_comparison_is_unmeasured_for_any_unmeasured_record(
    bad_record: dict[str, object],
) -> None:
    assert classify_obscurity_comparison(
        measure="exact",
        combination=_measured("unclassified"),
        constituents=[_measured("exact_match"), bad_record],
    ) == "unmeasured"
    assert classify_obscurity_comparison(
        measure="exact",
        combination=bad_record,
        constituents=[_measured("exact_match")],
    ) == "unmeasured"


@pytest.mark.parametrize(
    "recall",
    [
        True,
        False,
        float("nan"),
        float("inf"),
        float("-inf"),
        -0.1,
        1.1,
        "1.0",
    ],
)
def test_obscurity_comparison_rejects_invalid_recall_measurements(
    recall: object,
) -> None:
    assert classify_obscurity_comparison(
        measure="exact",
        combination=_measured("unclassified"),
        constituents=[_measured("exact_match", positive_recall=recall)],
    ) == "unmeasured"


def test_obscurity_comparison_rejects_unknown_measure() -> None:
    with pytest.raises(ValueError, match="measure"):
        classify_obscurity_comparison(
            measure="approximate",  # type: ignore[arg-type]
            combination=_measured("exact_match"),
            constituents=[_measured("exact_match")],
        )


def test_precision_only_cost_requires_no_improved_obscurity_and_worse_rate() -> None:
    constituents = [
        _measured(
            "exact_match",
            negative_false_positive_rate=0.1,
            benign_false_positive_rate=0.2,
        ),
        _measured(
            "exact_match",
            negative_false_positive_rate=0.2,
            benign_false_positive_rate=0.1,
        ),
    ]
    combination = _measured(
        "exact_match",
        negative_false_positive_rate=0.3,
        benign_false_positive_rate=0.2,
    )

    assert classify_precision_change(
        combination=combination,
        constituents=constituents,
        exact_comparison="no_obscurity_change",
        effective_comparison="no_obscurity_change",
    ) == "precision_only_cost"
    assert classify_precision_change(
        combination=combination,
        constituents=constituents,
        exact_comparison="improved_obscurity",
        effective_comparison="no_obscurity_change",
    ) == "no_precision_cost"


def test_precision_cost_requires_strictly_greater_than_every_constituent() -> None:
    combination = _measured(
        "exact_match",
        negative_false_positive_rate=0.2,
        benign_false_positive_rate=0.2,
    )
    constituents = [
        _measured(
            "exact_match",
            negative_false_positive_rate=0.2,
            benign_false_positive_rate=0.1,
        ),
        _measured(
            "exact_match",
            negative_false_positive_rate=0.1,
            benign_false_positive_rate=0.2,
        ),
    ]
    assert classify_precision_change(
        combination=combination,
        constituents=constituents,
        exact_comparison="no_obscurity_change",
        effective_comparison="no_obscurity_change",
    ) == "no_precision_cost"


@pytest.mark.parametrize(
    ("where", "field"),
    [
        ("combination", "negative_false_positive_rate"),
        ("combination", "benign_false_positive_rate"),
        ("constituent", "negative_false_positive_rate"),
        ("constituent", "benign_false_positive_rate"),
    ],
)
def test_precision_comparison_is_unmeasured_when_any_rate_is_missing(
    where: str, field: str
) -> None:
    combination = _measured("exact_match")
    constituent = _measured("exact_match")
    (combination if where == "combination" else constituent)[field] = None

    assert classify_precision_change(
        combination=combination,
        constituents=[constituent],
        exact_comparison="no_obscurity_change",
        effective_comparison="no_obscurity_change",
    ) == "unmeasured"


@pytest.mark.parametrize(
    "rate",
    [
        True,
        False,
        float("nan"),
        float("inf"),
        float("-inf"),
        -0.1,
        1.1,
        "0.5",
    ],
)
@pytest.mark.parametrize(
    ("where", "field"),
    [
        ("combination", "negative_false_positive_rate"),
        ("combination", "benign_false_positive_rate"),
        ("constituent", "negative_false_positive_rate"),
        ("constituent", "benign_false_positive_rate"),
    ],
)
def test_precision_comparison_rejects_invalid_rate_measurements(
    rate: object, where: str, field: str
) -> None:
    combination = _measured("exact_match")
    constituent = _measured("exact_match")
    (combination if where == "combination" else constituent)[field] = rate

    assert classify_precision_change(
        combination=combination,
        constituents=[constituent],
        exact_comparison="no_obscurity_change",
        effective_comparison="no_obscurity_change",
    ) == "unmeasured"


def _source(candidate_id: str, component: str, operator: str, **overrides: object):
    record = _measured(
        "exact_match",
        candidate_id=candidate_id,
        component=component,
        operator=operator,
        description=f"{component} {operator}",
        params={},
        rule=f"rule for {candidate_id}",
    )
    record.update(overrides)
    return record


def _write_jsonl(path: Path, records: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(record) + "\n" for record in records))


def _combination_project(root: Path) -> tuple[Path, Path, str]:
    source_run = "runs/mutations/dataset-component-mutations-v2"
    selected = {
        "fixture-a": ["fixture-a-flow", "fixture-a-content"],
        "fixture-b": ["fixture-b-pcre"],
    }
    source_records = {
        "fixture-a": [
            _source(
                "fixture-a-baseline",
                "baseline",
                "original",
                rule="fixture-a baseline rule",
            ),
            _source("fixture-a-flow", "flow", "remove"),
            _source("fixture-a-content", "content", "shorten_suffix"),
            # Latest-record semantics must win.
            _source(
                "fixture-a-flow",
                "flow",
                "remove",
                status="attacker_provider_failed",
                attacker_prediction=None,
                attacker_error="provider unavailable",
                attacker_exchange={
                    "prompt": "large private prompt",
                    "raw_response": "large raw response",
                    "error": "provider unavailable",
                },
                case_results={"P0": {"fired": True}},
                benign_capture_results={"HTTP": {"fired": False}},
            ),
        ],
        "fixture-b": [
            _source(
                "fixture-b-baseline",
                "baseline",
                "original",
                rule="fixture-b baseline rule",
            ),
            _source("fixture-b-pcre", "pcre", "remove"),
        ],
    }
    for fixture, records in source_records.items():
        _write_jsonl(root / source_run / fixture / "results.jsonl", records)

    manifest_payload = {
        "version": 1,
        "experiment_id": "combination-hybrid-v2",
        "source_run": source_run,
        "primary_fixtures": ["fixture-a"],
        "control_fixtures": [
            {"name": "fixture-b", "role": "near_cve_confusion_control"}
        ],
        "selection": {
            "strategy": "hybrid_ranked_v1",
            "max_blocks": 8,
            "minimum_combination_size": 2,
            "selected_blocks_by_fixture": selected,
        },
        "metrics": [
            "exact_cve",
            "effective_attribution",
            "positive_recall",
            "synthetic_precision",
            "benign_precision",
        ],
    }
    manifest_path = root / "experiments/combinations/manifest.json"
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text(json.dumps(manifest_payload))

    fixtures = root / "fixtures"
    fixtures.mkdir()
    fixtures.joinpath("dataset_manifest.json").write_text(
        json.dumps(
            {
                "records": [
                    {"name": "fixture-a", "cve": "CVE-2025-0001"},
                    {"name": "fixture-b", "cve": "CVE-2025-0002"},
                ]
            }
        )
    )
    registry_path = fixtures / "related_cve_registry.json"
    registry_path.write_text(json.dumps({"version": 1, "entries": []}))

    # Resolve once without relying on the module under test for the expected hash.
    from hardening_game.mutations.combination_manifest import load_combination_manifest

    expected_hash = manifest_hash(
        load_combination_manifest(manifest_path, project_root=root)
    )
    run_root = root / "runs/mutations/combination-run"
    run_root.mkdir(parents=True)
    run_root.joinpath("run_metadata.json").write_text(
        json.dumps(
            {
                "experiment_id": "combination-hybrid-v2",
                "experiment_manifest_hash": expected_hash,
                "manifest_path": "experiments/combinations/manifest.json",
                "source_run": source_run,
            }
        )
    )
    return run_root, registry_path, expected_hash


def _combination(expected_hash: str, **overrides: object) -> dict[str, object]:
    record = _measured(
        "exact_match",
        candidate_id="fixture-a-combination",
        component="combination",
        operator="blocks_2",
        block_count=2,
        source_candidate_ids=["fixture-a-content", "fixture-a-flow"],
        params={
            "source_candidate_ids": ["fixture-a-content", "fixture-a-flow"],
            "components": ["content", "flow"],
            "operators": ["shorten_suffix", "remove"],
            "source_categories": ["semantic", "semantic"],
        },
        experiment_manifest_hash=expected_hash,
    )
    record.update(overrides)
    return record


def test_resolves_canonical_manifest_and_locked_source_run(tmp_path: Path) -> None:
    run_root, registry_path, expected_hash = _combination_project(tmp_path)
    provenance = resolve_combination_provenance(tmp_path, run_root)
    registry = load_related_cve_registry(registry_path)
    sources = load_source_records(tmp_path, provenance, registry)

    assert provenance["manifest_hash"] == expected_hash
    assert provenance["source_run"] == (
        "runs/mutations/dataset-component-mutations-v2"
    )
    assert provenance["roles"] == {
        "fixture-a": "primary",
        "fixture-b": "near_cve_confusion_control",
    }
    assert sources["by_fixture"]["fixture-a"]["fixture-a-flow"]["status"] == (
        "attacker_provider_failed"
    )


def test_provenance_rejects_stored_hash_mismatch(tmp_path: Path) -> None:
    run_root, _, _ = _combination_project(tmp_path)
    metadata_path = run_root / "run_metadata.json"
    metadata = json.loads(metadata_path.read_text())
    metadata["experiment_manifest_hash"] = "0" * 64
    metadata_path.write_text(json.dumps(metadata))

    with pytest.raises(ManifestHashMismatch, match="manifest hash"):
        resolve_combination_provenance(tmp_path, run_root)


def test_extensions_preserve_manifest_order_and_separate_payload_sizes(
    tmp_path: Path,
) -> None:
    run_root, registry_path, expected_hash = _combination_project(tmp_path)
    provenance = resolve_combination_provenance(tmp_path, run_root)
    sources = load_source_records(
        tmp_path, provenance, load_related_cve_registry(registry_path)
    )
    record = _combination(expected_hash)

    index = build_combination_index_extensions(
        record, fixture="fixture-a", provenance=provenance, source_records=sources
    )
    detail = build_combination_detail_extensions(
        record, fixture="fixture-a", provenance=provenance, source_records=sources
    )

    assert index["experiment_role"] == "primary"
    assert index["included_components"] == ["flow", "content"]
    assert index["included_operators"] == ["remove", "shorten_suffix"]
    assert index["included_families"] == ["flow", "content"]
    assert index["included_block_labels"] == [
        "flow/remove",
        "content/shorten_suffix",
    ]
    assert index["exact_obscurity_comparison"] == "unmeasured"
    assert index["effective_obscurity_comparison"] == "unmeasured"
    assert index["precision_change"] == "unmeasured"
    assert "building_blocks" not in index
    assert [
        block["candidate_id"] for block in detail["building_blocks"]
    ] == ["fixture-a-flow", "fixture-a-content"]
    assert detail["building_blocks"][0]["attacker"]["status"] == "provider"
    assert detail["building_blocks"][0]["baseline_rule"] == (
        "fixture-a baseline rule"
    )
    assert detail["building_blocks"][0]["mutated_rule"] == (
        "rule for fixture-a-flow"
    )
    assert detail["building_blocks"][0]["exact_attribution"] == "unmeasured"
    assert detail["building_blocks"][0]["effective_attribution"] == "unmeasured"
    assert set(detail["building_blocks"][0]) == {
        "candidate_id",
        "join_status",
        "component",
        "operator",
        "description",
        "buffer",
        "params",
        "mutation_category",
        "positive_recall",
        "negative_false_positive_rate",
        "benign_false_positive_rate",
        "attacker",
        "attacker_prediction",
        "attacker_correct",
        "relationship_tier",
        "meaningful_obscurity",
        "baseline_rule",
        "mutated_rule",
        "exact_attribution",
        "effective_attribution",
    }
    assert set(detail["building_blocks"][0]["attacker"]) == {
        "status",
        "predicted_cve",
        "reasoning",
        "clues",
        "error",
    }
    for forbidden in (
        "attacker_exchange",
        "case_results",
        "benign_capture_results",
        "rule",
        "prompt",
        "raw_response",
    ):
        assert forbidden not in detail["building_blocks"][0]
    assert detail["join_diagnostics"] == []


@pytest.mark.parametrize(
    ("source_ids", "message"),
    [
        (["fixture-a-flow", "fixture-a-missing"], "missing source ID"),
        (["fixture-a-flow", "fixture-b-pcre"], "different fixture"),
    ],
)
def test_join_failures_are_explicit_diagnostics(
    tmp_path: Path, source_ids: list[str], message: str
) -> None:
    run_root, registry_path, expected_hash = _combination_project(tmp_path)
    provenance = resolve_combination_provenance(tmp_path, run_root)
    sources = load_source_records(
        tmp_path, provenance, load_related_cve_registry(registry_path)
    )
    detail = build_combination_detail_extensions(
        _combination(expected_hash, source_candidate_ids=source_ids),
        fixture="fixture-a",
        provenance=provenance,
        source_records=sources,
    )

    assert detail["exact_obscurity_comparison"] == "unmeasured"
    assert detail["effective_obscurity_comparison"] == "unmeasured"
    assert detail["precision_change"] == "unmeasured"
    assert any(message in diagnostic["error"] for diagnostic in detail["join_diagnostics"])
    assert any(
        block["join_status"] == "unavailable"
        for block in detail["building_blocks"]
    )


def test_record_hash_mismatch_is_diagnosed_without_joining(tmp_path: Path) -> None:
    run_root, registry_path, expected_hash = _combination_project(tmp_path)
    provenance = resolve_combination_provenance(tmp_path, run_root)
    sources = load_source_records(
        tmp_path, provenance, load_related_cve_registry(registry_path)
    )
    detail = build_combination_detail_extensions(
        _combination("0" * 64),
        fixture="fixture-a",
        provenance=provenance,
        source_records=sources,
    )

    assert detail["building_blocks"] == []
    assert "manifest hash" in detail["join_diagnostics"][0]["error"]


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        (
            {"source_candidate_ids": ["fixture-a-content", "fixture-a-missing"]},
            "missing source ID",
        ),
        (
            {"source_candidate_ids": ["fixture-a-content", "fixture-b-pcre"]},
            "different fixture",
        ),
        (
            {"source_candidate_ids": ["fixture-a-content", "fixture-a-baseline"]},
            "not selected",
        ),
        (
            {
                "source_candidate_ids": ["fixture-a-content"],
                "block_count": 2,
            },
            "block_count",
        ),
        (
            {
                "source_candidate_ids": [
                    "fixture-a-flow",
                    "fixture-a-content",
                ],
                "block_count": 1,
            },
            "block_count",
        ),
        (
            {
                "params": {
                    "source_candidate_ids": [
                        "fixture-a-flow",
                        "fixture-a-content",
                    ],
                    "components": ["flow"],
                    "operators": ["remove", "shorten_suffix"],
                    "source_categories": ["semantic", "semantic"],
                }
            },
            "components count",
        ),
        (
            {
                "params": {
                    "source_candidate_ids": [
                        "fixture-a-flow",
                        "fixture-a-missing",
                    ]
                }
            },
            "source IDs do not match",
        ),
        (
            {
                "source_candidate_ids": ["fixture-a-content", None],
            },
            "top-level source IDs",
        ),
        ({"operator": "blocks_3"}, "operator"),
    ],
)
def test_incomplete_or_inconsistent_joins_never_classify_partial_constituents(
    tmp_path: Path, overrides: dict[str, object], message: str
) -> None:
    run_root, registry_path, expected_hash = _combination_project(tmp_path)
    provenance = resolve_combination_provenance(tmp_path, run_root)
    sources = load_source_records(
        tmp_path, provenance, load_related_cve_registry(registry_path)
    )
    record = _combination(
        expected_hash,
        relationship_tier="unclassified",
        **overrides,
    )

    index = build_combination_index_extensions(
        record,
        fixture="fixture-a",
        provenance=provenance,
        source_records=sources,
    )
    detail = build_combination_detail_extensions(
        record,
        fixture="fixture-a",
        provenance=provenance,
        source_records=sources,
    )

    assert index["exact_obscurity_comparison"] == "unmeasured"
    assert index["effective_obscurity_comparison"] == "unmeasured"
    assert index["precision_change"] == "unmeasured"
    assert index["source_join_status"] == "unavailable"
    assert index["source_join_diagnostic_count"] >= 1
    assert "join_diagnostics" not in index
    assert any(message in item["error"] for item in detail["join_diagnostics"])


def test_malformed_source_data_prevents_comparison(tmp_path: Path) -> None:
    run_root, registry_path, expected_hash = _combination_project(tmp_path)
    provenance = resolve_combination_provenance(tmp_path, run_root)
    source_path = (
        tmp_path
        / "runs/mutations/dataset-component-mutations-v2"
        / "fixture-a/results.jsonl"
    )
    with source_path.open("a") as stream:
        stream.write("{not json\n")
    sources = load_source_records(
        tmp_path, provenance, load_related_cve_registry(registry_path)
    )

    index = build_combination_index_extensions(
        _combination(expected_hash, relationship_tier="unclassified"),
        fixture="fixture-a",
        provenance=provenance,
        source_records=sources,
    )

    assert index["exact_obscurity_comparison"] == "unmeasured"
    assert index["effective_obscurity_comparison"] == "unmeasured"
    assert index["precision_change"] == "unmeasured"
    assert index["source_join_status"] == "unavailable"


def test_missing_baseline_is_diagnosed_and_source_diff_is_unavailable(
    tmp_path: Path,
) -> None:
    run_root, registry_path, expected_hash = _combination_project(tmp_path)
    source_path = (
        tmp_path
        / "runs/mutations/dataset-component-mutations-v2"
        / "fixture-a/results.jsonl"
    )
    records = [
        json.loads(line)
        for line in source_path.read_text().splitlines()
        if "fixture-a-baseline" not in line
    ]
    _write_jsonl(source_path, records)
    provenance = resolve_combination_provenance(tmp_path, run_root)
    sources = load_source_records(
        tmp_path, provenance, load_related_cve_registry(registry_path)
    )

    detail = build_combination_detail_extensions(
        _combination(expected_hash),
        fixture="fixture-a",
        provenance=provenance,
        source_records=sources,
    )

    assert detail["exact_obscurity_comparison"] == "unmeasured"
    assert all(block["baseline_rule"] is None for block in detail["building_blocks"])
    assert any("baseline" in item["error"] for item in detail["join_diagnostics"])


@pytest.mark.parametrize("unsafe", ["run_root", "manifest_ancestor", "source_results"])
def test_combination_reads_reject_symlinks_and_outside_paths(
    tmp_path: Path, unsafe: str
) -> None:
    run_root, registry_path, _ = _combination_project(tmp_path)
    if unsafe == "run_root":
        real_run = run_root.with_name("real-combination-run")
        run_root.rename(real_run)
        run_root.symlink_to(real_run, target_is_directory=True)
        action = lambda: resolve_combination_provenance(tmp_path, run_root)
    elif unsafe == "manifest_ancestor":
        experiments = tmp_path / "experiments"
        real = tmp_path / "real-combinations"
        (experiments / "combinations").rename(real)
        (experiments / "combinations").symlink_to(real, target_is_directory=True)
        action = lambda: resolve_combination_provenance(tmp_path, run_root)
    else:
        results = (
            tmp_path
            / "runs/mutations/dataset-component-mutations-v2"
            / "fixture-a/results.jsonl"
        )
        real = results.with_name("real-results.jsonl")
        results.rename(real)
        results.symlink_to(real)
        action = lambda: resolve_combination_provenance(tmp_path, run_root)

    with pytest.raises(ValueError, match="symlink"):
        action()


def test_combination_run_root_must_stay_inside_project(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-combination-run"
    outside.mkdir(exist_ok=True)
    outside.joinpath("run_metadata.json").write_text("{}")

    with pytest.raises(ValueError, match="inside project root"):
        resolve_combination_provenance(tmp_path, outside)
