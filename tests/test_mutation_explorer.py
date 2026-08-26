import json
from pathlib import Path

import pytest

from hardening_game.mutations import explorer as mutation_explorer
from hardening_game.mutations.combination_manifest import (
    load_combination_manifest,
    manifest_hash,
)
from hardening_game.mutations.explorer import (
    build_index_entry,
    list_mutation_runs,
    load_mutation_record_detail,
    load_mutation_run_index,
)


TARGET = "CVE-2025-0108"


def _record(**overrides: object) -> dict[str, object]:
    record: dict[str, object] = {
        "candidate_id": "et-example-flow-remove",
        "component": "flow",
        "operator": "remove",
        "params": {},
        "status": "evaluated",
        "positive_recall": 1.0,
        "negative_false_positive_rate": 0.0,
        "benign_false_positive_rate": 0.0,
        "attacker_prediction": "CVE-2099-9999",
        "relationship_tier": "unclassified",
        "meaningful_obscurity": None,
    }
    record.update(overrides)
    return record


def test_emergent_balanced_and_close_flags() -> None:
    entry = build_index_entry(
        _record(
            attacker_prediction="CVE-2024-0012",
            relationship_tier="closely_related",
            meaningful_obscurity=False,
        ),
        fixture="et-example",
        target_cve=TARGET,
        baseline_exact=True,
    )

    assert entry["is_emergent_miss"] is True
    assert entry["is_balanced_emergent_miss"] is True
    assert entry["is_unbalanced_emergent_miss"] is False
    assert entry["is_closely_related_guess"] is True
    assert entry["meaningful_obscurity"] is False


@pytest.mark.parametrize(
    ("synthetic_rate", "benign_rate"),
    [(0.25, 0.0), (0.0, 0.25), (0.25, 0.25)],
)
def test_firing_precision_measurements_are_unbalanced(
    synthetic_rate: float, benign_rate: float
) -> None:
    entry = build_index_entry(
        _record(
            negative_false_positive_rate=synthetic_rate,
            benign_false_positive_rate=benign_rate,
        ),
        fixture="et-example",
        target_cve=TARGET,
        baseline_exact=True,
    )

    assert entry["is_balanced_emergent_miss"] is False
    assert entry["is_unbalanced_emergent_miss"] is True


@pytest.mark.parametrize(
    ("synthetic_rate", "benign_rate"), [(None, 0.0), (0.0, None), (None, None)]
)
def test_unmeasured_precision_is_unbalanced(
    synthetic_rate: float | None, benign_rate: float | None
) -> None:
    entry = build_index_entry(
        _record(
            negative_false_positive_rate=synthetic_rate,
            benign_false_positive_rate=benign_rate,
        ),
        fixture="et-example",
        target_cve=TARGET,
        baseline_exact=True,
    )

    assert entry["is_emergent_miss"] is True
    assert entry["is_balanced_emergent_miss"] is False
    assert entry["is_unbalanced_emergent_miss"] is True


@pytest.mark.parametrize(
    "changes",
    [
        {"attacker_prediction": None},
        {"attacker_prediction": ""},
        {"attacker_prediction": "   "},
        {"attacker_error": "legacy provider failure"},
    ],
)
def test_invalid_or_failed_attacker_output_is_not_a_miss(
    changes: dict[str, object],
) -> None:
    entry = build_index_entry(
        _record(**changes),
        fixture="et-example",
        target_cve=TARGET,
        baseline_exact=True,
    )

    assert entry["is_emergent_miss"] is False
    assert entry["is_balanced_emergent_miss"] is False
    assert entry["is_unbalanced_emergent_miss"] is False
    assert entry["is_closely_related_guess"] is False


@pytest.mark.parametrize(
    "changes",
    [
        {"baseline_exact": False},
        {"positive_recall": 0.75},
        {"status": "attacker_provider_failed"},
        {"status": "attacker_parse_failed"},
        {"status": "attacker_empty_response"},
        {"status": "attacker_empty_prediction"},
        {"attacker_prediction": TARGET, "relationship_tier": "exact_match"},
    ],
)
def test_ineligible_records_are_not_emergent(changes: dict[str, object]) -> None:
    baseline_exact = bool(changes.pop("baseline_exact", True))
    entry = build_index_entry(
        _record(**changes),
        fixture="et-example",
        target_cve=TARGET,
        baseline_exact=baseline_exact,
    )
    assert entry["is_emergent_miss"] is False
    assert entry["is_balanced_emergent_miss"] is False
    assert entry["is_unbalanced_emergent_miss"] is False


def _write_project(root: Path) -> tuple[str, str]:
    run_id = "dataset-component-mutations-v2"
    fixture = "et-example"
    fixture_dir = root / "runs" / "mutations" / run_id / fixture
    fixture_dir.mkdir(parents=True)
    (root / "fixtures" / "dataset").mkdir(parents=True)
    (root / "fixtures" / "dataset_manifest.json").write_text(
        json.dumps(
            {
                "records": [
                    {
                        "name": fixture,
                        "cve": TARGET,
                        "fixture": f"fixtures/dataset/{fixture}.json",
                        "suite": f"fixtures/dataset/{fixture}_suite.json",
                        "reason": "complete suite",
                    }
                ]
            }
        )
    )
    (root / "fixtures" / "related_cve_registry.json").write_text(
        json.dumps({"version": 1, "entries": []})
    )
    (root / "fixtures" / "dataset" / f"{fixture}.json").write_text(
        json.dumps({"name": fixture, "cve": TARGET, "rule": "baseline rule"})
    )
    (root / "fixtures" / "dataset" / f"{fixture}_suite.json").write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "P0",
                        "pcap": "pcap/dataset/et-example/P0-canonical.pcap",
                        "expected_alert": True,
                        "reason": "positive",
                    },
                    {
                        "name": "N0",
                        "pcap": "pcap/dataset/et-example/N0-negative.pcap",
                        "expected_alert": False,
                        "reason": "negative",
                        "predicate_id": "content-0",
                    },
                ]
            }
        )
    )
    records = [
        _record(
            candidate_id=f"{fixture}-baseline",
            component="baseline",
            operator="original",
            rule="baseline rule",
            attacker_prediction=TARGET,
            relationship_tier=None,
            case_results={},
            benign_capture_results={},
            attacker_exchange=None,
        ),
        _record(
            candidate_id=f"{fixture}-content-remove",
            component="content",
            rule="mutated rule",
            params={"index": 0},
            case_results={
                "P0": {"fired": True, "passed": True},
                "N0": {"fired": False, "passed": True},
            },
            benign_capture_results={
                "HTTP": {"source_id": "HTTP", "fired": False}
            },
            attacker_exchange={
                "parsed_response": {
                    "predicted_cve": "CVE-2099-9999",
                    "reasoning": "guess",
                    "clues": ["path"],
                },
                "prompt": "prompt",
                "raw_response": "{}",
            },
        ),
    ]
    (fixture_dir / "results.jsonl").write_text(
        "\n".join(json.dumps(record) for record in records)
        + '\n{"candidate_id":'
    )
    return run_id, fixture


def _write_combination_run(root: Path) -> tuple[str, str, list[str]]:
    source_run_id, fixture = _write_project(root)
    source_results = (
        root / "runs" / "mutations" / source_run_id / fixture / "results.jsonl"
    )
    source_ids = [
        f"{fixture}-flow-remove",
        f"{fixture}-content-remove",
        f"{fixture}-pcre-remove",
    ]
    source_records = [
        _record(
            candidate_id=source_ids[0],
            component="flow",
            operator="remove",
            description="remove flow",
            params={"direction": "to_server"},
            buffer="flow",
            rule="flow-only rule",
            mutation_category="semantic",
            attacker_prediction=TARGET,
        ),
        _record(
            candidate_id=source_ids[2],
            component="pcre",
            operator="remove",
            description="remove pcre",
            params={"index": 0},
            buffer="http_uri",
            rule="pcre-only rule",
            mutation_category="semantic",
            attacker_prediction=TARGET,
        ),
    ]
    valid_existing = [
        json.loads(line)
        for line in source_results.read_text().splitlines()
        if line != '{"candidate_id":'
    ]
    source_results.write_text(
        "\n".join(
            json.dumps(record) for record in [*valid_existing, *source_records]
        )
        + "\n"
    )
    other_fixture = "et-other"
    other_source_id = f"{other_fixture}-flow-remove"
    other_results = (
        root / "runs" / "mutations" / source_run_id / other_fixture / "results.jsonl"
    )
    other_results.parent.mkdir()
    other_results.write_text(
        "\n".join(
            json.dumps(record)
            for record in [
                _record(
                    candidate_id=f"{other_fixture}-baseline",
                    component="baseline",
                    operator="original",
                    rule="other baseline rule",
                    attacker_prediction=TARGET,
                ),
                _record(
                    candidate_id=other_source_id,
                    component="flow",
                    operator="remove",
                    rule="other flow rule",
                    attacker_prediction=TARGET,
                ),
            ]
        )
        + "\n"
    )
    dataset_manifest_path = root / "fixtures" / "dataset_manifest.json"
    dataset_manifest = json.loads(dataset_manifest_path.read_text())
    dataset_manifest["records"].append({"name": other_fixture, "cve": TARGET})
    dataset_manifest_path.write_text(json.dumps(dataset_manifest))

    manifest_payload = {
        "version": 1,
        "experiment_id": "combination-test-v1",
        "source_run": f"runs/mutations/{source_run_id}",
        "primary_fixtures": [fixture],
        "control_fixtures": [
            {"name": other_fixture, "role": "near_cve_confusion_control"}
        ],
        "selection": {
            "strategy": "hybrid_ranked_v1",
            "max_blocks": 8,
            "minimum_combination_size": 2,
            "selected_blocks_by_fixture": {
                fixture: source_ids,
                other_fixture: [other_source_id],
            },
        },
        "metrics": [
            "exact_cve",
            "effective_attribution",
            "positive_recall",
            "synthetic_precision",
            "benign_precision",
        ],
    }
    manifest_path = root / "experiments" / "combination-test" / "manifest.json"
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text(json.dumps(manifest_payload))
    locked_hash = manifest_hash(
        load_combination_manifest(manifest_path, project_root=root)
    )

    run_id = "combination-test-v1"
    run_root = root / "runs" / "mutations" / run_id
    run_root.mkdir(parents=True)
    run_root.joinpath("run_metadata.json").write_text(
        json.dumps(
            {
                "experiment_id": "combination-test-v1",
                "experiment_manifest_hash": locked_hash,
                "manifest_path": "experiments/combination-test/manifest.json",
                "source_run": f"runs/mutations/{source_run_id}",
            }
        )
    )
    combination_dir = run_root / fixture
    combination_dir.mkdir()

    def combination(
        candidate_id: str, selected: list[str], components: list[str]
    ) -> dict[str, object]:
        return _record(
            candidate_id=candidate_id,
            component="combination",
            operator=f"blocks_{len(selected)}",
            description=f"combine {len(selected)} blocks",
            params={
                "source_candidate_ids": selected,
                "components": components,
                "operators": ["remove"] * len(selected),
                "source_categories": ["semantic"] * len(selected),
            },
            rule=f"combined rule for {candidate_id}",
            source_candidate_ids=selected,
            block_count=len(selected),
            experiment_manifest_hash=locked_hash,
        )

    records = [
        combination(
            f"{fixture}-combination-z", [source_ids[1], source_ids[2]], ["content", "pcre"]
        ),
        combination(
            f"{fixture}-combination-a", [source_ids[0], source_ids[1]], ["flow", "content"]
        ),
        combination(
            f"{fixture}-combination-three",
            [source_ids[2], source_ids[1], source_ids[0]],
            ["pcre", "content", "flow"],
        ),
    ]
    combination_dir.joinpath("results.jsonl").write_text(
        "\n".join(json.dumps(record) for record in records) + "\n"
    )
    return run_id, fixture, source_ids


def test_combination_index_is_lightweight_sorted_and_detail_has_ordered_blocks(
    tmp_path: Path,
) -> None:
    run_id, fixture, source_ids = _write_combination_run(tmp_path)

    index = load_mutation_run_index(tmp_path, run_id)

    assert [record["candidate_id"] for record in index["records"]] == [
        f"{fixture}-combination-z",
        f"{fixture}-combination-a",
        f"{fixture}-combination-three",
    ]
    first = next(
        record
        for record in index["records"]
        if record["candidate_id"] == f"{fixture}-combination-a"
    )
    assert first["experiment_role"] == "primary"
    assert first["included_families"] == ["flow", "content"]
    assert first["included_block_labels"] == ["flow/remove", "content/remove"]
    assert first["source_join_status"] == "complete"
    assert first["source_join_diagnostic_count"] == 0
    assert "building_blocks" not in first
    assert "join_diagnostics" not in first

    detail = load_mutation_record_detail(
        tmp_path, run_id, f"{fixture}-combination-three"
    )
    assert [block["candidate_id"] for block in detail["building_blocks"]] == source_ids
    block = detail["building_blocks"][0]
    assert block["description"] == "remove flow"
    assert block["params"] == {"direction": "to_server"}
    assert block["buffer"] == "flow"
    assert block["baseline_rule"] == "baseline rule"
    assert block["mutated_rule"] == "flow-only rule"
    assert block["mutation_category"] == "semantic"
    assert block["positive_recall"] == 1.0
    assert block["negative_false_positive_rate"] == 0.0
    assert block["benign_false_positive_rate"] == 0.0
    assert block["attacker_prediction"] == TARGET
    assert block["attacker"]["status"] == "success"
    assert block["exact_attribution"] == "hit"
    assert block["effective_attribution"] == "hit"
    assert block["join_status"] == "available"
    assert detail["join_diagnostics"] == []


def test_combination_missing_and_cross_fixture_sources_are_explicit_diagnostics(
    tmp_path: Path,
) -> None:
    run_id, fixture, source_ids = _write_combination_run(tmp_path)
    results = (
        tmp_path / "runs" / "mutations" / run_id / fixture / "results.jsonl"
    )
    records = [json.loads(line) for line in results.read_text().splitlines()]
    records[0]["source_candidate_ids"] = [source_ids[0], "missing-source"]
    records[0]["params"]["source_candidate_ids"] = [source_ids[0], "missing-source"]
    records[1]["source_candidate_ids"] = [source_ids[0], "et-other-flow-remove"]
    records[1]["params"]["source_candidate_ids"] = [
        source_ids[0],
        "et-other-flow-remove",
    ]
    results.write_text("\n".join(json.dumps(record) for record in records) + "\n")

    index = load_mutation_run_index(tmp_path, run_id)
    missing_entry = next(
        record
        for record in index["records"]
        if record["candidate_id"] == f"{fixture}-combination-z"
    )
    cross_entry = next(
        record
        for record in index["records"]
        if record["candidate_id"] == f"{fixture}-combination-a"
    )
    missing_detail = load_mutation_record_detail(
        tmp_path, run_id, f"{fixture}-combination-z"
    )
    cross_detail = load_mutation_record_detail(
        tmp_path, run_id, f"{fixture}-combination-a"
    )

    assert missing_entry["source_join_status"] == "unavailable"
    assert missing_entry["source_join_diagnostic_count"] == 1
    assert missing_detail["join_diagnostics"] == [
        {
            "source_candidate_id": "missing-source",
            "error": "missing source ID: missing-source",
        }
    ]
    assert missing_detail["building_blocks"][-1]["join_status"] == "unavailable"
    assert cross_entry["source_join_status"] == "unavailable"
    assert cross_entry["source_join_diagnostic_count"] == 1
    assert cross_detail["join_diagnostics"] == [
        {
            "source_candidate_id": "et-other-flow-remove",
            "error": (
                "source ID belongs to a different fixture: "
                "et-other-flow-remove (et-other)"
            ),
        }
    ]


def test_combination_manifest_mismatch_is_visible_and_redacted(
    tmp_path: Path,
) -> None:
    run_id, _, _ = _write_combination_run(tmp_path)
    metadata_path = (
        tmp_path / "runs" / "mutations" / run_id / "run_metadata.json"
    )
    metadata = json.loads(metadata_path.read_text())
    metadata["experiment_manifest_hash"] = "0" * 64
    metadata_path.write_text(json.dumps(metadata))

    index = load_mutation_run_index(tmp_path, run_id)

    assert index["record_count"] == 3
    assert index["diagnostics"] == [
        {
            "file": "run_metadata.json",
            "line": 0,
            "error": index["diagnostics"][0]["error"],
        }
    ]
    assert "manifest hash" in index["diagnostics"][0]["error"]
    assert str(tmp_path) not in index["diagnostics"][0]["error"]
    assert all(
        "experiment_role" not in record for record in index["records"]
    )


def test_single_run_metadata_is_not_treated_as_combination_provenance(
    tmp_path: Path,
) -> None:
    run_id, fixture = _write_project(tmp_path)
    run_root = tmp_path / "runs" / "mutations" / run_id
    run_root.joinpath("run_metadata.json").write_text(
        json.dumps(
            {
                "experiment_id": "dataset-component-mutations-v2",
                "experiment_manifest_hash": "single-run-hash",
                "manifest_path": "experiments/single-run/manifest.json",
                "source_run": "runs/mutations/single-source",
            }
        )
    )

    index = load_mutation_run_index(tmp_path, run_id)
    detail = load_mutation_record_detail(
        tmp_path, run_id, f"{fixture}-content-remove"
    )

    assert index["record_count"] == 2
    assert index["diagnostics"][0]["line"] == 3
    assert all(
        "experiment_role" not in record for record in index["records"]
    )
    assert "building_blocks" not in detail


@pytest.mark.parametrize(
    "stored_metadata",
    [
        "{not json but says combination",
        json.dumps("combination-hybrid-v1"),
        json.dumps({"experiment_id": "combination-broken-v1"}),
        json.dumps(
            {
                "experiment_id": "generic-combination-name",
                "experiment_manifest_hash": "generic-hash",
                "manifest_path": "generic/combination/results.json",
                "source_run": "runs/mutations/generic-combination-source",
            }
        ),
        json.dumps(
            {
                "experiment_id": "",
                "experiment_manifest_hash": "hash",
                "manifest_path": "combination/manifest.json",
                "source_run": "runs/mutations/dataset-component-mutations-v2",
            }
        ),
    ],
)
def test_generic_metadata_is_never_guessed_from_names_or_raw_text(
    tmp_path: Path,
    stored_metadata: str,
) -> None:
    run_id, _ = _write_project(tmp_path)
    run_root = tmp_path / "runs" / "mutations" / run_id
    run_root.joinpath("run_metadata.json").write_text(stored_metadata)

    listing = list_mutation_runs(tmp_path)

    assert len(listing["runs"]) == 1
    assert listing["runs"][0]["run_id"] == run_id
    assert listing["runs"][0]["record_count"] == 2
    assert listing["runs"][0]["diagnostics"][0]["line"] == 3
    assert listing["omitted_run_count"] == 0


def test_run_listing_caches_shared_combination_provenance_and_sources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id, fixture, _ = _write_combination_run(tmp_path)
    runs_root = tmp_path / "runs" / "mutations"
    original = runs_root / run_id
    for clone_id in ("combination-test-clone-a", "combination-test-clone-b"):
        clone = runs_root / clone_id
        clone.mkdir()
        clone.joinpath("run_metadata.json").write_text(
            original.joinpath("run_metadata.json").read_text()
        )
        clone_fixture = clone / fixture
        clone_fixture.mkdir()
        clone_fixture.joinpath("results.jsonl").write_text(
            original.joinpath(fixture, "results.jsonl").read_text()
        )

    provenance_calls = 0
    source_calls = 0
    resolve = mutation_explorer.resolve_combination_provenance
    load_sources = mutation_explorer.load_source_records

    def counting_resolve(*args: object) -> dict[str, object]:
        nonlocal provenance_calls
        provenance_calls += 1
        return resolve(*args)

    def counting_load_sources(*args: object) -> dict[str, object]:
        nonlocal source_calls
        source_calls += 1
        return load_sources(*args)

    monkeypatch.setattr(
        mutation_explorer, "resolve_combination_provenance", counting_resolve
    )
    monkeypatch.setattr(mutation_explorer, "load_source_records", counting_load_sources)

    listing = list_mutation_runs(tmp_path)

    combination_runs = [
        run for run in listing["runs"] if run["run_id"].startswith("combination-test")
    ]
    assert len(combination_runs) == 3
    assert provenance_calls == 1
    assert source_calls == 1


def test_direct_index_and_detail_load_combination_sources_once_each(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id, fixture, _ = _write_combination_run(tmp_path)
    provenance_calls = 0
    source_calls = 0
    resolve = mutation_explorer.resolve_combination_provenance
    load_sources = mutation_explorer.load_source_records

    def counting_resolve(*args: object) -> dict[str, object]:
        nonlocal provenance_calls
        provenance_calls += 1
        return resolve(*args)

    def counting_load_sources(*args: object) -> dict[str, object]:
        nonlocal source_calls
        source_calls += 1
        return load_sources(*args)

    monkeypatch.setattr(
        mutation_explorer, "resolve_combination_provenance", counting_resolve
    )
    monkeypatch.setattr(mutation_explorer, "load_source_records", counting_load_sources)

    load_mutation_run_index(tmp_path, run_id)
    assert (provenance_calls, source_calls) == (1, 1)

    provenance_calls = 0
    source_calls = 0
    load_mutation_record_detail(
        tmp_path, run_id, f"{fixture}-combination-a"
    )
    assert (provenance_calls, source_calls) == (1, 1)


def test_single_run_payloads_have_no_combination_only_fields(tmp_path: Path) -> None:
    run_id, fixture = _write_project(tmp_path)
    combination_keys = {
        "experiment_role",
        "included_components",
        "included_operators",
        "included_families",
        "included_block_labels",
        "exact_obscurity_comparison",
        "effective_obscurity_comparison",
        "source_join_status",
        "source_join_diagnostic_count",
        "precision_change",
        "building_blocks",
        "join_diagnostics",
    }

    index = load_mutation_run_index(tmp_path, run_id)
    detail = load_mutation_record_detail(
        tmp_path, run_id, f"{fixture}-content-remove"
    )

    assert all(combination_keys.isdisjoint(record) for record in index["records"])
    assert combination_keys.isdisjoint(detail)


def test_scanning_index_and_lazy_detail_use_safe_lightweight_payloads(
    tmp_path: Path,
) -> None:
    run_id, fixture = _write_project(tmp_path)

    listing = list_mutation_runs(tmp_path)
    runs = listing["runs"]
    assert listing == {
        "runs": [
            {
                "run_id": run_id,
                "fixture_count": 1,
                "record_count": 2,
                "malformed_line_count": 1,
                "diagnostics": [
                    {
                        "file": f"{fixture}/results.jsonl",
                        "line": 3,
                        "error": runs[0]["diagnostics"][0]["error"],
                    }
                ],
            }
        ],
        "omitted_run_count": 0,
        "omitted_runs": [],
    }
    index = load_mutation_run_index(tmp_path, run_id)
    assert index["run_id"] == run_id
    assert [entry["component"] for entry in index["records"]] == [
        "content",
        "baseline",
    ]
    assert index["diagnostics"][0]["line"] == 3
    for large_field in (
        "rule",
        "attacker_exchange",
        "case_results",
        "benign_capture_results",
    ):
        assert large_field not in index["records"][0]

    detail = load_mutation_record_detail(
        tmp_path, run_id, f"{fixture}-content-remove"
    )
    assert detail["baseline_rule"] == "baseline rule"
    assert detail["mutated_rule"] == "mutated rule"
    assert detail["case_groups"]["positive"][0]["reason"] == "positive"
    assert detail["case_groups"]["positive"][0]["pcap"] == (
        "pcap/dataset/et-example/P0-canonical.pcap"
    )
    assert detail["case_groups"]["positive"][0]["pcap_name"] == "P0-canonical.pcap"
    assert detail["case_groups"]["negative"][0]["predicate_id"] == "content-0"
    assert detail["case_groups"]["negative"][0]["pcap_name"] == "N0-negative.pcap"
    assert detail["case_groups"]["benign"][0]["source_id"] == "HTTP"
    assert detail["attacker"] == {
        "status": "success",
        "predicted_cve": "CVE-2099-9999",
        "reasoning": "guess",
        "clues": ["path"],
        "prompt": "prompt",
        "raw_response": "{}",
        "error": None,
    }


def test_run_listing_skips_nested_non_explorer_artifacts(tmp_path: Path) -> None:
    run_id, _ = _write_project(tmp_path)
    nested = (
        tmp_path
        / "runs"
        / "mutations"
        / "expansion-smoke"
        / "preflight"
        / "et-example"
    )
    nested.mkdir(parents=True)
    nested.joinpath("results.jsonl").write_text("{}\n")

    listing = list_mutation_runs(tmp_path)

    assert [run["run_id"] for run in listing["runs"]] == [run_id]


def _legacy_combination_record(fixture: str) -> dict[str, object]:
    """Return an old combination record written before source_categories existed."""
    sources = [
        f"{fixture}-content-literal_as_hex-1e895a624e78",
        f"{fixture}-content-literal_as_hex-2e5fd7e2c32f",
    ]
    return _record(
        candidate_id=f"{fixture}-combination-2-a4caed20c1d5",
        component="combination",
        operator="blocks_2",
        description=(
            "Combine 2 baseline-relative mutations: "
            "content/literal_as_hex, content/literal_as_hex"
        ),
        params={
            "components": ["content", "content"],
            "operators": ["literal_as_hex", "literal_as_hex"],
            "source_candidate_ids": sources,
        },
        rule="mutated combination rule",
        source_candidate_ids=sources,
        block_count=2,
    )


def test_unknown_direct_fixture_sibling_is_a_diagnostic_not_a_failure(
    tmp_path: Path,
) -> None:
    run_id, fixture = _write_project(tmp_path)
    mutations = tmp_path / "runs" / "mutations"
    results = (mutations / run_id / fixture / "results.jsonl").read_text()
    smoke = mutations / "expansion-smoke"
    for name in (fixture, f"{fixture}-verified"):
        directory = smoke / name
        directory.mkdir(parents=True)
        directory.joinpath("results.jsonl").write_text(results)
    nested = smoke / "preflight" / fixture
    nested.mkdir(parents=True)
    nested.joinpath("results.jsonl").write_text(results)

    listed = {
        run["run_id"]: run for run in list_mutation_runs(tmp_path)["runs"]
    }
    index = load_mutation_run_index(tmp_path, "expansion-smoke")

    assert set(listed) == {run_id, "expansion-smoke"}
    assert listed["expansion-smoke"]["fixture_count"] == 1
    assert listed["expansion-smoke"]["record_count"] == 2
    assert listed["expansion-smoke"]["malformed_line_count"] == 1
    assert listed["expansion-smoke"]["diagnostics"] == index["diagnostics"]
    assert index["fixture_count"] == 1
    assert index["record_count"] == 2
    unknown = [
        diagnostic
        for diagnostic in index["diagnostics"]
        if diagnostic["file"] == f"{fixture}-verified/results.jsonl"
    ]
    assert len(unknown) == 1
    assert unknown[0]["line"] == 0
    assert "manifest" in unknown[0]["error"]


def test_legacy_combination_record_is_skipped_with_a_line_diagnostic(
    tmp_path: Path,
) -> None:
    run_id, fixture = _write_project(tmp_path)
    results = (
        tmp_path / "runs" / "mutations" / run_id / fixture / "results.jsonl"
    )
    with results.open("a") as stream:
        stream.write("\n" + json.dumps(_legacy_combination_record(fixture)))

    index = load_mutation_run_index(tmp_path, run_id)
    listed = list_mutation_runs(tmp_path)["runs"]

    assert [entry["candidate_id"] for entry in index["records"]] == [
        f"{fixture}-content-remove",
        f"{fixture}-baseline",
    ]
    skipped = [
        diagnostic
        for diagnostic in index["diagnostics"]
        if "source_categories" in diagnostic["error"]
    ]
    assert len(skipped) == 1
    assert skipped[0]["file"] == f"{fixture}/results.jsonl"
    assert skipped[0]["line"] == 4
    assert str(tmp_path) not in skipped[0]["error"]
    assert listed[0]["record_count"] == index["record_count"] == 2


def test_run_without_any_valid_record_is_omitted_but_still_readable(
    tmp_path: Path,
) -> None:
    run_id, fixture = _write_project(tmp_path)
    legacy_dir = tmp_path / "runs" / "mutations" / "combination-legacy" / fixture
    legacy_dir.mkdir(parents=True)
    legacy_dir.joinpath("results.jsonl").write_text(
        json.dumps(_legacy_combination_record(fixture)) + "\n"
    )

    listed = [run["run_id"] for run in list_mutation_runs(tmp_path)["runs"]]
    index = load_mutation_run_index(tmp_path, "combination-legacy")

    assert listed == [run_id]
    assert index["records"] == []
    assert len(index["diagnostics"]) == 1
    assert index["diagnostics"][0]["line"] == 1


def test_unknown_families_sort_by_name_like_the_client(tmp_path: Path) -> None:
    run_id, fixture = _write_project(tmp_path)
    results = (
        tmp_path / "runs" / "mutations" / run_id / fixture / "results.jsonl"
    )
    records = [
        _record(
            candidate_id=f"{fixture}-port-any",
            component="port",
            operator="any",
        ),
        _record(
            candidate_id=f"{fixture}-a-anchor-remove",
            component="a_anchor",
            operator="remove",
        ),
    ]
    with results.open("a") as stream:
        stream.write("\n" + "\n".join(json.dumps(record) for record in records))

    index = load_mutation_run_index(tmp_path, run_id)

    assert [entry["component"] for entry in index["records"]][-2:] == [
        "a_anchor",
        "port",
    ]


def _write_in_progress_fixture(root: Path, run_id: str, fixture: str) -> Path:
    """Create the shape an evaluator leaves before its first accepted record."""
    directory = root / "runs" / "mutations" / run_id / fixture
    directory.mkdir(parents=True, exist_ok=True)
    directory.joinpath("rejections.jsonl").write_text(
        json.dumps(
            {
                "component": "content",
                "operator": "remove",
                "reason": "mutation would empty the rule",
            }
        )
        + "\n"
    )
    directory.joinpath("baseline_context.json").write_text(
        json.dumps(
            {
                "fixture": fixture,
                "target_cve": TARGET,
                "baseline_exact": True,
                "rule": "baseline rule",
            }
        )
    )
    return directory


def test_in_progress_known_fixture_is_a_directory_diagnostic(
    tmp_path: Path,
) -> None:
    run_id, fixture = _write_project(tmp_path)
    manifest_path = tmp_path / "fixtures" / "dataset_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["records"].append(
        {
            "name": "et-other",
            "cve": TARGET,
            "fixture": f"fixtures/dataset/{fixture}.json",
            "suite": f"fixtures/dataset/{fixture}_suite.json",
        }
    )
    manifest_path.write_text(json.dumps(manifest))
    _write_in_progress_fixture(tmp_path, run_id, "et-other")

    listing = list_mutation_runs(tmp_path)
    index = load_mutation_run_index(tmp_path, run_id)

    assert [run["run_id"] for run in listing["runs"]] == [run_id]
    assert listing["runs"][0]["record_count"] == index["record_count"] == 2
    assert listing["runs"][0]["fixture_count"] == index["fixture_count"] == 1
    assert listing["runs"][0]["malformed_line_count"] == 1
    assert listing["omitted_run_count"] == 0
    pending = [
        diagnostic
        for diagnostic in index["diagnostics"]
        if diagnostic["file"] == "et-other/results.jsonl"
    ]
    assert len(pending) == 1
    assert pending[0]["line"] == 0
    assert "no results JSONL" in pending[0]["error"]
    assert str(tmp_path) not in pending[0]["error"]
    assert listing["runs"][0]["diagnostics"] == index["diagnostics"]


def test_in_progress_fixture_still_rejects_a_symlinked_results_path(
    tmp_path: Path,
) -> None:
    run_id, _ = _write_project(tmp_path)
    directory = _write_in_progress_fixture(tmp_path, run_id, "et-other")
    manifest_path = tmp_path / "fixtures" / "dataset_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["records"].append(
        {
            "name": "et-other",
            "cve": TARGET,
            "fixture": "fixtures/dataset/et-example.json",
            "suite": "fixtures/dataset/et-example_suite.json",
        }
    )
    manifest_path.write_text(json.dumps(manifest))
    directory.joinpath("results.jsonl").symlink_to(
        tmp_path / "runs" / "mutations" / run_id / "et-example" / "results.jsonl"
    )

    with pytest.raises(ValueError, match="symlink"):
        load_mutation_run_index(tmp_path, run_id)


def test_unreadable_run_is_omitted_with_a_redacted_reason(tmp_path: Path) -> None:
    run_id, fixture = _write_project(tmp_path)
    mutations = tmp_path / "runs" / "mutations"
    results = (mutations / run_id / fixture / "results.jsonl").read_text()
    manifest_path = tmp_path / "fixtures" / "dataset_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["records"].append(
        {
            "name": "et-other",
            "cve": TARGET,
            "fixture": f"fixtures/dataset/{fixture}.json",
            "suite": f"fixtures/dataset/{fixture}_suite.json",
        }
    )
    manifest_path.write_text(json.dumps(manifest))
    for name in (fixture, "et-other"):
        directory = mutations / "duplicate-candidates" / name
        directory.mkdir(parents=True)
        directory.joinpath("results.jsonl").write_text(results)

    listing = list_mutation_runs(tmp_path)

    assert [run["run_id"] for run in listing["runs"]] == [run_id]
    assert listing["omitted_run_count"] == 1
    assert listing["omitted_runs"] == [
        {
            "run_id": "duplicate-candidates",
            "error": listing["omitted_runs"][0]["error"],
        }
    ]
    assert "duplicate candidate ID" in listing["omitted_runs"][0]["error"]
    assert str(tmp_path) not in listing["omitted_runs"][0]["error"]
    with pytest.raises(ValueError, match="duplicate candidate ID"):
        load_mutation_run_index(tmp_path, "duplicate-candidates")


def test_symlinked_run_is_omitted_without_being_followed(tmp_path: Path) -> None:
    run_id, _ = _write_project(tmp_path)
    mutations = tmp_path / "runs" / "mutations"
    mutations.joinpath("linked-run").symlink_to(
        mutations / run_id, target_is_directory=True
    )

    listing = list_mutation_runs(tmp_path)

    assert [run["run_id"] for run in listing["runs"]] == [run_id]
    assert listing["omitted_run_count"] == 1
    assert listing["omitted_runs"][0]["run_id"] == "linked-run"
    assert "symlink" in listing["omitted_runs"][0]["error"]
    assert str(tmp_path) not in listing["omitted_runs"][0]["error"]


def test_flat_run_root_results_layout_explains_itself(tmp_path: Path) -> None:
    run_id, fixture = _write_project(tmp_path)
    mutations = tmp_path / "runs" / "mutations"
    flat = mutations / "et-example-mutations"
    flat.mkdir(parents=True)
    flat.joinpath("results.jsonl").write_text(
        (mutations / run_id / fixture / "results.jsonl").read_text()
    )

    listing = list_mutation_runs(tmp_path)
    index = load_mutation_run_index(tmp_path, "et-example-mutations")

    assert [run["run_id"] for run in listing["runs"]] == [run_id]
    assert listing["omitted_run_count"] == 0
    assert index["records"] == []
    assert index["fixture_count"] == 0
    assert index["diagnostics"] == [
        {
            "file": "results.jsonl",
            "line": 0,
            "error": index["diagnostics"][0]["error"],
        }
    ]
    assert "run root" in index["diagnostics"][0]["error"]
    assert "one directory per fixture" in index["diagnostics"][0]["error"]


@pytest.mark.parametrize(
    ("changes", "expected_status"),
    [
        ({"attacker_prediction": "   "}, "empty_prediction"),
        ({"attacker_error": "legacy provider failure"}, "provider"),
    ],
)
def test_inconsistent_evaluated_attacker_detail_matches_non_miss_index(
    tmp_path: Path,
    changes: dict[str, object],
    expected_status: str,
) -> None:
    run_id, fixture = _write_project(tmp_path)
    candidate_id = f"{fixture}-content-remove"
    inconsistent = _record(
        candidate_id=candidate_id,
        component="content",
        rule="mutated rule",
        **changes,
    )
    results = (
        tmp_path
        / "runs"
        / "mutations"
        / run_id
        / fixture
        / "results.jsonl"
    )
    with results.open("a") as stream:
        stream.write("\n" + json.dumps(inconsistent))

    index = load_mutation_run_index(tmp_path, run_id)
    entry = next(
        record for record in index["records"]
        if record["candidate_id"] == candidate_id
    )
    detail = load_mutation_record_detail(tmp_path, run_id, candidate_id)

    assert entry["is_emergent_miss"] is False
    assert entry["is_balanced_emergent_miss"] is False
    assert entry["is_unbalanced_emergent_miss"] is False
    assert detail["attacker"]["status"] == expected_status
    assert detail["attacker"]["status"] != "success"


def test_rejects_unsafe_unknown_and_duplicate_identifiers(tmp_path: Path) -> None:
    run_id, fixture = _write_project(tmp_path)
    with pytest.raises(ValueError, match="unsafe run ID"):
        load_mutation_run_index(tmp_path, "../escape")
    with pytest.raises(ValueError, match="unknown run"):
        load_mutation_run_index(tmp_path, "missing")
    with pytest.raises(ValueError, match="unknown candidate"):
        load_mutation_record_detail(tmp_path, run_id, "missing")

    duplicate_dir = tmp_path / "runs" / "mutations" / run_id / "et-other"
    duplicate_dir.mkdir()
    manifest_path = tmp_path / "fixtures" / "dataset_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["records"].append(
        {
            "name": "et-other",
            "cve": TARGET,
            "fixture": "fixtures/dataset/et-example.json",
            "suite": "fixtures/dataset/et-example_suite.json",
        }
    )
    manifest_path.write_text(json.dumps(manifest))
    source = (
        tmp_path
        / "runs"
        / "mutations"
        / run_id
        / fixture
        / "results.jsonl"
    )
    duplicate_dir.joinpath("results.jsonl").write_text(source.read_text())
    with pytest.raises(ValueError, match="duplicate candidate ID"):
        load_mutation_run_index(tmp_path, run_id)


def test_index_sorts_by_family_operator_fixture_and_candidate(tmp_path: Path) -> None:
    run_id, fixture = _write_project(tmp_path)
    results = (
        tmp_path
        / "runs"
        / "mutations"
        / run_id
        / fixture
        / "results.jsonl"
    )
    records = [
        _record(
            candidate_id=f"{fixture}-flow-z",
            component="flow",
            operator="remove_established",
        ),
        _record(
            candidate_id=f"{fixture}-flow-a-2",
            component="flow",
            operator="remove_direction",
        ),
        _record(
            candidate_id=f"{fixture}-flow-a-1",
            component="flow",
            operator="remove_direction",
        ),
    ]
    with results.open("a") as stream:
        stream.write("\n" + "\n".join(json.dumps(record) for record in records))

    index = load_mutation_run_index(tmp_path, run_id)

    assert [
        (entry["component"], entry["operator"], entry["candidate_id"])
        for entry in index["records"]
    ][:3] == [
        ("flow", "remove_direction", f"{fixture}-flow-a-1"),
        ("flow", "remove_direction", f"{fixture}-flow-a-2"),
        ("flow", "remove_established", f"{fixture}-flow-z"),
    ]


def _replace_with_symlink(path: Path) -> None:
    target = path.with_name(f"{path.name}-real")
    path.rename(target)
    path.symlink_to(target, target_is_directory=target.is_dir())


@pytest.mark.parametrize(
    "component",
    ["runs", "mutations", "run", "fixture", "results"],
)
def test_rejects_symlink_at_every_run_tree_ancestor(
    tmp_path: Path, component: str
) -> None:
    run_id, fixture = _write_project(tmp_path)
    paths = {
        "runs": tmp_path / "runs",
        "mutations": tmp_path / "runs" / "mutations",
        "run": tmp_path / "runs" / "mutations" / run_id,
        "fixture": tmp_path / "runs" / "mutations" / run_id / fixture,
        "results": (
            tmp_path
            / "runs"
            / "mutations"
            / run_id
            / fixture
            / "results.jsonl"
        ),
    }
    _replace_with_symlink(paths[component])

    with pytest.raises(ValueError, match="symlink"):
        load_mutation_run_index(tmp_path, run_id)


def test_rejects_symlinked_project_root(tmp_path: Path) -> None:
    real_root = tmp_path / "real"
    _write_project(real_root)
    linked_root = tmp_path / "linked"
    linked_root.symlink_to(real_root, target_is_directory=True)

    with pytest.raises(ValueError, match="project root.*symlink"):
        load_mutation_run_index(linked_root, "dataset-component-mutations-v2")


def test_rejects_symlink_ancestor_in_fixture_and_suite_paths(
    tmp_path: Path,
) -> None:
    run_id, fixture = _write_project(tmp_path)
    _replace_with_symlink(tmp_path / "fixtures" / "dataset")

    with pytest.raises(ValueError, match="symlink"):
        load_mutation_run_index(tmp_path, run_id)


@pytest.mark.parametrize("field", ["fixture", "suite"])
def test_rejects_internal_traversal_in_manifest_paths(
    tmp_path: Path, field: str
) -> None:
    run_id, fixture = _write_project(tmp_path)
    manifest_path = tmp_path / "fixtures" / "dataset_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    filename = (
        "et-example.json"
        if field == "fixture"
        else "et-example_suite.json"
    )
    manifest["records"][0][field] = f"fixtures/dataset/../dataset/{filename}"
    manifest_path.write_text(json.dumps(manifest))

    with pytest.raises(ValueError, match=r"must not contain \.\."):
        load_mutation_run_index(tmp_path, run_id)
