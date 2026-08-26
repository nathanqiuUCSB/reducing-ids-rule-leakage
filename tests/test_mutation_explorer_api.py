import json
from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from hardening_game.api import create_app
from hardening_game.mutations import explorer as mutation_explorer


TARGET_CVE = "CVE-2025-0108"
CLOSE_CVE = "CVE-2024-0012"
PROJECT_ROOT = Path(__file__).resolve().parents[1]
COMBINATION_RUN_ID = "combination-hybrid-v1"
COMBINATION_RUN = PROJECT_ROOT / "runs" / "mutations" / COMBINATION_RUN_ID
COMBINATION_MANIFEST = (
    PROJECT_ROOT / "experiments" / COMBINATION_RUN_ID / "manifest.json"
)
COMBINATION_SOURCE_RUN = (
    PROJECT_ROOT / "runs" / "mutations" / "dataset-component-mutations-v2"
)
COMBINATION_FIXTURES = {
    "et-2052951",
    "et-2059741",
    "et-2050340",
    "et-2057330",
    "et-2060144",
    "et-2067354",
    "et-2060086",
}


def test_public_api_exposes_explorer_without_game_routes(tmp_path: Path) -> None:
    app = create_app(project_root=tmp_path)
    paths = {route.path for route in app.routes}

    assert "/api/health" in paths
    assert "/api/mutations/runs" in paths
    assert "/api/mutations/runs/{run_id}/records" in paths
    assert "/api/mutations/runs/{run_id}/records/{candidate_id}" in paths
    assert "/api/games" not in paths
    assert "/api/models" not in paths


def _record(**overrides: object) -> dict[str, object]:
    record: dict[str, object] = {
        "candidate_id": "et-example-content-remove",
        "component": "content",
        "operator": "remove",
        "params": {"index": 0},
        "status": "evaluated",
        "rule": "mutated rule",
        "positive_recall": 1.0,
        "negative_false_positive_rate": 0.0,
        "benign_false_positive_rate": 0.0,
        "attacker_prediction": CLOSE_CVE,
        "case_results": {
            "P0": {"fired": True, "passed": True},
            "N0": {"fired": False, "passed": True},
        },
        "benign_capture_results": {
            "HTTP": {"source_id": "HTTP", "fired": False}
        },
        "attacker_exchange": {
            "parsed_response": {
                "predicted_cve": CLOSE_CVE,
                "reasoning": "same product",
                "clues": ["management path"],
            },
            "prompt": "exact prompt",
            "raw_response": '{"predicted_cve":"CVE-2024-0012"}',
        },
    }
    record.update(overrides)
    return record


def _write_project(root: Path) -> tuple[str, str]:
    run_id = "dataset-component-mutations-v2"
    fixture = "et-example"
    fixture_dir = root / "runs" / "mutations" / run_id / fixture
    fixture_dir.mkdir(parents=True)
    dataset_dir = root / "fixtures" / "dataset"
    dataset_dir.mkdir(parents=True)
    (root / "fixtures" / "dataset_manifest.json").write_text(
        json.dumps(
            {
                "records": [
                    {
                        "name": fixture,
                        "cve": TARGET_CVE,
                        "fixture": f"fixtures/dataset/{fixture}.json",
                        "suite": f"fixtures/dataset/{fixture}_suite.json",
                        "reason": "complete suite",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (root / "fixtures" / "related_cve_registry.json").write_text(
        json.dumps(
            {
                "version": 1,
                "entries": [
                    {
                        "target_cve": TARGET_CVE,
                        "predicted_cve": CLOSE_CVE,
                        "tier": "closely_related",
                        "vendor": "Example",
                        "product": "Example appliance",
                        "rationale": "Same product and vulnerability class.",
                        "provenance": "API test fixture",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (dataset_dir / f"{fixture}.json").write_text(
        json.dumps({"name": fixture, "cve": TARGET_CVE, "rule": "baseline rule"}),
        encoding="utf-8",
    )
    (dataset_dir / f"{fixture}_suite.json").write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "P0",
                        "pcap": "pcap/dataset/et-example/P0-canonical.pcap",
                        "expected_alert": True,
                        "reason": "positive case",
                    },
                    {
                        "name": "N0",
                        "pcap": "pcap/dataset/et-example/N0-negative.pcap",
                        "expected_alert": False,
                        "reason": "negative case",
                        "predicate_id": "content-0",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    records = [
        _record(
            candidate_id=f"{fixture}-baseline",
            component="baseline",
            operator="original",
            params={},
            rule="baseline rule",
            attacker_prediction=TARGET_CVE,
            case_results={},
            benign_capture_results={},
            attacker_exchange=None,
        ),
        _record(),
        _record(
            candidate_id=f"{fixture}-flow-provider-failure",
            component="flow",
            operator="remove_established",
            status="attacker_provider_failed",
            attacker_prediction=None,
            attacker_error="provider unavailable",
            attacker_exchange={"error": "provider unavailable"},
        ),
    ]
    (fixture_dir / "results.jsonl").write_text(
        "\n".join(json.dumps(record) for record in records)
        + '\n{"candidate_id":',
        encoding="utf-8",
    )
    return run_id, fixture


def test_lists_mutation_runs_with_counts_and_malformed_line_warnings(
    tmp_path: Path,
) -> None:
    run_id, fixture = _write_project(tmp_path)
    client = TestClient(create_app(project_root=tmp_path))

    response = client.get("/api/mutations/runs")

    assert response.status_code == 200
    assert response.json() == {
        "runs": [
            {
                "run_id": run_id,
                "fixture_count": 1,
                "record_count": 3,
                "malformed_line_count": 1,
                "diagnostics": [
                    {
                        "file": f"{fixture}/results.jsonl",
                        "line": 4,
                        "error": response.json()["runs"][0]["diagnostics"][0]["error"],
                    }
                ],
            }
        ],
        "omitted_run_count": 0,
        "omitted_runs": [],
    }


def _legacy_combination_record(fixture: str) -> dict[str, object]:
    sources = [
        f"{fixture}-content-literal_as_hex-1e895a624e78",
        f"{fixture}-content-literal_as_hex-2e5fd7e2c32f",
    ]
    return _record(
        candidate_id=f"{fixture}-combination-2-a4caed20c1d5",
        component="combination",
        operator="blocks_2",
        params={
            "components": ["content", "content"],
            "operators": ["literal_as_hex", "literal_as_hex"],
            "source_candidate_ids": sources,
        },
        rule="mutated combination rule",
        source_candidate_ids=sources,
        block_count=2,
    )


def test_every_listed_run_serves_its_records_without_a_server_error(
    tmp_path: Path,
) -> None:
    run_id, fixture = _write_project(tmp_path)
    mutations = tmp_path / "runs" / "mutations"
    results = (mutations / run_id / fixture / "results.jsonl").read_text(
        encoding="utf-8"
    )
    for name in (fixture, f"{fixture}-verified"):
        directory = mutations / "expansion-smoke" / name
        directory.mkdir(parents=True)
        directory.joinpath("results.jsonl").write_text(results, encoding="utf-8")
    nested = mutations / "expansion-smoke" / "preflight" / fixture
    nested.mkdir(parents=True)
    nested.joinpath("results.jsonl").write_text(results, encoding="utf-8")
    combination = mutations / "combination-hybrid-v1" / fixture
    combination.mkdir(parents=True)
    combination.joinpath("results.jsonl").write_text(
        results + "\n" + json.dumps(_legacy_combination_record(fixture)),
        encoding="utf-8",
    )
    client = TestClient(create_app(project_root=tmp_path))

    listing = client.get("/api/mutations/runs")

    assert listing.status_code == 200
    listed = [run["run_id"] for run in listing.json()["runs"]]
    assert listed == ["combination-hybrid-v1", run_id, "expansion-smoke"]
    for summary in listing.json()["runs"]:
        response = client.get(
            f"/api/mutations/runs/{summary['run_id']}/records"
        )
        assert response.status_code == 200
        payload = response.json()
        assert payload["record_count"] == summary["record_count"]
        assert payload["record_count"] >= 1
        assert payload["diagnostics"] == summary["diagnostics"]


def test_run_listing_reports_an_in_progress_fixture_without_failing(
    tmp_path: Path,
) -> None:
    run_id, fixture = _write_project(tmp_path)
    fixture_dir = tmp_path / "runs" / "mutations" / run_id / fixture
    fixture_dir.joinpath("results.jsonl").unlink()
    fixture_dir.joinpath("rejections.jsonl").write_text(
        json.dumps({"reason": "mutation would empty the rule"}) + "\n",
        encoding="utf-8",
    )
    fixture_dir.joinpath("baseline_context.json").write_text(
        json.dumps({"fixture": fixture, "baseline_exact": True}),
        encoding="utf-8",
    )
    client = TestClient(create_app(project_root=tmp_path))

    listing = client.get("/api/mutations/runs")
    records = client.get(f"/api/mutations/runs/{run_id}/records")

    assert listing.status_code == 200
    assert listing.json() == {
        "runs": [],
        "omitted_run_count": 0,
        "omitted_runs": [],
    }
    assert records.status_code == 200
    assert records.json()["records"] == []
    assert records.json()["diagnostics"] == [
        {
            "file": f"{fixture}/results.jsonl",
            "line": 0,
            "error": records.json()["diagnostics"][0]["error"],
        }
    ]
    assert "no results JSONL" in records.json()["diagnostics"][0]["error"]
    assert str(tmp_path) not in listing.text
    assert str(tmp_path) not in records.text


def test_run_listing_isolates_and_reports_an_unreadable_run(
    tmp_path: Path,
) -> None:
    run_id, fixture = _write_project(tmp_path)
    mutations = tmp_path / "runs" / "mutations"
    results = (mutations / run_id / fixture / "results.jsonl").read_text(
        encoding="utf-8"
    )
    manifest_path = tmp_path / "fixtures" / "dataset_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["records"].append(
        {
            "name": "et-other",
            "cve": TARGET_CVE,
            "fixture": f"fixtures/dataset/{fixture}.json",
            "suite": f"fixtures/dataset/{fixture}_suite.json",
        }
    )
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    for name in (fixture, "et-other"):
        directory = mutations / "duplicate-candidates" / name
        directory.mkdir(parents=True)
        directory.joinpath("results.jsonl").write_text(results, encoding="utf-8")
    client = TestClient(create_app(project_root=tmp_path))

    listing = client.get("/api/mutations/runs")

    assert listing.status_code == 200
    payload = listing.json()
    assert [run["run_id"] for run in payload["runs"]] == [run_id]
    assert payload["omitted_run_count"] == 1
    assert payload["omitted_runs"][0]["run_id"] == "duplicate-candidates"
    assert "duplicate candidate ID" in payload["omitted_runs"][0]["error"]
    assert str(tmp_path) not in listing.text
    for summary in payload["runs"]:
        response = client.get(
            f"/api/mutations/runs/{summary['run_id']}/records"
        )
        assert response.status_code == 200


def test_flat_run_root_layout_is_explained_when_requested_directly(
    tmp_path: Path,
) -> None:
    run_id, fixture = _write_project(tmp_path)
    mutations = tmp_path / "runs" / "mutations"
    flat = mutations / "et-example-mutations"
    flat.mkdir(parents=True)
    flat.joinpath("results.jsonl").write_text(
        (mutations / run_id / fixture / "results.jsonl").read_text(
            encoding="utf-8"
        ),
        encoding="utf-8",
    )
    client = TestClient(create_app(project_root=tmp_path))

    listing = client.get("/api/mutations/runs")
    records = client.get("/api/mutations/runs/et-example-mutations/records")

    assert [run["run_id"] for run in listing.json()["runs"]] == [run_id]
    assert listing.json()["omitted_run_count"] == 0
    assert records.status_code == 200
    assert records.json()["records"] == []
    assert records.json()["diagnostics"][0]["file"] == "results.jsonl"
    assert "run root" in records.json()["diagnostics"][0]["error"]
    assert str(tmp_path) not in records.text


def test_returns_run_metadata_and_stably_sorted_lightweight_records(
    tmp_path: Path,
) -> None:
    run_id, _ = _write_project(tmp_path)
    client = TestClient(create_app(project_root=tmp_path))

    run_response = client.get(f"/api/mutations/runs/{run_id}")
    records_response = client.get(f"/api/mutations/runs/{run_id}/records")

    assert run_response.status_code == 200
    assert run_response.json()["record_count"] == 3
    assert run_response.json()["diagnostics"][0]["line"] == 4
    assert "records" not in run_response.json()
    assert records_response.status_code == 200
    payload = records_response.json()
    assert [record["component"] for record in payload["records"]] == [
        "flow",
        "content",
        "baseline",
    ]
    assert "attacker_exchange" not in payload["records"][0]
    assert payload["records"][0]["is_emergent_miss"] is False
    close_record = payload["records"][1]
    assert close_record["is_balanced_emergent_miss"] is True
    assert close_record["is_closely_related_guess"] is True
    assert close_record["meaningful_obscurity"] is False


@pytest.mark.skipif(
    not (
        COMBINATION_RUN.is_dir()
        and COMBINATION_MANIFEST.is_file()
        and COMBINATION_SOURCE_RUN.is_dir()
    ),
    reason="committed combination explorer artifacts are absent",
)
def test_real_combination_fixture_flows_through_existing_api_routes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = TestClient(create_app(project_root=PROJECT_ROOT))

    records_response = client.get(
        f"/api/mutations/runs/{COMBINATION_RUN_ID}/records"
    )

    assert records_response.status_code == 200
    payload = records_response.json()
    assert payload["record_count"] == 432
    assert payload["fixture_count"] == 7
    assert payload["diagnostics"] == []
    records = payload["records"]
    assert {record["fixture"] for record in records} == COMBINATION_FIXTURES
    assert records == sorted(
        records,
        key=lambda record: (
            record["fixture"],
            record["block_count"],
            tuple(record["included_families"]),
            record["candidate_id"],
        ),
    )
    assert {record["experiment_role"] for record in records} == {
        "primary",
        "near_cve_confusion_control",
    }
    assert all("building_blocks" not in record for record in records)
    assert all("join_diagnostics" not in record for record in records)

    provenance_calls = 0
    resolve_provenance = mutation_explorer.resolve_combination_provenance

    def counting_resolve_provenance(*args: object) -> dict[str, object]:
        nonlocal provenance_calls
        provenance_calls += 1
        return resolve_provenance(*args)

    monkeypatch.setattr(
        mutation_explorer,
        "resolve_combination_provenance",
        counting_resolve_provenance,
    )
    representative_ids = {
        fixture: next(
            record["candidate_id"]
            for record in records
            if record["fixture"] == fixture
        )
        for fixture in COMBINATION_FIXTURES
    }
    max_block_count = max(record["block_count"] for record in records)
    max_block_ids = {
        record["candidate_id"]
        for record in records
        if record["block_count"] == max_block_count
    }
    assert max_block_count == 7
    assert len(max_block_ids) == 2

    detail_ids = set(representative_ids.values()) | max_block_ids
    for detail_id in detail_ids:
        detail_response = client.get(
            f"/api/mutations/runs/{COMBINATION_RUN_ID}/records/{detail_id}"
        )
        assert detail_response.status_code == 200
        detail = detail_response.json()
        assert len(detail["building_blocks"]) == detail["block_count"]
        assert {
            block["candidate_id"] for block in detail["building_blocks"]
        } == set(detail["source_candidate_ids"])
        assert all(
            block["join_status"] == "available"
            for block in detail["building_blocks"]
        )
        assert detail["join_diagnostics"] == []
    assert provenance_calls == len(detail_ids)


def test_returns_full_record_detail_and_attacker_failure_labels(
    tmp_path: Path,
) -> None:
    run_id, fixture = _write_project(tmp_path)
    client = TestClient(create_app(project_root=tmp_path))

    detail = client.get(
        f"/api/mutations/runs/{run_id}/records/{fixture}-content-remove"
    )
    failure = client.get(
        f"/api/mutations/runs/{run_id}/records/{fixture}-flow-provider-failure"
    )

    assert detail.status_code == 200
    payload = detail.json()
    assert payload["baseline_rule"] == "baseline rule"
    assert payload["mutated_rule"] == "mutated rule"
    assert payload["params"] == {"index": 0}
    assert payload["case_groups"]["positive"][0]["reason"] == "positive case"
    assert payload["case_groups"]["negative"][0]["predicate_id"] == "content-0"
    assert payload["case_groups"]["benign"][0]["source_id"] == "HTTP"
    assert payload["attacker"]["reasoning"] == "same product"
    assert payload["relationship_tier"] == "closely_related"
    assert payload["meaningful_obscurity"] is False
    assert "building_blocks" not in payload
    assert "join_diagnostics" not in payload
    assert failure.status_code == 200
    assert failure.json()["attacker"]["status"] == "provider"


@pytest.mark.parametrize(
    "path",
    [
        "/api/mutations/runs/unknown",
        "/api/mutations/runs/$unsafe",
        "/api/mutations/runs/../escape",
        (
            "/api/mutations/runs/dataset-component-mutations-v2/"
            "records/unknown"
        ),
        (
            "/api/mutations/runs/dataset-component-mutations-v2/"
            "records/$unsafe"
        ),
    ],
)
def test_returns_404_for_unknown_traversal_and_unsafe_ids(
    tmp_path: Path, path: str
) -> None:
    _write_project(tmp_path)
    client = TestClient(create_app(project_root=tmp_path))

    response = client.get(path)

    assert response.status_code == 404
    assert str(tmp_path) not in response.text


@pytest.mark.parametrize("component", ["project_root", "runs", "mutations", "run"])
def test_returns_redacted_404_for_symlinked_run_tree_ancestors(
    tmp_path: Path, component: str
) -> None:
    real_root = tmp_path / "real" if component == "project_root" else tmp_path
    run_id, _ = _write_project(real_root)
    project_root = real_root
    if component == "project_root":
        project_root = tmp_path / "linked"
        project_root.symlink_to(real_root, target_is_directory=True)
    else:
        paths = {
            "runs": real_root / "runs",
            "mutations": real_root / "runs" / "mutations",
            "run": real_root / "runs" / "mutations" / run_id,
        }
        path = paths[component]
        target = path.with_name(f"{path.name}-real")
        path.rename(target)
        path.symlink_to(target, target_is_directory=True)
    client = TestClient(create_app(project_root=project_root))

    response = client.get(f"/api/mutations/runs/{run_id}/records")

    assert response.status_code == 404
    assert response.json() == {
        "detail": "Mutation explorer resource not found"
    }
    assert str(tmp_path) not in response.text


def test_returns_500_for_duplicate_candidate_ids(tmp_path: Path) -> None:
    run_id, fixture = _write_project(tmp_path)
    duplicate = tmp_path / "runs" / "mutations" / run_id / "et-other"
    duplicate.mkdir()
    source = (
        tmp_path
        / "runs"
        / "mutations"
        / run_id
        / fixture
        / "results.jsonl"
    )
    duplicate.joinpath("results.jsonl").write_text(
        source.read_text(encoding="utf-8"), encoding="utf-8"
    )
    manifest_path = tmp_path / "fixtures" / "dataset_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["records"].append(
        {
            "name": "et-other",
            "cve": TARGET_CVE,
            "fixture": f"fixtures/dataset/{fixture}.json",
            "suite": f"fixtures/dataset/{fixture}_suite.json",
        }
    )
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    client = TestClient(create_app(project_root=tmp_path))

    response = client.get(f"/api/mutations/runs/{run_id}/records")

    assert response.status_code == 500
    assert str(tmp_path) not in response.text


def test_returns_redacted_500_for_unsafe_persisted_fixture_id(
    tmp_path: Path,
) -> None:
    run_id, fixture = _write_project(tmp_path)
    fixture_dir = tmp_path / "runs" / "mutations" / run_id / fixture
    fixture_dir.rename(fixture_dir.with_name("$unsafe"))
    client = TestClient(create_app(project_root=tmp_path))

    response = client.get(f"/api/mutations/runs/{run_id}/records")

    assert response.status_code == 500
    assert response.json() == {
        "detail": "Mutation explorer configuration is invalid"
    }
    assert str(tmp_path) not in response.text
    assert "$unsafe" not in response.text


def test_returns_redacted_500_for_unsafe_persisted_candidate_id(
    tmp_path: Path,
) -> None:
    run_id, fixture = _write_project(tmp_path)
    results = (
        tmp_path
        / "runs"
        / "mutations"
        / run_id
        / fixture
        / "results.jsonl"
    )
    with results.open("a", encoding="utf-8") as stream:
        stream.write("\n" + json.dumps(_record(candidate_id="$unsafe")))
    client = TestClient(create_app(project_root=tmp_path))

    response = client.get(f"/api/mutations/runs/{run_id}/records")

    assert response.status_code == 500
    assert response.json() == {
        "detail": "Mutation explorer configuration is invalid"
    }
    assert str(tmp_path) not in response.text
    assert "$unsafe" not in response.text


def test_redacts_malformed_committed_configuration_errors(tmp_path: Path) -> None:
    run_id, _ = _write_project(tmp_path)
    (tmp_path / "fixtures" / "dataset_manifest.json").write_text(
        "{", encoding="utf-8"
    )
    client = TestClient(create_app(project_root=tmp_path))

    response = client.get(f"/api/mutations/runs/{run_id}/records")

    assert response.status_code == 500
    assert response.json() == {
        "detail": "Mutation explorer configuration is invalid"
    }
    assert str(tmp_path) not in response.text
