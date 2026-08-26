import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from hardening_game.fixture import load_fixture_path, sanitize_l5_rule
from hardening_game import dataset_suites
from hardening_game.dataset_recipes import predicate_refs, recipes
from hardening_game.dataset_suites import (
    EXCLUDED_SIDS,
    build_suite_cases,
    ensure_sid_and_revision,
    load_dataset_records,
    plan_dataset_suites,
)
from hardening_game.suricata.validate import syntax_check_rule
from hardening_game.mutations import cli as mutation_cli
from hardening_game.mutations.cli import build_parser, run_dataset_experiments, run_experiment
from hardening_game.mutations.engine import generate_generic_candidates


DATASET = Path(__file__).resolve().parents[1] / "datasets" / "gpt55_exact_cve_l5_2023plus_20.jsonl"


def _dataset_rules() -> dict[int, str]:
    return {
        record.sid: ensure_sid_and_revision(
            sanitize_l5_rule(record.rule), sid=record.sid
        )
        for record in load_dataset_records(DATASET)
    }


def test_loader_reads_all_records_and_normalizes_rule_identity() -> None:
    records = load_dataset_records(DATASET)

    assert len(records) == 20
    assert records[0].name == "et-2044143"
    normalized = ensure_sid_and_revision(records[0].rule, sid=records[0].sid)
    assert "sid:2044143;" in normalized
    assert "rev:1;" in normalized


def test_planner_assigns_an_explicit_suite_or_structured_unsupported_status() -> None:
    plans = plan_dataset_suites(load_dataset_records(DATASET))

    assert len(plans) == 20
    assert {plan.name for plan in plans} == {
        record.name for record in load_dataset_records(DATASET)
    }
    assert all(
        plan.suite_type or plan.status in {"unsupported", "excluded"} for plan in plans
    )
    assert all(plan.reason for plan in plans)
    assert {plan.sid for plan in plans if plan.status == "excluded"} == {2044680}
    assert any(plan.suite_type == "raw_tcp" for plan in plans)
    assert sum(plan.suite_type == "http" for plan in plans) >= 16


_CATALOG_RULE = (
    "alert http $EXTERNAL_NET any -> $HOME_NET 8080 ( flow:established,to_server; "
    'http.uri; bsize:11; content:"/a"; startswith; nocase; pcre:"/^b/R"; '
    'http.header_names; content:!"Referer|0d 0a|"; '
    "byte_test:1,&,0x80,0,relative; sid:1; rev:1;)"
)


def test_predicate_refs_derive_stable_ids_for_each_rule_predicate() -> None:
    refs = {ref.id: ref for ref in predicate_refs(_CATALOG_RULE)}

    assert refs["flow-established"].kind == "flow"
    assert refs["flow-to_server"].kind == "flow"
    assert refs["header-src-address"].kind == "address"
    assert refs["header-dst-address"].kind == "address"
    assert refs["header-dst-port"].kind == "port"
    assert "header-src-port" not in refs
    assert refs["content-0"].buffer == "http.uri"
    assert refs["content-0-startswith"].kind == "boundary"
    assert refs["content-0-nocase"].kind == "case"
    assert refs["bsize-0"].buffer == "http.uri"
    assert refs["pcre-0"].buffer == "http.uri"
    assert refs["content-1"].kind == "negated_content"
    assert refs["content-1"].buffer == "http.header_names"
    assert refs["byte_test-0"].buffer == "http.header_names"
    assert refs["rule-baseline"].kind == "whole_signature"


def test_predicate_refs_are_unique_ordered_and_end_with_the_whole_signature() -> None:
    ids = [ref.id for ref in predicate_refs(_CATALOG_RULE)]

    assert len(ids) == len(set(ids))
    assert ids[-1] == "rule-baseline"
    assert ids.index("content-0") < ids.index("content-1")
    assert all(ref.description for ref in predicate_refs(_CATALOG_RULE))


def test_recipes_cover_every_dataset_rule_except_the_excluded_smtp_rule() -> None:
    catalog = recipes()

    assert EXCLUDED_SIDS == frozenset({2044680})
    assert set(catalog) | set(EXCLUDED_SIDS) == set(_dataset_rules())
    assert len(catalog) == 19


def test_recipe_predicate_declarations_match_the_parsed_rule_catalog() -> None:
    rules = _dataset_rules()

    for sid, recipe in recipes().items():
        declared = tuple(ref.id for ref in recipe.predicates)
        derived = tuple(ref.id for ref in predicate_refs(rules[sid]))
        assert declared == derived, sid


def test_every_declared_predicate_is_covered_or_explicitly_unsupported() -> None:
    for sid, recipe in recipes().items():
        declared = {ref.id for ref in recipe.predicates}
        covered = {
            case.predicate_id for case in recipe.cases if not case.expected_alert
        }
        unsupported = {entry.id: entry.reason for entry in recipe.unsupported}

        assert covered <= declared, sid
        assert set(unsupported) <= declared, sid
        assert not covered & set(unsupported), sid
        assert covered | set(unsupported) == declared, sid
        assert all(unsupported.values()), sid


def test_negatives_always_name_a_predicate_and_positives_never_do() -> None:
    for sid, recipe in recipes().items():
        for case in recipe.cases:
            if case.expected_alert:
                assert case.predicate_id is None, (sid, case.name)
                assert "signature-positive" in case.reason, (sid, case.name)
            else:
                assert case.predicate_id, (sid, case.name)


def test_every_recipe_has_canonical_segmentation_and_retransmission_positives() -> None:
    for sid, recipe in recipes().items():
        positives = [case for case in recipe.cases if case.expected_alert]

        assert [case.name for case in positives][0] == "P0-canonical", sid
        assert any(case.split_after for case in positives), sid
        assert any(case.uniform_segment_size for case in positives), sid
        assert any(case.retransmit_segment is not None for case in positives), sid


def test_recipes_that_require_an_established_flow_test_an_unestablished_one() -> None:
    for sid, recipe in recipes().items():
        if "flow-established" not in {ref.id for ref in recipe.predicates}:
            continue
        assert any(not case.established for case in recipe.cases), sid


def test_every_recipe_has_a_random_protocol_valid_negative() -> None:
    for sid, recipe in recipes().items():
        assert any(
            case.predicate_id == "rule-baseline" and not case.expected_alert
            for case in recipe.cases
        ), sid


def test_case_names_are_unique_and_every_case_states_a_reason() -> None:
    for sid, recipe in recipes().items():
        names = [case.name for case in recipe.cases]

        assert len(names) == len(set(names)), sid
        assert all(case.reason for case in recipe.cases), sid


def test_no_recipe_contains_two_payload_and_transport_equivalent_cases() -> None:
    for sid, recipe in recipes().items():
        fingerprints = [case.fingerprint for case in build_suite_cases(recipe)]

        assert len(fingerprints) == len(set(fingerprints)), sid


def test_built_cases_are_deterministic_across_repeated_builds() -> None:
    recipe = recipes()[2052951]

    first = build_suite_cases(recipe)
    second = build_suite_cases(recipe)

    assert [case.fingerprint for case in first] == [case.fingerprint for case in second]
    assert first[0].payload.startswith(
        b"GET /api/index.php/v1/config/application?public=true HTTP/1.1"
    )


def test_minimal_suricata_config_supports_dataset_address_and_port_variables() -> None:
    record = next(
        record for record in load_dataset_records(DATASET) if record.sid == 2044585
    )

    result = syntax_check_rule(ensure_sid_and_revision(record.rule, sid=record.sid))

    assert result.valid, result.error


def test_mutation_cli_selects_generic_candidates_from_fixture_json_path(
    tmp_path: Path, monkeypatch
) -> None:
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    fixture_path = fixtures / "dataset-example.json"
    fixture_path.write_text(
        json.dumps(
            {
                "name": "dataset-example",
                "sid": 1,
                "revision": 1,
                "cve": "CVE-2023-0001",
                "pcap": "positive.pcap",
                "rule": (
                    'alert tcp any any -> any 8080 (flow:established,to_server; '
                    'content:"POST"; sid:1; rev:1;)'
                ),
            }
        )
    )

    captured: dict[str, object] = {}
    events: list[str] = []

    class FakeEvaluator:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)

        def validate_baseline(self, candidate: object) -> None:
            events.append("baseline")
            captured["baseline"] = candidate

        def persist_rejections(self, rejections: object) -> None:
            captured["rejections"] = rejections

        def evaluate(self, candidates: list[object], *, resume: bool) -> list[object]:
            captured["candidates"] = candidates
            captured["resume"] = resume
            return []

    monkeypatch.setattr(mutation_cli, "MutationEvaluator", FakeEvaluator)

    def fake_client_factory(**_kwargs: object) -> object:
        events.append("client")
        return object()

    results = run_experiment(
        fixture_name="fixtures/dataset-example.json",
        attacker_model="unused",
        api_key="unused",
        run_id="unused",
        project_root=tmp_path,
        client_factory=fake_client_factory,
        skip_benign=True,
    )

    assert results == []
    assert captured["baseline"].id == "dataset-example-baseline"
    assert any(
        candidate.component == "destination_port"
        for candidate in captured["candidates"]
    )
    assert all(
        candidate.id.startswith("dataset-example-")
        for candidate in captured["candidates"]
    )
    assert events == ["baseline", "client"]
    assert captured["benign_enabled"] is False


def test_run_experiment_finds_the_baseline_by_component_not_position(
    tmp_path: Path, monkeypatch
) -> None:
    """locked_candidates (the --experiment-manifest path) must not assume the
    baseline sits at index 0. The manifest happens to put baseline first for
    every fixture today, but validate_baseline must not silently validate the
    wrong candidate if that ever changes."""
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    fixture_path = fixtures / "dataset-example.json"
    fixture_path.write_text(
        json.dumps(
            {
                "name": "dataset-example",
                "sid": 1,
                "revision": 1,
                "cve": "CVE-2023-0001",
                "pcap": "positive.pcap",
                "rule": (
                    'alert tcp any any -> any 8080 (flow:established,to_server; '
                    'content:"POST"; sid:1; rev:1;)'
                ),
            }
        )
    )

    from hardening_game.mutations.engine import MutationCandidate

    mutated_first = MutationCandidate(
        id="dataset-example-flow-remove-aaaa",
        component="flow",
        operator="remove",
        params={},
        description="A mutation, deliberately ordered before the baseline.",
        rule='alert tcp any any -> any 8080 (content:"POST"; sid:1; rev:2;)',
        revision=2,
        fingerprint="mutated",
    )
    baseline_last = MutationCandidate(
        id="dataset-example-baseline",
        component="baseline",
        operator="original",
        params={},
        description="Original validated fixture rule.",
        rule=(
            'alert tcp any any -> any 8080 (flow:established,to_server; '
            'content:"POST"; sid:1; rev:1;)'
        ),
        revision=1,
        fingerprint="baseline",
    )

    captured: dict[str, object] = {}

    class FakeEvaluator:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)

        def validate_baseline(self, candidate: object) -> None:
            captured["baseline"] = candidate

        def persist_rejections(self, rejections: object) -> None:
            pass

        def evaluate(self, candidates: list[object], *, resume: bool) -> list[object]:
            return []

    monkeypatch.setattr(mutation_cli, "MutationEvaluator", FakeEvaluator)

    run_experiment(
        fixture_name="fixtures/dataset-example.json",
        attacker_model="unused",
        api_key="unused",
        run_id="unused",
        project_root=tmp_path,
        client_factory=lambda **_kwargs: object(),
        skip_benign=True,
        locked_candidates=(mutated_first, baseline_last),
        experiment_manifest_hash="test-hash",
    )

    assert captured["baseline"].id == "dataset-example-baseline"
    assert captured["baseline"].component == "baseline"


def test_mutation_cli_loads_only_available_mapped_benign_cases(
    tmp_path: Path, monkeypatch
) -> None:
    fixture_path = tmp_path / "fixtures" / "dataset-example.json"
    fixture_path.parent.mkdir()
    fixture_path.write_text(
        json.dumps(
            {
                "name": "dataset-example",
                "sid": 1,
                "revision": 1,
                "cve": "CVE-2023-0001",
                "pcap": "positive.pcap",
                "rule": 'alert http any any -> any 80 (sid:1; rev:1;)',
            }
        )
    )
    payload = b"valid capture"
    cache = tmp_path / "cache"
    capture = cache / "level1/http/http.cap"
    capture.parent.mkdir(parents=True)
    capture.write_bytes(payload)
    benign_sources = tmp_path / "benign_sources"
    benign_sources.mkdir()
    (benign_sources / "benign_registry.json").write_text(
        json.dumps(
            {
                "version": 1,
                "cache_root": "unused",
                "sources": [
                    {
                        "source_id": "HTTP_SIMPLE",
                        "url": "https://example.invalid/http.cap",
                        "relative_path": "level1/http/http.cap",
                        "sha256": hashlib.sha256(payload).hexdigest(),
                        "license_note": "test",
                        "capture_format": "pcap",
                        "inspection_status": "confirmed",
                        "protocol": "http",
                    },
                    {
                        "source_id": "HTTP_MISSING",
                        "url": "https://example.invalid/missing.cap",
                        "relative_path": "level1/http/missing.cap",
                        "sha256": "0" * 64,
                        "license_note": "test",
                        "capture_format": "pcap",
                        "inspection_status": "confirmed",
                        "protocol": "http",
                    },
                ],
            }
        )
    )
    (benign_sources / "fixture_benign_mappings.json").write_text(
        json.dumps(
            {
                "version": 1,
                "mappings": [
                    {
                        "fixture_name": "dataset-example",
                        "source_id": source_id,
                        "coverage_tier": "level1",
                        "relevance_note": "HTTP protocol coverage",
                    }
                    for source_id in ("HTTP_SIMPLE", "HTTP_MISSING")
                ],
            }
        )
    )
    captured: dict[str, object] = {}

    class FakeEvaluator:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)

        def validate_baseline(self, _candidate: object) -> None:
            pass

        def persist_rejections(self, _rejections: object) -> None:
            pass

        def evaluate(self, _candidates: list[object], *, resume: bool) -> list[object]:
            return []

    monkeypatch.setattr(mutation_cli, "MutationEvaluator", FakeEvaluator)
    run_experiment(
        fixture_name=str(fixture_path),
        attacker_model="unused",
        api_key="unused",
        run_id="unused",
        project_root=tmp_path,
        client_factory=lambda **_kwargs: object(),
        benign_cache=cache,
    )

    assert [case.source_id for case in captured["benign_cases"]] == ["HTTP_SIMPLE"]
    assert captured["benign_requested"] == 2
    assert captured["benign_cache_errors"] == (
        "HTTP_MISSING: capture is missing",
    )
    assert captured["benign_enabled"] is True


def test_mutation_cli_default_benign_cache_resolves_relative_to_project_root(
    tmp_path: Path,
) -> None:
    """Without --benign-cache, the cache_root is under project_root, not benign_sources/.

    The registry's cache_root ("online_benign_pcaps") names a directory that
    sits alongside benign_sources/ at the project root, not inside it. A
    default that joins sources_dir/registry.cache_root can never find a real
    capture and silently produces zero benign cases and a null benign
    false-positive rate for the whole run.
    """
    payload = b"valid capture"
    capture = tmp_path / "online_benign_pcaps" / "level1" / "http" / "http.cap"
    capture.parent.mkdir(parents=True)
    capture.write_bytes(payload)
    benign_sources = tmp_path / "benign_sources"
    benign_sources.mkdir()
    (benign_sources / "benign_registry.json").write_text(
        json.dumps(
            {
                "version": 1,
                "cache_root": "online_benign_pcaps",
                "sources": [
                    {
                        "source_id": "HTTP_SIMPLE",
                        "url": "https://example.invalid/http.cap",
                        "relative_path": "level1/http/http.cap",
                        "sha256": hashlib.sha256(payload).hexdigest(),
                        "license_note": "test",
                        "capture_format": "pcap",
                        "inspection_status": "confirmed",
                        "protocol": "http",
                    },
                ],
            }
        )
    )
    (benign_sources / "fixture_benign_mappings.json").write_text(
        json.dumps(
            {
                "version": 1,
                "mappings": [
                    {
                        "fixture_name": "dataset-example",
                        "source_id": "HTTP_SIMPLE",
                        "coverage_tier": "level1",
                        "relevance_note": "HTTP protocol coverage",
                    }
                ],
            }
        )
    )

    cases, requested, cache_errors = mutation_cli.load_benign_context(
        "dataset-example", project_root=tmp_path, benign_cache=None
    )

    assert [case.source_id for case in cases] == ["HTTP_SIMPLE"]
    assert requested == 1
    assert cache_errors == ()


def test_mutation_cli_accepts_benign_control_options() -> None:
    args = build_parser().parse_args(
        [
            "--attacker-model",
            "unused",
            "--benign-cache",
            "/tmp/cache",
            "--skip-benign",
        ]
    )

    assert args.benign_cache == Path("/tmp/cache")
    assert args.skip_benign is True


def test_dataset_mutation_mode_iterates_only_fixture_jsons_without_live_inference(
    tmp_path: Path, monkeypatch
) -> None:
    fixtures = tmp_path / "fixtures" / "dataset"
    fixtures.mkdir(parents=True)
    for name in ("et-a", "et-b"):
        (fixtures / f"{name}.json").write_text("{}")
    (fixtures / "et-a_suite.json").write_text("{}")
    calls: list[dict[str, object]] = []

    def fake_run_experiment(**kwargs: object) -> list[object]:
        calls.append(kwargs)
        return []

    monkeypatch.setattr(mutation_cli, "run_experiment", fake_run_experiment)

    results = run_dataset_experiments(
        attacker_model="unused",
        api_key="unused",
        run_id="dataset-run",
        project_root=tmp_path,
        resume=True,
    )

    assert results == {"fixtures": 2, "candidate_results": 0}
    assert [Path(call["fixture_name"]).name for call in calls] == ["et-a.json", "et-b.json"]
    assert all(call["resume"] is True for call in calls)
    assert all(call["client_factory"] is not None for call in calls)


def test_generated_manifest_is_portable_and_only_references_validated_artifacts() -> None:
    root = DATASET.parents[1]
    manifest = json.loads((root / "fixtures" / "dataset_manifest.json").read_text())

    assert manifest["dataset"] == "datasets/gpt55_exact_cve_l5_2023plus_20.jsonl"
    assert len(manifest["records"]) == 20
    for record in manifest["records"]:
        if record["status"] == "validated":
            assert (root / record["fixture"]).is_file()
            assert (root / record["suite"]).is_file()
        else:
            assert "fixture" not in record
            assert "suite" not in record


def test_all_validated_dataset_fixtures_have_generic_mutation_candidates() -> None:
    root = DATASET.parents[1]
    manifest = json.loads((root / "fixtures" / "dataset_manifest.json").read_text())
    validated = [
        record for record in manifest["records"] if record["status"] == "validated"
    ]

    assert len(validated) == 19
    for record in validated:
        fixture = load_fixture_path(root / record["fixture"], project_root=root)
        candidates = generate_generic_candidates(
            fixture.sanitized_rule,
            revision=fixture.revision,
            fixture_name=fixture.name,
        )
        assert candidates.accepted[0].id == f"{fixture.name}-baseline"
        assert len(candidates.accepted) > 1


def test_dataset_suite_cli_revalidates_manifest_with_explicit_dataset_path(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    captured: dict[str, Path] = {}

    def fake_generate(*, dataset_path: Path, project_root: Path) -> dict[str, object]:
        captured["dataset_path"] = dataset_path
        captured["project_root"] = project_root
        return {"records": [{"status": "validated"}, {"status": "unsupported"}]}

    monkeypatch.setattr(dataset_suites, "generate_dataset_suites", fake_generate)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "hardening-dataset-suites",
            "--dataset",
            "datasets/custom.jsonl",
            "--project-root",
            str(tmp_path),
        ],
    )

    dataset_suites.main()

    assert captured == {
        "dataset_path": tmp_path / "datasets" / "custom.jsonl",
        "project_root": tmp_path,
    }
    assert "Validated 1 of 2 dataset records." in capsys.readouterr().out


def _single_record_dataset(tmp_path: Path) -> tuple[Path, str]:
    record = next(record for record in load_dataset_records(DATASET) if record.sid == 2044143)
    dataset_path = tmp_path / "dataset.jsonl"
    dataset_path.write_text(
        json.dumps(
            {
                "name": record.name,
                "sid": record.sid,
                "cve": record.cve,
                "rule": record.rule,
            }
        )
        + "\n"
    )
    return dataset_path, record.name


def _stale_dataset_artifacts(project_root: Path, fixture_name: str) -> tuple[Path, Path, Path]:
    suite_dir = project_root / "pcap" / "dataset" / fixture_name
    suite_dir.mkdir(parents=True)
    for name in ("positive.pcap", "negative.pcap", "stale.pcap"):
        (suite_dir / name).write_bytes(b"stale")
    fixture_path = project_root / "fixtures" / "dataset" / f"{fixture_name}.json"
    suite_path = project_root / "fixtures" / "dataset" / f"{fixture_name}_suite.json"
    fixture_path.parent.mkdir(parents=True)
    fixture_path.write_text("{}")
    suite_path.write_text("{}")
    return suite_dir, fixture_path, suite_path


def test_generation_removes_only_current_fixture_legacy_artifacts_before_replacement(
    tmp_path: Path, monkeypatch
) -> None:
    dataset_path, fixture_name = _single_record_dataset(tmp_path)
    suite_dir, fixture_path, suite_path = _stale_dataset_artifacts(tmp_path, fixture_name)
    untouched = tmp_path / "pcap" / "dataset" / "other-fixture" / "keep.pcap"
    untouched.parent.mkdir(parents=True)
    untouched.write_bytes(b"keep")

    monkeypatch.setattr(
        dataset_suites,
        "syntax_check_rule",
        lambda _rule: SimpleNamespace(valid=False, error="synthetic syntax failure"),
    )

    manifest = dataset_suites.generate_dataset_suites(
        dataset_path=dataset_path, project_root=tmp_path
    )

    assert manifest["records"][0]["status"] == "baseline_invalid"
    assert not suite_dir.exists()
    assert not fixture_path.exists()
    assert not suite_path.exists()
    assert untouched.read_bytes() == b"keep"


def test_replay_failure_removes_current_fixture_generated_artifacts(
    tmp_path: Path, monkeypatch
) -> None:
    dataset_path, fixture_name = _single_record_dataset(tmp_path)
    suite_dir, fixture_path, suite_path = _stale_dataset_artifacts(tmp_path, fixture_name)

    monkeypatch.setattr(
        dataset_suites,
        "replay_suite",
        lambda *_args, **_kwargs: SimpleNamespace(
            fired=False, error="synthetic replay failure", cases=[]
        ),
    )

    manifest = dataset_suites.generate_dataset_suites(
        dataset_path=dataset_path, project_root=tmp_path
    )

    assert manifest["records"][0]["status"] == "replay_failed"
    assert not suite_dir.exists()
    assert not fixture_path.exists()
    assert not suite_path.exists()


def test_suite_json_persistence_failure_removes_current_fixture_generated_artifacts(
    tmp_path: Path, monkeypatch
) -> None:
    dataset_path, fixture_name = _single_record_dataset(tmp_path)
    suite_dir, fixture_path, suite_path = _stale_dataset_artifacts(tmp_path, fixture_name)
    original_replace = Path.replace

    def fail_suite_replace(path: Path, target: Path) -> Path:
        if target == suite_path:
            raise OSError("synthetic suite JSON replace failure")
        return original_replace(path, target)

    monkeypatch.setattr(Path, "replace", fail_suite_replace)
    monkeypatch.setattr(
        dataset_suites,
        "replay_suite",
        lambda *_args, **_kwargs: SimpleNamespace(fired=True),
    )

    with pytest.raises(OSError, match="synthetic suite JSON replace failure"):
        dataset_suites.generate_dataset_suites(
            dataset_path=dataset_path, project_root=tmp_path
        )

    assert not suite_dir.exists()
    assert not fixture_path.exists()
    assert not suite_path.exists()


def test_fixture_json_persistence_failure_removes_current_fixture_generated_artifacts(
    tmp_path: Path, monkeypatch
) -> None:
    dataset_path, fixture_name = _single_record_dataset(tmp_path)
    suite_dir, fixture_path, suite_path = _stale_dataset_artifacts(tmp_path, fixture_name)
    original_replace = Path.replace

    def fail_fixture_replace(path: Path, target: Path) -> Path:
        if target == fixture_path:
            raise OSError("synthetic fixture JSON replace failure")
        return original_replace(path, target)

    monkeypatch.setattr(Path, "replace", fail_fixture_replace)
    monkeypatch.setattr(
        dataset_suites,
        "replay_suite",
        lambda *_args, **_kwargs: SimpleNamespace(fired=True),
    )

    with pytest.raises(OSError, match="synthetic fixture JSON replace failure"):
        dataset_suites.generate_dataset_suites(
            dataset_path=dataset_path, project_root=tmp_path
        )

    assert not suite_dir.exists()
    assert not fixture_path.exists()
    assert not suite_path.exists()


def test_2049007_isolates_each_within_link_and_documents_nocase_evidence() -> None:
    recipe = recipes()[2049007]
    cases = {case.name: case for case in recipe.cases}
    unsupported = {entry.id: entry.reason for entry in recipe.unsupported}

    assert cases["N-body-first-separator-beyond-within"].predicate_id == "content-6-within"
    assert cases["N-body-second-separator-beyond-within"].predicate_id == "content-7-within"
    assert cases["P5-lowercase-csrf-header"].expected_alert
    assert cases["P6-uppercase-ipaddress-key"].expected_alert
    assert "P5-lowercase-csrf-header" in unsupported["content-3-nocase"]
    assert "P6-uppercase-ipaddress-key" in unsupported["content-4-nocase"]
    assert not {
        "content-6-within",
        "content-7-within",
    } & set(unsupported)
