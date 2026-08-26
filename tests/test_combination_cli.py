import json
import hashlib
from dataclasses import replace
from pathlib import Path

import pytest

import hardening_game.agents as agents
from hardening_game.agents import (
    ATTACKER_PROMPT_VERSION,
    ATTACKER_RULE_SANITIZER_VERSION,
    ATTACKER_RESPONSE_SCHEMA_VERSION,
)
from hardening_game.mutations import cli as single_mutation_cli
from hardening_game.mutations import combination_cli
from hardening_game.mutations.combination_manifest import (
    load_combination_manifest,
    manifest_hash,
)
from hardening_game.mutations.combiner import (
    generate_fixture_combinations,
    load_fixture_sources,
)
from hardening_game.mutations.evaluator import ManifestHashMismatch
from hardening_game.suricata.validate import (
    BenignReplayResult,
    ReplayResult,
    SyntaxResult,
)


PRIMARY = "et-2052951"
CONTROL = "et-2060086"
SOURCE_RUN = "runs/mutations/dataset-component-mutations-v2"
FAKE_PREDICTION = "CVE-2024-0002"

PRIMARY_BASELINE = (
    "alert tcp any any -> $HOME_NET 80 ( flow:established,to_server; http.uri; "
    'content:"/admin"; nocase; content:"token"; distance:0; sid:1000001; rev:1;)'
)
PRIMARY_BLOCKS = {
    f"{PRIMARY}-flow-remove-000000000001": (
        "flow",
        "remove",
        "alert tcp any any -> $HOME_NET 80 ( http.uri; "
        'content:"/admin"; nocase; content:"token"; distance:0; sid:1000001; rev:2;)',
    ),
    f"{PRIMARY}-content-shorten_suffix-000000000002": (
        "content",
        "shorten_suffix",
        "alert tcp any any -> $HOME_NET 80 ( flow:established,to_server; http.uri; "
        'content:"/adm"; nocase; content:"token"; distance:0; sid:1000001; rev:3;)',
    ),
    f"{PRIMARY}-content-literal_as_hex-000000000003": (
        "content",
        "literal_as_hex",
        "alert tcp any any -> $HOME_NET 80 ( flow:established,to_server; http.uri; "
        'content:"|2f 61 64 6d 69 6e|"; nocase; content:"token"; distance:0; '
        "sid:1000001; rev:4;)",
    ),
    f"{PRIMARY}-content_modifier-remove_nocase-000000000004": (
        "content_modifier",
        "remove_nocase",
        "alert tcp any any -> $HOME_NET 80 ( flow:established,to_server; http.uri; "
        'content:"/admin"; content:"token"; distance:0; sid:1000001; rev:5;)',
    ),
}

CONTROL_BASELINE = (
    "alert tcp any any -> $HOME_NET 8080 ( flow:established,to_server; "
    'content:"/beta"; sid:1000002; rev:1;)'
)
CONTROL_BLOCKS = {
    f"{CONTROL}-flow-remove-000000000005": (
        "flow",
        "remove",
        'alert tcp any any -> $HOME_NET 8080 ( content:"/beta"; sid:1000002; rev:2;)',
    ),
    f"{CONTROL}-content-shorten_suffix-000000000006": (
        "content",
        "shorten_suffix",
        "alert tcp any any -> $HOME_NET 8080 ( flow:established,to_server; "
        'content:"/bet"; sid:1000002; rev:3;)',
    ),
    f"{CONTROL}-content-literal_as_hex-000000000007": (
        "content",
        "literal_as_hex",
        "alert tcp any any -> $HOME_NET 8080 ( flow:established,to_server; "
        'content:"|2f 62 65 74 61|"; sid:1000002; rev:4;)',
    ),
    f"{CONTROL}-flow-remove_direction-000000000008": (
        "flow",
        "remove_direction",
        "alert tcp any any -> $HOME_NET 8080 ( flow:established; "
        'content:"/beta"; sid:1000002; rev:5;)',
    ),
}


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _source_results(
    fixture: str,
    baseline_rule: str,
    blocks: dict[str, tuple[str, str, str]],
    *,
    baseline_prediction: str | None = None,
    baseline_correct: bool = True,
) -> str:
    records = [
        {
            "candidate_id": f"{fixture}-baseline",
            "component": "baseline",
            "operator": "original",
            "description": "Original validated fixture rule.",
            "rule": baseline_rule,
            "revision": 1,
            "status": "evaluated",
            "attacker_prediction": baseline_prediction,
            "attacker_correct": baseline_correct,
        }
    ]
    records.extend(
        {
            "candidate_id": candidate_id,
            "component": component,
            "operator": operator,
            "description": f"{component}/{operator}",
            "rule": rule,
            "revision": 2,
            "status": "evaluated",
        }
        for candidate_id, (component, operator, rule) in blocks.items()
    )
    return "".join(json.dumps(record, sort_keys=True) + "\n" for record in records)


def _write_fixture(
    project_root: Path, fixture: str, *, sid: int, cve: str, rule: str
) -> None:
    _write_json(
        project_root / "fixtures" / "dataset" / f"{fixture}.json",
        {
            "name": fixture,
            "sid": sid,
            "revision": 1,
            "cve": cve,
            "pcap": f"pcap/{fixture}-positive.pcap",
            "rule": rule,
            "suite": f"fixtures/dataset/{fixture}_suite.json",
        },
    )
    _write_json(
        project_root / "fixtures" / "dataset" / f"{fixture}_suite.json",
        {
            "cases": [
                {
                    "name": "P0-canonical",
                    "pcap": f"pcap/{fixture}-positive.pcap",
                    "expected_alert": True,
                    "reason": "must fire",
                },
                {
                    "name": "N0-decoy",
                    "pcap": f"pcap/{fixture}-negative.pcap",
                    "expected_alert": False,
                    "reason": "must stay silent",
                },
            ]
        },
    )


def _project(
    tmp_path: Path,
    *,
    experiment_id: str = "combination-test",
    baseline_correct: bool = True,
) -> Path:
    project_root = tmp_path / "project"
    for fixture, baseline, blocks, cve in (
        (PRIMARY, PRIMARY_BASELINE, PRIMARY_BLOCKS, "CVE-2024-0001"),
        (CONTROL, CONTROL_BASELINE, CONTROL_BLOCKS, "CVE-2024-0003"),
    ):
        results = project_root / SOURCE_RUN / fixture / "results.jsonl"
        results.parent.mkdir(parents=True, exist_ok=True)
        results.write_text(
            _source_results(
                fixture,
                baseline,
                blocks,
                baseline_prediction=cve if baseline_correct else FAKE_PREDICTION,
                baseline_correct=baseline_correct,
            ),
            encoding="utf-8",
        )

    _write_fixture(
        project_root, PRIMARY, sid=1000001, cve="CVE-2024-0001", rule=PRIMARY_BASELINE
    )
    _write_fixture(
        project_root, CONTROL, sid=1000002, cve="CVE-2024-0003", rule=CONTROL_BASELINE
    )
    _write_json(
        project_root / "fixtures" / "related_cve_registry.json",
        {
            "version": 1,
            "entries": [
                {
                    "target_cve": "CVE-2024-0001",
                    "predicted_cve": FAKE_PREDICTION,
                    "tier": "closely_related",
                    "vendor": "example",
                    "product": "example",
                    "rationale": "same product family",
                    "provenance": "test",
                }
            ],
        },
    )
    _write_json(
        project_root / "experiments" / experiment_id / "manifest.json",
        {
            "version": 1,
            "experiment_id": experiment_id,
            "source_run": SOURCE_RUN,
            "primary_fixtures": [PRIMARY],
            "control_fixtures": [
                {"name": CONTROL, "role": "near_cve_confusion_control"}
            ],
            "selection": {
                "strategy": "hybrid_ranked_v1",
                "max_blocks": 8,
                "minimum_combination_size": 2,
                "selected_blocks_by_fixture": {
                    PRIMARY: list(PRIMARY_BLOCKS),
                    CONTROL: list(CONTROL_BLOCKS),
                },
            },
            "metrics": [
                "exact_cve",
                "effective_attribution",
                "positive_recall",
                "synthetic_precision",
                "benign_precision",
            ],
        },
    )
    return project_root


def _manifest_path(project_root: Path, experiment_id: str = "combination-test") -> Path:
    return project_root / "experiments" / experiment_id / "manifest.json"


def _combinations(project_root: Path, fixture: str):
    manifest = load_combination_manifest(
        _manifest_path(project_root), project_root=project_root
    )
    return generate_fixture_combinations(
        fixture, manifest=manifest, project_root=project_root
    )


def _fixture_sources(project_root: Path, fixture: str):
    manifest = load_combination_manifest(
        _manifest_path(project_root), project_root=project_root
    )
    return load_fixture_sources(
        fixture, manifest=manifest, project_root=project_root
    )


def _forbidden_client(**_kwargs: object):
    raise AssertionError("a live attacker client must not be constructed")


def _syntax_valid(_rule: str) -> SyntaxResult:
    return SyntaxResult(True, None)


def _replay_expected(rule: str, pcap_path: Path, *, expected_sid: int) -> ReplayResult:
    return ReplayResult(fired="positive" in pcap_path.name, error=None, alerts=[])


def _benign_silent(
    rule: str, pcap_path: Path, *, expected_sid: int
) -> BenignReplayResult:
    return BenignReplayResult(
        fired=False,
        total_alerts=0,
        relevant_flow_count=1,
        alerting_relevant_flow_count=0,
        alerts_per_relevant_flow=0.0,
        error=None,
    )


def _run(project_root: Path, tmp_path: Path, **overrides: object):
    options: dict[str, object] = dict(
        manifest_path=_manifest_path(project_root),
        attacker_model="fake-model",
        run_id="combination-test-run",
        project_root=project_root,
        output_root=tmp_path / "out",
        skip_benign=True,
        fake_attacker_prediction=FAKE_PREDICTION,
        syntax_check=_syntax_valid,
        replay=_replay_expected,
        benign_replay=_benign_silent,
        client_factory=_forbidden_client,
    )
    options.update(overrides)
    return combination_cli.run_combination_experiment(**options)


def _records(run_root: Path, fixture: str) -> list[dict[str, object]]:
    path = run_root / fixture / "results.jsonl"
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _metadata(run_root: Path) -> dict[str, object]:
    return json.loads((run_root / "run_metadata.json").read_text(encoding="utf-8"))


def _fixture_metadata(run_root: Path, fixture: str) -> dict[str, object]:
    entries = _metadata(run_root)["fixtures"]
    assert isinstance(entries, list)
    return next(entry for entry in entries if entry["fixture"] == fixture)


def test_parser_exposes_the_required_combination_arguments() -> None:
    parser = combination_cli.build_parser()

    destinations = {action.dest for action in parser._actions}
    defaults = parser.parse_args(
        ["--manifest", "manifest.json", "--attacker-model", "model-a"]
    )

    assert {
        "manifest",
        "attacker_model",
        "run_id",
        "benign_cache",
        "resume",
        "skip_benign",
        "fake_attacker_prediction",
    } <= destinations
    assert defaults.base_url is None


def test_full_run_persists_provenance_for_every_combination(tmp_path: Path) -> None:
    project_root = _project(tmp_path)
    expected_hash = manifest_hash(
        load_combination_manifest(
            _manifest_path(project_root), project_root=project_root
        )
    )

    summary = _run(project_root, tmp_path)

    run_root = tmp_path / "out" / "combination-test-run"
    assert summary.experiment_manifest_hash == expected_hash
    assert summary.run_root == run_root
    assert summary.run_complete is True
    metadata = _metadata(run_root)
    assert metadata["attacker_prompt_version"] == ATTACKER_PROMPT_VERSION
    assert (
        metadata["attacker_response_schema_version"]
        == ATTACKER_RESPONSE_SCHEMA_VERSION
    )
    assert (
        metadata["attacker_rule_sanitizer_version"]
        == ATTACKER_RULE_SANITIZER_VERSION
    )
    assert metadata["attacker_model"] == "fake-model"
    assert metadata["attacker_trial_count"] is None
    assert metadata["clue_registry_hash"] is None
    assert metadata["source_rule_content_hash"]
    assert metadata["related_cve_registry_hash"] == hashlib.sha256(
        (project_root / "fixtures" / "related_cve_registry.json").read_bytes()
    ).hexdigest()
    for fixture in (PRIMARY, CONTROL):
        generated = _combinations(project_root, fixture)
        records = _records(run_root, fixture)
        assert [record["candidate_id"] for record in records] == [
            candidate.id for candidate in generated.accepted
        ]
        by_id = {candidate.id: candidate for candidate in generated.accepted}
        for record in records:
            candidate = by_id[str(record["candidate_id"])]
            assert record["experiment_manifest_hash"] == expected_hash
            assert record["source_candidate_ids"] == list(
                candidate.source_candidate_ids
            )
            assert record["block_count"] == len(candidate.source_candidate_ids)
            assert record["status"] == "evaluated"
            assert record["positive_recall"] == 1.0


def test_source_rule_content_hash_is_canonical_across_input_order(
    tmp_path: Path,
) -> None:
    project_root = _project(tmp_path)
    primary = _fixture_sources(project_root, PRIMARY)
    control = _fixture_sources(project_root, CONTROL)
    reordered_primary = replace(primary, blocks=tuple(reversed(primary.blocks)))

    first = combination_cli.source_rule_content_hash(
        {PRIMARY: primary, CONTROL: control}
    )
    second = combination_cli.source_rule_content_hash(
        {CONTROL: control, PRIMARY: reordered_primary}
    )

    assert first == second
    assert len(first) == 64


def test_source_rule_content_hash_changes_when_same_id_rule_bytes_change(
    tmp_path: Path,
) -> None:
    project_root = _project(tmp_path)
    primary = _fixture_sources(project_root, PRIMARY)
    original = combination_cli.source_rule_content_hash({PRIMARY: primary})
    first_block = primary.blocks[0]
    changed_block = replace(first_block, rule=first_block.rule.replace("/admin", "/Admin"))
    changed_sources = replace(
        primary, blocks=(changed_block, *primary.blocks[1:])
    )

    changed = combination_cli.source_rule_content_hash(
        {PRIMARY: changed_sources}
    )

    assert changed != original
    assert changed_block.candidate_id == first_block.candidate_id


def test_source_rule_content_hash_includes_required_baseline_context(
    tmp_path: Path,
) -> None:
    project_root = _project(tmp_path)
    primary = _fixture_sources(project_root, PRIMARY)
    original = combination_cli.source_rule_content_hash({PRIMARY: primary})
    changed_sources = replace(
        primary, baseline_attacker_prediction="CVE-2099-9999"
    )

    assert (
        combination_cli.source_rule_content_hash({PRIMARY: changed_sources})
        != original
    )


def test_combination_resume_rejects_changed_rule_bytes_for_same_source_id(
    tmp_path: Path,
) -> None:
    project_root = _project(tmp_path)
    _run(project_root, tmp_path, fixtures=[PRIMARY], limit=1)
    run_root = tmp_path / "out" / "combination-test-run"
    manifest = load_combination_manifest(
        _manifest_path(project_root), project_root=project_root
    )
    changed_id = manifest.selected_blocks(PRIMARY)[0]
    source_path = project_root / SOURCE_RUN / PRIMARY / "results.jsonl"
    records = [
        json.loads(line)
        for line in source_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    changed = next(record for record in records if record["candidate_id"] == changed_id)
    changed["rule"] += " "
    source_path.write_text(
        "".join(json.dumps(record, sort_keys=True) + "\n" for record in records),
        encoding="utf-8",
    )
    before = _tree_bytes(run_root)

    with pytest.raises(ValueError, match="source_rule_content_hash"):
        _run(project_root, tmp_path, resume=True)

    assert _tree_bytes(run_root) == before


def test_control_fixture_is_labeled_separately_from_primaries(tmp_path: Path) -> None:
    project_root = _project(tmp_path)

    _run(project_root, tmp_path)

    run_root = tmp_path / "out" / "combination-test-run"
    primary = _fixture_metadata(run_root, PRIMARY)
    control = _fixture_metadata(run_root, CONTROL)
    assert primary["role"] == "primary"
    assert primary["control"] is False
    assert control["role"] == "near_cve_confusion_control"
    assert control["control"] is True

    report = json.loads(
        (run_root / "combination_summary.json").read_text(encoding="utf-8")
    )
    assert report["experiment_manifest_hash"] == _metadata(run_root)[
        "experiment_manifest_hash"
    ]
    assert report["primary"]["fixtures"] == 1
    assert report["control"]["fixtures"] == 1
    assert report["primary"]["persisted_results"] == len(_records(run_root, PRIMARY))
    assert report["control"]["persisted_results"] == len(_records(run_root, CONTROL))
    assert "Control fixtures" in (run_root / "combination_summary.md").read_text(
        encoding="utf-8"
    )


def test_combination_summary_reports_the_locked_precision_metrics(
    tmp_path: Path,
) -> None:
    project_root = _project(tmp_path)

    _run(project_root, tmp_path)

    run_root = tmp_path / "out" / "combination-test-run"
    report = json.loads(
        (run_root / "combination_summary.json").read_text(encoding="utf-8")
    )
    records = _records(run_root, PRIMARY)
    synthetic = report["primary"]["synthetic_precision"]
    assert synthetic == {
        "denominator": (
            "persisted_records_with_a_measured_negative_false_positive_rate"
        ),
        "measured_record_count": len(records),
        "unmeasured_record_count": 0,
        "mean_false_positive_rate": 0.0,
        "zero_false_positive_count": len(records),
        "zero_false_positive_rate": 1.0,
    }
    benign = report["primary"]["benign_precision"]
    assert benign == {
        "denominator": (
            "persisted_records_with_a_measured_benign_false_positive_rate"
        ),
        "measured_record_count": 0,
        "unmeasured_record_count": len(records),
        "mean_false_positive_rate": None,
        "zero_false_positive_count": 0,
        "zero_false_positive_rate": None,
    }

    markdown = (run_root / "combination_summary.md").read_text(encoding="utf-8")
    assert (
        "- Synthetic precision: measured="
        f"{len(records)} (denominator: "
        "persisted_records_with_a_measured_negative_false_positive_rate)" in markdown
    )
    assert "- Benign precision: measured=0" in markdown
    assert "mean false-positive rate=n/a" in markdown


def test_combination_summary_reports_source_categories_and_mix_groups(
    tmp_path: Path,
) -> None:
    project_root = _project(tmp_path)

    _run(project_root, tmp_path)

    run_root = tmp_path / "out" / "combination-test-run"
    report = json.loads(
        (run_root / "combination_summary.json").read_text(encoding="utf-8")
    )
    records = _records(run_root, PRIMARY)
    mix = report["primary"]["combination_mix"]
    assert mix["combination_record_count"] == len(records)
    assert mix["single_mutation_record_count"] == 0
    assert mix["records_without_source_categories"] == 0
    assert mix["total_source_category_block_count"] == sum(
        int(record["block_count"]) for record in records
    )
    assert set(mix["source_category_blocks"]) == {
        "semantic",
        "representation",
        "performance",
    }
    assert mix["mix_groups"]
    for key, group in mix["mix_groups"].items():
        assert set(key.split("+")) <= {"semantic", "representation", "performance"}
        assert group["record_count"] >= 1
        assert group["evaluated"] == group["record_count"]
        assert "synthetic_precision" in group
    assert sum(
        group["record_count"] for group in mix["mix_groups"].values()
    ) == len(records)

    markdown = (run_root / "combination_summary.md").read_text(encoding="utf-8")
    assert f"- Combination records: {len(records)}" in markdown
    assert "- `semantic` blocks:" in markdown


def test_combination_summary_surfaces_a_torn_result_line(tmp_path: Path) -> None:
    project_root = _project(tmp_path)
    _run(project_root, tmp_path)
    run_root = tmp_path / "out" / "combination-test-run"
    expected = len(_records(run_root, PRIMARY))
    with (run_root / PRIMARY / "results.jsonl").open("a", encoding="utf-8") as handle:
        handle.write('{"candidate_id": "torn-candidate", "component":')

    summary = _run(project_root, tmp_path, resume=True)

    report = json.loads(
        (run_root / "combination_summary.json").read_text(encoding="utf-8")
    )
    quality = report["data_quality"]
    assert quality["malformed_line_count"] == 1
    assert quality["files_with_malformed_lines"] == 1
    assert quality["results_files_read"] == 2
    assert quality["malformed_lines"][0]["file"] == f"{PRIMARY}/results.jsonl"
    assert quality["malformed_lines"][0]["line"] == expected + 1
    assert report["primary"]["persisted_results"] == expected
    assert summary.run_complete is True

    markdown = (run_root / "combination_summary.md").read_text(encoding="utf-8")
    assert "## Data quality" in markdown
    assert f"`{PRIMARY}/results.jsonl:{expected + 1}`" in markdown


def test_conflict_rejections_stay_separate_and_are_never_evaluated(
    tmp_path: Path,
) -> None:
    project_root = _project(tmp_path)

    _run(project_root, tmp_path)

    run_root = tmp_path / "out" / "combination-test-run"
    generated = _combinations(project_root, PRIMARY)
    assert generated.rejected, "the fixture must exercise at least one conflict"
    rejections = [
        json.loads(line)
        for line in (run_root / PRIMARY / "rejections.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    rejected_ids = {rejection.id for rejection in generated.rejected}
    assert {record["id"] for record in rejections} == rejected_ids
    assert all(record["reason"] for record in rejections)
    expected_hash = _metadata(run_root)["experiment_manifest_hash"]
    assert all(
        record["experiment_manifest_hash"] == expected_hash for record in rejections
    )
    persisted_ids = {record["candidate_id"] for record in _records(run_root, PRIMARY)}
    assert persisted_ids.isdisjoint(rejected_ids)
    assert _fixture_metadata(run_root, PRIMARY)["conflict_rejections"] == len(
        rejected_ids
    )


def test_attacker_runs_only_after_syntax_and_full_positive_recall(
    tmp_path: Path,
) -> None:
    project_root = _project(tmp_path)
    accepted = _combinations(project_root, PRIMARY).accepted
    invalid_rule = accepted[0].rule
    missing_recall_rule = accepted[1].rule

    def syntax_check(rule: str) -> SyntaxResult:
        if rule == invalid_rule:
            return SyntaxResult(False, "simulated parse failure")
        return SyntaxResult(True, None)

    def replay(rule: str, pcap_path: Path, *, expected_sid: int) -> ReplayResult:
        if rule == missing_recall_rule and "positive" in pcap_path.name:
            return ReplayResult(fired=False, error=None, alerts=[])
        return _replay_expected(rule, pcap_path, expected_sid=expected_sid)

    _run(
        project_root,
        tmp_path,
        syntax_check=syntax_check,
        replay=replay,
        fixtures=[PRIMARY],
    )

    run_root = tmp_path / "out" / "combination-test-run"
    by_id = {
        str(record["candidate_id"]): record for record in _records(run_root, PRIMARY)
    }
    gated = [by_id[accepted[0].id], by_id[accepted[1].id]]
    assert gated[0]["status"] == "syntax_invalid"
    assert gated[1]["status"] == "positive_recall_failed"
    assert all(record["attacker_prediction"] is None for record in gated)
    assert all(record["case_results"] == {} for record in gated[:1])
    attacked = [
        record
        for record in by_id.values()
        if record["attacker_prediction"] == FAKE_PREDICTION
    ]
    assert len(attacked) == len(accepted) - 2
    assert all(record["positive_recall"] == 1.0 for record in attacked)


def test_fake_attacker_prediction_never_constructs_a_live_client(
    tmp_path: Path,
) -> None:
    project_root = _project(tmp_path)

    _run(project_root, tmp_path, client_factory=_forbidden_client)

    run_root = tmp_path / "out" / "combination-test-run"
    record = _records(run_root, PRIMARY)[0]
    assert record["attacker_prediction"] == FAKE_PREDICTION
    assert record["attacker_exchange"] is None
    assert _metadata(run_root)["attacker_mode"] == "fake"


def test_live_mode_builds_no_client_when_no_candidate_reaches_the_attacker(
    tmp_path: Path,
) -> None:
    project_root = _project(tmp_path)

    _run(
        project_root,
        tmp_path,
        fixtures=[PRIMARY],
        fake_attacker_prediction=None,
        api_key="test-key",
        syntax_check=lambda rule: SyntaxResult(
            rule == PRIMARY_BASELINE, None if rule == PRIMARY_BASELINE else "simulated"
        ),
        client_factory=_forbidden_client,
    )

    run_root = tmp_path / "out" / "combination-test-run"
    records = _records(run_root, PRIMARY)
    assert records
    assert all(record["status"] == "syntax_invalid" for record in records)
    assert all(record["attacker_prediction"] is None for record in records)
    assert _metadata(run_root)["attacker_mode"] == "live"


def test_combination_live_attacker_receives_only_sanitized_rule(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project_root = _project(tmp_path)
    prompts: list[str] = []
    sanitizer_calls: list[str] = []
    real_sanitizer = agents.sanitize_attacker_rule

    def counting_sanitizer(rule: str) -> str:
        sanitizer_calls.append(rule)
        return real_sanitizer(rule)

    monkeypatch.setattr(agents, "sanitize_attacker_rule", counting_sanitizer)

    class RecordingClient:
        def complete(self, *, model: str, prompt: str) -> str:
            prompts.append(prompt)
            return json.dumps(
                {
                    "predicted_cve": FAKE_PREDICTION,
                    "reasoning": "The remaining detection predicates are distinctive.",
                    "clues": [
                        {
                            "description": "URI buffer",
                            "rule_evidence": ["http.uri;"],
                        }
                    ],
                }
            )

    _run(
        project_root,
        tmp_path,
        fixtures=[PRIMARY],
        limit=1,
        fake_attacker_prediction=None,
        api_key="test-key",
        client_factory=lambda **_kwargs: RecordingClient(),
    )

    assert len(prompts) == 1
    assert len(sanitizer_calls) == 1
    assert 'content:"' in prompts[0]
    assert "sid:1000001;" not in prompts[0]
    assert "rev:" not in prompts[0]
    record = _records(tmp_path / "out" / "combination-test-run", PRIMARY)[0]
    assert record["attacker_exchange"]["parsed_response"] == {
        "predicted_cve": FAKE_PREDICTION,
        "reasoning": "The remaining detection predicates are distinctive.",
        "clues": [
            {
                "description": "URI buffer",
                "rule_evidence": ["http.uri;"],
            }
        ],
    }


def test_live_mode_without_an_api_key_is_refused(tmp_path: Path) -> None:
    project_root = _project(tmp_path)

    with pytest.raises(ValueError, match="API key"):
        _run(project_root, tmp_path, fake_attacker_prediction=None)


def test_related_cve_registry_is_reused_for_attribution(tmp_path: Path) -> None:
    project_root = _project(tmp_path)

    _run(project_root, tmp_path)

    run_root = tmp_path / "out" / "combination-test-run"
    record = _records(run_root, PRIMARY)[0]
    assert record["target_cve"] == "CVE-2024-0001"
    assert record["relationship_tier"] == "closely_related"
    assert record["mutation_category"] in {"semantic", "representation", "performance"}


def test_benign_context_is_loaded_with_the_shared_single_mutation_helper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project_root = _project(tmp_path)
    calls: list[tuple[str, Path, Path | None]] = []

    def fake_context(fixture_name, *, project_root, benign_cache):
        calls.append((fixture_name, project_root, benign_cache))
        return ((), 0, ())

    assert combination_cli.load_benign_context is single_mutation_cli.load_benign_context
    monkeypatch.setattr(combination_cli, "load_benign_context", fake_context)

    _run(
        project_root,
        tmp_path,
        skip_benign=False,
        benign_cache=project_root / "online_benign_pcaps",
    )

    assert [call[0] for call in calls] == [PRIMARY, CONTROL]
    assert calls[0][1] == project_root
    assert calls[0][2] == project_root / "online_benign_pcaps"


def test_limited_run_does_not_mark_unrun_candidates_complete(tmp_path: Path) -> None:
    project_root = _project(tmp_path)

    summary = _run(project_root, tmp_path, fixtures=[PRIMARY], limit=1)

    run_root = tmp_path / "out" / "combination-test-run"
    generated = _combinations(project_root, PRIMARY)
    assert summary.evaluated_records == 1
    assert len(_records(run_root, PRIMARY)) == 1
    assert _records(run_root, CONTROL) == []

    metadata = _metadata(run_root)
    assert metadata["selection_limited"] is True
    assert metadata["run_complete"] is False
    assert summary.run_complete is False
    primary = _fixture_metadata(run_root, PRIMARY)
    assert primary["generated_candidates"] == len(generated.accepted)
    assert primary["persisted_results"] == 1
    assert primary["pending_candidates"] == len(generated.accepted) - 1
    assert primary["complete"] is False
    control = _fixture_metadata(run_root, CONTROL)
    assert control["selected"] is False
    assert control["persisted_results"] == 0
    assert control["complete"] is False


def test_block_count_filter_evaluates_only_that_combination_width(
    tmp_path: Path,
) -> None:
    project_root = _project(tmp_path)
    generated = _combinations(project_root, PRIMARY)
    widest = max(candidate.block_count for candidate in generated.accepted)
    expected = [
        candidate.id
        for candidate in generated.accepted
        if candidate.block_count == widest
    ]

    summary = _run(project_root, tmp_path, fixtures=[PRIMARY], block_counts=[widest])

    run_root = tmp_path / "out" / "combination-test-run"
    records = _records(run_root, PRIMARY)
    assert [record["candidate_id"] for record in records] == expected
    assert all(record["block_count"] == widest for record in records)
    assert summary.evaluated_records == len(expected)

    metadata = _metadata(run_root)
    assert metadata["selection_limited"] is True
    assert metadata["block_counts"] == [widest]
    assert metadata["run_complete"] is False
    primary = _fixture_metadata(run_root, PRIMARY)
    assert primary["generated_candidates"] == len(generated.accepted)
    assert primary["pending_candidates"] == len(generated.accepted) - len(expected)
    assert primary["complete"] is False


def test_block_count_filter_below_the_minimum_combination_size_is_refused(
    tmp_path: Path,
) -> None:
    project_root = _project(tmp_path)

    with pytest.raises(ValueError, match="block count"):
        _run(project_root, tmp_path, block_counts=[1])


def test_resume_after_a_limited_run_evaluates_only_the_remaining_candidates(
    tmp_path: Path,
) -> None:
    project_root = _project(tmp_path)
    _run(project_root, tmp_path, fixtures=[PRIMARY], limit=1)
    run_root = tmp_path / "out" / "combination-test-run"
    first = [record["candidate_id"] for record in _records(run_root, PRIMARY)]

    summary = _run(project_root, tmp_path, resume=True)

    generated = _combinations(project_root, PRIMARY)
    control_generated = _combinations(project_root, CONTROL)
    persisted = [record["candidate_id"] for record in _records(run_root, PRIMARY)]
    assert persisted[:1] == first
    assert sorted(persisted) == sorted(
        candidate.id for candidate in generated.accepted
    )
    assert summary.evaluated_records == (
        len(generated.accepted) - 1 + len(control_generated.accepted)
    )
    assert _metadata(run_root)["run_complete"] is True
    assert _fixture_metadata(run_root, PRIMARY)["complete"] is True
    assert _fixture_metadata(run_root, PRIMARY)["pending_candidates"] == 0


def test_a_candidate_whose_attacker_step_failed_is_pending_and_retried(
    tmp_path: Path,
) -> None:
    project_root = _project(tmp_path)

    _run(
        project_root,
        tmp_path,
        fixtures=[PRIMARY],
        limit=1,
        fake_attacker_prediction="",
    )

    run_root = tmp_path / "out" / "combination-test-run"
    generated = _combinations(project_root, PRIMARY)
    failed = _records(run_root, PRIMARY)
    assert [record["status"] for record in failed] == ["attacker_empty_prediction"]
    primary = _fixture_metadata(run_root, PRIMARY)
    assert primary["persisted_results"] == 1
    assert primary["pending_candidates"] == len(generated.accepted)
    assert primary["complete"] is False

    summary = _run(project_root, tmp_path, resume=True)

    persisted = _records(run_root, PRIMARY)
    retried = [
        record
        for record in persisted
        if record["candidate_id"] == failed[0]["candidate_id"]
    ]
    assert [record["status"] for record in retried] == [
        "attacker_empty_prediction",
        "evaluated",
    ]
    assert summary.run_complete is True
    assert _fixture_metadata(run_root, PRIMARY)["persisted_results"] == len(
        generated.accepted
    )
    assert _fixture_metadata(run_root, PRIMARY)["pending_candidates"] == 0


def test_stale_fixture_results_are_refused_before_any_fixture_is_evaluated(
    tmp_path: Path,
) -> None:
    project_root = _project(tmp_path)
    run_root = tmp_path / "out" / "combination-test-run"
    stale = run_root / CONTROL / "results.jsonl"
    stale.parent.mkdir(parents=True)
    stale.write_text(
        json.dumps(
            {
                "candidate_id": f"{CONTROL}-combination-2-stale",
                "experiment_manifest_hash": "0" * 64,
                "status": "evaluated",
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="missing run metadata"):
        _run(project_root, tmp_path)

    assert not (run_root / PRIMARY / "results.jsonl").exists()
    assert not (run_root / PRIMARY / "rejections.jsonl").exists()


def test_resume_refuses_a_run_directory_from_a_different_manifest(
    tmp_path: Path,
) -> None:
    project_root = _project(tmp_path)
    _run(project_root, tmp_path, fixtures=[PRIMARY], limit=1)
    run_root = tmp_path / "out" / "combination-test-run"
    metadata = _metadata(run_root)
    metadata["experiment_manifest_hash"] = "0" * 64
    (run_root / "run_metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    before = (run_root / PRIMARY / "results.jsonl").read_text(encoding="utf-8")

    with pytest.raises(ManifestHashMismatch):
        _run(project_root, tmp_path, resume=True)

    assert (run_root / PRIMARY / "results.jsonl").read_text(encoding="utf-8") == before


def test_resume_refuses_metadata_from_old_attacker_rule_contract(
    tmp_path: Path,
) -> None:
    project_root = _project(tmp_path)
    _run(project_root, tmp_path, fixtures=[PRIMARY], limit=1)
    run_root = tmp_path / "out" / "combination-test-run"
    metadata = _metadata(run_root)
    metadata["attacker_prompt_version"] = "ranked-clues-v1"
    metadata["attacker_response_schema_version"] = 2
    metadata.pop("attacker_rule_sanitizer_version")
    (run_root / "run_metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    before = _tree_bytes(run_root)

    with pytest.raises(ValueError, match="attacker metadata mismatch"):
        _run(project_root, tmp_path, resume=True)

    assert _tree_bytes(run_root) == before


@pytest.mark.parametrize(
    ("field", "incompatible"),
    [
        ("attacker_model", "other-model"),
        ("attacker_prompt_version", "other-prompt"),
        ("attacker_response_schema_version", 999),
        ("attacker_rule_sanitizer_version", "other-sanitizer"),
        ("attacker_trial_count", 3),
        ("related_cve_registry_hash", "0" * 64),
        ("clue_registry_hash", "0" * 64),
        ("source_rule_content_hash", "0" * 64),
    ],
)
def test_combination_resume_refuses_every_incompatible_attacker_metadata_field(
    tmp_path: Path, field: str, incompatible: object
) -> None:
    project_root = _project(tmp_path)
    _run(project_root, tmp_path, fixtures=[PRIMARY], limit=1)
    run_root = tmp_path / "out" / "combination-test-run"
    metadata = _metadata(run_root)
    metadata[field] = incompatible
    (run_root / "run_metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    before = _tree_bytes(run_root)

    with pytest.raises(ValueError, match=field):
        _run(
            project_root,
            tmp_path,
            resume=True,
            syntax_check=lambda _rule: (_ for _ in ()).throw(
                AssertionError("metadata mismatch must precede evaluation")
            ),
        )

    assert _tree_bytes(run_root) == before


def test_combination_metadata_contract_exists_before_first_evaluation_write(
    tmp_path: Path,
) -> None:
    project_root = _project(tmp_path)
    run_root = tmp_path / "out" / "combination-test-run"
    observed: list[dict[str, object]] = []

    def syntax_check(_rule: str) -> SyntaxResult:
        observed.append(_metadata(run_root))
        assert not (run_root / PRIMARY / "results.jsonl").exists()
        return SyntaxResult(True, None)

    _run(
        project_root,
        tmp_path,
        fixtures=[PRIMARY],
        limit=1,
        syntax_check=syntax_check,
    )

    assert observed
    assert observed[0]["attacker_model"] == "fake-model"
    assert observed[0]["experiment_manifest_hash"]


def _tree_bytes(root: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(root)): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def test_combination_resume_refuses_populated_run_with_missing_metadata(
    tmp_path: Path,
) -> None:
    project_root = _project(tmp_path)
    _run(project_root, tmp_path, fixtures=[PRIMARY], limit=1)
    run_root = tmp_path / "out" / "combination-test-run"
    metadata_path = run_root / "run_metadata.json"
    metadata_path.unlink()
    before = _tree_bytes(run_root)

    with pytest.raises(ValueError, match="missing run metadata"):
        _run(project_root, tmp_path, resume=True)

    assert _tree_bytes(run_root) == before
    assert not metadata_path.exists()


def test_combination_resume_creates_metadata_in_genuinely_empty_directory(
    tmp_path: Path,
) -> None:
    project_root = _project(tmp_path)
    run_root = tmp_path / "out" / "combination-test-run"
    run_root.mkdir(parents=True)

    _run(project_root, tmp_path, fixtures=[PRIMARY], limit=1, resume=True)

    assert _metadata(run_root)["source_rule_content_hash"]


def test_a_populated_run_directory_without_resume_is_refused_before_any_work(
    tmp_path: Path,
) -> None:
    project_root = _project(tmp_path)
    _run(project_root, tmp_path, fixtures=[PRIMARY], limit=1)
    run_root = tmp_path / "out" / "combination-test-run"
    before = _tree_bytes(run_root)
    syntax_calls: list[str] = []
    replay_calls: list[str] = []

    def counting_syntax(rule: str) -> SyntaxResult:
        syntax_calls.append(rule)
        return _syntax_valid(rule)

    def counting_replay(rule: str, pcap_path: Path, *, expected_sid: int):
        replay_calls.append(rule)
        return _replay_expected(rule, pcap_path, expected_sid=expected_sid)

    with pytest.raises(combination_cli.PopulatedRunDirectory, match="--resume"):
        _run(
            project_root,
            tmp_path,
            syntax_check=counting_syntax,
            replay=counting_replay,
            fake_attacker_prediction=None,
            api_key="test-key",
            client_factory=_forbidden_client,
        )

    assert syntax_calls == []
    assert replay_calls == []
    assert _tree_bytes(run_root) == before


def test_locked_source_baseline_context_is_persisted_immutably(tmp_path: Path) -> None:
    project_root = _project(tmp_path)
    expected_hash = manifest_hash(
        load_combination_manifest(
            _manifest_path(project_root), project_root=project_root
        )
    )

    _run(project_root, tmp_path, fixtures=[PRIMARY], limit=1)

    run_root = tmp_path / "out" / "combination-test-run"
    path = run_root / PRIMARY / "baseline_context.json"
    context = json.loads(path.read_text(encoding="utf-8"))
    assert context == {
        "baseline_attacker_correct": True,
        "baseline_attacker_prediction": "CVE-2024-0001",
        "baseline_candidate_id": f"{PRIMARY}-baseline",
        "baseline_exact": True,
        "experiment_manifest_hash": expected_hash,
        "fixture": PRIMARY,
        "source_run": SOURCE_RUN,
        "target_cve": "CVE-2024-0001",
    }
    assert _fixture_metadata(run_root, PRIMARY)["baseline_exact"] is True

    before = path.read_bytes()
    _run(project_root, tmp_path, resume=True)
    assert path.read_bytes() == before


def test_a_source_baseline_the_attacker_missed_is_recorded_as_not_exact(
    tmp_path: Path,
) -> None:
    project_root = _project(tmp_path, baseline_correct=False)

    _run(project_root, tmp_path, fixtures=[PRIMARY], limit=1)

    run_root = tmp_path / "out" / "combination-test-run"
    context = json.loads(
        (run_root / PRIMARY / "baseline_context.json").read_text(encoding="utf-8")
    )
    assert context["baseline_attacker_correct"] is False
    assert context["baseline_exact"] is False
    assert _fixture_metadata(run_root, PRIMARY)["baseline_exact"] is False


def test_combination_records_carry_the_three_category_taxonomy(tmp_path: Path) -> None:
    project_root = _project(tmp_path)

    _run(project_root, tmp_path, fixtures=[PRIMARY])

    run_root = tmp_path / "out" / "combination-test-run"
    records = _records(run_root, PRIMARY)
    assert records
    categories = {str(record["mutation_category"]) for record in records}
    assert categories <= {"semantic", "representation", "performance"}
    assert "combination" not in categories
    mixed = [
        record
        for record in records
        if "representation" in record["params"]["source_categories"]
        and len(set(record["params"]["source_categories"])) > 1
    ]
    assert mixed, "the fixture must exercise at least one mixed-category combination"
    assert all(record["mutation_category"] == "semantic" for record in mixed)
    assert all(
        len(record["params"]["source_categories"]) == record["block_count"]
        for record in records
    )


def test_block_count_outside_a_selected_fixtures_range_is_refused(
    tmp_path: Path,
) -> None:
    project_root = _project(tmp_path)
    run_root = tmp_path / "out" / "combination-test-run"

    with pytest.raises(ValueError, match=f"{CONTROL} has no combinations"):
        _run(project_root, tmp_path, fixtures=[CONTROL], block_counts=[5])

    assert not run_root.exists()


def _tamper_baseline_context(
    run_root: Path, fixture_name: str, **changes: object
) -> Path:
    path = run_root / fixture_name / "baseline_context.json"
    context = json.loads(path.read_text(encoding="utf-8"))
    context.update(changes)
    path.write_text(json.dumps(context, indent=2, sort_keys=True) + "\n", "utf-8")
    return path


def _resume_refuses(
    project_root: Path, tmp_path: Path, error: type[BaseException], match: str
) -> None:
    """Assert a resumed run is refused with zero calls and a byte-identical tree."""
    run_root = tmp_path / "out" / "combination-test-run"
    before = _tree_bytes(run_root)
    syntax_calls: list[str] = []
    replay_calls: list[str] = []

    def counting_syntax(rule: str) -> SyntaxResult:
        syntax_calls.append(rule)
        return _syntax_valid(rule)

    def counting_replay(rule: str, pcap_path: Path, *, expected_sid: int):
        replay_calls.append(rule)
        return _replay_expected(rule, pcap_path, expected_sid=expected_sid)

    with pytest.raises(error, match=match):
        _run(
            project_root,
            tmp_path,
            resume=True,
            syntax_check=counting_syntax,
            replay=counting_replay,
            fake_attacker_prediction=None,
            api_key="test-key",
            client_factory=_forbidden_client,
        )

    assert syntax_calls == []
    assert replay_calls == []
    assert _tree_bytes(run_root) == before


def test_a_tampered_baseline_context_hash_is_refused_before_any_work(
    tmp_path: Path,
) -> None:
    project_root = _project(tmp_path)
    _run(project_root, tmp_path, fixtures=[PRIMARY], limit=1)
    run_root = tmp_path / "out" / "combination-test-run"
    _tamper_baseline_context(run_root, PRIMARY, experiment_manifest_hash="0" * 64)

    _resume_refuses(project_root, tmp_path, ManifestHashMismatch, "0{64}")


def test_a_baseline_context_naming_another_fixture_is_refused(tmp_path: Path) -> None:
    project_root = _project(tmp_path)
    _run(project_root, tmp_path, fixtures=[PRIMARY], limit=1)
    run_root = tmp_path / "out" / "combination-test-run"
    _tamper_baseline_context(
        run_root,
        PRIMARY,
        fixture=CONTROL,
        baseline_candidate_id=f"{CONTROL}-baseline",
    )

    _resume_refuses(project_root, tmp_path, ValueError, "fixture")


def test_a_baseline_context_target_cve_mismatch_is_refused(tmp_path: Path) -> None:
    project_root = _project(tmp_path)
    _run(project_root, tmp_path, fixtures=[PRIMARY], limit=1)
    run_root = tmp_path / "out" / "combination-test-run"
    _tamper_baseline_context(run_root, PRIMARY, target_cve="CVE-2099-9999")

    _resume_refuses(project_root, tmp_path, ValueError, "target CVE")


def test_a_baseline_context_source_run_mismatch_is_refused(tmp_path: Path) -> None:
    project_root = _project(tmp_path)
    _run(project_root, tmp_path, fixtures=[PRIMARY], limit=1)
    run_root = tmp_path / "out" / "combination-test-run"
    _tamper_baseline_context(run_root, PRIMARY, source_run="runs/mutations/other-run")

    _resume_refuses(project_root, tmp_path, ValueError, "source run")


@pytest.mark.parametrize("value", ["true", 1, None])
def test_a_non_boolean_baseline_exact_is_refused(tmp_path: Path, value) -> None:
    project_root = _project(tmp_path)
    _run(project_root, tmp_path, fixtures=[PRIMARY], limit=1)
    run_root = tmp_path / "out" / "combination-test-run"
    _tamper_baseline_context(run_root, PRIMARY, baseline_exact=value)

    _resume_refuses(project_root, tmp_path, ValueError, "baseline_exact")


def test_a_corrupt_baseline_context_is_refused_with_a_clear_error(
    tmp_path: Path,
) -> None:
    project_root = _project(tmp_path)
    _run(project_root, tmp_path, fixtures=[PRIMARY], limit=1)
    run_root = tmp_path / "out" / "combination-test-run"
    (run_root / PRIMARY / "baseline_context.json").write_text("{not json", "utf-8")

    _resume_refuses(
        project_root, tmp_path, ValueError, "baseline_context.json is not valid JSON"
    )


def test_an_impossible_width_for_a_later_fixture_stops_the_earlier_one(
    tmp_path: Path,
) -> None:
    project_root = _project(tmp_path)
    primary_widths = {
        candidate.block_count for candidate in _combinations(project_root, PRIMARY).accepted
    }
    control_widths = {
        candidate.block_count for candidate in _combinations(project_root, CONTROL).accepted
    }
    assert 3 in primary_widths, "the earlier fixture must be able to run this width"
    assert 3 not in control_widths, "conflicts must block this width for the control"
    run_root = tmp_path / "out" / "combination-test-run"

    with pytest.raises(ValueError, match="generated no combinations"):
        _run(project_root, tmp_path, block_counts=[3])

    assert not (run_root / PRIMARY).exists()
    assert not (run_root / CONTROL).exists()


def test_a_block_count_that_generated_no_combination_is_refused(
    tmp_path: Path,
) -> None:
    project_root = _project(tmp_path)
    generated = _combinations(project_root, PRIMARY)
    widths = {candidate.block_count for candidate in generated.accepted}
    assert 4 not in widths, "conflicts must leave the widest width unreachable"
    run_root = tmp_path / "out" / "combination-test-run"

    with pytest.raises(ValueError, match="generated no combinations"):
        _run(project_root, tmp_path, fixtures=[PRIMARY], block_counts=[4])

    assert not (run_root / PRIMARY / "results.jsonl").exists()
    assert not (run_root / PRIMARY / "rejections.jsonl").exists()


def test_baseline_validation_precedes_persisting_rejections_and_summaries(
    tmp_path: Path,
) -> None:
    project_root = _project(tmp_path)

    def replay(rule: str, pcap_path: Path, *, expected_sid: int) -> ReplayResult:
        if rule == PRIMARY_BASELINE:
            return ReplayResult(fired=False, error=None, alerts=[])
        return _replay_expected(rule, pcap_path, expected_sid=expected_sid)

    with pytest.raises(RuntimeError, match="baseline replay validation failed"):
        _run(project_root, tmp_path, fixtures=[PRIMARY], replay=replay)

    fixture_dir = tmp_path / "out" / "combination-test-run" / PRIMARY
    assert not (fixture_dir / "rejections.jsonl").exists()
    assert not (fixture_dir / "summary.json").exists()
    assert not (fixture_dir / "results.jsonl").exists()


def test_corrupt_run_metadata_is_refused_with_a_clear_error(tmp_path: Path) -> None:
    project_root = _project(tmp_path)
    run_root = tmp_path / "out" / "combination-test-run"
    run_root.mkdir(parents=True)
    (run_root / "run_metadata.json").write_text("{not json", encoding="utf-8")

    with pytest.raises(ValueError, match="run_metadata.json is not valid JSON"):
        _run(project_root, tmp_path)


def test_an_unexpected_fixture_directory_in_the_run_tree_is_refused(
    tmp_path: Path,
) -> None:
    project_root = _project(tmp_path)
    run_root = tmp_path / "out" / "combination-test-run"
    intruder = run_root / "et-9999999" / "results.jsonl"
    intruder.parent.mkdir(parents=True)
    intruder.write_text("", encoding="utf-8")

    with pytest.raises(ValueError, match="missing run metadata"):
        _run(project_root, tmp_path)

    assert not (run_root / PRIMARY).exists()


def test_stale_rejection_artifacts_are_refused_before_any_fixture_is_evaluated(
    tmp_path: Path,
) -> None:
    project_root = _project(tmp_path)
    run_root = tmp_path / "out" / "combination-test-run"
    stale = run_root / CONTROL / "rejections.jsonl"
    stale.parent.mkdir(parents=True)
    stale.write_text(
        json.dumps(
            {
                "id": f"{CONTROL}-combination-rejected-2-stale",
                "experiment_manifest_hash": "0" * 64,
                "reason": "duplicate_fingerprint",
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="missing run metadata"):
        _run(project_root, tmp_path)

    assert not (run_root / PRIMARY).exists()


def test_limit_help_states_its_resume_dependent_semantics() -> None:
    parser = combination_cli.build_parser()

    help_text = next(
        action.help for action in parser._actions if action.dest == "limit"
    )

    assert "--resume" in help_text
    assert "terminal" in help_text


def test_unknown_fixture_filter_is_refused(tmp_path: Path) -> None:
    project_root = _project(tmp_path)

    with pytest.raises(ValueError, match="not in the manifest"):
        _run(project_root, tmp_path, fixtures=["et-9999999"])


def test_baseline_drift_between_fixture_and_source_run_is_refused(
    tmp_path: Path,
) -> None:
    project_root = _project(tmp_path)
    _write_fixture(
        project_root,
        PRIMARY,
        sid=1000001,
        cve="CVE-2024-0001",
        rule=PRIMARY_BASELINE.replace('content:"token"', 'content:"tokens"'),
    )

    with pytest.raises(ValueError, match="baseline"):
        _run(project_root, tmp_path, fixtures=[PRIMARY])
