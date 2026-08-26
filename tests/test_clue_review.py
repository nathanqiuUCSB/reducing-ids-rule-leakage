import json
import hashlib
from pathlib import Path

import pytest

import hardening_game.mutations.cli as mutation_cli
from hardening_game.attribution.clue_registry import (
    BaselineClueRegistry,
    load_baseline_clue_registry,
)
from hardening_game.mutations.clue_review import (
    _rule_predicates,
    _sanitizer_audit,
    audit_review_packet_mapping,
    build_review_packet,
    qualification_summary,
    validate_reviewed_registry,
    write_review_artifacts,
    write_review_packet,
)
from hardening_game.suricata.rule_model import parse_suricata_rule


def _write_fixture_tree(tmp_path: Path) -> tuple[Path, Path]:
    fixture_dir = tmp_path / "fixtures" / "dataset"
    fixture_dir.mkdir(parents=True)
    fixture_path = fixture_dir / "example.json"
    fixture_path.write_text(
        json.dumps(
            {
                "name": "example",
                "sid": 7,
                "revision": 1,
                "cve": "CVE-2025-0001",
                "pcap": "positive.pcap",
                "rule": (
                    'alert http any any -> $HOME_NET 8080 '
                    '(flow:established,to_server; http.method; content:"POST"; '
                    'http.uri; content:"/admin"; sid:7; rev:1;)'
                ),
                "suite": "fixtures/dataset/example_suite.json",
            }
        ),
        encoding="utf-8",
    )
    (fixture_dir / "example_suite.json").write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "P0",
                        "pcap": "positive.pcap",
                        "expected_alert": True,
                        "reason": "positive",
                        "predicate_id": None,
                    },
                    {
                        "name": "N0",
                        "pcap": "negative.pcap",
                        "expected_alert": False,
                        "reason": "remove URI",
                        "predicate_id": "content-1",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    manifest_path = tmp_path / "fixtures" / "dataset_manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "records": [
                    {
                        "name": "example",
                        "cve": "CVE-2025-0001",
                        "status": "validated",
                        "fixture": "fixtures/dataset/example.json",
                        "suite": "fixtures/dataset/example_suite.json",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    run_dir = tmp_path / "runs" / "mutations" / "baseline-v1" / "example"
    run_dir.mkdir(parents=True)
    traffic = {
        "candidate_id": "example-baseline",
        "status": "traffic_complete",
        "case_results": {
            "P0": {"expected_alert": True, "passed": True},
            "N0": {"expected_alert": False, "passed": True},
        },
    }
    evaluated = {
        **traffic,
        "status": "evaluated",
        "attacker_prediction": "CVE-2025-0001",
    }
    (run_dir / "results.jsonl").write_text(
        "\n".join(json.dumps(record) for record in (traffic, evaluated)) + "\n",
        encoding="utf-8",
    )
    trials = [
        {
            "candidate_id": "example-baseline",
            "trial_index": index,
            "status": "succeeded",
            "exchange": {
                "prompt": (
                    "Infer the CVE.\n\nRule:\n"
                    'alert http any any -> $HOME_NET 8080 (flow:established,to_server; '
                    'http.method; content:"POST"; http.uri; content:"/admin";)\n'
                ),
                "parsed_response": {
                    "predicted_cve": "CVE-2025-0001",
                    "reasoning": f"reason {index}",
                    "clues": [
                        {
                            "description": "POST to /admin",
                            "rule_evidence": ['content:"POST"', 'content:"/admin"'],
                        }
                    ],
                }
            },
            "prediction": "CVE-2025-0001",
            "error": None,
        }
        for index in range(3)
    ]
    (run_dir / "attacker_trials.jsonl").write_text(
        "\n".join(json.dumps(trial) for trial in trials) + "\n", encoding="utf-8"
    )
    (run_dir / "run_metadata.json").write_text(
        json.dumps(
            {
                "attacker_model": "model-a",
                "attacker_prompt_version": "ranked-clues-sanitized-rule-v2",
                "attacker_response_schema_version": 3,
                "attacker_rule_sanitizer_version": "suricata-metadata-options-v2",
                "attacker_trial_count": 3,
                "baseline_only": True,
                "clue_registry_hash": "a" * 64,
                "mutation_manifest_hash": "b" * 64,
                "related_cve_registry_hash": "c" * 64,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return manifest_path, tmp_path / "runs" / "mutations" / "baseline-v1"


def test_review_packet_is_deterministic_and_contains_review_evidence(
    tmp_path: Path,
) -> None:
    manifest_path, run_root = _write_fixture_tree(tmp_path)

    packet = build_review_packet(
        project_root=tmp_path,
        manifest_path=manifest_path,
        run_root=run_root,
    )

    assert packet == build_review_packet(
        project_root=tmp_path,
        manifest_path=manifest_path,
        run_root=run_root,
    )
    assert packet["run_id"] == "baseline-v1"
    assert packet["rules"][0]["qualification"] == "primary_qualified"
    assert packet["rules"][0]["trial_indexes"] == [0, 1, 2]
    assert packet["rules"][0]["traffic_result_count"] == 1
    assert packet["rules"][0]["trial_outputs"][0]["parsed_response"]["clues"]
    assert packet["rules"][0]["suite_predicate_evidence"] == [
        {
            "case": "N0",
            "expected_alert": False,
            "predicate_id": "content-1",
            "predicate_ids": ["content-1"],
            "reason": "remove URI",
        }
    ]
    assert "content-0" in packet["rules"][0]["rule_predicates"]
    assert packet["rules"][0]["target_prediction_pairs"] == [
        {"count": 3, "predicted_cve": "CVE-2025-0001", "target_cve": "CVE-2025-0001"}
    ]


@pytest.mark.parametrize("version", [1, 3, None, True])
def test_every_review_packet_consumer_rejects_unsupported_schema_versions(
    tmp_path: Path, version: object
) -> None:
    manifest_path, run_root = _write_fixture_tree(tmp_path)
    packet = build_review_packet(
        project_root=tmp_path,
        manifest_path=manifest_path,
        run_root=run_root,
    )
    packet["version"] = version
    message = "unsupported review packet version"

    with pytest.raises(ValueError, match=message):
        qualification_summary(packet)
    with pytest.raises(ValueError, match=message):
        audit_review_packet_mapping(packet)
    with pytest.raises(ValueError, match=message):
        validate_reviewed_registry(BaselineClueRegistry(version=1, rules=()), packet)
    with pytest.raises(ValueError, match=message):
        _sanitizer_audit(packet, run_root=run_root)


@pytest.mark.parametrize("fixture_name", ["et-2049007", "et-2049080"])
def test_review_predicates_emit_each_physical_pcre_once(fixture_name: str) -> None:
    root = Path(__file__).parents[1]
    fixture = json.loads(
        (root / "fixtures" / "dataset" / f"{fixture_name}.json").read_text()
    )

    predicates = _rule_predicates(parse_suricata_rule(fixture["rule"]))

    assert [predicate_id for predicate_id in predicates if "pcre" in predicate_id] == [
        "pcre-0"
    ]
    assert predicates["pcre-0"]["option_index"] >= 0
    assert predicates["pcre-0"]["normalized_option"].startswith("pcre:")
    assert predicates["pcre-0"]["source_span"]["start"] < predicates["pcre-0"][
        "source_span"
    ]["end"]


def test_review_predicates_use_suite_vocabulary_for_real_option_shapes() -> None:
    root = Path(__file__).parents[1]
    rsync = json.loads(
        (root / "fixtures" / "dataset" / "et-2067354.json").read_text()
    )
    bsize = json.loads(
        (root / "fixtures" / "dataset" / "et-2059741.json").read_text()
    )
    flowbits = json.loads(
        (root / "fixtures" / "dataset" / "et-2050988.json").read_text()
    )

    rsync_predicates = _rule_predicates(parse_suricata_rule(rsync["rule"]))
    bsize_predicates = _rule_predicates(parse_suricata_rule(bsize["rule"]))
    flowbits_predicates = _rule_predicates(parse_suricata_rule(flowbits["rule"]))

    assert {"byte_test-0", "byte_test-1", "byte_test-2"}.issubset(rsync_predicates)
    assert not any("-byte_test-" in predicate_id for predicate_id in rsync_predicates)
    assert "bsize-0" in bsize_predicates
    assert not any("-bsize-" in predicate_id for predicate_id in bsize_predicates)
    assert {"flow-established", "flow-to_server"}.issubset(rsync_predicates)
    assert "flow" not in rsync_predicates
    assert flowbits_predicates["flowbits-0"]["value"].startswith("set,")
    assert flowbits_predicates["flowbits-0"]["flowbits_action"] == "set"
    assert (
        flowbits_predicates["flowbits-0"]["flowbits_name"]
        == "ET.ScreenConnectAuthBypass.Attempt"
    )


def test_review_packet_resolves_suite_header_aliases_to_canonical_ids(
    tmp_path: Path,
) -> None:
    manifest_path, run_root = _write_fixture_tree(tmp_path)
    packet = build_review_packet(
        project_root=tmp_path,
        manifest_path=manifest_path,
        run_root=run_root,
    )

    predicates = packet["rules"][0]["rule_predicates"]
    suite = packet["rules"][0]["suite_predicate_evidence"]

    assert "header-dst-port" in predicates
    assert "header-destination-port" not in predicates
    assert suite[0]["predicate_ids"] == ["content-1"]


def test_review_packet_rejects_missing_or_duplicate_trial_slots(tmp_path: Path) -> None:
    manifest_path, run_root = _write_fixture_tree(tmp_path)
    trials_path = run_root / "example" / "attacker_trials.jsonl"
    trials = trials_path.read_text(encoding="utf-8").splitlines()
    trials_path.write_text("\n".join([trials[0], trials[0], trials[2]]) + "\n")

    with pytest.raises(ValueError, match="missing successful attacker trial slot 1"):
        build_review_packet(
            project_root=tmp_path,
            manifest_path=manifest_path,
            run_root=run_root,
        )


def test_review_packet_selects_successful_retry_and_preserves_failed_history(
    tmp_path: Path,
) -> None:
    manifest_path, run_root = _write_fixture_tree(tmp_path)
    trials_path = run_root / "example" / "attacker_trials.jsonl"
    trials = [json.loads(line) for line in trials_path.read_text().splitlines()]
    failed = {
        "candidate_id": "example-baseline",
        "trial_index": 1,
        "status": "failed",
        "exchange": None,
        "prediction": None,
        "error": "Request timed out.",
    }
    trials_path.write_text(
        "\n".join(
            json.dumps(trial)
            for trial in (trials[0], failed, trials[2], trials[1])
        )
        + "\n",
        encoding="utf-8",
    )

    packet = build_review_packet(
        project_root=tmp_path,
        manifest_path=manifest_path,
        run_root=run_root,
    )

    rule = packet["rules"][0]
    assert rule["trial_indexes"] == [0, 1, 2]
    assert rule["attempt_count"] == 4
    assert rule["failed_attempts"] == [failed]
    assert packet["attempt_count"] == 4


def test_review_packet_exposes_tolerated_torn_tail_diagnostics(
    tmp_path: Path,
) -> None:
    manifest_path, run_root = _write_fixture_tree(tmp_path)
    trials_path = run_root / "example" / "attacker_trials.jsonl"
    with trials_path.open("a", encoding="utf-8") as handle:
        handle.write('{"candidate_id":"example-baseline","trial_index":')

    packet = build_review_packet(
        project_root=tmp_path,
        manifest_path=manifest_path,
        run_root=run_root,
    )

    diagnostic = (
        f"{trials_path}:4: ignored malformed unterminated final JSONL record"
    )
    rule = packet["rules"][0]
    assert rule["torn_tail_count"] == 1
    assert rule["torn_tail_diagnostics"] == [diagnostic]
    assert packet["torn_tail_count"] == 1
    assert packet["torn_tail_diagnostics"] == [diagnostic]
    assert packet["attempt_count"] == 3


def test_review_packet_rejects_conflicting_successful_retry(tmp_path: Path) -> None:
    manifest_path, run_root = _write_fixture_tree(tmp_path)
    trials_path = run_root / "example" / "attacker_trials.jsonl"
    trials = [json.loads(line) for line in trials_path.read_text().splitlines()]
    conflict = json.loads(json.dumps(trials[1]))
    conflict["prediction"] = "CVE-2025-9999"
    conflict["exchange"]["parsed_response"]["predicted_cve"] = "CVE-2025-9999"
    trials_path.write_text(
        "\n".join(json.dumps(trial) for trial in (*trials, conflict)) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="conflicting successful attacker trial slot 1"):
        build_review_packet(
            project_root=tmp_path,
            manifest_path=manifest_path,
            run_root=run_root,
        )


@pytest.mark.parametrize("trial_index", [-1, 3, True])
def test_review_packet_rejects_invalid_or_out_of_range_slot(
    tmp_path: Path, trial_index: object
) -> None:
    manifest_path, run_root = _write_fixture_tree(tmp_path)
    trials_path = run_root / "example" / "attacker_trials.jsonl"
    trials = [json.loads(line) for line in trials_path.read_text().splitlines()]
    trials[1]["trial_index"] = trial_index
    trials_path.write_text(
        "\n".join(json.dumps(trial) for trial in trials) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="trial_index"):
        build_review_packet(
            project_root=tmp_path,
            manifest_path=manifest_path,
            run_root=run_root,
        )


def test_review_packet_rejects_success_invariant_violation(tmp_path: Path) -> None:
    manifest_path, run_root = _write_fixture_tree(tmp_path)
    trials_path = run_root / "example" / "attacker_trials.jsonl"
    trials = [json.loads(line) for line in trials_path.read_text().splitlines()]
    trials[1]["exchange"] = None
    trials_path.write_text(
        "\n".join(json.dumps(trial) for trial in trials) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="succeeded attacker trial"):
        build_review_packet(
            project_root=tmp_path,
            manifest_path=manifest_path,
            run_root=run_root,
        )


def test_qualification_summary_preserves_unstable_controls(tmp_path: Path) -> None:
    manifest_path, run_root = _write_fixture_tree(tmp_path)
    trials_path = run_root / "example" / "attacker_trials.jsonl"
    trials = [json.loads(line) for line in trials_path.read_text().splitlines()]
    trials[2]["exchange"]["parsed_response"]["predicted_cve"] = "CVE-2024-0001"
    trials[2]["prediction"] = "CVE-2024-0001"
    trials_path.write_text(
        "\n".join(json.dumps(trial) for trial in trials) + "\n", encoding="utf-8"
    )

    summary = qualification_summary(
        build_review_packet(
            project_root=tmp_path,
            manifest_path=manifest_path,
            run_root=run_root,
        )
    )

    assert summary == {
        "control_or_unstable_count": 1,
        "primary_qualified_count": 0,
        "total_validated_fixtures": 1,
    }


def test_packet_writer_uses_canonical_json(tmp_path: Path) -> None:
    manifest_path, run_root = _write_fixture_tree(tmp_path)
    destination = tmp_path / "review_packet.json"

    write_review_packet(
        destination,
        build_review_packet(
            project_root=tmp_path,
            manifest_path=manifest_path,
            run_root=run_root,
        ),
    )

    assert destination.read_text(encoding="utf-8").endswith("\n")
    assert json.loads(destination.read_text(encoding="utf-8"))["version"] == 2


def test_review_artifact_command_writes_summary_and_sanitizer_audit(
    tmp_path: Path,
) -> None:
    manifest_path, run_root = _write_fixture_tree(tmp_path)

    post_calibration = write_review_artifacts(
        project_root=tmp_path,
        manifest_path=manifest_path,
        run_root=run_root,
    )

    packet_path = run_root / "review_packet.json"
    assert post_calibration["packet_sha256"] == hashlib.sha256(
        packet_path.read_bytes()
    ).hexdigest()
    assert json.loads(
        (run_root / "qualification_summary.json").read_text(encoding="utf-8")
    ) == {
        "control_or_unstable_count": 0,
        "primary_qualified_count": 1,
        "total_validated_fixtures": 1,
    }
    assert post_calibration["fixture_count"] == 1
    assert post_calibration["successful_slot_count"] == 3
    assert post_calibration["attempt_count"] == 3
    assert post_calibration["sanitizer_audit"] == {
        "audited_prompt_count": 3,
        "passed": True,
        "sanitizer_version": "suricata-metadata-options-v2",
    }
    assert json.loads(
        (run_root / "post_calibration.json").read_text(encoding="utf-8")
    ) == post_calibration


def test_baseline_run_metadata_hashes_the_baseline_clue_registry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    (fixtures / "dataset-example.json").write_text(
        json.dumps(
            {
                "name": "dataset-example",
                "sid": 1,
                "revision": 1,
                "cve": "CVE-2025-0001",
                "pcap": "positive.pcap",
                "rule": 'alert tcp any any -> any 80 (content:"x"; sid:1; rev:1;)',
            }
        ),
        encoding="utf-8",
    )
    clue_registry = fixtures / "baseline_clue_registry.json"
    clue_registry.write_text('{"version": 1, "rules": []}\n', encoding="utf-8")

    class FakeEvaluator:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def persist_rejections(self, _rejections: object) -> None:
            pass

        def validate_baseline(self, _candidate: object) -> None:
            pass

        def evaluate(self, _candidates: object, *, resume: bool) -> list[object]:
            assert resume is False
            return []

    monkeypatch.setattr(mutation_cli, "MutationEvaluator", FakeEvaluator)
    mutation_cli.run_experiment(
        fixture_name="fixtures/dataset-example.json",
        attacker_model="gpt-5.5",
        api_key="unused",
        run_id="baseline-v1",
        baseline_only=True,
        skip_benign=True,
        project_root=tmp_path,
        client_factory=lambda **_kwargs: object(),
    )

    metadata = json.loads(
        (tmp_path / "runs" / "mutations" / "baseline-v1" / "run_metadata.json").read_text()
    )
    assert metadata["clue_registry_hash"]


def test_reviewed_registry_requires_every_fixture_and_known_predicates(
    tmp_path: Path,
) -> None:
    manifest_path, run_root = _write_fixture_tree(tmp_path)
    registry_path = tmp_path / "fixtures" / "baseline_clue_registry.json"
    registry_path.write_text(
        json.dumps(
            {
                "version": 1,
                "rules": [
                    {
                        "rule_id": "example",
                        "target_cve": "CVE-2025-0001",
                        "clues": [
                            {
                                "clue_id": f"example-major-{rank}",
                                "rank": rank,
                                "description": f"major {rank}",
                                "rationale": "reviewed evidence",
                                "provenance": "review packet baseline-v1",
                                "predicate_ids": [predicate_id],
                                "targetable": True,
                            }
                            for rank, predicate_id in enumerate(
                                ("content-0", "content-1", "flow"), start=1
                            )
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    validate_reviewed_registry(
        load_baseline_clue_registry(registry_path),
        build_review_packet(
            project_root=tmp_path,
            manifest_path=manifest_path,
            run_root=run_root,
        ),
    )

    payload = json.loads(registry_path.read_text())
    payload["rules"][0]["clues"][2]["predicate_ids"] = ["not-a-rule-predicate"]
    registry_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="unknown rule predicate"):
        validate_reviewed_registry(
            load_baseline_clue_registry(registry_path),
            build_review_packet(
                project_root=tmp_path,
                manifest_path=manifest_path,
                run_root=run_root,
            ),
        )
