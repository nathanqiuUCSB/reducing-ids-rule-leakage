import json
from pathlib import Path

import pytest

from hardening_game.dataset_pipeline import run as run_module
from hardening_game.dataset_pipeline.ingest import add_dataset
from hardening_game.dataset_pipeline.manifest import (
    BaselineEvidence,
    DatasetRecord,
    MutationEvidence,
    SuiteEvidence,
    load_manifest,
    save_manifest,
)
from hardening_game.dataset_pipeline.report import (
    registry_path,
    report_for_dataset,
    report_lines,
)
from hardening_game.dataset_pipeline.run import (
    experiment_run_root,
    pending_rules,
    run_dataset_experiment,
)


TARGET = "CVE-2025-10000"
RULE = (
    'alert http any any -> $HOME_NET any (flow:established,to_server; '
    'http.uri; content:"/acme/endpoint"; sid:9000001; rev:1;)'
)


def _prepared_dataset(tmp_path: Path, *names: str) -> None:
    source = tmp_path / "rules.jsonl"
    source.write_text(
        "\n".join(
            json.dumps(
                {
                    "name": name,
                    "sid": 9000001 + index,
                    "cve": TARGET,
                    "rule": RULE.replace("9000001", str(9000001 + index)),
                }
            )
            for index, name in enumerate(names)
        )
        + "\n",
        encoding="utf-8",
    )
    add_dataset(source, dataset_id="acme", project_root=tmp_path)
    manifest = load_manifest("acme", project_root=tmp_path)
    for name in names:
        record = manifest.record(name)
        manifest = manifest.with_record(
            DatasetRecord(
                name=record.name,
                sid=record.sid,
                cve=record.cve,
                rule=record.rule,
                status="mutations_generated",
                baseline=BaselineEvidence(
                    trial_count=3, exact_trial_count=3, predictions=(TARGET,) * 3
                ),
                suite=SuiteEvidence(kind="auto_http", case_count=2),
                mutations=MutationEvidence(generated=True, candidate_count=4),
            )
        )
    save_manifest(manifest, project_root=tmp_path)


def _fake_run_experiment(tmp_path: Path, *, predictions: dict[str, list[str | None]]):
    """Stand in for the real evaluator: write the results.jsonl it would write."""
    seen: list[str] = []

    def fake(*, fixture_name, run_id, **kwargs):
        name = Path(fixture_name).stem
        seen.append(name)
        directory = tmp_path / "runs" / "mutations" / run_id
        directory.mkdir(parents=True, exist_ok=True)
        rows = [
            {
                "candidate_id": f"{name}-baseline",
                "component": "baseline",
                "operator": "original",
                "params": {},
                "status": "evaluated",
                "positive_recall": 1.0,
                "attacker_prediction": TARGET,
                "attacker_correct": True,
            }
        ]
        for index, prediction in enumerate(predictions[name]):
            rows.append(
                {
                    "candidate_id": f"{name}-content-{index}",
                    "component": "content",
                    "operator": "remove",
                    "params": {},
                    "status": "evaluated",
                    "positive_recall": 1.0,
                    "attacker_prediction": prediction,
                    "attacker_correct": prediction == TARGET,
                }
            )
        (directory / "results.jsonl").write_text(
            "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
        )
        return []

    fake.seen = seen  # type: ignore[attr-defined]
    return fake


def test_only_prepared_rules_are_pending(tmp_path: Path) -> None:
    _prepared_dataset(tmp_path, "ready", "also-ready")
    manifest = load_manifest("acme", project_root=tmp_path)
    manifest = manifest.with_record(
        DatasetRecord(
            name="also-ready",
            sid=9000002,
            cve=TARGET,
            rule=RULE,
            status="suite_needs_manual_pcap",
            reason="pcre",
        )
    )

    assert pending_rules(manifest, resume=True) == ("ready",)


def test_the_run_writes_one_directory_per_rule_under_the_dataset_tree(
    tmp_path: Path, monkeypatch
) -> None:
    _prepared_dataset(tmp_path, "rule-a", "rule-b")
    fake = _fake_run_experiment(
        tmp_path, predictions={"rule-a": [TARGET], "rule-b": [None]}
    )
    monkeypatch.setattr(run_module, "run_experiment", fake)

    manifest = run_dataset_experiment(
        "acme",
        attacker_model="fake",
        api_key="unused",
        project_root=tmp_path,
    )

    root = experiment_run_root("acme", project_root=tmp_path)
    assert sorted(path.parent.name for path in root.glob("*/results.jsonl")) == [
        "rule-a",
        "rule-b",
    ]
    assert all(record.status == "experiment_complete" for record in manifest.records)


def test_a_resumed_run_does_not_re_evaluate_finished_rules(
    tmp_path: Path, monkeypatch
) -> None:
    _prepared_dataset(tmp_path, "rule-a")
    fake = _fake_run_experiment(tmp_path, predictions={"rule-a": [TARGET]})
    monkeypatch.setattr(run_module, "run_experiment", fake)
    run_dataset_experiment(
        "acme", attacker_model="fake", api_key="unused", project_root=tmp_path
    )

    run_dataset_experiment(
        "acme", attacker_model="fake", api_key="unused", project_root=tmp_path
    )

    assert fake.seen == ["rule-a"]  # not evaluated a second time


def test_benign_replay_is_off_unless_asked_for(tmp_path: Path, monkeypatch) -> None:
    """A newly added dataset has no benign mappings, so benign precision must
    come out explicitly unmeasured rather than as an unearned zero."""
    _prepared_dataset(tmp_path, "rule-a")
    captured: dict[str, object] = {}
    fake = _fake_run_experiment(tmp_path, predictions={"rule-a": [TARGET]})

    def recording(**kwargs):
        captured.update(kwargs)
        return fake(**kwargs)

    monkeypatch.setattr(run_module, "run_experiment", recording)

    run_dataset_experiment(
        "acme", attacker_model="fake", api_key="unused", project_root=tmp_path
    )

    assert captured["skip_benign"] is True


def test_the_report_reads_the_dataset_manifest_and_writes_both_artifacts(
    tmp_path: Path, monkeypatch
) -> None:
    """This is the test that catches a manifest-name / run-directory-name
    mismatch: reanalyze_run_tree raises if a run directory is not in the
    manifest it is given."""
    _prepared_dataset(tmp_path, "rule-a", "rule-b")
    monkeypatch.setattr(
        run_module,
        "run_experiment",
        _fake_run_experiment(
            tmp_path,
            # rule-a: attacker still right, so no miss. rule-b: wrong twice.
            predictions={"rule-a": [TARGET], "rule-b": ["CVE-2099-9999", None]},
        ),
    )
    run_dataset_experiment(
        "acme", attacker_model="fake", api_key="unused", project_root=tmp_path
    )

    report = report_for_dataset("acme", project_root=tmp_path)

    root = experiment_run_root("acme", project_root=tmp_path)
    assert report["totals"]["analyzed_rule_count"] == 2
    assert report["rules"]["rule-a"]["exact_miss_count"] == 0
    # a wrong CVE and a no-answer are both exact misses
    assert report["rules"]["rule-b"]["exact_miss_count"] == 2
    assert report["totals"]["exact_miss_count"] == 2
    assert json.loads((root / "attribution_report.json").read_text()) == report
    assert "# Mutation attribution report" in (root / "attribution_report.md").read_text()
    assert "Rules analyzed: 2" in report_lines(report, run_root=root)


def test_the_report_uses_the_dataset_s_own_related_cve_registry(
    tmp_path: Path, monkeypatch
) -> None:
    _prepared_dataset(tmp_path, "rule-a")
    close = "CVE-2024-0012"
    registry_path("acme", project_root=tmp_path).write_text(
        json.dumps(
            {
                "version": 1,
                "entries": [
                    {
                        "target_cve": TARGET,
                        "predicted_cve": close,
                        "tier": "closely_related",
                        "vendor": "Acme",
                        "product": "Widget",
                        "rationale": "Same component, adjacent advisories.",
                        "provenance": "Test registry.",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        run_module,
        "run_experiment",
        _fake_run_experiment(tmp_path, predictions={"rule-a": [close]}),
    )
    run_dataset_experiment(
        "acme", attacker_model="fake", api_key="unused", project_root=tmp_path
    )

    report = report_for_dataset("acme", project_root=tmp_path)

    # named a different CVE, but a curated close one: an exact miss that does
    # not count as effective obscurity
    assert report["rules"]["rule-a"]["exact_miss_count"] == 1
    assert report["rules"]["rule-a"]["effective_miss_count"] == 0
    assert report["rules"]["rule-a"]["closely_related_miss_count"] == 1


def test_reporting_before_any_run_says_what_to_do(tmp_path: Path) -> None:
    _prepared_dataset(tmp_path, "rule-a")

    with pytest.raises(FileNotFoundError, match="hardening-experiment run acme"):
        report_for_dataset("acme", project_root=tmp_path)
