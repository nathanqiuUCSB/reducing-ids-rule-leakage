"""The whole pipeline, once, with real Suricata and a scripted attacker.

Every other dataset_pipeline test fakes at least one stage boundary. This one
fakes only the paid part - the model - so a mismatch between what one stage
writes and what the next stage expects to read has somewhere to show up.
"""

import json
from pathlib import Path

import pytest

from hardening_game.dataset_pipeline.baseline_gate import run_baseline_gate
from hardening_game.dataset_pipeline.generate import generate_for_dataset
from hardening_game.dataset_pipeline.ingest import add_dataset
from hardening_game.dataset_pipeline.report import report_for_dataset
from hardening_game.dataset_pipeline.run import (
    experiment_run_root,
    run_dataset_experiment,
)


TARGET = "CVE-2025-31337"
RULE = (
    'alert http any any -> $HOME_NET any (flow:established,to_server; '
    'http.method; content:"POST"; http.uri; content:"/acme/lic/accept"; '
    'sid:9100001; rev:1;)'
)


class ScriptedAttacker:
    """Names the target CVE unless the URI literal is gone from the rule.

    That is the whole experiment in miniature: the URI literal is the clue, so
    a mutation that removes it should cost the attacker the answer.
    """

    def __init__(self, **_kwargs: object) -> None:
        pass

    def complete(self, *, model: str, prompt: str) -> str:
        knows = "/acme/lic/accept" in prompt
        return json.dumps(
            {
                "predicted_cve": TARGET if knows else "CVE-2099-9999",
                "reasoning": "the uri literal names the vulnerable endpoint",
                "clues": ["the request uri literal"],
            }
        )


@pytest.fixture
def dataset(tmp_path: Path) -> Path:
    source = tmp_path / "rules.jsonl"
    source.write_text(
        json.dumps(
            {"name": "acme-lic", "sid": 9100001, "cve": TARGET, "rule": RULE}
        )
        + "\n",
        encoding="utf-8",
    )
    add_dataset(source, dataset_id="acme", project_root=tmp_path)
    return tmp_path


@pytest.mark.integration
def test_add_baseline_generate_run_report(dataset: Path) -> None:
    project_root = dataset

    qualified = run_baseline_gate(
        "acme",
        attacker_model="scripted",
        api_key="unused",
        project_root=project_root,
        client_factory=ScriptedAttacker,
    )
    assert qualified.record("acme-lic").status == "baseline_qualified"

    prepared = generate_for_dataset("acme", project_root=project_root)
    record = prepared.record("acme-lic")
    assert record.status == "mutations_generated", record.reason
    assert record.suite is not None and record.suite.kind == "auto_http"
    assert record.mutations is not None and record.mutations.candidate_count > 1

    finished = run_dataset_experiment(
        "acme",
        attacker_model="scripted",
        api_key="unused",
        project_root=project_root,
        client_factory=ScriptedAttacker,
    )
    assert finished.record("acme-lic").status == "experiment_complete"

    report = report_for_dataset("acme", project_root=project_root)

    summary = report["rules"]["acme-lic"]
    assert summary["eligible_record_count"] > 0
    # the baseline is answered right, so any miss is attributable to a mutation
    assert summary["baseline_exact"] is True
    assert summary["baseline_source"] == "run_baseline_record"
    # and at least one mutation did remove the clue the attacker relied on
    assert summary["exact_miss_count"] > 0
    root = experiment_run_root("acme", project_root=project_root)
    assert (root / "attribution_report.md").is_file()
