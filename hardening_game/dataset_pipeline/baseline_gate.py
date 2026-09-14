"""The mandatory baseline gate: only reliably-identified rules go forward.

A mutation experiment can only measure whether an edit *removed* the attacker's
ability to name the CVE if the attacker could reliably name it to begin with.
This stage runs three independent attacker trials against each unmodified rule
and admits only the rules answered exactly right all three times. Everything
else is retained in the manifest as a recorded rejection, not silently dropped
- a rule the attacker cannot identify unmutated is a control, not a hardening
success.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Sequence

from hardening_game.agents import LiteLLMClient
from hardening_game.mutations.attacker_trials import AttackerTrial, load_attacker_trials
from hardening_game.mutations.cli import run_experiment
from hardening_game.dataset_pipeline.manifest import (
    BaselineEvidence,
    DatasetManifest,
    DatasetRecord,
    dataset_root,
    load_manifest,
    save_manifest,
)


REQUIRED_TRIAL_COUNT = 3


def exact_trial_count(
    trials: Iterable[AttackerTrial], *, target_cve: str
) -> int:
    """Count trials that succeeded AND named exactly the target CVE."""
    return sum(
        1
        for trial in trials
        if trial.status == "succeeded"
        and isinstance(trial.prediction, str)
        and trial.prediction.upper() == target_cve.upper()
    )


def qualifies(
    trials: Sequence[AttackerTrial],
    *,
    target_cve: str,
    trial_count: int = REQUIRED_TRIAL_COUNT,
) -> bool:
    """Qualified means every configured trial named the exact target CVE.

    Deliberately duplicated from `clue_review._qualification` rather than
    imported: that function is private to the clue-registry workflow, and this
    gate must keep working if that module changes. `test_dataset_pipeline_
    baseline_gate.py` pins both implementations to identical behaviour.
    """
    return exact_trial_count(trials, target_cve=target_cve) == trial_count


def fixture_path(dataset_id: str, rule_name: str, *, project_root: Path) -> Path:
    root = dataset_root(dataset_id, project_root=project_root)
    return root / "fixtures" / f"{rule_name}.json"


def write_baseline_fixture(
    record: DatasetRecord, *, dataset_id: str, project_root: Path
) -> Path:
    """Write a suite-less fixture: baseline-only never replays a suite.

    `pcap` points at where the auto-generated positive case will be written by
    the `generate` stage, so the same fixture stays correct once a suite
    exists and does not have to be rewritten from scratch.
    """
    path = fixture_path(dataset_id, record.name, project_root=project_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    relative_root = dataset_root(dataset_id, project_root=project_root).relative_to(
        project_root
    )
    payload = {
        "name": record.name,
        "sid": record.sid,
        "revision": 1,
        "cve": record.cve,
        "pcap": str(relative_root / "pcap" / record.name / "P0-auto-canonical.pcap"),
        "rule": record.rule,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def baseline_run_id(dataset_id: str, rule_name: str) -> str:
    return f"{dataset_id}/baseline/{rule_name}"


def _trials_for(
    dataset_id: str, rule_name: str, *, project_root: Path, trial_count: int
) -> list[AttackerTrial]:
    path = (
        project_root
        / "runs"
        / "mutations"
        / baseline_run_id(dataset_id, rule_name)
        / "attacker_trials.jsonl"
    )
    if not path.is_file():
        return []
    return [
        trial
        for trial in load_attacker_trials(path, trial_count=trial_count)
        if trial.candidate_id == f"{rule_name}-baseline"
    ]


def run_baseline_gate(
    dataset_id: str,
    *,
    attacker_model: str,
    api_key: str,
    base_url: str | None = None,
    attacker_trials: int = REQUIRED_TRIAL_COUNT,
    project_root: Path,
    client_factory=LiteLLMClient,
    resume: bool = True,
) -> DatasetManifest:
    """Qualify every not-yet-decided rule, updating the manifest as it goes.

    The manifest is saved after each rule so an interrupted gate keeps every
    attacker call it already paid for.
    """
    manifest = load_manifest(dataset_id, project_root=project_root)
    for record in manifest.records:
        if resume and record.status in {"baseline_qualified", "baseline_rejected"}:
            continue
        fixture = write_baseline_fixture(
            record, dataset_id=dataset_id, project_root=project_root
        )
        run_experiment(
            fixture_name=str(fixture),
            attacker_model=attacker_model,
            api_key=api_key,
            run_id=baseline_run_id(dataset_id, record.name),
            base_url=base_url,
            attacker_trial_count=attacker_trials,
            baseline_only=True,
            skip_benign=True,
            project_root=project_root,
            client_factory=client_factory,
            resume=resume,
        )
        trials = _trials_for(
            dataset_id,
            record.name,
            project_root=project_root,
            trial_count=attacker_trials,
        )
        exact = exact_trial_count(trials, target_cve=record.cve)
        passed = exact == attacker_trials
        updated = DatasetRecord(
            name=record.name,
            sid=record.sid,
            cve=record.cve,
            rule=record.rule,
            status="baseline_qualified" if passed else "baseline_rejected",
            baseline=BaselineEvidence(
                trial_count=attacker_trials,
                exact_trial_count=exact,
                predictions=tuple(trial.prediction for trial in trials),
            ),
            reason=(
                None
                if passed
                else (
                    f"the attacker named the exact CVE in {exact} of "
                    f"{attacker_trials} baseline trials; a rule it cannot "
                    "identify unmutated is a control, not a hardening target"
                )
            ),
        )
        manifest = manifest.with_record(updated)
        save_manifest(manifest, project_root=project_root)
    return manifest
