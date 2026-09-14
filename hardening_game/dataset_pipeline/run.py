"""Run the real experiment: every mutation of every prepared rule, three times.

One resumable run directory per rule, under a single dataset-scoped tree, so
`report` can analyze the whole dataset at once. Only records that reached
`mutations_generated` are run - a rule still waiting on a hand-supplied PCAP is
skipped and reported, never run with a suite that was never validated.
"""

from __future__ import annotations

from pathlib import Path

from hardening_game.agents import LiteLLMClient
from hardening_game.dataset_pipeline.baseline_gate import (
    REQUIRED_TRIAL_COUNT,
    fixture_path,
)
from hardening_game.dataset_pipeline.manifest import (
    DatasetManifest,
    DatasetRecord,
    load_manifest,
    save_manifest,
)
from hardening_game.mutations.cli import run_experiment


def experiment_run_root(dataset_id: str, *, project_root: Path) -> Path:
    return project_root / "runs" / "mutations" / dataset_id / "experiment"


def experiment_run_id(dataset_id: str, rule_name: str) -> str:
    return f"{dataset_id}/experiment/{rule_name}"


def pending_rules(manifest: DatasetManifest, *, resume: bool) -> tuple[str, ...]:
    """Names of the rules this run would evaluate, in manifest order."""
    eligible = {"mutations_generated"} if resume else {
        "mutations_generated",
        "experiment_complete",
    }
    return tuple(
        record.name for record in manifest.records if record.status in eligible
    )


def run_dataset_experiment(
    dataset_id: str,
    *,
    attacker_model: str,
    api_key: str,
    base_url: str | None = None,
    attacker_trials: int = REQUIRED_TRIAL_COUNT,
    project_root: Path,
    client_factory=LiteLLMClient,
    resume: bool = True,
    skip_benign: bool = True,
) -> DatasetManifest:
    """Evaluate the full mutation matrix for every prepared rule.

    Benign replay is off by default: it needs a `benign_sources/` registry with
    per-fixture mappings, which a newly-added dataset does not have. The report
    then shows benign precision as explicitly unmeasured rather than as a zero
    false-positive rate nobody measured. Pass `skip_benign=False` once you have
    mapped benign captures to these fixture names.

    The manifest is saved after each rule, so an interrupted experiment keeps
    every attacker call it already paid for; re-running with `resume=True`
    picks up from the first rule that has not finished.
    """
    manifest = load_manifest(dataset_id, project_root=project_root)
    for name in pending_rules(manifest, resume=resume):
        record = manifest.record(name)
        run_experiment(
            fixture_name=str(
                fixture_path(dataset_id, name, project_root=project_root)
            ),
            attacker_model=attacker_model,
            api_key=api_key,
            run_id=experiment_run_id(dataset_id, name),
            base_url=base_url,
            attacker_trial_count=attacker_trials,
            baseline_only=False,
            skip_benign=skip_benign,
            project_root=project_root,
            client_factory=client_factory,
            resume=resume,
        )
        manifest = manifest.with_record(
            DatasetRecord(
                name=record.name,
                sid=record.sid,
                cve=record.cve,
                rule=record.rule,
                status="experiment_complete",
                baseline=record.baseline,
                suite=record.suite,
                mutations=record.mutations,
                reason=record.reason,
            )
        )
        save_manifest(manifest, project_root=project_root)
    return manifest
