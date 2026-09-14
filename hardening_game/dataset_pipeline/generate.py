"""Generate the mutation matrix and the validation suite for qualified rules.

Nothing here spends an attacker call. It produces the two artifacts the real
experiment needs - the deterministic single-mutation candidate set, and a
Suricata-validated PCAP suite - and records per rule whether both succeeded.
A rule whose traffic could not be synthesized automatically is left at
`suite_needs_manual_pcap` with the blocking option named, so it can be finished
with `explain` + `complete-pcap` and picked up by the next `generate` run
rather than being dropped from the dataset.
"""

from __future__ import annotations

import json
from pathlib import Path

from hardening_game.dataset_pipeline.assist import complete_manual_pcap
from hardening_game.dataset_pipeline.auto_suite import (
    AutoSuiteResult,
    generate_auto_suite,
)
from hardening_game.dataset_pipeline.baseline_gate import fixture_path
from hardening_game.dataset_pipeline.manifest import (
    DatasetManifest,
    DatasetRecord,
    MutationEvidence,
    SuiteEvidence,
    dataset_root,
    load_manifest,
    save_manifest,
)
from hardening_game.fixture import ValidationCase
from hardening_game.mutations.engine import generate_generic_candidates


FIXTURE_REVISION = 1

#: Statuses `generate` is willing to advance. `baseline_rejected` never moves
#: forward, and `experiment_complete` is never regenerated underneath a run.
GENERATABLE = frozenset({"baseline_qualified", "suite_needs_manual_pcap"})


def candidates_path(dataset_id: str, rule_name: str, *, project_root: Path) -> Path:
    root = dataset_root(dataset_id, project_root=project_root)
    return root / "fixtures" / f"{rule_name}_candidates.json"


def suite_path(dataset_id: str, rule_name: str, *, project_root: Path) -> Path:
    root = dataset_root(dataset_id, project_root=project_root)
    return root / "fixtures" / f"{rule_name}_suite.json"


def pcap_dir(dataset_id: str, rule_name: str, *, project_root: Path) -> Path:
    return dataset_root(dataset_id, project_root=project_root) / "pcap" / rule_name


def _relative(path: Path, *, project_root: Path) -> str:
    return path.relative_to(project_root).as_posix()


def write_candidates(
    record: DatasetRecord, *, dataset_id: str, project_root: Path
) -> int:
    """Persist the mutation matrix as JSON and return how many were accepted.

    This is a preview, not an input: `run_experiment` regenerates the matrix
    deterministically from the same rule text. Writing it out lets the user see
    exactly what the experiment will test - and how many attacker calls it will
    cost - before paying for a single one.
    """
    candidates = generate_generic_candidates(
        record.rule, revision=FIXTURE_REVISION, fixture_name=record.name
    )
    path = candidates_path(dataset_id, record.name, project_root=project_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "fixture_name": record.name,
        "accepted": [
            {
                "id": candidate.id,
                "component": candidate.component,
                "operator": candidate.operator,
                "params": candidate.params,
                "description": candidate.description,
                "rule": candidate.rule,
                "revision": candidate.revision,
                "fingerprint": candidate.fingerprint,
                "buffer": candidate.buffer,
                "option_index": candidate.option_index,
            }
            for candidate in candidates.accepted
        ],
        "rejected": [
            {
                "id": rejected.id,
                "component": rejected.component,
                "operator": rejected.operator,
                "params": rejected.params,
                "reason": rejected.reason,
                "diagnostic": rejected.diagnostic,
            }
            for rejected in candidates.rejected
        ],
    }
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return len(candidates.accepted)


def write_suite_and_fixture(
    record: DatasetRecord,
    cases: tuple[ValidationCase, ...],
    *,
    dataset_id: str,
    project_root: Path,
) -> Path:
    """Write the suite JSON and point the fixture at it and at its positive.

    The fixture's own `pcap` must be one of the suite's positives: that is the
    capture `validate_baseline` replays before any attacker call is made.
    """
    positive = next((case for case in cases if case.expected_alert), None)
    if positive is None:
        raise ValueError(
            f"suite for {record.name!r} has no positive case, so the baseline "
            "rule has nothing to prove it still detects"
        )
    suite = suite_path(dataset_id, record.name, project_root=project_root)
    suite.parent.mkdir(parents=True, exist_ok=True)
    suite.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": case.name,
                        "pcap": _relative(case.pcap_path, project_root=project_root),
                        "expected_alert": case.expected_alert,
                        "reason": case.reason,
                        "predicate_id": case.predicate_id,
                    }
                    for case in cases
                ]
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    path = fixture_path(dataset_id, record.name, project_root=project_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "name": record.name,
                "sid": record.sid,
                "revision": FIXTURE_REVISION,
                "cve": record.cve,
                "pcap": _relative(positive.pcap_path, project_root=project_root),
                "rule": record.rule,
                "suite": _relative(suite, project_root=project_root),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def _advanced(
    record: DatasetRecord,
    *,
    result: AutoSuiteResult,
    candidate_count: int,
    kind: str | None = None,
) -> DatasetRecord:
    generated = result.status == "generated"
    return DatasetRecord(
        name=record.name,
        sid=record.sid,
        cve=record.cve,
        rule=record.rule,
        status="mutations_generated" if generated else "suite_needs_manual_pcap",
        baseline=record.baseline,
        suite=(
            SuiteEvidence(
                kind=kind or result.kind or "manual", case_count=len(result.cases)
            )
            if generated
            else None
        ),
        mutations=MutationEvidence(generated=True, candidate_count=candidate_count),
        reason=None if generated else result.reason,
    )


def generate_for_dataset(
    dataset_id: str, *, project_root: Path, resume: bool = True
) -> DatasetManifest:
    """Write candidates and a validated suite for every qualified rule."""
    manifest = load_manifest(dataset_id, project_root=project_root)
    for record in manifest.records:
        eligible = GENERATABLE if resume else GENERATABLE | {"mutations_generated"}
        if record.status not in eligible:
            continue
        candidate_count = write_candidates(
            record, dataset_id=dataset_id, project_root=project_root
        )
        result = generate_auto_suite(
            record.rule,
            rule_name=record.name,
            sid=record.sid,
            output_dir=pcap_dir(dataset_id, record.name, project_root=project_root),
            project_root=project_root,
        )
        if result.status == "generated":
            write_suite_and_fixture(
                record,
                result.cases,
                dataset_id=dataset_id,
                project_root=project_root,
            )
        manifest = manifest.with_record(
            _advanced(record, result=result, candidate_count=candidate_count)
        )
        save_manifest(manifest, project_root=project_root)
    return manifest


def apply_manual_suite(
    dataset_id: str,
    rule_name: str,
    *,
    fill: bytes,
    project_root: Path,
    insert_after: str | None = None,
) -> tuple[DatasetManifest, AutoSuiteResult]:
    """Complete one blocked rule from user-supplied bytes, then advance it.

    The manifest only moves forward if real Suricata agreed with the suite, so
    a wrong guess leaves the record exactly where it was, with the failure
    reason recorded for the next attempt.
    """
    manifest = load_manifest(dataset_id, project_root=project_root)
    record = manifest.record(rule_name)
    result = complete_manual_pcap(
        record,
        dataset_id=dataset_id,
        fill=fill,
        project_root=project_root,
        insert_after=insert_after,
    )
    candidate_count = (
        record.mutations.candidate_count
        if record.mutations is not None
        else write_candidates(
            record, dataset_id=dataset_id, project_root=project_root
        )
    )
    if result.status == "generated":
        write_suite_and_fixture(
            record, result.cases, dataset_id=dataset_id, project_root=project_root
        )
    manifest = manifest.with_record(
        _advanced(
            record,
            result=result,
            candidate_count=candidate_count,
            kind="manual",
        )
    )
    save_manifest(manifest, project_root=project_root)
    return manifest, result
