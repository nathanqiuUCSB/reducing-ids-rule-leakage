"""CLI for evaluating locked multi-block rule combinations.

Candidates come from a locked manifest and are evaluated with the same
`MutationEvaluator`, benign context, and related-CVE registry as the
single-mutation experiment.  Every persisted result carries the manifest hash,
its ordered source candidate IDs, and its block count, so a run directory can
only ever be resumed under the manifest that produced it.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from hardening_game.agents import (
    ATTACKER_PROMPT_VERSION,
    ATTACKER_RULE_SANITIZER_VERSION,
    ATTACKER_RESPONSE_SCHEMA_VERSION,
    LiteLLMClient,
    attacker_response_payload,
    parse_attacker_response,
    prepare_attacker_input,
)
from hardening_game.attribution import RelatedCveRegistry, load_related_cve_registry
from hardening_game.benign.registry import BenignCaptureCase
from hardening_game.config import configured_litellm_base_url, load_project_env
from hardening_game.fixture import ValidationCase, load_fixture_path
from hardening_game.mutations.cli import load_benign_context
from hardening_game.mutations.combination_manifest import (
    CombinationManifest,
    load_combination_manifest,
    manifest_hash,
)
from hardening_game.mutations.combiner import (
    CombinationCandidate,
    CombinationSet,
    FixtureSources,
    generate_combinations,
    load_fixture_sources,
)
from hardening_game.mutations.engine import MutationCandidate, canonical_fingerprint
from hardening_game.mutations.evaluator import (
    TERMINAL_STATUSES,
    ManifestHashMismatch,
    MutationEvaluator,
    latest_records,
)
from hardening_game.mutations.reporting import (
    read_baseline_context,
    read_jsonl_records,
    render_data_quality_lines,
    render_mix_group_lines,
    render_precision_lines,
    render_source_category_lines,
    summarize_combination_mix,
    summarize_data_quality,
    summarize_precision,
)
from hardening_game.suricata.validate import (
    replay_benign_capture,
    replay_rule,
    syntax_check_rule,
)


_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_PRIMARY_ROLE = "primary"
_RUN_METADATA = "run_metadata.json"
_BASELINE_CONTEXT = "baseline_context.json"
_FIXTURE_ARTIFACTS = ("results.jsonl", "rejections.jsonl", _BASELINE_CONTEXT)
_ATTACKER_FAILURE_STATUSES = (
    "attacker_provider_failed",
    "attacker_parse_failed",
    "attacker_empty_response",
    "attacker_empty_prediction",
)
# A combination run summarizes every persisted record, not only the eligible
# ones a rule-level attribution report keeps, so its precision denominators say
# so explicitly.
_PERSISTED_POPULATION = "persisted_records"


class PopulatedRunDirectory(RuntimeError):
    """A fresh run was pointed at a run directory that already holds results."""


@dataclass(frozen=True)
class FixtureRunSummary:
    fixture: str
    role: str
    control: bool
    selected: bool
    generated_candidates: int
    conflict_rejections: int
    persisted_results: int
    pending_candidates: int
    complete: bool
    baseline_exact: bool | None = None


@dataclass(frozen=True)
class CombinationRunSummary:
    run_root: Path
    experiment_manifest_hash: str
    evaluated_records: int
    run_complete: bool
    fixtures: tuple[FixtureRunSummary, ...]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Evaluate locked multi-block rule combinations."
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        required=True,
        help="Locked combination manifest, such as "
        "experiments/combination-hybrid-v1/manifest.json.",
    )
    parser.add_argument("--attacker-model", required=True, help="LiteLLM attacker model ID.")
    parser.add_argument("--run-id", default=None, help="Directory name under runs/mutations.")
    parser.add_argument("--benign-cache", type=Path, default=None)
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Skip candidate IDs already persisted in results.jsonl.",
    )
    parser.add_argument("--skip-benign", action="store_true")
    parser.add_argument(
        "--fake-attacker-prediction",
        default=None,
        help=(
            "Return this CVE instead of calling the attacker model. No API "
            "client is constructed and no credits are consumed."
        ),
    )
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--api-key-env", default="LITELLM_API_KEY")
    parser.add_argument(
        "--fixture",
        action="append",
        default=None,
        help=(
            "Evaluate only this manifest fixture; repeat to select several. "
            "Defaults to every primary fixture and then the labeled control."
        ),
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help=(
            "Evaluate at most this many candidates per selected fixture: with "
            "--resume, the first candidates whose persisted record is not yet "
            "terminal; without it, the first candidates of an empty run "
            "directory. Intended for one-candidate smoke gates."
        ),
    )
    parser.add_argument(
        "--block-count",
        type=int,
        action="append",
        default=None,
        dest="block_counts",
        help=(
            "Evaluate only combinations of this many blocks; repeat to select "
            "several widths. Intended for smoke gates that must reach the "
            "widest compositions."
        ),
    )
    return parser


def _fixture_roles(manifest: CombinationManifest) -> dict[str, str]:
    """Return every manifest fixture in evaluation order with its label."""
    roles = {name: _PRIMARY_ROLE for name in manifest.primary_fixtures}
    roles.update({control.name: control.role for control in manifest.control_fixtures})
    return roles


def _selected_fixtures(
    roles: dict[str, str], fixtures: Sequence[str] | None
) -> tuple[str, ...]:
    if fixtures is None:
        return tuple(roles)
    unknown = sorted({name for name in fixtures if name not in roles})
    if unknown:
        raise ValueError(f"fixture is not in the manifest: {', '.join(unknown)}")
    requested = set(fixtures)
    return tuple(name for name in roles if name in requested)


def _selected_block_counts(
    block_counts: Sequence[int] | None, manifest: CombinationManifest
) -> frozenset[int] | None:
    if block_counts is None:
        return None
    minimum = manifest.selection.minimum_combination_size
    maximum = manifest.selection.max_blocks
    outside = sorted(
        {count for count in block_counts if not minimum <= count <= maximum}
    )
    if outside:
        raise ValueError(
            "block count must be between "
            f"{minimum} and {maximum}: {', '.join(str(count) for count in outside)}"
        )
    return frozenset(block_counts)


def _require_reachable_block_counts(
    block_counts: frozenset[int] | None,
    *,
    manifest: CombinationManifest,
    selected: Sequence[str],
) -> None:
    """Refuse a width no selected fixture can produce instead of evaluating none."""
    if block_counts is None:
        return
    minimum = manifest.selection.minimum_combination_size
    for fixture_name in selected:
        available = min(
            len(manifest.selected_blocks(fixture_name)), manifest.selection.max_blocks
        )
        unreachable = sorted(
            count for count in block_counts if not minimum <= count <= available
        )
        if unreachable:
            raise ValueError(
                f"{fixture_name} has no combinations of block count "
                + ", ".join(str(count) for count in unreachable)
                + f"; it offers {minimum} through {available}"
            )


def _require_generated_block_counts(
    block_counts: frozenset[int] | None,
    *,
    generated: Mapping[str, CombinationSet],
    selected: Sequence[str],
) -> None:
    """Refuse a width conflicts made unreachable, before any fixture is evaluated.

    A fixture can declare enough blocks for a width and still generate none of
    them, because conflicting subsets are rejected. Checking every selected
    fixture up front stops an impossible request from writing earlier fixtures
    first and only then failing.
    """
    if block_counts is None:
        return
    for fixture_name in selected:
        available = sorted(
            {candidate.block_count for candidate in generated[fixture_name].accepted}
        )
        missing = sorted(count for count in block_counts if count not in available)
        if missing:
            raise ValueError(
                f"{fixture_name} generated no combinations of block count "
                + ", ".join(str(count) for count in missing)
                + "; conflict-free widths are "
                + ", ".join(str(count) for count in available)
            )


def _as_mutation_candidate(candidate: CombinationCandidate) -> MutationCandidate:
    return MutationCandidate(
        id=candidate.id,
        component=candidate.component,
        operator=candidate.operator,
        params=candidate.params,
        description=candidate.description,
        rule=candidate.rule,
        revision=candidate.revision,
        fingerprint=candidate.fingerprint,
        experiment_manifest_hash=candidate.experiment_manifest_hash,
        source_candidate_ids=candidate.source_candidate_ids,
        block_count=candidate.block_count,
    )


def _baseline_candidate(sources: FixtureSources) -> MutationCandidate:
    return MutationCandidate(
        id=sources.baseline_candidate_id,
        component="baseline",
        operator="original",
        params={},
        description="Locked source-run baseline rule.",
        rule=sources.baseline_rule,
        revision=sources.baseline_revision,
        fingerprint=canonical_fingerprint(sources.baseline_rule),
    )


def _fake_attacker(prediction: str):
    """Return a no-cost attacker that never constructs an API client."""

    def attacker(_rule: str) -> str:
        return prediction

    return attacker


def _load_registry(project_root: Path) -> RelatedCveRegistry | None:
    path = project_root / "fixtures" / "related_cve_registry.json"
    return load_related_cve_registry(path) if path.is_file() else None


def _file_hash(path: Path) -> str | None:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def source_rule_content_hash(
    fixture_sources: Mapping[str, FixtureSources],
) -> str:
    """Hash exact locked source rules and baseline context in canonical order."""
    payload = [
        {
            "fixture": fixture_name,
            "baseline": {
                "candidate_id": sources.baseline_candidate_id,
                "rule": sources.baseline_rule,
                "fingerprint": canonical_fingerprint(sources.baseline_rule),
                "revision": sources.baseline_revision,
                "attacker_prediction": sources.baseline_attacker_prediction,
                "attacker_correct": sources.baseline_attacker_correct,
            },
            "selected_sources": [
                {
                    "candidate_id": block.candidate_id,
                    "rule": block.rule,
                    "fingerprint": canonical_fingerprint(block.rule),
                }
                for block in sorted(
                    sources.blocks, key=lambda candidate: candidate.candidate_id
                )
            ],
        }
        for fixture_name, sources in sorted(fixture_sources.items())
    ]
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _attacker_run_contract(
    *,
    experiment_manifest_hash: str,
    attacker_model: str,
    project_root: Path,
    source_content_hash: str,
) -> dict[str, object]:
    return {
        "experiment_manifest_hash": experiment_manifest_hash,
        "attacker_model": attacker_model,
        "attacker_prompt_version": ATTACKER_PROMPT_VERSION,
        "attacker_response_schema_version": ATTACKER_RESPONSE_SCHEMA_VERSION,
        "attacker_rule_sanitizer_version": ATTACKER_RULE_SANITIZER_VERSION,
        "attacker_trial_count": None,
        "related_cve_registry_hash": _file_hash(
            project_root / "fixtures" / "related_cve_registry.json"
        ),
        "clue_registry_hash": None,
        "source_rule_content_hash": source_content_hash,
    }


def _jsonl_records(path: Path) -> list[dict[str, object]]:
    if not path.is_file():
        return []
    return read_jsonl_records(path)[0]


def _persisted_records(
    fixture_dir: Path,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    """Return one fixture's whole records and a diagnostic per skipped line."""
    path = fixture_dir / "results.jsonl"
    if not path.is_file():
        return [], []
    return read_jsonl_records(path, label=f"{fixture_dir.name}/results.jsonl")


def _require_run_manifest(
    run_root: Path,
    attacker_contract: Mapping[str, object],
    fixtures: Iterable[str],
) -> None:
    """Refuse a run directory locked to a different manifest before any write.

    The run metadata, every fixture's results and rejections, and the set of
    fixture directories present are all checked up front, so neither a stale
    artifact nor a foreign fixture late in the order can abort a run that has
    already appended records for earlier fixtures.
    """
    fixtures = tuple(fixtures)
    experiment_manifest_hash = attacker_contract["experiment_manifest_hash"]
    path = run_root / _RUN_METADATA
    if path.is_file():
        text = path.read_text(encoding="utf-8")
        try:
            metadata = json.loads(text)
        except json.JSONDecodeError as error:
            raise ValueError(f"{path} is not valid JSON: {error}") from error
        if not isinstance(metadata, dict):
            raise ValueError(f"{path} is not valid JSON: expected a JSON object")
        stored = metadata.get("experiment_manifest_hash")
        if stored != experiment_manifest_hash:
            raise ManifestHashMismatch(
                f"{path} belongs to manifest hash {stored!r}, "
                f"not {experiment_manifest_hash!r}"
            )
        mismatches = {
            key: (metadata.get(key), expected)
            for key, expected in attacker_contract.items()
            if key not in metadata or metadata.get(key) != expected
        }
        if mismatches:
            raise ValueError(f"attacker metadata mismatch at {path}: {mismatches}")
    if run_root.is_dir():
        unexpected = sorted(
            child.name
            for child in run_root.iterdir()
            if child.is_dir() and child.name not in fixtures
        )
        if unexpected:
            raise ValueError(
                f"{run_root} holds fixture directories that are not in the "
                "manifest: " + ", ".join(unexpected)
            )
    for fixture_name in fixtures:
        fixture_dir = run_root / fixture_name
        for artifact in ("results.jsonl", "rejections.jsonl"):
            artifact_path = fixture_dir / artifact
            for record in _jsonl_records(artifact_path):
                stored = record.get("experiment_manifest_hash")
                if stored != experiment_manifest_hash:
                    raise ManifestHashMismatch(
                        f"{artifact_path} was written under manifest hash "
                        f"{stored!r}, not {experiment_manifest_hash!r}"
                    )


def _require_metadata_for_populated_run(run_root: Path) -> None:
    metadata_path = run_root / _RUN_METADATA
    if (
        not metadata_path.is_file()
        and run_root.is_dir()
        and any(path.is_file() for path in run_root.rglob("*"))
    ):
        raise ValueError(
            f"missing run metadata at {metadata_path} for populated "
            "experiment directory"
        )


def _persist_initial_run_contract(
    run_root: Path, attacker_contract: Mapping[str, object]
) -> None:
    path = run_root / _RUN_METADATA
    if path.is_file():
        return
    _atomic_write(
        path,
        json.dumps(dict(attacker_contract), indent=2, sort_keys=True) + "\n",
    )


def _require_fresh_or_resume(
    run_root: Path, fixtures: Iterable[str], *, resume: bool
) -> None:
    """Refuse a fresh run into a populated tree before any replay or attacker call.

    Without --resume every selected candidate is evaluated again, so an
    already-populated run directory would silently duplicate measurements and
    spend attacker calls on work that is already recorded.
    """
    if resume:
        return
    populated = sorted(
        str((run_root / fixture_name / artifact).relative_to(run_root))
        for fixture_name in fixtures
        for artifact in _FIXTURE_ARTIFACTS
        if (run_root / fixture_name / artifact).is_file()
        and (run_root / fixture_name / artifact).stat().st_size > 0
    )
    if populated:
        raise PopulatedRunDirectory(
            f"{run_root} already holds combination artifacts "
            f"({', '.join(populated)}); rerun with --resume or choose a new "
            "--run-id"
        )


def _baseline_context(
    sources: FixtureSources,
    *,
    target_cve: str,
    source_run: str,
    experiment_manifest_hash: str,
) -> dict[str, object]:
    """Freeze the locked source run's baseline attribution for later reporting."""
    prediction = sources.baseline_attacker_prediction
    correct = sources.baseline_attacker_correct
    if correct is None and prediction is not None:
        correct = prediction == target_cve
    return {
        "fixture": sources.fixture_name,
        "source_run": source_run,
        "baseline_candidate_id": sources.baseline_candidate_id,
        "target_cve": target_cve,
        "baseline_attacker_prediction": prediction,
        "baseline_attacker_correct": correct,
        "baseline_exact": correct is True,
        "experiment_manifest_hash": experiment_manifest_hash,
    }


def _write_baseline_context(fixture_dir: Path, context: dict[str, object]) -> None:
    """Write the immutable baseline context once and never rewrite it."""
    path = fixture_dir / _BASELINE_CONTEXT
    if path.is_file():
        return
    _atomic_write(path, json.dumps(context, indent=2, sort_keys=True) + "\n")


def _fixture_target_cve(project_root: Path, fixture_name: str) -> str:
    """Read one fixture's target CVE from its committed dataset record."""
    path = project_root / "fixtures" / "dataset" / f"{fixture_name}.json"
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise ValueError(
            f"{path} is missing, so {fixture_name} has no target CVE to check"
        ) from error
    except json.JSONDecodeError as error:
        raise ValueError(f"{path} is not valid JSON: {error}") from error
    cve = record.get("cve") if isinstance(record, dict) else None
    if not isinstance(cve, str):
        raise ValueError(f"{path} does not record a target CVE for {fixture_name}")
    return cve


def _load_baseline_context(
    run_root: Path,
    fixture_name: str,
    *,
    project_root: Path,
    manifest: CombinationManifest,
    experiment_manifest_hash: str,
) -> dict[str, object] | None:
    if not (run_root / fixture_name / _BASELINE_CONTEXT).is_file():
        return None
    return read_baseline_context(
        run_root / fixture_name,
        fixture=fixture_name,
        target_cve=_fixture_target_cve(project_root, fixture_name),
        experiment_manifest_hash=experiment_manifest_hash,
        source_run=manifest.source_run,
    )


def _require_baseline_contexts(
    run_root: Path,
    fixtures: Iterable[str],
    *,
    project_root: Path,
    manifest: CombinationManifest,
    experiment_manifest_hash: str,
) -> None:
    """Refuse a stale, foreign, or edited baseline context before any write.

    The context is what reporting believes about the locked source run's
    baseline, so a bad one silently changes which records are eligible. Every
    existing context is validated up front, before any fixture is replayed.
    """
    for fixture_name in fixtures:
        _load_baseline_context(
            run_root,
            fixture_name,
            project_root=project_root,
            manifest=manifest,
            experiment_manifest_hash=experiment_manifest_hash,
        )


def _atomic_write(path: Path, contents: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(contents, encoding="utf-8")
    os.replace(temporary, path)


def _mix_group_summary(records: Sequence[Mapping[str, object]]) -> dict[str, object]:
    return {
        "record_count": len(records),
        "evaluated": sum(record.get("status") == "evaluated" for record in records),
        "attacker_correct": sum(
            record.get("attacker_correct") is True for record in records
        ),
        **summarize_precision(records, population=_PERSISTED_POPULATION),
    }


def _group_counts(
    summaries: Iterable[FixtureRunSummary],
    records_by_fixture: dict[str, list[dict[str, object]]],
) -> dict[str, object]:
    summaries = tuple(summaries)
    records = [
        record
        for summary in summaries
        for record in records_by_fixture.get(summary.fixture, [])
    ]
    return {
        "fixtures": len(summaries),
        "complete_fixtures": sum(summary.complete for summary in summaries),
        "generated_candidates": sum(
            summary.generated_candidates for summary in summaries
        ),
        "conflict_rejections": sum(
            summary.conflict_rejections for summary in summaries
        ),
        "persisted_results": sum(summary.persisted_results for summary in summaries),
        "pending_candidates": sum(summary.pending_candidates for summary in summaries),
        "evaluated": sum(record.get("status") == "evaluated" for record in records),
        "syntax_invalid": sum(
            record.get("status") == "syntax_invalid" for record in records
        ),
        "positive_recall_failed": sum(
            record.get("status") == "positive_recall_failed" for record in records
        ),
        "attacker_failed": sum(
            record.get("status") in _ATTACKER_FAILURE_STATUSES for record in records
        ),
        "attacker_correct": sum(
            record.get("attacker_correct") is True for record in records
        ),
        **summarize_precision(records, population=_PERSISTED_POPULATION),
        "combination_mix": summarize_combination_mix(
            records, group_summary=_mix_group_summary
        ),
    }


def _write_reports(
    run_root: Path,
    *,
    attacker_contract: Mapping[str, object],
    manifest: CombinationManifest,
    manifest_path: Path,
    experiment_manifest_hash: str,
    fake_attacker_prediction: str | None,
    skip_benign: bool,
    selected: Sequence[str],
    limit: int | None,
    block_counts: frozenset[int] | None,
    fixtures: Sequence[str] | None,
    summaries: Sequence[FixtureRunSummary],
    records_by_fixture: dict[str, list[dict[str, object]]],
    run_complete: bool,
    data_quality: dict[str, object],
) -> None:
    metadata = {
        **attacker_contract,
        "experiment_id": manifest.experiment_id,
        "manifest_path": str(manifest_path),
        "source_run": manifest.source_run,
        "attacker_mode": "fake" if fake_attacker_prediction is not None else "live",
        "fake_attacker_prediction": fake_attacker_prediction,
        "benign_enabled": not skip_benign,
        "selection_limited": (
            fixtures is not None or limit is not None or block_counts is not None
        ),
        "selected_fixtures": list(selected),
        "candidate_limit": limit,
        "block_counts": sorted(block_counts) if block_counts is not None else None,
        "run_complete": run_complete,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "fixtures": [
            {
                "fixture": summary.fixture,
                "role": summary.role,
                "control": summary.control,
                "selected": summary.selected,
                "generated_candidates": summary.generated_candidates,
                "conflict_rejections": summary.conflict_rejections,
                "persisted_results": summary.persisted_results,
                "pending_candidates": summary.pending_candidates,
                "complete": summary.complete,
                "baseline_exact": summary.baseline_exact,
            }
            for summary in summaries
        ],
    }
    _atomic_write(
        run_root / _RUN_METADATA, json.dumps(metadata, indent=2, sort_keys=True) + "\n"
    )

    primary = [summary for summary in summaries if not summary.control]
    control = [summary for summary in summaries if summary.control]
    report = {
        "experiment_id": manifest.experiment_id,
        "experiment_manifest_hash": experiment_manifest_hash,
        "run_complete": run_complete,
        "primary": _group_counts(primary, records_by_fixture),
        "control": _group_counts(control, records_by_fixture),
        "data_quality": data_quality,
    }
    _atomic_write(
        run_root / "combination_summary.json",
        json.dumps(report, indent=2, sort_keys=True) + "\n",
    )
    _atomic_write(
        run_root / "combination_summary.md",
        _render_summary(report, primary=primary, control=control),
    )


def _render_group(title: str, counts: Mapping[str, object]) -> list[str]:
    mix = counts["combination_mix"]
    assert isinstance(mix, dict)
    return [
        f"## {title}",
        "",
        f"- Fixtures: {counts['fixtures']} ({counts['complete_fixtures']} complete)",
        f"- Generated combinations: {counts['generated_candidates']}",
        f"- Conflict rejections: {counts['conflict_rejections']}",
        f"- Persisted results: {counts['persisted_results']}",
        f"- Pending candidates: {counts['pending_candidates']}",
        f"- Fully evaluated: {counts['evaluated']}",
        f"- Syntax-invalid: {counts['syntax_invalid']}",
        f"- Positive-recall failures: {counts['positive_recall_failed']}",
        f"- Attacker failures: {counts['attacker_failed']}",
        f"- Exact CVE attributions: {counts['attacker_correct']}",
        *render_precision_lines(counts),
        *render_source_category_lines(mix),
        *render_mix_group_lines(mix),
        "",
    ]


def _render_summary(
    report: dict[str, object],
    *,
    primary: Sequence[FixtureRunSummary],
    control: Sequence[FixtureRunSummary],
) -> str:
    primary_counts = report["primary"]
    control_counts = report["control"]
    data_quality = report["data_quality"]
    assert isinstance(primary_counts, dict) and isinstance(control_counts, dict)
    assert isinstance(data_quality, dict)
    lines = [
        "# Combination mutation experiment",
        "",
        f"- Experiment: `{report['experiment_id']}`",
        f"- Manifest hash: `{report['experiment_manifest_hash']}`",
        f"- Run complete: {report['run_complete']}",
        "",
        "## Data quality",
        "",
        *render_data_quality_lines(data_quality),
        "",
        *_render_group("Primary fixtures", primary_counts),
        *_render_group("Control fixtures", control_counts),
        "## Fixtures",
        "",
    ]
    lines.extend(
        f"- `{summary.fixture}` ({summary.role}): "
        f"{summary.persisted_results}/{summary.generated_candidates} evaluated, "
        f"{summary.conflict_rejections} rejected, complete={summary.complete}"
        for summary in (*primary, *control)
    )
    lines.append("")
    return "\n".join(lines)


def _evaluate_fixture(
    *,
    fixture_name: str,
    sources: FixtureSources,
    combination_set: CombinationSet,
    fixture_dir: Path,
    project_root: Path,
    source_run: str,
    experiment_manifest_hash: str,
    registry: RelatedCveRegistry | None,
    attacker,
    syntax_check,
    replay,
    benign_replay,
    benign_cache: Path | None,
    skip_benign: bool,
    resume: bool,
    limit: int | None,
    block_counts: frozenset[int] | None,
) -> int:
    fixture = load_fixture_path(
        project_root / "fixtures" / "dataset" / f"{fixture_name}.json",
        project_root=project_root,
    )
    if canonical_fingerprint(fixture.sanitized_rule) != canonical_fingerprint(
        sources.baseline_rule
    ):
        raise ValueError(
            f"{fixture_name}: committed fixture rule and locked source-run "
            "baseline rule differ"
        )
    if skip_benign:
        benign_cases: tuple[BenignCaptureCase, ...] = ()
        benign_requested = 0
        benign_cache_errors: tuple[str, ...] = ()
    else:
        benign_cases, benign_requested, benign_cache_errors = load_benign_context(
            fixture_name, project_root=project_root, benign_cache=benign_cache
        )

    def case_replay(rule: str, case: ValidationCase):
        return replay(rule, case.pcap_path, expected_sid=fixture.sid)

    def capture_replay(rule: str, case: BenignCaptureCase):
        return benign_replay(rule, case.pcap_path, expected_sid=fixture.sid)

    evaluator = MutationEvaluator(
        fixture=fixture,
        syntax_check=syntax_check,
        replay=case_replay,
        attacker=attacker,
        output_dir=fixture_dir,
        benign_cases=benign_cases,
        benign_replay=capture_replay,
        benign_requested=benign_requested,
        benign_cache_errors=benign_cache_errors,
        benign_enabled=not skip_benign,
        related_cve_registry=registry,
        experiment_manifest_hash=experiment_manifest_hash,
    )
    candidates = [
        _as_mutation_candidate(candidate)
        for candidate in combination_set.accepted
        if block_counts is None or candidate.block_count in block_counts
    ]
    evaluator.require_manifest_agreement(candidates)
    evaluator.validate_baseline(_baseline_candidate(sources))
    _write_baseline_context(
        fixture_dir,
        _baseline_context(
            sources,
            target_cve=fixture.cve,
            source_run=source_run,
            experiment_manifest_hash=experiment_manifest_hash,
        ),
    )
    evaluator.persist_rejections(combination_set.rejected)

    if resume:
        completed = evaluator.completed_candidate_ids()
        candidates = [
            candidate for candidate in candidates if candidate.id not in completed
        ]
    if limit is not None:
        candidates = candidates[:limit]
    return len(evaluator.evaluate(candidates, resume=resume))


def run_combination_experiment(
    *,
    manifest_path: Path,
    attacker_model: str,
    run_id: str,
    api_key: str | None = None,
    base_url: str | None = None,
    fixtures: Sequence[str] | None = None,
    limit: int | None = None,
    block_counts: Sequence[int] | None = None,
    resume: bool = False,
    benign_cache: Path | None = None,
    skip_benign: bool = False,
    fake_attacker_prediction: str | None = None,
    project_root: Path = _PROJECT_ROOT,
    output_root: Path | None = None,
    client_factory=LiteLLMClient,
    syntax_check=syntax_check_rule,
    replay=replay_rule,
    benign_replay=replay_benign_capture,
) -> CombinationRunSummary:
    """Evaluate every locked combination, primaries first and the control last."""
    if limit is not None and limit < 1:
        raise ValueError("limit must be a positive integer")
    if fake_attacker_prediction is None and not api_key:
        raise ValueError("a live attacker run requires an API key")

    manifest = load_combination_manifest(manifest_path, project_root=project_root)
    selected_block_counts = _selected_block_counts(block_counts, manifest)
    experiment_manifest_hash = manifest_hash(manifest)
    roles = _fixture_roles(manifest)
    controls = {control.name for control in manifest.control_fixtures}
    selected = _selected_fixtures(roles, fixtures)
    _require_reachable_block_counts(
        selected_block_counts, manifest=manifest, selected=selected
    )
    run_root = (output_root or project_root / "runs" / "mutations") / run_id
    _require_metadata_for_populated_run(run_root)
    _require_fresh_or_resume(run_root, roles, resume=resume)
    _require_baseline_contexts(
        run_root,
        roles,
        project_root=project_root,
        manifest=manifest,
        experiment_manifest_hash=experiment_manifest_hash,
    )

    # Generate every fixture up front so an impossible --block-count is refused
    # before the first fixture writes anything.
    fixture_sources = {
        fixture_name: load_fixture_sources(
            fixture_name, manifest=manifest, project_root=project_root
        )
        for fixture_name in roles
    }
    attacker_contract = _attacker_run_contract(
        experiment_manifest_hash=experiment_manifest_hash,
        attacker_model=attacker_model,
        project_root=project_root,
        source_content_hash=source_rule_content_hash(fixture_sources),
    )
    _require_run_manifest(run_root, attacker_contract, roles)
    generated = {
        fixture_name: generate_combinations(
            sources,
            experiment_manifest_hash=experiment_manifest_hash,
            max_blocks=manifest.selection.max_blocks,
        )
        for fixture_name, sources in fixture_sources.items()
    }
    _require_generated_block_counts(
        selected_block_counts, generated=generated, selected=selected
    )
    registry = _load_registry(project_root)
    _persist_initial_run_contract(run_root, attacker_contract)
    client_holder: dict[str, object] = {}

    def live_attacker(rule: str) -> dict[str, object]:
        # Constructed on first use, which the evaluator reaches only after
        # syntax validation and full positive recall.
        client = client_holder.get("client")
        if client is None:
            client = client_factory(api_key=api_key, base_url=base_url)
            client_holder["client"] = client
        attacker_input = prepare_attacker_input(rule)
        raw_response = client.complete(
            model=attacker_model, prompt=attacker_input.prompt
        )
        parsed = parse_attacker_response(
            raw_response, visible_rule=attacker_input.visible_rule
        )
        return {
            "prompt": attacker_input.prompt,
            "raw_response": raw_response,
            "parsed_response": attacker_response_payload(parsed),
        }

    attacker = (
        live_attacker
        if fake_attacker_prediction is None
        else _fake_attacker(fake_attacker_prediction)
    )

    summaries: list[FixtureRunSummary] = []
    records_by_fixture: dict[str, list[dict[str, object]]] = {}
    malformed: list[dict[str, object]] = []
    results_files_read = 0
    evaluated_records = 0
    for fixture_name, role in roles.items():
        sources = fixture_sources[fixture_name]
        combination_set = generated[fixture_name]
        fixture_dir = run_root / fixture_name
        is_selected = fixture_name in selected
        if is_selected:
            evaluated_records += _evaluate_fixture(
                fixture_name=fixture_name,
                sources=sources,
                combination_set=combination_set,
                fixture_dir=fixture_dir,
                project_root=project_root,
                source_run=manifest.source_run,
                experiment_manifest_hash=experiment_manifest_hash,
                registry=registry,
                attacker=attacker,
                syntax_check=syntax_check,
                replay=replay,
                benign_replay=benign_replay,
                benign_cache=benign_cache,
                skip_benign=skip_benign,
                resume=resume,
                limit=limit,
                block_counts=selected_block_counts,
            )
        raw_records, read_errors = _persisted_records(fixture_dir)
        malformed.extend(read_errors)
        if (fixture_dir / "results.jsonl").is_file():
            results_files_read += 1
        records = latest_records(raw_records)
        records_by_fixture[fixture_name] = records
        completed_ids = {
            str(record["candidate_id"])
            for record in records
            if record.get("status") in TERMINAL_STATUSES
        }
        pending = [
            candidate
            for candidate in combination_set.accepted
            if candidate.id not in completed_ids
        ]
        context = _load_baseline_context(
            run_root,
            fixture_name,
            project_root=project_root,
            manifest=manifest,
            experiment_manifest_hash=experiment_manifest_hash,
        )
        summaries.append(
            FixtureRunSummary(
                fixture=fixture_name,
                role=role,
                control=fixture_name in controls,
                selected=is_selected,
                generated_candidates=len(combination_set.accepted),
                conflict_rejections=len(combination_set.rejected),
                persisted_results=len(records),
                pending_candidates=len(pending),
                complete=not pending,
                baseline_exact=(
                    None if context is None else bool(context.get("baseline_exact"))
                ),
            )
        )

    run_complete = all(summary.complete for summary in summaries)
    _write_reports(
        run_root,
        attacker_contract=attacker_contract,
        manifest=manifest,
        manifest_path=manifest_path,
        experiment_manifest_hash=experiment_manifest_hash,
        fake_attacker_prediction=fake_attacker_prediction,
        skip_benign=skip_benign,
        selected=selected,
        limit=limit,
        block_counts=selected_block_counts,
        fixtures=fixtures,
        summaries=summaries,
        records_by_fixture=records_by_fixture,
        run_complete=run_complete,
        data_quality=summarize_data_quality(
            malformed, results_files_read=results_files_read
        ),
    )
    return CombinationRunSummary(
        run_root=run_root,
        experiment_manifest_hash=experiment_manifest_hash,
        evaluated_records=evaluated_records,
        run_complete=run_complete,
        fixtures=tuple(summaries),
    )


def main() -> None:
    args = build_parser().parse_args()
    load_project_env(_PROJECT_ROOT / ".env")
    api_key = None
    if args.fake_attacker_prediction is None:
        args.base_url = args.base_url or configured_litellm_base_url()
        if not args.base_url:
            raise SystemExit(
                "Set --base-url or LITELLM_BASE_URL before running attacker trials."
            )
        api_key = os.environ.get(args.api_key_env)
        if not api_key:
            raise SystemExit(f"Set {args.api_key_env} before running a live experiment.")
    run_id = args.run_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    summary = run_combination_experiment(
        manifest_path=args.manifest,
        attacker_model=args.attacker_model,
        run_id=run_id,
        api_key=api_key,
        base_url=args.base_url,
        fixtures=args.fixture,
        limit=args.limit,
        block_counts=args.block_counts,
        resume=args.resume,
        benign_cache=args.benign_cache,
        skip_benign=args.skip_benign,
        fake_attacker_prediction=args.fake_attacker_prediction,
    )
    print(
        f"Recorded {summary.evaluated_records} combination results; "
        f"run complete: {summary.run_complete}."
    )
    for fixture in summary.fixtures:
        print(
            f"  {fixture.fixture} ({fixture.role}): "
            f"{fixture.persisted_results}/{fixture.generated_candidates} evaluated, "
            f"{fixture.conflict_rejections} conflict rejections"
        )
    print(f"Manifest hash: {summary.experiment_manifest_hash}")
    print(f"Artifacts: {summary.run_root}")


if __name__ == "__main__":
    main()
