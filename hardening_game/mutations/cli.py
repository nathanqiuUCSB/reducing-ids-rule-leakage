"""CLI for deterministic Smart Install and generic fixture mutation experiments."""

from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path

from hardening_game.agents import (
    ATTACKER_PROMPT_VERSION,
    ATTACKER_RULE_SANITIZER_VERSION,
    ATTACKER_RESPONSE_SCHEMA_VERSION,
    LiteLLMClient,
    attacker_response_payload,
    parse_attacker_response,
    prepare_attacker_input,
)
from hardening_game.benign.registry import (
    BenignCaptureCase,
    benign_cases_for_fixture,
    load_benign_registry,
    load_fixture_mappings,
    validate_benign_cache,
)
from hardening_game.config import configured_litellm_base_url, load_project_env
from hardening_game.fixture import ValidationCase, load_fixture, load_fixture_path
from hardening_game.mutations.engine import (
    MutationCandidate,
    generate_baseline_candidate,
    generate_generic_candidates,
    generate_smart_install_candidates,
)
from hardening_game.mutations.attacker_trials import (
    load_attacker_trials,
    validate_trial_count,
)
from hardening_game.mutations.clue_manifest import (
    ATTACKER_MODEL as CLUE_MANIFEST_ATTACKER_MODEL,
    ATTACKER_TRIAL_COUNT as CLUE_MANIFEST_TRIAL_COUNT,
    EXPECTED_OUTPUT_RUN_ID as CLUE_MANIFEST_OUTPUT_RUN_ID,
    load_manifest as load_clue_manifest,
    manifest_candidates_for_fixture,
    preflight_manifest,
)
from hardening_game.mutations.evaluator import MutationEvaluator
from hardening_game.suricata.validate import (
    replay_benign_capture,
    replay_rule,
    syntax_check_rule,
)


_PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _positive_trial_count(value: str) -> int:
    return validate_trial_count(int(value))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Evaluate deterministic rule mutations against a validated fixture."
    )
    parser.add_argument(
        "--fixture",
        default="smart_install",
        help=(
            "Fixture short name (smart_install) or JSON path relative to the project "
            "root, such as fixtures/dataset/et-2044143.json."
        ),
    )
    parser.add_argument("--attacker-model", required=True, help="LiteLLM attacker model ID.")
    parser.add_argument(
        "--attacker-trials",
        type=_positive_trial_count,
        default=3,
        help="Independent attacker measurements per evaluated candidate (default: 3).",
    )
    parser.add_argument(
        "--baseline-only",
        action="store_true",
        help="Evaluate only each fixture baseline and its attacker trials.",
    )
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--api-key-env", default="LITELLM_API_KEY")
    parser.add_argument("--run-id", default=None, help="Directory name under runs/mutations.")
    parser.add_argument(
        "--family",
        action="append",
        default=None,
        help="Candidate component to evaluate; repeat to select multiple families.",
    )
    parser.add_argument(
        "--resume", action="store_true", help="Skip candidate IDs already in results.jsonl."
    )
    parser.add_argument(
        "--dataset-fixtures",
        action="store_true",
        help="Evaluate every validated fixtures/dataset/*.json fixture (never *_suite.json).",
    )
    parser.add_argument("--benign-cache", type=Path, default=None)
    parser.add_argument("--skip-benign", action="store_true")
    parser.add_argument(
        "--experiment-manifest",
        type=Path,
        default=None,
        help="Strict clue-targeted manifest whose exact candidates must be evaluated.",
    )
    parser.add_argument(
        "--preflight",
        action="store_true",
        help="Validate all manifest and output locks without writing or calling an attacker.",
    )
    return parser


def select_experiment_candidates(
    candidates: list[MutationCandidate] | tuple[MutationCandidate, ...],
    *,
    families: list[str] | None,
    baseline_only: bool,
) -> list[MutationCandidate]:
    """Apply the baseline gate before optional mutation-family filtering."""
    if baseline_only:
        baseline = next(
            (candidate for candidate in candidates if candidate.component == "baseline"),
            None,
        )
        if baseline is None:
            raise ValueError("candidate set has no baseline")
        return [baseline]
    selected = [
        candidate
        for candidate in candidates
        if families is None or candidate.component in set(families)
    ]
    if not selected:
        raise ValueError("family filter selected no candidates")
    return selected


def _file_hash(path: Path | None) -> str | None:
    if path is None or not path.is_file():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_run_metadata(
    *,
    attacker_model: str,
    attacker_trial_count: int,
    candidates: list[MutationCandidate] | tuple[MutationCandidate, ...],
    baseline_only: bool,
    clue_registry_path: Path | None,
    related_cve_registry_path: Path | None,
) -> dict[str, object]:
    """Build the immutable attacker and input contract for a mutation run."""
    trial_count = validate_trial_count(attacker_trial_count)
    candidate_data = [asdict(candidate) for candidate in candidates]
    canonical_manifest = json.dumps(
        candidate_data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return {
        "attacker_prompt_version": ATTACKER_PROMPT_VERSION,
        "attacker_response_schema_version": ATTACKER_RESPONSE_SCHEMA_VERSION,
        "attacker_rule_sanitizer_version": ATTACKER_RULE_SANITIZER_VERSION,
        "attacker_model": attacker_model,
        "attacker_trial_count": trial_count,
        "baseline_only": baseline_only,
        "clue_registry_hash": _file_hash(clue_registry_path),
        "related_cve_registry_hash": _file_hash(related_cve_registry_path),
        "mutation_manifest_hash": hashlib.sha256(
            canonical_manifest.encode("utf-8")
        ).hexdigest(),
    }


def _persist_run_metadata(path: Path, metadata: dict[str, object]) -> None:
    if path.exists():
        stored = json.loads(path.read_text(encoding="utf-8"))
        if stored != metadata:
            raise ValueError(f"run metadata mismatch at {path}")
        return
    if path.parent.is_dir() and any(
        candidate.is_file() for candidate in path.parent.rglob("*")
    ):
        raise ValueError(
            f"missing run metadata at {path} for populated experiment directory"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _load_experiment_fixture(fixture_ref: str, *, project_root: Path):
    path = Path(fixture_ref)
    if path.suffix.casefold() == ".json":
        return load_fixture_path(
            path if path.is_absolute() else project_root / path,
            project_root=project_root,
        )
    return load_fixture(fixture_ref, project_root=project_root)


def load_benign_context(
    fixture_name: str,
    *,
    project_root: Path,
    benign_cache: Path | None,
) -> tuple[tuple[BenignCaptureCase, ...], int, tuple[str, ...]]:
    """Return one fixture's mapped benign cases, request count, and cache errors."""
    sources_dir = project_root / "benign_sources"
    registry = load_benign_registry(sources_dir / "benign_registry.json")
    mappings = load_fixture_mappings(
        sources_dir / "fixture_benign_mappings.json",
        registry=registry,
    )
    fixture_mappings = tuple(
        mapping for mapping in mappings if mapping.fixture_name == fixture_name
    )
    cache_root = (
        benign_cache
        if benign_cache is not None
        else project_root / registry.cache_root
    )
    report = validate_benign_cache(registry, cache_root)
    mapped_source_ids = {mapping.source_id for mapping in fixture_mappings}
    cache_errors = tuple(
        f"{entry.source_id}: {entry.error}"
        for entry in report.entries
        if entry.source_id in mapped_source_ids and entry.sha256_valid is not True
    )
    cases = benign_cases_for_fixture(
        fixture_name,
        registry=registry,
        mappings=mappings,
        report=report,
    )
    return cases, len(fixture_mappings), cache_errors


def run_experiment(
    *,
    fixture_name: str,
    attacker_model: str,
    api_key: str,
    run_id: str,
    base_url: str | None = None,
    families: list[str] | None = None,
    resume: bool = False,
    attacker_trial_count: int = 3,
    baseline_only: bool = False,
    benign_cache: Path | None = None,
    skip_benign: bool = False,
    project_root: Path = _PROJECT_ROOT,
    client_factory=LiteLLMClient,
    locked_candidates: tuple[MutationCandidate, ...] | None = None,
    experiment_manifest_hash: str | None = None,
) -> list[object]:
    """Run an experiment using real Suricata and one LiteLLM attacker client."""
    fixture = _load_experiment_fixture(fixture_name, project_root=project_root)
    if locked_candidates is not None:
        if baseline_only or families is not None:
            raise ValueError("locked manifest candidates cannot be filtered")
        accepted = locked_candidates
        rejected = ()
    elif baseline_only:
        accepted: list[MutationCandidate] | tuple[MutationCandidate, ...] = (
            generate_baseline_candidate(
                fixture.sanitized_rule,
                revision=fixture.revision,
                fixture_name=fixture.name,
            ),
        )
        rejected = ()
    else:
        candidates = (
            generate_smart_install_candidates(
                fixture.sanitized_rule, revision=fixture.revision
            )
            if fixture.name == "smart_install"
            else generate_generic_candidates(
                fixture.sanitized_rule,
                revision=fixture.revision,
                fixture_name=fixture.name,
            )
        )
        if fixture.name == "smart_install":
            accepted = candidates
            rejected = ()
        else:
            accepted = candidates.accepted
            rejected = candidates.rejected
    selected = select_experiment_candidates(
        accepted,
        families=families,
        baseline_only=baseline_only,
    )
    output_dir = project_root / "runs" / "mutations" / run_id
    metadata = build_run_metadata(
        attacker_model=attacker_model,
        attacker_trial_count=attacker_trial_count,
        candidates=selected,
        baseline_only=baseline_only,
        clue_registry_path=project_root / "fixtures" / "baseline_clue_registry.json",
        related_cve_registry_path=(
            project_root / "fixtures" / "related_cve_registry.json"
        ),
    )
    if experiment_manifest_hash is not None:
        metadata["experiment_manifest_hash"] = experiment_manifest_hash
    _persist_run_metadata(output_dir / "run_metadata.json", metadata)

    def replay(rule: str, case: ValidationCase):
        return replay_rule(rule, case.pcap_path, expected_sid=fixture.sid)

    if skip_benign:
        benign_cases: tuple[BenignCaptureCase, ...] = ()
        benign_requested = 0
        benign_cache_errors: tuple[str, ...] = ()
    else:
        benign_cases, benign_requested, benign_cache_errors = load_benign_context(
            fixture.name,
            project_root=project_root,
            benign_cache=benign_cache,
        )

    def benign_replay(rule: str, case: BenignCaptureCase):
        return replay_benign_capture(
            rule,
            case.pcap_path,
            expected_sid=fixture.sid,
        )

    def attacker(rule: str) -> dict[str, object]:
        # Assigned only after baseline syntax and replay validation succeeds.
        client = client_holder["client"]
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

    evaluator = MutationEvaluator(
        fixture=fixture,
        syntax_check=syntax_check_rule,
        replay=replay,
        attacker=attacker,
        output_dir=output_dir,
        benign_cases=benign_cases,
        benign_replay=benign_replay,
        benign_requested=benign_requested,
        benign_cache_errors=benign_cache_errors,
        benign_enabled=not skip_benign,
        attacker_trial_count=attacker_trial_count,
        experiment_manifest_hash=experiment_manifest_hash,
    )
    if not baseline_only:
        evaluator.persist_rejections(rejected)
    baseline_candidate = next(
        (candidate for candidate in accepted if candidate.component == "baseline"),
        None,
    )
    if baseline_candidate is None:
        raise ValueError("candidate set has no baseline")
    evaluator.validate_baseline(baseline_candidate)
    client_holder = {"client": client_factory(api_key=api_key, base_url=base_url)}
    return evaluator.evaluate(selected, resume=resume)


def run_dataset_experiments(
    *,
    attacker_model: str,
    api_key: str,
    run_id: str,
    base_url: str | None = None,
    families: list[str] | None = None,
    resume: bool = False,
    attacker_trial_count: int = 3,
    baseline_only: bool = False,
    benign_cache: Path | None = None,
    skip_benign: bool = False,
    project_root: Path = _PROJECT_ROOT,
    client_factory=LiteLLMClient,
) -> dict[str, int]:
    """Evaluate only validated dataset fixture JSON files, one resumable run each."""
    fixture_dir = project_root / "fixtures" / "dataset"
    fixtures = sorted(
        path for path in fixture_dir.glob("*.json") if not path.name.endswith("_suite.json")
    )
    candidate_results = 0
    for path in fixtures:
        results = run_experiment(
            fixture_name=str(path),
            attacker_model=attacker_model,
            api_key=api_key,
            run_id=f"{run_id}/{path.stem}",
            base_url=base_url,
            families=families,
            resume=resume,
            attacker_trial_count=attacker_trial_count,
            baseline_only=baseline_only,
            benign_cache=benign_cache,
            skip_benign=skip_benign,
            project_root=project_root,
            client_factory=client_factory,
        )
        candidate_results += len(results)
    return {"fixtures": len(fixtures), "candidate_results": candidate_results}


def run_clue_manifest_experiments(
    *,
    manifest_path: Path,
    attacker_model: str,
    api_key: str,
    run_id: str,
    base_url: str | None = None,
    resume: bool = False,
    benign_cache: Path | None = None,
    skip_benign: bool = False,
    project_root: Path = _PROJECT_ROOT,
    client_factory=LiteLLMClient,
) -> dict[str, int]:
    """Evaluate exactly the candidates selected by a validated clue manifest."""
    manifest = load_clue_manifest(manifest_path, project_root=project_root)
    if run_id != CLUE_MANIFEST_OUTPUT_RUN_ID:
        raise ValueError(
            f"clue manifest output run ID must be {CLUE_MANIFEST_OUTPUT_RUN_ID!r}"
        )
    if attacker_model != CLUE_MANIFEST_ATTACKER_MODEL:
        raise ValueError(
            f"clue manifest attacker model must be {CLUE_MANIFEST_ATTACKER_MODEL!r}"
        )
    preflight = preflight_manifest(
        manifest_path,
        project_root=project_root,
        output_root=project_root / "runs/mutations" / run_id,
        resume=resume,
    )
    run_root = project_root / "runs/mutations" / run_id
    fixture_entries = manifest["fixtures"]
    assert isinstance(fixture_entries, list)
    prepared = [
        (
            str(entry["fixture"]),
            str(entry["target_cve"]),
            manifest_candidates_for_fixture(
                manifest, str(entry["fixture"]), project_root=project_root
            ),
        )
        for entry in fixture_entries
        if isinstance(entry, dict)
    ]
    if len(prepared) != len(fixture_entries):
        raise ValueError("manifest fixture entry is not an object")
    _persist_run_metadata(
        run_root / "run_metadata.json",
        dict(preflight["run_metadata"]),
    )
    result_count = 0
    for fixture_name, _target_cve, candidates in prepared:
        results = run_experiment(
            fixture_name=f"fixtures/dataset/{fixture_name}.json",
            attacker_model=attacker_model,
            api_key=api_key,
            run_id=f"{run_id}/{fixture_name}",
            base_url=base_url,
            resume=resume,
            attacker_trial_count=CLUE_MANIFEST_TRIAL_COUNT,
            benign_cache=benign_cache,
            skip_benign=skip_benign,
            project_root=project_root,
            client_factory=client_factory,
            locked_candidates=candidates,
            experiment_manifest_hash=str(manifest["manifest_hash"]),
        )
        result_count += len(results)
    qualification_records = []
    for fixture_name, target_cve, candidates in prepared:
        baseline = next(
            candidate for candidate in candidates if candidate.component == "baseline"
        )
        trials = load_attacker_trials(
            run_root / fixture_name / "attacker_trials.jsonl",
            trial_count=CLUE_MANIFEST_TRIAL_COUNT,
        )
        baseline_trials = [
            trial
            for trial in trials
            if trial.candidate_id == baseline.id and trial.status == "succeeded"
        ]
        exact_count = sum(trial.prediction == target_cve for trial in baseline_trials)
        qualification_records.append(
            {
                "fixture": fixture_name,
                "target_cve": target_cve,
                "successful_trial_count": len(baseline_trials),
                "exact_trial_count": exact_count,
                "qualification": (
                    "primary_qualified"
                    if len(baseline_trials) == 3 and exact_count == 3
                    else (
                        "control_or_unstable"
                        if len(baseline_trials) == 3
                        else "incomplete"
                    )
                ),
                "calibration_role": next(
                    entry["calibration"]["qualification"]
                    for entry in fixture_entries
                    if isinstance(entry, dict) and entry["fixture"] == fixture_name
                ),
            }
        )
    qualification_path = run_root / "baseline_qualification.json"
    temporary = qualification_path.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(
            {
                "experiment_manifest_hash": manifest["manifest_hash"],
                "trial_count": CLUE_MANIFEST_TRIAL_COUNT,
                "fixtures": qualification_records,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, qualification_path)
    return {"fixtures": len(fixture_entries), "candidate_results": result_count}


def main() -> None:
    args = build_parser().parse_args()
    if args.preflight and args.experiment_manifest is None:
        raise SystemExit("--preflight requires --experiment-manifest.")
    if args.experiment_manifest is not None:
        if not args.dataset_fixtures:
            raise SystemExit("--experiment-manifest requires --dataset-fixtures.")
        if args.family or args.baseline_only:
            raise SystemExit(
                "--experiment-manifest cannot be combined with --family or --baseline-only."
            )
        run_id = args.run_id or CLUE_MANIFEST_OUTPUT_RUN_ID
        if run_id != CLUE_MANIFEST_OUTPUT_RUN_ID:
            raise SystemExit(
                f"--experiment-manifest requires --run-id "
                f"{CLUE_MANIFEST_OUTPUT_RUN_ID}."
            )
        if args.attacker_model != CLUE_MANIFEST_ATTACKER_MODEL:
            raise SystemExit(
                f"--experiment-manifest requires --attacker-model "
                f"{CLUE_MANIFEST_ATTACKER_MODEL}."
            )
        if args.attacker_trials != CLUE_MANIFEST_TRIAL_COUNT:
            raise SystemExit(
                f"--experiment-manifest requires --attacker-trials "
                f"{CLUE_MANIFEST_TRIAL_COUNT}."
            )
        preflight = preflight_manifest(
            args.experiment_manifest,
            project_root=_PROJECT_ROOT,
            output_root=_PROJECT_ROOT / "runs/mutations" / run_id,
            resume=args.resume,
        )
        if args.preflight:
            print(
                f"PREFLIGHT OK manifest={preflight['manifest_hash']} "
                f"candidates={preflight['candidate_count']} "
                f"max_attacker_calls={preflight['expected_max_attacker_calls']}"
            )
            return
        load_project_env(_PROJECT_ROOT / ".env")
        args.base_url = args.base_url or configured_litellm_base_url()
        if not args.base_url:
            raise SystemExit(
                "Set --base-url or LITELLM_BASE_URL before running attacker trials."
            )
        api_key = os.environ.get(args.api_key_env)
        if not api_key:
            raise SystemExit(f"Set {args.api_key_env} before running a live experiment.")
        summary = run_clue_manifest_experiments(
            manifest_path=args.experiment_manifest,
            attacker_model=args.attacker_model,
            api_key=api_key,
            run_id=run_id,
            base_url=args.base_url,
            resume=args.resume,
            benign_cache=args.benign_cache,
            skip_benign=args.skip_benign,
        )
        print(
            f"Recorded {summary['candidate_results']} candidate results across "
            f"{summary['fixtures']} dataset fixtures."
        )
        print(f"Artifacts: {_PROJECT_ROOT / 'runs' / 'mutations' / run_id}")
        return
    load_project_env(_PROJECT_ROOT / ".env")
    args.base_url = args.base_url or configured_litellm_base_url()
    if not args.base_url:
        raise SystemExit(
            "Set --base-url or LITELLM_BASE_URL before running attacker trials."
        )
    api_key = os.environ.get(args.api_key_env)
    if not api_key:
        raise SystemExit(f"Set {args.api_key_env} before running a live experiment.")
    run_id = args.run_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if args.dataset_fixtures:
        summary = run_dataset_experiments(
            attacker_model=args.attacker_model,
            api_key=api_key,
            run_id=run_id,
            base_url=args.base_url,
            families=args.family,
            resume=args.resume,
            attacker_trial_count=args.attacker_trials,
            baseline_only=args.baseline_only,
            benign_cache=args.benign_cache,
            skip_benign=args.skip_benign,
        )
        print(
            f"Recorded {summary['candidate_results']} candidate results across "
            f"{summary['fixtures']} dataset fixtures."
        )
    else:
        results = run_experiment(
            fixture_name=args.fixture,
            attacker_model=args.attacker_model,
            api_key=api_key,
            run_id=run_id,
            base_url=args.base_url,
            families=args.family,
            resume=args.resume,
            attacker_trial_count=args.attacker_trials,
            baseline_only=args.baseline_only,
            benign_cache=args.benign_cache,
            skip_benign=args.skip_benign,
        )
        print(f"Recorded {len(results)} candidate results.")
    print(f"Artifacts: {_PROJECT_ROOT / 'runs' / 'mutations' / run_id}")


if __name__ == "__main__":
    main()
