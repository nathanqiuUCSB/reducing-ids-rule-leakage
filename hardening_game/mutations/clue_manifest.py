"""Build and validate the hash-locked clue-targeted single-mutation experiment."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import shlex
import shutil
from typing import Mapping

from hardening_game.agents import (
    ATTACKER_PROMPT_VERSION,
    ATTACKER_RESPONSE_SCHEMA_VERSION,
    ATTACKER_RULE_SANITIZER_VERSION,
)
from hardening_game.attribution import (
    load_baseline_clue_registry,
    registry_sha256,
)
from hardening_game.benign.registry import benign_corpus_digest, load_benign_registry
from hardening_game.fixture import load_fixture_path
from hardening_game.mutations.clue_targets import (
    build_clue_targeted_manifest,
    load_clue_target_recipes,
    recipes_sha256,
)
from hardening_game.mutations.engine import MutationCandidate
from hardening_game.mutations.task4_evidence import task4_evidence_digest


EXPECTED_EXPERIMENT_ID = "single-clue-targeted-v1"
EXPECTED_OUTPUT_RUN_ID = "dataset-clue-targeted-singles-v1"
SOURCE_RUN = "runs/mutations/dataset-component-mutations-v2"
CALIBRATION_RUN = "runs/mutations/dataset-clue-baseline-v2"
ATTACKER_MODEL = "gpt-5.5"
ATTACKER_TRIAL_COUNT = 3
SURICATA_VERSION = "7.0.3 RELEASE"
SESSION_NAME = "mutation-clue-singles-v1"

_MANIFEST_RELATIVE_PATH = Path("experiments/single-clue-targeted-v1/manifest.json")
_RECIPE_PATH = Path("fixtures/clue_targeted_mutation_recipes.json")
_CLUE_REGISTRY_PATH = Path("fixtures/baseline_clue_registry.json")
_RELATED_REGISTRY_PATH = Path("fixtures/related_cve_registry.json")
_BENIGN_REGISTRY_PATH = Path("benign_sources/benign_registry.json")
_BENIGN_MAPPINGS_PATH = Path("benign_sources/fixture_benign_mappings.json")
_TASK4_EVIDENCE_DIGEST = (
    "3e10db7dc59f6b783f9d76d023bd3f7df379821f72026607307dd2560760ba79"
)


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def canonical_manifest_hash(value: Mapping[str, object]) -> str:
    """Hash canonical JSON, excluding the self-referential manifest_hash field."""
    payload = dict(value)
    payload.pop("manifest_hash", None)
    return hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def _file_hash(path: Path) -> str:
    if not path.is_file():
        raise ValueError(f"required locked input does not exist: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_json_file_hash(path: Path) -> str:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError(f"locked JSON is invalid at {path}: {error}") from error
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _jsonl(path: Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError as error:
        raise ValueError(f"required locked source does not exist: {path}") from error
    for line_number, line in enumerate(lines, start=1):
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"invalid JSON at {path}:{line_number}") from error
        if not isinstance(value, dict):
            raise ValueError(f"source record at {path}:{line_number} is not an object")
        records.append(value)
    return records


def _source_candidates(path: Path) -> dict[str, dict[str, object]]:
    selected: dict[str, dict[str, object]] = {}
    for record in _jsonl(path):
        candidate_id = record.get("candidate_id")
        if not isinstance(candidate_id, str) or not candidate_id:
            raise ValueError(f"source record has no candidate_id: {path}")
        if candidate_id in selected:
            raise ValueError(f"duplicate source candidate ID {candidate_id!r} at {path}")
        selected[candidate_id] = record
    return selected


def _candidate_record(fixture: str, mapped) -> dict[str, object]:
    candidate = mapped.candidate
    record = {
        "fixture": fixture,
        "candidate_id": candidate.id,
        "status": mapped.status,
        "component": candidate.component,
        "operator": candidate.operator,
        "revision": candidate.revision,
        "fingerprint": candidate.fingerprint,
        "rule": candidate.rule,
        "rule_sha256": hashlib.sha256(candidate.rule.encode("utf-8")).hexdigest(),
        "params": candidate.params,
        "description": candidate.description,
        "category": mapped.category,
        "clue_ids": list(mapped.clue_ids),
        "clue_ranks": list(mapped.clue_ranks),
        "touched_predicate_ids": list(mapped.touched_predicate_ids),
        "rationale": mapped.rationale,
        "recipe_id": mapped.recipe_id,
        "match_set_effect": mapped.match_set_effect,
    }
    record["content_sha256"] = hashlib.sha256(_canonical_bytes(record)).hexdigest()
    return record


def _calibration_by_fixture(packet: Mapping[str, object]) -> dict[str, dict[str, object]]:
    raw_rules = packet.get("rules")
    if not isinstance(raw_rules, list):
        raise ValueError("v2 review packet has no rules array")
    result: dict[str, dict[str, object]] = {}
    for raw in raw_rules:
        if not isinstance(raw, dict):
            raise ValueError("v2 review packet rule is not an object")
        fixture = raw.get("fixture")
        target = raw.get("target_cve")
        trials = raw.get("trial_outputs")
        if (
            not isinstance(fixture, str)
            or not isinstance(target, str)
            or not isinstance(trials, list)
        ):
            raise ValueError("v2 review packet rule is incomplete")
        if fixture in result:
            raise ValueError(f"duplicate v2 calibration fixture: {fixture}")
        predictions = [
            trial.get("prediction")
            for trial in trials
            if isinstance(trial, dict) and trial.get("status") == "succeeded"
        ]
        result[fixture] = {
            "qualification": raw.get("qualification"),
            "target_cve": target,
            "attempt_count": raw.get("attempt_count"),
            "successful_trial_count": len(predictions),
            "exact_trial_count": sum(prediction == target for prediction in predictions),
            "predictions": predictions,
        }
    return result


def _task4_report_path(project_root: Path) -> Path:
    """Optional private rebuild artifact; absent in the public showcase checkout."""
    return project_root / "docs" / "task4-evidence-report.md"


def build_manifest(*, project_root: Path) -> dict[str, object]:
    """Rebuild the complete manifest from current locked inputs without writing."""
    project_root = project_root.resolve()
    clue_path = project_root / _CLUE_REGISTRY_PATH
    related_path = project_root / _RELATED_REGISTRY_PATH
    recipe_path = project_root / _RECIPE_PATH
    calibration_root = project_root / CALIBRATION_RUN
    packet_path = calibration_root / "review_packet.json"
    post_path = calibration_root / "post_calibration.json"
    qualification_path = calibration_root / "qualification_summary.json"

    registry = load_baseline_clue_registry(clue_path)
    recipes = load_clue_target_recipes(recipe_path)
    if len(registry.rules) != 19:
        raise ValueError(f"expected exactly 19 clue-registry rules, got {len(registry.rules)}")
    fixture_names = [rule.rule_id for rule in registry.rules]
    if fixture_names != sorted(fixture_names) or len(set(fixture_names)) != 19:
        raise ValueError("clue-registry fixture IDs must be unique and sorted")

    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    if not isinstance(packet, dict):
        raise ValueError("v2 review packet must be an object")
    calibration = _calibration_by_fixture(packet)
    if set(calibration) != set(fixture_names):
        raise ValueError("v2 calibration fixture IDs differ from clue registry")

    fixture_records: list[dict[str, object]] = []
    all_ids: set[str] = set()
    all_fingerprints: set[tuple[str, str]] = set()
    generic_count = targeted_count = baseline_count = 0
    major_strength = Counter()
    major_effect = Counter()

    for rule_clues in registry.rules:
        fixture_name = rule_clues.rule_id
        fixture_path = project_root / f"fixtures/dataset/{fixture_name}.json"
        suite_path = project_root / f"fixtures/dataset/{fixture_name}_suite.json"
        fixture = load_fixture_path(fixture_path, project_root=project_root)
        generated = build_clue_targeted_manifest(
            fixture_name=fixture_name,
            baseline_rule=fixture.sanitized_rule,
            revision=fixture.revision,
            rule_clues=rule_clues,
            recipes=recipes,
        )
        source_path = project_root / SOURCE_RUN / fixture_name / "results.jsonl"
        source = _source_candidates(source_path)
        existing = {
            mapped.candidate.id: mapped
            for mapped in generated.candidates
            if mapped.status == "existing"
        }
        if set(source) != set(existing):
            raise ValueError(
                f"source candidate IDs drift for {fixture_name}: "
                f"source={len(source)}, generated={len(existing)}"
            )
        for candidate_id, mapped in existing.items():
            locked = source[candidate_id]
            candidate = mapped.candidate
            if (
                locked.get("rule") != candidate.rule
                or locked.get("fingerprint") != candidate.fingerprint
            ):
                raise ValueError(
                    f"source candidate content drift for {fixture_name}/{candidate_id}"
                )

        candidates = [_candidate_record(fixture_name, item) for item in generated.candidates]
        for record in candidates:
            candidate_id = str(record["candidate_id"])
            fingerprint_key = (fixture_name, str(record["fingerprint"]))
            if candidate_id in all_ids:
                raise ValueError(f"duplicate candidate ID: {candidate_id}")
            if fingerprint_key in all_fingerprints:
                raise ValueError(f"duplicate rule fingerprint in {fixture_name}")
            all_ids.add(candidate_id)
            all_fingerprints.add(fingerprint_key)
        generic_count += len(existing)
        targeted_count += sum(item.status == "new" for item in generated.candidates)
        baseline_count += sum(
            item.candidate.component == "baseline" for item in generated.candidates
        )

        clue_by_id = {clue.clue_id: clue for clue in rule_clues.clues}
        coverage = [asdict(item) for item in generated.coverage]
        for item in generated.coverage:
            clue = clue_by_id[item.clue_id]
            if clue.rank is not None:
                major_strength[item.coverage_strength] += 1
                major_effect[item.match_set_evidence or "none"] += 1
        top_three = [
            {
                "clue_id": clue.clue_id,
                "rank": clue.rank,
                "description": clue.description,
                "predicate_ids": list(clue.predicate_ids),
                "targetable": clue.targetable,
                "coverage": next(
                    item for item in coverage if item["clue_id"] == clue.clue_id
                ),
            }
            for clue in rule_clues.clues
            if clue.rank is not None
        ]
        if [item["rank"] for item in top_three] != [1, 2, 3]:
            raise ValueError(f"{fixture_name} does not have exactly ranked major clues 1-3")

        fixture_records.append(
            {
                "fixture": fixture_name,
                "fixture_sha256": _file_hash(fixture_path),
                "suite_sha256": _file_hash(suite_path),
                "source_results_sha256": _file_hash(source_path),
                "target_cve": fixture.cve,
                "calibration": calibration[fixture_name],
                "top_three_clues": top_three,
                "coverage": coverage,
                "candidate_counts": {
                    "existing": len(existing),
                    "new": sum(item.status == "new" for item in generated.candidates),
                    "total": len(candidates),
                },
                "candidate_content_sha256": hashlib.sha256(
                    _canonical_bytes(candidates)
                ).hexdigest(),
                "candidates": candidates,
            }
        )

    selected_count = generic_count + targeted_count
    if (generic_count, targeted_count, baseline_count, selected_count) != (719, 57, 19, 776):
        raise ValueError(
            "candidate count drift: "
            f"generic={generic_count}, targeted={targeted_count}, "
            f"baseline={baseline_count}, selected={selected_count}"
        )
    expected_strength = {
        "semantic": 55,
        "rejected_semantic": 2,
        "representation_only": 0,
        "uncovered": 0,
    }
    actual_strength = {key: major_strength.get(key, 0) for key in expected_strength}
    if actual_strength != expected_strength:
        raise ValueError(f"57-major coverage drift: {actual_strength}")

    evidence = task4_evidence_digest(project_root=project_root)
    if evidence.digest != _TASK4_EVIDENCE_DIGEST:
        raise ValueError(
            f"Task 4 evidence digest drift: {evidence.digest} != {_TASK4_EVIDENCE_DIGEST}"
        )
    if SURICATA_VERSION not in evidence.suricata_version:
        raise ValueError(
            f"Suricata version drift: expected {SURICATA_VERSION}, "
            f"got {evidence.suricata_version}"
        )

    qualification = json.loads(qualification_path.read_text(encoding="utf-8"))
    if qualification != {
        "control_or_unstable_count": 9,
        "primary_qualified_count": 10,
        "total_validated_fixtures": 19,
    }:
        raise ValueError(f"calibration qualification counts drift: {qualification}")

    benign_registry_path = project_root / _BENIGN_REGISTRY_PATH
    benign_registry = load_benign_registry(benign_registry_path)
    benign = benign_corpus_digest(
        registry_path=benign_registry_path,
        mappings_path=project_root / _BENIGN_MAPPINGS_PATH,
        # The single source of truth for the cache location is the registry's
        # own cache_root, resolved the same way the run CLI resolves it — two
        # independent hardcodings of this path is exactly how it drifted before.
        cache_root=project_root / benign_registry.cache_root,
    )
    if benign.missing_sources:
        raise ValueError(
            "benign corpus is missing or invalid for source(s) "
            f"{list(benign.missing_sources)}; refusing to build a manifest that "
            "would launch with a silent null benign_false_positive_rate"
        )
    if set(benign.mapped_fixtures) != set(fixture_names):
        raise ValueError(
            "benign fixture mappings do not cover exactly the 19 clue-registry "
            f"fixtures: mapped={sorted(benign.mapped_fixtures)}"
        )

    manifest: dict[str, object] = {
        "version": 1,
        "experiment_id": EXPECTED_EXPERIMENT_ID,
        "output_run_id": EXPECTED_OUTPUT_RUN_ID,
        "source_generic_run": SOURCE_RUN,
        "calibration_run": CALIBRATION_RUN,
        "attacker_contract": {
            "model": ATTACKER_MODEL,
            "trial_count": ATTACKER_TRIAL_COUNT,
            "prompt_version": ATTACKER_PROMPT_VERSION,
            "response_schema_version": ATTACKER_RESPONSE_SCHEMA_VERSION,
            "rule_sanitizer_version": ATTACKER_RULE_SANITIZER_VERSION,
        },
        "input_locks": {
            "clue_registry_canonical_sha256": registry_sha256(registry),
            "clue_registry_file_sha256": _file_hash(clue_path),
            "related_registry_canonical_sha256": _canonical_json_file_hash(related_path),
            "related_registry_file_sha256": _file_hash(related_path),
            "targeted_recipes_canonical_sha256": recipes_sha256(recipes),
            "targeted_recipes_file_sha256": _file_hash(recipe_path),
            "v2_review_packet_sha256": _file_hash(packet_path),
            "v2_post_calibration_sha256": _file_hash(post_path),
            "v2_qualification_summary_sha256": _file_hash(qualification_path),
            "task4_report_sha256": _file_hash(_task4_report_path(project_root)),
            "task4_evidence_sha256": evidence.digest,
            "suite_sha256": evidence.components["suite_json"],
            "fixture_sha256": evidence.components["fixture_json"],
            "pcap_sha256": evidence.components["pcap"],
            "benign_registry_sha256": benign.registry_sha256,
            "benign_mappings_sha256": benign.mappings_sha256,
            "benign_corpus_digest": benign.digest,
            "benign_total_sources": benign.total_sources,
            "benign_available_sources": benign.available_sources,
            "benign_mapped_fixture_count": len(benign.mapped_fixtures),
            "source_generic_results_sha256": hashlib.sha256(
                _canonical_bytes(
                    [
                        {
                            "fixture": item["fixture"],
                            "sha256": item["source_results_sha256"],
                        }
                        for item in fixture_records
                    ]
                )
            ).hexdigest(),
        },
        "suricata_version": evidence.suricata_version,
        "calibration_status": qualification,
        "coverage": {
            "major_total": 57,
            "major_coverage_strength": actual_strength,
            "major_match_set_evidence": {
                key: major_effect.get(key, 0)
                for key in ("observed", "logical_only", "preserving", "none")
            },
        },
        "counts": {
            "fixtures": 19,
            "generic_candidates": generic_count,
            "targeted_candidates": targeted_count,
            "baseline_candidates": baseline_count,
            "single_mutation_candidates": selected_count - baseline_count,
            "selected_candidates": selected_count,
            "attacker_trials_per_recall_preserving_candidate": ATTACKER_TRIAL_COUNT,
            "expected_max_attacker_calls": selected_count * ATTACKER_TRIAL_COUNT,
        },
        "fixtures": fixture_records,
    }
    manifest["manifest_hash"] = canonical_manifest_hash(manifest)
    return manifest


def historical_rebuild_inputs_available(project_root: Path) -> bool:
    """Return whether private calibration/source trees needed to rebuild exist."""
    packet = project_root / CALIBRATION_RUN / "review_packet.json"
    source_root = project_root / SOURCE_RUN
    return packet.is_file() and source_root.is_dir()


def validate_frozen_manifest(
    manifest: Mapping[str, object], *, project_root: Path
) -> None:
    """Validate a committed manifest without private historical run trees.

    Confirms the canonical hash, shipped registry/recipe bytes, and per-fixture
    fixture/suite hashes. Skips locks that only exist in private calibration or
    generic source-run trees.
    """
    locks = manifest.get("input_locks")
    if not isinstance(locks, dict):
        raise ValueError("manifest input_locks must be an object")
    expected_pairs = (
        ("clue_registry_file_sha256", project_root / _CLUE_REGISTRY_PATH),
        ("related_registry_file_sha256", project_root / _RELATED_REGISTRY_PATH),
        ("related_registry_canonical_sha256", None),
        ("targeted_recipes_file_sha256", project_root / _RECIPE_PATH),
    )
    for key, path in expected_pairs:
        stored = locks.get(key)
        if not isinstance(stored, str) or not stored:
            raise ValueError(f"manifest input_locks.{key} is required")
        if key == "related_registry_canonical_sha256":
            actual = _canonical_json_file_hash(
                project_root / _RELATED_REGISTRY_PATH
            )
        else:
            assert path is not None
            actual = _file_hash(path)
        if stored != actual:
            raise ValueError(f"manifest input lock drift for {key}")

    fixtures = manifest.get("fixtures")
    if not isinstance(fixtures, list) or not fixtures:
        raise ValueError("manifest fixtures must be a non-empty array")
    for entry in fixtures:
        if not isinstance(entry, dict):
            raise ValueError("manifest fixture entry must be an object")
        fixture_name = entry.get("fixture")
        if not isinstance(fixture_name, str) or not fixture_name:
            raise ValueError("manifest fixture entry is missing fixture id")
        fixture_path = project_root / f"fixtures/dataset/{fixture_name}.json"
        suite_path = project_root / f"fixtures/dataset/{fixture_name}_suite.json"
        if entry.get("fixture_sha256") != _file_hash(fixture_path):
            raise ValueError(f"fixture lock drift for {fixture_name}")
        if entry.get("suite_sha256") != _file_hash(suite_path):
            raise ValueError(f"suite lock drift for {fixture_name}")
        candidates = entry.get("candidates")
        if not isinstance(candidates, list) or not candidates:
            raise ValueError(f"manifest candidates missing for {fixture_name}")


def load_manifest(path: Path, *, project_root: Path) -> dict[str, object]:
    """Load a manifest and require byte-current agreement with every locked input."""
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid clue manifest JSON at {path}: {error}") from error
    if not isinstance(loaded, dict):
        raise ValueError("clue manifest must be a JSON object")
    stored_hash = loaded.get("manifest_hash")
    if stored_hash != canonical_manifest_hash(loaded):
        raise ValueError("clue manifest canonical hash mismatch")
    if historical_rebuild_inputs_available(project_root):
        expected = build_manifest(project_root=project_root)
        if _canonical_bytes(loaded) != _canonical_bytes(expected):
            raise ValueError(
                "clue manifest content drift: candidate IDs/rules/fingerprints, "
                "metadata, source locks, or current input bytes differ"
            )
    else:
        validate_frozen_manifest(loaded, project_root=project_root)
    return loaded


def _fixture_entry(manifest: Mapping[str, object], fixture: str) -> Mapping[str, object]:
    entries = manifest.get("fixtures")
    if not isinstance(entries, list):
        raise ValueError("manifest fixtures must be an array")
    matches = [
        entry
        for entry in entries
        if isinstance(entry, dict) and entry.get("fixture") == fixture
    ]
    if len(matches) != 1:
        raise ValueError(f"manifest does not contain exactly one fixture {fixture!r}")
    return matches[0]


def manifest_candidates_for_fixture(
    manifest: Mapping[str, object], fixture: str, *, project_root: Path
) -> tuple[MutationCandidate, ...]:
    """Resolve only the candidates named by the already-validated manifest."""
    if historical_rebuild_inputs_available(project_root):
        current = build_manifest(project_root=project_root)
        if _canonical_bytes(manifest) != _canonical_bytes(current):
            raise ValueError("manifest content drift before candidate selection")
    else:
        validate_frozen_manifest(manifest, project_root=project_root)
    entry = _fixture_entry(manifest, fixture)
    raw_candidates = entry.get("candidates")
    if not isinstance(raw_candidates, list):
        raise ValueError(f"manifest candidates for {fixture} must be an array")
    return tuple(
        MutationCandidate(
            id=str(record["candidate_id"]),
            component=str(record["component"]),
            operator=str(record["operator"]),
            params=dict(record["params"]),
            description=str(record["description"]),
            revision=int(record["revision"]),
            rule=str(record["rule"]),
            fingerprint=str(record["fingerprint"]),
            experiment_manifest_hash=str(manifest["manifest_hash"]),
        )
        for record in raw_candidates
        if isinstance(record, dict)
    )


def _run_metadata(manifest: Mapping[str, object]) -> dict[str, object]:
    contract = manifest["attacker_contract"]
    locks = manifest["input_locks"]
    assert isinstance(contract, dict) and isinstance(locks, dict)
    return {
        "experiment_id": EXPECTED_EXPERIMENT_ID,
        "experiment_manifest_hash": manifest["manifest_hash"],
        "output_run_id": EXPECTED_OUTPUT_RUN_ID,
        "source_generic_run": SOURCE_RUN,
        "calibration_run": CALIBRATION_RUN,
        "attacker_model": contract["model"],
        "attacker_trial_count": contract["trial_count"],
        "attacker_prompt_version": contract["prompt_version"],
        "attacker_response_schema_version": contract["response_schema_version"],
        "attacker_rule_sanitizer_version": contract["rule_sanitizer_version"],
        "clue_registry_hash": locks["clue_registry_file_sha256"],
        "related_cve_registry_hash": locks["related_registry_file_sha256"],
        "task4_evidence_sha256": locks["task4_evidence_sha256"],
        "candidate_selection_count": manifest["counts"]["selected_candidates"],
        "manifest_input_locks": locks,
        "calibration_role": "selection_context_only; final baseline qualification is recalculated",
    }


def preflight_manifest(
    path: Path,
    *,
    project_root: Path,
    output_root: Path | None = None,
    resume: bool = False,
) -> dict[str, object]:
    """Validate all locks and output compatibility without writing any artifact."""
    manifest = load_manifest(path, project_root=project_root)
    output = output_root or project_root / "runs/mutations" / EXPECTED_OUTPUT_RUN_ID
    metadata = _run_metadata(manifest)
    metadata_path = output / "run_metadata.json"
    if output.is_dir() and any(child.is_file() for child in output.rglob("*")):
        if not metadata_path.is_file():
            raise ValueError(
                f"missing run metadata at {metadata_path} for populated output"
            )
        try:
            stored = json.loads(metadata_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise ValueError(f"{metadata_path} is not valid JSON") from error
        if stored != metadata:
            raise ValueError(f"run metadata mismatch at {metadata_path}")
        if not resume:
            raise ValueError(f"{output} is populated; relaunch with --resume")
    return {
        "manifest_hash": manifest["manifest_hash"],
        "run_metadata": metadata,
        "output_root": str(output),
        "resume": resume,
        "candidate_count": manifest["counts"]["selected_candidates"],
        "expected_max_attacker_calls": manifest["counts"]["expected_max_attacker_calls"],
    }


def write_manifest(path: Path, manifest: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def live_disk_space_report(*, project_root: Path) -> str:
    """Freshly measured free space for the root filesystem and the launch
    TMPDIR's filesystem. This is a launch-time preflight reading, not part of
    the versioned review document: free space moves, so baking a snapshot into
    committed text would either go stale (like the "root filesystem is full"
    claim this replaces) or make the document's regeneration non-deterministic
    from one run to the next. Call this immediately before launch instead.
    """
    root_usage = shutil.disk_usage("/")
    tmp_target = _launch_tmpdir(project_root=project_root)
    # disk_usage only needs an existing path on the same filesystem.
    existing_ancestor = next(
        candidate for candidate in (tmp_target, *tmp_target.parents) if candidate.exists()
    )
    tmp_usage = shutil.disk_usage(existing_ancestor)
    root_gb = root_usage.free / (1024**3)
    tmp_gb = tmp_usage.free / (1024**3)
    return (
        f"/ currently has {root_gb:.1f} GiB free; the launch TMPDIR filesystem "
        f"({tmp_target}) currently has {tmp_gb:.1f} GiB free."
    )


_MAJOR_STRENGTH_ORDER = ("semantic", "rejected_semantic", "representation_only", "uncovered")
_MAJOR_EVIDENCE_ORDER = ("observed", "logical_only", "preserving", "none")


def _ordered_counts(values: Mapping[str, object], order: tuple[str, ...]) -> str:
    """Render counts in a fixed key order so the text is identical whether
    ``values`` came from a freshly built manifest or one round-tripped through
    ``json.dumps(..., sort_keys=True)`` and reloaded from disk. Relying on
    Python dict repr here would make review.md's exact text depend on which
    of those two paths produced the manifest passed in."""
    missing = set(values) - set(order)
    if missing:
        raise ValueError(f"unordered keys not in the fixed rendering order: {missing}")
    return ", ".join(f"{key}={values.get(key, 0)}" for key in order)


def render_review(manifest: Mapping[str, object], *, project_root: Path) -> str:
    """Render the human review gate from locked manifest facts.

    ``project_root`` is required and used only to resolve absolute paths for
    the disk-space note and the launch command; it is never inferred from the
    current working directory, so the rendered text is identical regardless of
    where this is invoked from.
    """
    counts = manifest["counts"]
    coverage = manifest["coverage"]
    locks = manifest["input_locks"]
    assert isinstance(counts, dict) and isinstance(coverage, dict) and isinstance(locks, dict)
    lines = [
        "# single-clue-targeted-v1 pre-run review",
        "",
        f"- Manifest SHA-256: `{manifest['manifest_hash']}`",
        f"- Output run: `{EXPECTED_OUTPUT_RUN_ID}`",
        f"- Benign corpus lock: {locks['benign_available_sources']}/"
        f"{locks['benign_total_sources']} sources present and hash-valid, mapped "
        f"across {locks['benign_mapped_fixture_count']} fixtures; corpus digest "
        f"`{locks['benign_corpus_digest']}`.",
        f"- Selection: {counts['selected_candidates']} total records "
        f"({counts['baseline_candidates']} baselines + "
        f"{counts['single_mutation_candidates']} single mutations)",
        f"- Provenance: {counts['generic_candidates']} preserved generic records + "
        f"{counts['targeted_candidates']} new clue-targeted records",
        f"- Attacker: `{ATTACKER_MODEL}`, exactly {ATTACKER_TRIAL_COUNT} trials per "
        "recall-preserving selected record",
        f"- Expected maximum attacker calls: **{counts['expected_max_attacker_calls']}**",
        f"- Calibration role: 10 primary-qualified and 9 control-or-unstable fixtures; "
        "the final run recalculates baseline qualification from its own three trials.",
        "- Major clue coverage: "
        f"`{_ordered_counts(coverage['major_coverage_strength'], _MAJOR_STRENGTH_ORDER)}`",
        "- Major match-set evidence: "
        f"`{_ordered_counts(coverage['major_match_set_evidence'], _MAJOR_EVIDENCE_ORDER)}`",
        "",
        "## Per-fixture calibration and candidate review",
        "",
    ]
    fixtures = manifest["fixtures"]
    assert isinstance(fixtures, list)
    for entry in fixtures:
        assert isinstance(entry, dict)
        calibration = entry["calibration"]
        candidate_counts = entry["candidate_counts"]
        assert isinstance(calibration, dict) and isinstance(candidate_counts, dict)
        lines.extend(
            [
                f"### {entry['fixture']} — {entry['target_cve']}",
                "",
                f"- Calibration: `{calibration['qualification']}`; "
                f"{calibration['exact_trial_count']}/3 exact, predictions "
                f"`{calibration['predictions']}`.",
                f"- Candidates: {candidate_counts['existing']} existing + "
                f"{candidate_counts['new']} new = {candidate_counts['total']} total.",
                "- Top-three reviewed clues:",
            ]
        )
        top_three = entry["top_three_clues"]
        assert isinstance(top_three, list)
        for clue in top_three:
            assert isinstance(clue, dict)
            clue_coverage = clue["coverage"]
            assert isinstance(clue_coverage, dict)
            lines.append(
                f"  {clue['rank']}. `{clue['clue_id']}` — {clue['description']} "
                f"Coverage `{clue_coverage['coverage_strength']}`, effect "
                f"`{clue_coverage['match_set_evidence']}`; "
                f"{len(clue_coverage['candidate_ids'])} candidates."
            )
        new_records = [
            record
            for record in entry["candidates"]
            if isinstance(record, dict) and record["status"] == "new"
        ]
        if new_records:
            lines.append("- New targeted candidates:")
            lines.extend(
                f"  - `{record['candidate_id']}` ({record['category']}, "
                f"`{record['match_set_effect']}`): {record['rationale']}"
                for record in new_records
            )
        lines.append("")
    lines.extend(
        [
            "## Superseded pre-v2 (`dataset-component-mutations`) candidates",
            "",
            "The unsuffixed `dataset-component-mutations` run predates the dependency-safety "
            "checks in `hardening_game/mutations/dependencies.py` and the predicate/clue "
            "annotation keys added to candidate params. Reconciling its 207 recall-preserving "
            "candidates against the current engine (`tests/test_v1_candidate_reconciliation.py`) "
            "found 39 without an identical candidate ID in the current generic matrix. Every one "
            "is accounted for, and none is added to this manifest:",
            "",
            "- 14 are the same edit already present in the current accepted set under a "
            "different ID, because a params-schema change (e.g. `relative_constraint/remove` "
            "gained `from`/`to`/`direction`/`compensation` and dropped `value`) or an "
            "insignificant rendering difference (whitespace around an option separator) moved "
            "the identity hash without changing the rendered rule's meaning.",
            "- 22 are edits the current engine now correctly refuses with a `structural` "
            "downstream-dependency rejection (a `distance`/`within`/relative-`pcre` consumer, or "
            "a sticky buffer with relative consumers) that did not exist when the pre-v2 run was "
            "generated. The pre-v2 run accepted these without that check.",
            "- 3 are `content/remove` candidates whose pre-v2 rendering left the removed "
            "content's own `fast_pattern` modifier dangling in the output rule. Suricata binds "
            "`fast_pattern` to the nearest preceding content, so the leftover modifier silently "
            "reattached to a different, earlier content than intended. The current engine "
            "removes every modifier scoped to a removed predicate together with it.",
            "",
            "Three fixtures in this manifest (`et-2060086`, `et-2060144`, `et-2067354`) have no "
            "pre-v2 directory at all: they were added to the dataset after that run, so there is "
            "nothing from it to reconcile for them.",
            "",
            "## Precision and environment caveats",
            "",
            "- Synthetic negatives and the mapped benign corpus are bounded preflights, "
            "not a real-world false-positive-rate estimate. Logical widenings without a "
            "distinguishing committed capture remain explicitly unobserved.",
            "- Disk space is not pinned here because free space moves; run "
            "`hardening-mutations-clue-manifest validate` (or `df -h`) immediately "
            "before launch and pick a writable `TMPDIR` from that live reading, not "
            "from this document.",
            f"- Suricata lock: `{manifest['suricata_version']}`.",
            "",
            "## Approved launch",
            "",
            f"- tmux session: `{SESSION_NAME}`",
            f"- exact command: `{render_launch_command(project_root=project_root)}`",
            "",
        ]
    )
    return "\n".join(lines)


def _launch_tmpdir(*, project_root: Path) -> Path:
    root = project_root.resolve()
    worktree_root = root.parents[1]
    return worktree_root / ".tmp/task5-live"


def _launch_log_dir(*, project_root: Path) -> Path:
    root = project_root.resolve()
    worktree_root = root.parents[1]
    # Deliberately outside runs/mutations: anything that lists run directories
    # under runs/mutations/* must never see a launch-log directory as a run.
    return worktree_root / ".tmp/launch-logs"


def render_launch_command(*, project_root: Path, resume: bool = False) -> str:
    """Return the exact tmux command without starting it.

    ``resume=True`` adds ``--resume`` and writes to a log file distinct from
    the first launch's, so a resume can never overwrite the diagnostic history
    of what failed and why — which is usually exactly what motivated it.
    """
    root = project_root.resolve()
    tmpdir = _launch_tmpdir(project_root=root)
    log_dir = _launch_log_dir(project_root=root)
    log_suffix = "-resume" if resume else ""
    log_path = log_dir / f"{EXPECTED_OUTPUT_RUN_ID}{log_suffix}.log"
    manifest_path = root / _MANIFEST_RELATIVE_PATH
    python = root / ".venv/bin/python"
    resume_flag = " --resume" if resume else ""
    inner = (
        "set -o pipefail; "
        f"export TMPDIR={shlex.quote(str(tmpdir))}; "
        f"cd {shlex.quote(str(root))}; "
        f"{shlex.quote(str(python))} -m hardening_game.mutations.cli "
        f"--experiment-manifest {shlex.quote(str(manifest_path))} "
        f"--run-id {EXPECTED_OUTPUT_RUN_ID} --attacker-model {ATTACKER_MODEL} "
        f"--attacker-trials {ATTACKER_TRIAL_COUNT} --dataset-fixtures{resume_flag} "
        f"2>&1 | tee {shlex.quote(str(log_path))}; "
        # `set -o pipefail` makes `$?` reflect either side of the pipe: the
        # python process's own failure, or tee's (e.g. ENOSPC writing the
        # log). Capturing only PIPESTATUS[0] would silently ignore the latter.
        'code=$?; echo "EXIT:${code}" | '
        f"tee -a {shlex.quote(str(log_path))}; exit $code"
    )
    return (
        f"mkdir -p {shlex.quote(str(tmpdir))} {shlex.quote(str(log_dir))} && "
        f"tmux new-session -d -s {SESSION_NAME} "
        f"{shlex.quote('bash -lc ' + shlex.quote(inner))}"
    )
