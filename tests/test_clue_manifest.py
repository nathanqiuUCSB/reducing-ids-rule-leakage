import json
from pathlib import Path

import pytest

from hardening_game.mutations.clue_manifest import (
    EXPECTED_EXPERIMENT_ID,
    EXPECTED_OUTPUT_RUN_ID,
    build_manifest,
    canonical_manifest_hash,
    load_manifest,
    manifest_candidates_for_fixture,
    preflight_manifest,
    render_launch_command,
)


PROJECT_ROOT = Path(__file__).parents[1]
MANIFEST_PATH = PROJECT_ROOT / "experiments/single-clue-targeted-v1/manifest.json"


def test_canonical_hash_ignores_json_whitespace() -> None:
    data = {"z": [3, 2, 1], "a": {"value": "é"}}
    compact = json.loads(json.dumps(data, separators=(",", ":")))
    pretty = json.loads(json.dumps(data, indent=4))

    assert canonical_manifest_hash(compact) == canonical_manifest_hash(pretty)


def test_built_manifest_selects_exactly_locked_generic_and_targeted_candidates() -> None:
    manifest = build_manifest(project_root=PROJECT_ROOT)

    assert manifest["experiment_id"] == EXPECTED_EXPERIMENT_ID
    assert manifest["output_run_id"] == EXPECTED_OUTPUT_RUN_ID
    assert manifest["counts"] == {
        "fixtures": 19,
        "generic_candidates": 719,
        "targeted_candidates": 57,
        "baseline_candidates": 19,
        "single_mutation_candidates": 757,
        "selected_candidates": 776,
        "attacker_trials_per_recall_preserving_candidate": 3,
        "expected_max_attacker_calls": 2328,
    }
    records = [
        candidate
        for fixture in manifest["fixtures"]
        for candidate in fixture["candidates"]
    ]
    assert len({record["candidate_id"] for record in records}) == 776
    assert len({(record["fixture"], record["fingerprint"]) for record in records}) == 776
    assert sum(record["status"] == "existing" for record in records) == 719
    assert sum(record["status"] == "new" for record in records) == 57
    assert sum(record["component"] == "baseline" for record in records) == 19


def test_baseline_candidate_is_first_for_every_fixture() -> None:
    """Documents the ordering invariant the generic engine and the targeted
    layer both preserve by construction. run_experiment no longer depends on
    this (it looks up the baseline by component), but the manifest keeping it
    first is what a human review expects, so a silent reorder should fail
    loudly here rather than only be caught by symptom elsewhere."""
    manifest = build_manifest(project_root=PROJECT_ROOT)

    for fixture in manifest["fixtures"]:
        first = fixture["candidates"][0]
        assert first["component"] == "baseline", fixture["fixture"]
        assert first["candidate_id"] == f"{fixture['fixture']}-baseline"


def test_locked_manifest_validates_current_bytes_and_major_coverage() -> None:
    manifest = load_manifest(MANIFEST_PATH, project_root=PROJECT_ROOT)

    assert canonical_manifest_hash(manifest) == manifest["manifest_hash"]
    assert manifest["coverage"]["major_total"] == 57
    assert manifest["coverage"]["major_coverage_strength"] == {
        "semantic": 55,
        "rejected_semantic": 2,
        "representation_only": 0,
        "uncovered": 0,
    }


def test_current_manifest_resolves_exact_candidate_objects() -> None:
    manifest = load_manifest(MANIFEST_PATH, project_root=PROJECT_ROOT)
    selected = manifest_candidates_for_fixture(
        manifest, "et-2044143", project_root=PROJECT_ROOT
    )
    locked = next(
        fixture for fixture in manifest["fixtures"] if fixture["fixture"] == "et-2044143"
    )["candidates"]

    assert [
        (candidate.id, candidate.rule, candidate.fingerprint) for candidate in selected
    ] == [
        (record["candidate_id"], record["rule"], record["fingerprint"])
        for record in locked
    ]


def test_loader_rejects_candidate_rule_drift_before_any_output_write(
    tmp_path: Path,
) -> None:
    payload = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    payload["fixtures"][0]["candidates"][0]["rule"] += " "
    payload["manifest_hash"] = canonical_manifest_hash(payload)
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    output = tmp_path / "runs/mutations/dataset-clue-targeted-singles-v1"

    with pytest.raises(ValueError, match="candidate.*drift|fingerprint|content"):
        preflight_manifest(path, project_root=PROJECT_ROOT, output_root=output)

    assert not output.exists()


def test_preflight_refuses_populated_output_without_compatible_metadata(
    tmp_path: Path,
) -> None:
    output = tmp_path / EXPECTED_OUTPUT_RUN_ID
    output.mkdir()
    (output / "stray.log").write_text("occupied\n", encoding="utf-8")

    with pytest.raises(ValueError, match="missing run metadata|populated"):
        preflight_manifest(
            MANIFEST_PATH,
            project_root=PROJECT_ROOT,
            output_root=output,
            resume=True,
        )


def test_preflight_refuses_non_resume_duplicate_launch(tmp_path: Path) -> None:
    output = tmp_path / EXPECTED_OUTPUT_RUN_ID
    first = preflight_manifest(
        MANIFEST_PATH, project_root=PROJECT_ROOT, output_root=output
    )
    output.mkdir()
    (output / "run_metadata.json").write_text(
        json.dumps(first["run_metadata"]), encoding="utf-8"
    )
    (output / "et-2044143").mkdir()
    (output / "et-2044143/results.jsonl").write_text("{}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="--resume"):
        preflight_manifest(
            MANIFEST_PATH, project_root=PROJECT_ROOT, output_root=output
        )

    resumed = preflight_manifest(
        MANIFEST_PATH,
        project_root=PROJECT_ROOT,
        output_root=output,
        resume=True,
    )
    assert resumed["run_metadata"] == first["run_metadata"]


def test_preflight_rejects_incompatible_resume_metadata(tmp_path: Path) -> None:
    output = tmp_path / EXPECTED_OUTPUT_RUN_ID
    expected = preflight_manifest(
        MANIFEST_PATH, project_root=PROJECT_ROOT, output_root=output
    )
    output.mkdir()
    incompatible = {**expected["run_metadata"], "attacker_model": "other-model"}
    (output / "run_metadata.json").write_text(
        json.dumps(incompatible), encoding="utf-8"
    )
    before = (output / "run_metadata.json").read_bytes()

    with pytest.raises(ValueError, match="metadata mismatch"):
        preflight_manifest(
            MANIFEST_PATH,
            project_root=PROJECT_ROOT,
            output_root=output,
            resume=True,
        )

    assert (output / "run_metadata.json").read_bytes() == before


def test_launch_command_is_exact_safe_and_preserves_pipeline_exit_status() -> None:
    command = render_launch_command(project_root=PROJECT_ROOT)

    assert "tmux new-session -d -s mutation-clue-singles-v1" in command
    assert "mkdir -p" in command
    assert str(PROJECT_ROOT.resolve()) in command
    assert "TMPDIR=" in command
    assert ".venv/bin/python" in command
    assert "--experiment-manifest" in command
    assert "--run-id dataset-clue-targeted-singles-v1" in command
    assert "--attacker-model gpt-5.5" in command
    assert "--attacker-trials 3" in command
    assert "set -o pipefail" in command
    # With pipefail set, plain `$?` after `... | tee log` already reflects
    # either side's failure (the rightmost non-zero, or python's if tee
    # succeeds) - PIPESTATUS[0] would have silently ignored a tee failure.
    assert "code=$?" in command
    assert "PIPESTATUS" not in command
    assert "EXIT:" in command
    assert "--resume" not in command


def test_launch_command_writes_logs_outside_runs_mutations() -> None:
    command = render_launch_command(project_root=PROJECT_ROOT)

    assert "runs/mutations" not in command
    assert ".tmp/launch-logs" in command


def test_resume_launch_command_adds_resume_flag_and_a_distinct_log() -> None:
    first = render_launch_command(project_root=PROJECT_ROOT)
    resumed = render_launch_command(project_root=PROJECT_ROOT, resume=True)

    assert "--resume" not in first
    assert " --resume" in resumed
    # A resume must never overwrite the original launch's log: the diagnostic
    # history of what failed and why is exactly what motivated the resume.
    assert "dataset-clue-targeted-singles-v1.log" in first
    assert "dataset-clue-targeted-singles-v1-resume.log" in resumed
    assert "dataset-clue-targeted-singles-v1.log" not in resumed.replace(
        "dataset-clue-targeted-singles-v1-resume.log", ""
    )
    # Same session, same manifest, same model/trial contract in both.
    for shared in (
        "tmux new-session -d -s mutation-clue-singles-v1",
        "--experiment-manifest",
        "--attacker-model gpt-5.5",
        "--attacker-trials 3",
        "--dataset-fixtures",
    ):
        assert shared in first and shared in resumed


def test_render_review_is_identical_for_a_fresh_and_a_disk_round_tripped_manifest() -> None:
    """write_manifest serializes with sort_keys=True, which reorders every
    dict's keys alphabetically on disk. render_review must render the same
    text whether it is handed the freshly built manifest or the same manifest
    after a json.dumps/json.loads round trip, or review.md's exact text would
    depend on which path last regenerated it."""
    from hardening_game.mutations.clue_manifest import render_review

    fresh = build_manifest(project_root=PROJECT_ROOT)
    round_tripped = json.loads(json.dumps(fresh, sort_keys=True))

    assert render_review(fresh, project_root=PROJECT_ROOT) == render_review(
        round_tripped, project_root=PROJECT_ROOT
    )


def test_committed_review_is_the_canonical_render_of_the_committed_manifest() -> None:
    """Pins regeneration: the committed review.md must be exactly what render_review
    produces from the committed manifest today, not a stale snapshot from an
    earlier candidate set or an earlier disk-space reading."""
    from hardening_game.mutations.clue_manifest import render_review

    manifest = load_manifest(MANIFEST_PATH, project_root=PROJECT_ROOT)
    review_path = PROJECT_ROOT / "experiments/single-clue-targeted-v1/review.md"
    expected = render_review(manifest, project_root=PROJECT_ROOT) + "\n"

    assert review_path.read_text(encoding="utf-8") == expected


def test_render_review_is_independent_of_the_current_working_directory(
    tmp_path: Path,
) -> None:
    import os

    from hardening_game.mutations.clue_manifest import build_manifest, render_review

    manifest = build_manifest(project_root=PROJECT_ROOT)
    previous_cwd = Path.cwd()
    os.chdir(tmp_path)
    try:
        from_elsewhere = render_review(manifest, project_root=PROJECT_ROOT)
    finally:
        os.chdir(previous_cwd)
    from_project_root = render_review(manifest, project_root=PROJECT_ROOT)

    assert from_elsewhere == from_project_root
