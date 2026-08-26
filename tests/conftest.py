"""Public-repo test adaptations for intentionally omitted private run trees."""

from __future__ import annotations

from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
_HAS_COMPONENT_V2 = (
    PROJECT_ROOT / "runs/mutations/dataset-component-mutations-v2"
).is_dir()
_HAS_BASELINE_V2 = (
    PROJECT_ROOT / "runs/mutations/dataset-clue-baseline-v2"
).is_dir()
_HAS_BENIGN_CACHE = (PROJECT_ROOT / "online_benign_pcaps").is_dir()

# Historical experiment trees are intentionally excluded from the public
# showcase repository. Skip only the locked-regression tests that require them.
_COMPONENT_V2_TESTS = {
    "test_locked_generic_candidate_ids_and_fingerprints_survive",
    "test_locked_run_covers_every_generic_candidate_of_every_fixture",
    "test_targeted_candidate_ids_do_not_collide_with_locked_ids",
    "test_every_locked_rejection_regenerates_and_no_generic_rejection_appeared",
    "test_generate_combinations_persists_conflicts_as_rejections",
    "test_fully_disjoint_fixture_accepts_every_subset",
    "test_locked_fixture_generation_is_deterministic",
    "test_locked_fixture_candidates_are_valid_and_traceable",
    "test_locked_fixture_subsets_are_exhaustive",
    "test_every_locked_candidate_carries_its_source_block_categories",
    "test_generate_manifest_combinations_pins_the_locked_generation",
    "test_generation_is_pinned_across_interpreter_hash_seeds",
    "test_locked_fixture_candidates_differ_from_every_source_rule",
    "test_locked_manifest_resolves_all_fixture_sources",
    "test_all_57_v2_trials_are_included_in_deterministic_mapping_audit",
}
_BASELINE_V2_TESTS = {
    "test_built_manifest_selects_exactly_locked_generic_and_targeted_candidates",
    "test_baseline_candidate_is_first_for_every_fixture",
    "test_locked_manifest_validates_current_bytes_and_major_coverage",
    "test_current_manifest_resolves_exact_candidate_objects",
    "test_loader_rejects_candidate_rule_drift_before_any_output_write",
    "test_preflight_refuses_populated_output_without_compatible_metadata",
    "test_preflight_refuses_non_resume_duplicate_launch",
    "test_preflight_rejects_incompatible_resume_metadata",
    "test_render_review_is_identical_for_a_fresh_and_a_disk_round_tripped_manifest",
    "test_committed_review_is_the_canonical_render_of_the_committed_manifest",
    "test_render_review_is_independent_of_the_current_working_directory",
}
_BENIGN_CACHE_TESTS = {
    "test_committed_benign_corpus_is_fully_present_and_valid",
}


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    skip_component = pytest.mark.skip(
        reason="historical dataset-component-mutations-v2 run not shipped publicly"
    )
    skip_baseline = pytest.mark.skip(
        reason="historical dataset-clue-baseline-v2 review packet not shipped publicly"
    )
    skip_benign = pytest.mark.skip(
        reason="downloaded benign PCAP cache is optional; use benign_sources/download script"
    )
    for item in items:
        name = item.name.split("[", 1)[0]
        if not _HAS_COMPONENT_V2 and name in _COMPONENT_V2_TESTS:
            item.add_marker(skip_component)
        if not _HAS_BASELINE_V2 and name in _BASELINE_V2_TESTS:
            item.add_marker(skip_baseline)
        if not _HAS_BENIGN_CACHE and name in _BENIGN_CACHE_TESTS:
            item.add_marker(skip_benign)
