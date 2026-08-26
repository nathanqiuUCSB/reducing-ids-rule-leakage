import hashlib
import json
import os
import subprocess
import sys
from itertools import combinations
from pathlib import Path

import pytest

from hardening_game.mutations.combination_manifest import (
    load_combination_manifest,
    manifest_hash,
)
from hardening_game.mutations.combiner import (
    CombinationBlock,
    CombinationConflict,
    OptionEdit,
    compose_combination,
    compose_rule,
    derive_edits,
    generate_combinations,
    generate_fixture_combinations,
    generate_manifest_combinations,
    load_fixture_sources,
    structural_preflight,
    verify_edits,
)
from hardening_game.mutations.taxonomy import classify_mutation_category
from hardening_game.suricata import rule_model
from hardening_game.suricata.rule_model import parse_suricata_rule


PROJECT_ROOT = Path(__file__).parents[1]
MANIFEST_PATH = PROJECT_ROOT / "experiments/combination-hybrid-v1/manifest.json"
MANIFEST_FIXTURES = (
    "et-2052951",
    "et-2059741",
    "et-2050340",
    "et-2057330",
    "et-2060144",
    "et-2067354",
    "et-2060086",
)
LOCKED_MANIFEST_HASH = (
    "25b628b697d244097ff76ab4961a924a746073d3336724bc341211c65cd6f91a"
)
LOCKED_GENERATION_DIGEST = (
    "5c07c7aec3e88e0f771fd12fe0e75b40f0c50fcfd3d6e1a202c046229b676b93"
)
LOCKED_ET_2057330_DIGEST = (
    "0f8cedb5867fee62e4b36fc4d516b9a9957f18536d1166003b1d6684b064bd91"
)
LOCKED_ACCEPTED = 432
LOCKED_REJECTED = 16

BASELINE = (
    "alert tcp any any -> $HOME_NET 80 ( flow:established,to_server; http.uri; "
    'content:"/admin"; nocase; content:"token"; distance:0; sid:1000001; rev:1;)'
)


def _block(candidate_id: str, rule: str, **overrides: str) -> CombinationBlock:
    return CombinationBlock(
        candidate_id=candidate_id,
        component=overrides.get("component", "content"),
        operator=overrides.get("operator", "shorten_suffix"),
        description=overrides.get("description", candidate_id),
        rule=rule,
    )


FLOW_BLOCK = _block(
    "fixture-flow-remove-000000000001",
    "alert tcp any any -> $HOME_NET 80 ( http.uri; "
    'content:"/admin"; nocase; content:"token"; distance:0; sid:1000001; rev:2;)',
    component="flow",
    operator="remove",
)
URI_BLOCK = _block(
    "fixture-content-shorten_suffix-000000000002",
    "alert tcp any any -> $HOME_NET 80 ( flow:established,to_server; http.uri; "
    'content:"/adm"; nocase; content:"token"; distance:0; sid:1000001; rev:3;)',
)
REMOVE_CONTENT = _block(
    "fixture-content-remove-000000000003",
    "alert tcp any any -> $HOME_NET 80 ( flow:established,to_server; http.uri; "
    'content:"token"; distance:0; sid:1000001; rev:4;)',
    operator="remove",
)
SHORTEN_SAME_CONTENT = URI_BLOCK
RELATIVE_BLOCK = _block(
    "fixture-relative_constraint-remove-000000000004",
    "alert tcp any any -> $HOME_NET 80 ( flow:established,to_server; http.uri; "
    'content:"/admin"; nocase; content:"token"; sid:1000001; rev:5;)',
    component="relative_constraint",
    operator="remove",
)
MODIFIER_BLOCK = _block(
    "fixture-content_modifier-remove_nocase-000000000005",
    "alert tcp any any -> $HOME_NET 80 ( flow:established,to_server; http.uri; "
    'content:"/admin"; content:"token"; distance:0; sid:1000001; rev:6;)',
    component="content_modifier",
    operator="remove_nocase",
)
MULTI_WINDOW_BLOCK = _block(
    "fixture-multi-window-000000000006",
    "alert tcp any any -> $HOME_NET 80 ( flow:established; http.uri; "
    'content:"/admin"; nocase; content:"tok"; distance:0; sid:1000001; rev:7;)',
    component="multi",
    operator="two_windows",
)
REMOVE_TOKEN_BLOCK = _block(
    "fixture-content-remove-000000000014",
    "alert tcp any any -> $HOME_NET 80 ( flow:established,to_server; http.uri; "
    'content:"/admin"; nocase; sid:1000001; rev:10;)',
    operator="remove",
)
INSERT_NOCASE_BLOCK = _block(
    "fixture-content_modifier-add_nocase-000000000007",
    "alert tcp any any -> $HOME_NET 80 ( flow:established,to_server; http.uri; "
    'content:"/admin"; nocase; content:"token"; nocase; distance:0; '
    "sid:1000001; rev:8;)",
    component="content_modifier",
    operator="add_nocase",
)
INSERT_RAWBYTES_BLOCK = _block(
    "fixture-content_modifier-add_rawbytes-000000000008",
    "alert tcp any any -> $HOME_NET 80 ( flow:established,to_server; http.uri; "
    'content:"/admin"; nocase; content:"token"; rawbytes; distance:0; '
    "sid:1000001; rev:9;)",
    component="content_modifier",
    operator="add_rawbytes",
)

AMBIGUOUS_BASELINE = (
    "alert tcp any any -> $HOME_NET 80 ( flow:established,to_server; "
    'content:"AAA"; content:"AAA"; sid:1000002; rev:1;)'
)
AMBIGUOUS_BLOCK = _block(
    "fixture-content-remove-000000000009",
    "alert tcp any any -> $HOME_NET 80 ( flow:established,to_server; "
    'content:"AAA"; sid:1000002; rev:2;)',
    operator="remove",
)
AMBIGUOUS_FLOW_BLOCK = _block(
    "fixture-flow-remove-000000000010",
    'alert tcp any any -> $HOME_NET 80 ( content:"AAA"; content:"AAA"; '
    "sid:1000002; rev:3;)",
    component="flow",
    operator="remove",
)


UNCLOSED_BLOCK = _block(
    "fixture-unclosed-000000000016",
    "alert tcp any any -> $HOME_NET 80 ( flow:established,to_server; http.uri; "
    'content:"/admin"; nocase; content:"token"; distance:0; sid:1000001; rev:11;',
    component="malformed",
    operator="drop_option_block_close",
)
ESCAPED_CONTENT_RULE = (
    'alert tcp any any -> $HOME_NET 80 ( content:"a\\;b|41 42|"; sid:1; rev:1;)'
)


def _generation_digest(sets) -> tuple[int, int, str]:
    digest = hashlib.sha256()
    accepted = rejected = 0
    for combination_set in sets:
        for candidate in combination_set.accepted:
            digest.update((candidate.id + "\x00" + candidate.rule + "\x00").encode())
            accepted += 1
        for rejection in combination_set.rejected:
            digest.update((rejection.id + "\x00" + rejection.reason + "\x00").encode())
            rejected += 1
    return accepted, rejected, digest.hexdigest()


_SUBPROCESS_DIGEST_SCRIPT = """
import hashlib
import json
import sys
from pathlib import Path

from hardening_game.mutations.combination_manifest import (
    load_combination_manifest,
    manifest_hash,
)
from hardening_game.mutations.combiner import generate_fixture_combinations

root = Path(sys.argv[1])
fixture = sys.argv[2]
manifest = load_combination_manifest(
    root / "experiments/combination-hybrid-v1/manifest.json", project_root=root
)
generated = generate_fixture_combinations(
    fixture, manifest=manifest, project_root=root
)
digest = hashlib.sha256()
for candidate in generated.accepted:
    digest.update((candidate.id + "\\x00" + candidate.rule + "\\x00").encode())
for rejection in generated.rejected:
    digest.update((rejection.id + "\\x00" + rejection.reason + "\\x00").encode())
print(
    json.dumps(
        {
            "accepted": len(generated.accepted),
            "rejected": len(generated.rejected),
            "digest": digest.hexdigest(),
            "manifest_hash": manifest_hash(manifest),
        }
    )
)
"""


def _manifest():
    return load_combination_manifest(MANIFEST_PATH, project_root=PROJECT_ROOT)


def _fixture_set(fixture: str):
    return generate_fixture_combinations(
        fixture, manifest=_manifest(), project_root=PROJECT_ROOT
    )


def test_non_overlapping_mutations_are_order_independent() -> None:
    left = compose_rule(BASELINE, [FLOW_BLOCK, URI_BLOCK], revision=9)
    right = compose_rule(BASELINE, [URI_BLOCK, FLOW_BLOCK], revision=9)
    assert left == right
    assert left == (
        "alert tcp any any -> $HOME_NET 80 ( http.uri; "
        'content:"/adm"; nocase; content:"token"; distance:0; '
        "sid:1000001; rev:9;)"
    )


def test_overlapping_baseline_spans_are_rejected() -> None:
    with pytest.raises(CombinationConflict) as error:
        compose_rule(BASELINE, [REMOVE_CONTENT, SHORTEN_SAME_CONTENT], revision=9)
    assert error.value.reason == "overlapping_edit"


def test_competing_insertions_at_the_same_position_are_rejected() -> None:
    with pytest.raises(CombinationConflict) as error:
        compose_rule(
            BASELINE, [INSERT_NOCASE_BLOCK, INSERT_RAWBYTES_BLOCK], revision=9
        )
    assert error.value.reason == "competing_insertion"


def test_composition_is_baseline_relative_not_sequential() -> None:
    composed = compose_rule(
        BASELINE, [FLOW_BLOCK, URI_BLOCK, RELATIVE_BLOCK], revision=11
    )
    assert composed == (
        "alert tcp any any -> $HOME_NET 80 ( http.uri; "
        'content:"/adm"; nocase; content:"token"; sid:1000001; rev:11;)'
    )
    # Deriving a block against an already-mutated rule reinstates whatever that
    # rule removed, so every edit is re-derived from the baseline instead.
    against_mutated = derive_edits(FLOW_BLOCK.rule, URI_BLOCK.rule)
    assert any(
        "flow:established,to_server;" in edit.replacement for edit in against_mutated
    )


@pytest.mark.parametrize("size", [0, 1, 9])
def test_combination_size_must_be_between_two_and_eight(size: int) -> None:
    blocks = [
        _block(f"fixture-block-{index}", BASELINE.replace("rev:1;", f"rev:{index + 2};"))
        for index in range(size)
    ]
    with pytest.raises(CombinationConflict) as error:
        compose_rule(BASELINE, blocks, revision=9)
    assert error.value.reason == "block_count"


def test_composed_rule_carries_one_deterministic_revision() -> None:
    composed = compose_rule(BASELINE, [FLOW_BLOCK, URI_BLOCK], revision=42)
    assert composed.count("rev:") == 1
    assert "rev:42;" in composed


def test_derive_edits_returns_baseline_relative_option_aligned_spans() -> None:
    edits = derive_edits(BASELINE, FLOW_BLOCK.rule)
    normalized_baseline = BASELINE.replace("rev:1;", "rev:0;")
    assert len(edits) == 1
    edit = edits[0]
    assert isinstance(edit, OptionEdit)
    assert normalized_baseline[edit.start : edit.end] == " flow:established,to_server;"
    assert edit.replacement == ""


def test_derive_edits_splits_independent_windows() -> None:
    edits = derive_edits(BASELINE, MULTI_WINDOW_BLOCK.rule)
    normalized_baseline = BASELINE.replace("rev:1;", "rev:0;")
    assert [
        (normalized_baseline[edit.start : edit.end], edit.replacement)
        for edit in edits
    ] == [
        (" flow:established,to_server;", " flow:established;"),
        (' content:"token";', ' content:"tok";'),
    ]


def test_multi_window_edits_still_detect_competing_edits() -> None:
    with pytest.raises(CombinationConflict) as error:
        compose_rule(BASELINE, [MULTI_WINDOW_BLOCK, FLOW_BLOCK], revision=9)
    assert error.value.reason == "competing_edit"


def test_multi_window_edits_still_detect_overlap() -> None:
    with pytest.raises(CombinationConflict) as error:
        compose_rule(BASELINE, [MULTI_WINDOW_BLOCK, REMOVE_TOKEN_BLOCK], revision=9)
    assert error.value.reason == "overlapping_edit"


def test_ambiguous_repeated_substring_edit_is_rejected() -> None:
    with pytest.raises(CombinationConflict) as error:
        derive_edits(AMBIGUOUS_BASELINE, AMBIGUOUS_BLOCK.rule)
    assert error.value.reason == "ambiguous_edit"

    with pytest.raises(CombinationConflict) as conflict:
        compose_rule(
            AMBIGUOUS_BASELINE,
            [AMBIGUOUS_BLOCK, AMBIGUOUS_FLOW_BLOCK],
            revision=9,
        )
    assert conflict.value.reason == "ambiguous_edit"


def test_identical_edits_from_two_blocks_are_not_treated_as_conflicts() -> None:
    twin = _block("fixture-content-shorten_suffix-000000000011", URI_BLOCK.rule)
    composed = compose_rule(BASELINE, [URI_BLOCK, twin], revision=9)
    assert composed == (
        "alert tcp any any -> $HOME_NET 80 ( flow:established,to_server; http.uri; "
        'content:"/adm"; nocase; content:"token"; distance:0; sid:1000001; rev:9;)'
    )


def test_repeating_one_block_in_a_subset_is_rejected() -> None:
    with pytest.raises(CombinationConflict) as error:
        compose_rule(BASELINE, [FLOW_BLOCK, FLOW_BLOCK], revision=9)
    assert error.value.reason == "duplicate_block"
    assert FLOW_BLOCK.candidate_id in error.value.detail


def test_edits_that_do_not_reproduce_the_candidate_are_underivable() -> None:
    derived = derive_edits(BASELINE, FLOW_BLOCK.rule)
    verify_edits(BASELINE, FLOW_BLOCK.rule, derived)

    truncated = tuple(
        OptionEdit(edit.start, edit.end - 1, edit.replacement) for edit in derived
    )
    with pytest.raises(CombinationConflict) as error:
        verify_edits(BASELINE, FLOW_BLOCK.rule, truncated)
    assert error.value.reason == "underivable_edit"

    with pytest.raises(CombinationConflict) as dropped:
        verify_edits(BASELINE, FLOW_BLOCK.rule, ())
    assert dropped.value.reason == "underivable_edit"


def test_unparseable_composition_is_caught_by_structural_preflight() -> None:
    with pytest.raises(CombinationConflict) as error:
        compose_combination(
            BASELINE,
            [UNCLOSED_BLOCK, FLOW_BLOCK],
            fixture_name="fixture",
            revision=9,
            experiment_manifest_hash="deadbeef",
        )
    assert error.value.reason == "preflight_failed"
    assert "rule_parses" in error.value.detail


def test_compose_rule_rejects_a_candidate_equal_to_the_baseline() -> None:
    unchanged = _block("fixture-noop-000000000012", BASELINE.replace("rev:1;", "rev:7;"))
    with pytest.raises(CombinationConflict) as error:
        compose_rule(BASELINE, [unchanged, FLOW_BLOCK], revision=9)
    assert error.value.reason == "no_effect"


def test_compose_combination_id_is_a_stable_order_independent_hash() -> None:
    left = compose_combination(
        BASELINE,
        [FLOW_BLOCK, URI_BLOCK],
        fixture_name="fixture",
        revision=9,
        experiment_manifest_hash="deadbeef",
    )
    right = compose_combination(
        BASELINE,
        [URI_BLOCK, FLOW_BLOCK],
        fixture_name="fixture",
        revision=9,
        experiment_manifest_hash="deadbeef",
    )
    assert left == right
    assert left.source_candidate_ids == tuple(
        sorted((FLOW_BLOCK.candidate_id, URI_BLOCK.candidate_id))
    )
    assert left.block_count == 2
    assert left.experiment_manifest_hash == "deadbeef"
    assert left.id.startswith("fixture-combination-2-")
    assert len(left.id.rsplit("-", 1)[1]) == 12


def test_compose_combination_rejects_duplicate_fingerprints() -> None:
    accepted = compose_combination(
        BASELINE,
        [FLOW_BLOCK, URI_BLOCK],
        fixture_name="fixture",
        revision=9,
        experiment_manifest_hash="deadbeef",
    )
    with pytest.raises(CombinationConflict) as error:
        compose_combination(
            BASELINE,
            [URI_BLOCK, FLOW_BLOCK],
            fixture_name="fixture",
            revision=10,
            experiment_manifest_hash="deadbeef",
            known_fingerprints={accepted.fingerprint: accepted.id},
        )
    assert error.value.reason == "duplicate_fingerprint"


def test_compose_combination_rejects_structural_preflight_failures() -> None:
    stripped = _block(
        "fixture-content-remove_all-000000000013",
        "alert tcp any any -> $HOME_NET 80 ( flow:established,to_server; http.uri; "
        "nocase; content:\"token\"; distance:0; sid:1000001; rev:4;)",
        operator="remove_value",
    )
    with pytest.raises(CombinationConflict) as error:
        compose_combination(
            BASELINE,
            [stripped, RELATIVE_BLOCK],
            fixture_name="fixture",
            revision=9,
            experiment_manifest_hash="deadbeef",
        )
    assert error.value.reason == "preflight_failed"
    assert "modifiers_bound_to_content" in error.value.detail


def test_combiner_reuses_the_parser_domain_definitions() -> None:
    from hardening_game.mutations import combiner

    assert combiner.CONTENT_MODIFIERS is rule_model.CONTENT_MODIFIERS
    assert combiner.CONTENT_OPTION is rule_model.CONTENT_OPTION
    assert combiner.is_relative_consumer is rule_model.is_relative_consumer
    assert combiner.decode_content is rule_model.decode_content


def test_escaped_content_is_structurally_valid_although_the_parser_declines_it() -> None:
    predicate = parse_suricata_rule(ESCAPED_CONTENT_RULE).sticky_groups[0].predicates[0]
    assert predicate.value is None
    assert predicate.representation == "mixed"

    result = structural_preflight(ESCAPED_CONTENT_RULE)
    assert result.passed, result.failures


def test_structural_preflight_accepts_a_well_formed_rule() -> None:
    result = structural_preflight(BASELINE, expected_sid="1000001")
    assert result.passed
    assert result.failures == ()
    assert "detection_predicate_present" in result.checks


@pytest.mark.parametrize(
    ("rule", "failure"),
    [
        (
            "alert tcp any any -> $HOME_NET 80 ( flow:established,to_server; "
            "nocase; sid:1; rev:1;)",
            "modifiers_bound_to_content",
        ),
        (
            'alert tcp any any -> $HOME_NET 80 ( content:""; sid:1; rev:1;)',
            "content_values_valid",
        ),
        (
            'alert tcp any any -> $HOME_NET 80 ( content:"|zz|"; sid:1; rev:1;)',
            "content_values_valid",
        ),
        (
            "alert tcp any any -> $HOME_NET 80 ( flow:established; sid:1; rev:1;)",
            "detection_predicate_present",
        ),
        (
            "alert tcp any any -> $HOME_NET 80 ( flow:established; "
            'content:"a"; sid:1; sid:2; rev:1;)',
            "sid_present_once",
        ),
        (
            "alert tcp any any -> $HOME_NET 80 ( flow:established; "
            'content:"a"; byte_test:1,=,1,0,relative; sid:1; rev:1;)',
            "",
        ),
    ],
)
def test_structural_preflight_reports_named_failures(rule: str, failure: str) -> None:
    result = structural_preflight(rule)
    if failure:
        assert not result.passed
        assert failure in result.failures
    else:
        assert result.passed, result.failures


def test_structural_preflight_reports_dangling_relative_options() -> None:
    result = structural_preflight(
        "alert tcp any any -> $HOME_NET 80 ( flow:established; "
        "byte_test:1,=,1,0,relative; content:\"a\"; sid:1; rev:1;)"
    )
    assert not result.passed
    assert "relative_options_bound_to_content" in result.failures


def test_generate_combinations_persists_conflicts_as_rejections() -> None:
    sources = load_fixture_sources(
        "et-2057330", manifest=_manifest(), project_root=PROJECT_ROOT
    )
    generated = generate_combinations(
        sources, experiment_manifest_hash=manifest_hash(_manifest())
    )
    total = sum(
        1
        for size in range(2, len(sources.blocks) + 1)
        for _ in combinations(sources.blocks, size)
    )
    assert len(generated.accepted) + len(generated.rejected) == total
    assert any(
        rejection.reason == "overlapping_edit" for rejection in generated.rejected
    )
    accepted_ids = {candidate.id for candidate in generated.accepted}
    rejected_ids = {rejection.id for rejection in generated.rejected}
    assert not accepted_ids & rejected_ids
    assert len(accepted_ids) == len(generated.accepted)
    assert len(rejected_ids) == len(generated.rejected)
    assert all(
        rejection.reason
        in {
            "ambiguous_edit",
            "block_count",
            "competing_edit",
            "competing_insertion",
            "duplicate_block",
            "duplicate_fingerprint",
            "no_effect",
            "overlapping_edit",
            "preflight_failed",
            "underivable_edit",
        }
        for rejection in generated.rejected
    )


def test_fully_disjoint_fixture_accepts_every_subset() -> None:
    generated = _fixture_set("et-2060144")
    assert len(generated.accepted) == 11
    assert generated.rejected == ()
    assert sorted(candidate.block_count for candidate in generated.accepted) == [
        2,
        2,
        2,
        2,
        2,
        2,
        3,
        3,
        3,
        3,
        4,
    ]


@pytest.mark.parametrize("fixture", MANIFEST_FIXTURES)
def test_locked_fixture_generation_is_deterministic(fixture: str) -> None:
    first = _fixture_set(fixture)
    second = _fixture_set(fixture)
    assert [candidate.id for candidate in first.accepted] == [
        candidate.id for candidate in second.accepted
    ]
    assert [candidate.rule for candidate in first.accepted] == [
        candidate.rule for candidate in second.accepted
    ]
    assert [candidate.fingerprint for candidate in first.accepted] == [
        candidate.fingerprint for candidate in second.accepted
    ]
    assert [rejection.id for rejection in first.rejected] == [
        rejection.id for rejection in second.rejected
    ]
    assert [rejection.reason for rejection in first.rejected] == [
        rejection.reason for rejection in second.rejected
    ]


@pytest.mark.parametrize("fixture", MANIFEST_FIXTURES)
def test_locked_fixture_candidates_are_valid_and_traceable(fixture: str) -> None:
    manifest = _manifest()
    expected_hash = manifest_hash(manifest)
    locked_blocks = set(manifest.selected_blocks(fixture))
    generated = _fixture_set(fixture)
    assert generated.accepted, f"no accepted combinations for {fixture}"
    fingerprints = set()
    for candidate in generated.accepted:
        assert 2 <= candidate.block_count <= 8
        assert candidate.block_count == len(candidate.source_candidate_ids)
        assert set(candidate.source_candidate_ids) <= locked_blocks
        assert candidate.source_candidate_ids == tuple(
            sorted(candidate.source_candidate_ids)
        )
        assert candidate.experiment_manifest_hash == expected_hash
        assert candidate.fixture_name == fixture
        parse_suricata_rule(candidate.rule)
        preflight = structural_preflight(candidate.rule)
        assert preflight.passed, (candidate.id, preflight.failures)
        assert candidate.fingerprint not in fingerprints
        fingerprints.add(candidate.fingerprint)
    for rejection in generated.rejected:
        assert set(rejection.source_candidate_ids) <= locked_blocks
        assert rejection.experiment_manifest_hash == expected_hash
        assert rejection.diagnostic


@pytest.mark.parametrize("fixture", MANIFEST_FIXTURES)
def test_locked_fixture_subsets_are_exhaustive(fixture: str) -> None:
    manifest = _manifest()
    blocks = manifest.selected_blocks(fixture)
    generated = _fixture_set(fixture)
    expected = {
        tuple(sorted(subset))
        for size in range(2, min(len(blocks), 8) + 1)
        for subset in combinations(blocks, size)
    }
    produced = {
        candidate.source_candidate_ids for candidate in generated.accepted
    } | {rejection.source_candidate_ids for rejection in generated.rejected}
    assert produced == expected


def test_every_locked_candidate_carries_its_source_block_categories() -> None:
    manifest = _manifest()
    allowed = {"semantic", "representation", "performance"}
    for fixture in MANIFEST_FIXTURES:
        sources = load_fixture_sources(
            fixture, manifest=manifest, project_root=PROJECT_ROOT
        )
        block_categories = {
            block.candidate_id: classify_mutation_category(
                component=block.component,
                operator=block.operator,
                params=dict(block.params),
            )
            for block in sources.blocks
        }
        generated = generate_fixture_combinations(
            fixture, manifest=manifest, project_root=PROJECT_ROOT
        )
        for candidate in generated.accepted:
            categories = candidate.params["source_categories"]
            assert isinstance(categories, list)
            assert set(categories) <= allowed
            assert categories == [
                block_categories[candidate_id]
                for candidate_id in candidate.source_candidate_ids
            ]
            assert len(categories) == candidate.block_count
            assert classify_mutation_category(
                component=candidate.component,
                operator=candidate.operator,
                params=dict(candidate.params),
            ) in allowed


def test_mixed_category_combination_keeps_every_source_category() -> None:
    representation = CombinationBlock(
        candidate_id="et-x-content-literal_as_hex-1",
        component="content",
        operator="literal_as_hex",
        description="Re-encode a literal as hex.",
        rule=BASELINE.replace('content:"/admin"', 'content:"|2f 61 64 6d 69 6e|"'),
        params={},
    )
    semantic = CombinationBlock(
        candidate_id="et-x-flow-remove-2",
        component="flow",
        operator="remove",
        description="Remove the flow option.",
        rule=BASELINE.replace(" flow:established,to_server;", ""),
        params={},
    )

    candidate = compose_combination(
        BASELINE,
        [representation, semantic],
        fixture_name="et-x",
        revision=9,
        experiment_manifest_hash="0" * 64,
    )

    assert candidate.params["source_categories"] == ["representation", "semantic"]
    assert (
        classify_mutation_category(
            component=candidate.component,
            operator=candidate.operator,
            params=dict(candidate.params),
        )
        == "semantic"
    )


def test_generate_manifest_combinations_pins_the_locked_generation() -> None:
    manifest = _manifest()
    generated = generate_manifest_combinations(
        manifest=manifest, project_root=PROJECT_ROOT
    )
    assert [combination_set.fixture_name for combination_set in generated] == list(
        MANIFEST_FIXTURES
    )
    assert all(
        combination_set.experiment_manifest_hash == LOCKED_MANIFEST_HASH
        for combination_set in generated
    )
    assert _generation_digest(generated) == (
        LOCKED_ACCEPTED,
        LOCKED_REJECTED,
        LOCKED_GENERATION_DIGEST,
    )


@pytest.mark.parametrize("hash_seed", ["0", "524287"])
def test_generation_is_pinned_across_interpreter_hash_seeds(hash_seed: str) -> None:
    environment = {
        **os.environ,
        "PYTHONHASHSEED": hash_seed,
        "PYTHONPATH": str(PROJECT_ROOT),
    }
    completed = subprocess.run(
        [sys.executable, "-c", _SUBPROCESS_DIGEST_SCRIPT, str(PROJECT_ROOT), "et-2057330"],
        capture_output=True,
        text=True,
        timeout=300,
        env=environment,
        cwd=str(PROJECT_ROOT),
    )
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout.splitlines()[-1]) == {
        "accepted": 41,
        "rejected": 16,
        "digest": LOCKED_ET_2057330_DIGEST,
        "manifest_hash": LOCKED_MANIFEST_HASH,
    }


def test_locked_fixture_candidates_differ_from_every_source_rule() -> None:
    manifest = _manifest()
    for fixture in MANIFEST_FIXTURES:
        sources = load_fixture_sources(
            fixture, manifest=manifest, project_root=PROJECT_ROOT
        )
        source_rules = {sources.baseline_rule, *(block.rule for block in sources.blocks)}
        generated = generate_fixture_combinations(
            fixture, manifest=manifest, project_root=PROJECT_ROOT
        )
        for candidate in generated.accepted:
            assert candidate.rule not in source_rules
            assert candidate.rule.count("rev:") == 1
            assert f"sid:{fixture.split('-')[1]};" in candidate.rule.replace(" ", "")
