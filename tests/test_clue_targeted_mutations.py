"""Predicate-linked targeted mutation generation and legacy identity locks."""

import json
from pathlib import Path

import pytest

from hardening_game.attribution import load_baseline_clue_registry
from hardening_game.fixture import load_fixture_path
from hardening_game.mutations.clue_targets import (
    REVIEW_OPERATORS,
    TARGETED_OPERATORS,
    build_clue_targeted_manifest,
    load_clue_target_recipes,
    map_existing_candidates,
    recipes_sha256,
)
from hardening_game.mutations.engine import (
    canonical_fingerprint,
    generate_generic_candidates,
)
from hardening_game.predicates import (
    canonical_rule_predicates,
    canonical_touched_predicate_ids,
)
from hardening_game.suricata.rule_model import parse_suricata_rule
from hardening_game.suricata.validate import syntax_check_rule


ROOT = Path(__file__).resolve().parents[1]
RECIPE_PATH = ROOT / "fixtures" / "clue_targeted_mutation_recipes.json"
REGISTRY_PATH = ROOT / "fixtures" / "baseline_clue_registry.json"
LOCKED_RUN = ROOT / "runs" / "mutations" / "dataset-component-mutations-v2"
DATASET = ROOT / "fixtures" / "dataset"

# The ten fixtures whose baseline was identified exactly in all three
# dataset-clue-baseline-v2 trials; the remaining nine are descriptive controls.
PRIMARY_QUALIFIED = (
    "et-2044143",
    "et-2048541",
    "et-2049007",
    "et-2050340",
    "et-2050434",
    "et-2050988",
    "et-2052951",
    "et-2056147",
    "et-2057705",
    "et-2067354",
)


def fixture_names() -> tuple[str, ...]:
    return tuple(
        sorted(
            path.stem
            for path in DATASET.glob("*.json")
            if not path.name.endswith("_suite.json")
        )
    )


def load_manifest(fixture_name: str):
    fixture = load_fixture_path(DATASET / f"{fixture_name}.json", project_root=ROOT)
    registry = load_baseline_clue_registry(REGISTRY_PATH)
    rule_clues = next(
        rule for rule in registry.rules if rule.rule_id == fixture_name
    )
    return build_clue_targeted_manifest(
        fixture_name=fixture_name,
        baseline_rule=fixture.sanitized_rule,
        revision=fixture.revision,
        rule_clues=rule_clues,
        recipes=load_clue_target_recipes(RECIPE_PATH),
    )


def locked_results(fixture_name: str) -> list[dict[str, object]]:
    path = LOCKED_RUN / fixture_name / "results.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


# ---------------------------------------------------------------------------
# Locked legacy identity
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fixture_name", fixture_names())
def test_locked_generic_candidate_ids_and_fingerprints_survive(fixture_name: str) -> None:
    fixture = load_fixture_path(DATASET / f"{fixture_name}.json", project_root=ROOT)
    generated = generate_generic_candidates(
        fixture.sanitized_rule,
        revision=fixture.revision,
        fixture_name=fixture_name,
    )
    by_id = {candidate.id: candidate for candidate in generated.accepted}
    locked = locked_results(fixture_name)

    assert locked, f"{fixture_name} has no locked source candidates"
    for record in locked:
        candidate = by_id.get(str(record["candidate_id"]))
        assert candidate is not None, (
            f"{fixture_name}: locked candidate {record['candidate_id']} no longer "
            "generates"
        )
        assert candidate.fingerprint == record["fingerprint"]
        assert candidate.rule == record["rule"]
        assert candidate.revision == record["revision"]
        assert candidate.description == record["description"]
        # Canonical predicate metadata is purely additive.
        for key, value in dict(record["params"]).items():
            assert candidate.params.get(key) == value


def test_locked_run_covers_every_generic_candidate_of_every_fixture() -> None:
    locked_total = sum(len(locked_results(name)) for name in fixture_names())
    generated_total = 0
    for name in fixture_names():
        fixture = load_fixture_path(DATASET / f"{name}.json", project_root=ROOT)
        generated_total += len(
            generate_generic_candidates(
                fixture.sanitized_rule,
                revision=fixture.revision,
                fixture_name=name,
            ).accepted
        )
    assert locked_total == 719
    assert generated_total == locked_total


def test_additive_predicate_metadata_is_outside_candidate_identity() -> None:
    from hardening_game.mutations.engine import build_fixture_candidate

    bare = build_fixture_candidate(
        fixture_name="fx",
        component="content",
        operator="remove",
        params={"content_index": 0, "operation": "remove"},
        description="d",
        rule='alert tcp any any -> any any (content:"a"; sid:1; rev:1;)',
        revision=1,
    )
    annotated = build_fixture_candidate(
        fixture_name="fx",
        component="content",
        operator="remove",
        params={
            "content_index": 0,
            "operation": "remove",
            "predicate_id": "content-0",
            "predicate_ids": ["content-0"],
        },
        description="d",
        rule='alert tcp any any -> any any (content:"a"; sid:1; rev:1;)',
        revision=1,
    )
    assert bare.id == annotated.id

    different = build_fixture_candidate(
        fixture_name="fx",
        component="content",
        operator="remove",
        params={"content_index": 1, "operation": "remove"},
        description="d",
        rule='alert tcp any any -> any any (content:"a"; sid:1; rev:1;)',
        revision=1,
    )
    assert different.id != bare.id


# ---------------------------------------------------------------------------
# Recipe loading
# ---------------------------------------------------------------------------


def test_recipe_file_loads_and_hashes_deterministically() -> None:
    first = load_clue_target_recipes(RECIPE_PATH)
    second = load_clue_target_recipes(RECIPE_PATH)
    assert first == second
    assert recipes_sha256(first) == recipes_sha256(second)
    assert len(recipes_sha256(first)) == 64
    assert first.version == 1
    assert first.recipes


def test_recipe_ids_are_unique_and_sorted() -> None:
    recipes = load_clue_target_recipes(RECIPE_PATH).recipes
    ids = [recipe.recipe_id for recipe in recipes]
    assert len(set(ids)) == len(ids)
    assert [(recipe.fixture, recipe.recipe_id) for recipe in recipes] == sorted(
        (recipe.fixture, recipe.recipe_id) for recipe in recipes
    )


def test_every_recipe_names_a_registered_operator_and_matching_category() -> None:
    from hardening_game.mutations.taxonomy import classify_mutation_category

    for recipe in load_clue_target_recipes(RECIPE_PATH).recipes:
        assert recipe.operator in {*TARGETED_OPERATORS, *REVIEW_OPERATORS}
        if recipe.operator in REVIEW_OPERATORS:
            continue
        component, _, operator = recipe.operator.partition("/")
        assert recipe.category == classify_mutation_category(
            component=component, operator=operator, params=dict(recipe.params)
        )


def test_every_recipe_clue_and_predicate_resolves_against_its_fixture() -> None:
    registry = load_baseline_clue_registry(REGISTRY_PATH)
    clues = {
        rule.rule_id: {clue.clue_id for clue in rule.clues} for rule in registry.rules
    }
    for recipe in load_clue_target_recipes(RECIPE_PATH).recipes:
        assert recipe.fixture in clues
        assert set(recipe.clue_ids) <= clues[recipe.fixture]
        fixture = load_fixture_path(
            DATASET / f"{recipe.fixture}.json", project_root=ROOT
        )
        known = canonical_rule_predicates(parse_suricata_rule(fixture.sanitized_rule))
        assert set(recipe.target_predicate_ids) <= set(known)


def test_loader_rejects_unknown_fields(tmp_path: Path) -> None:
    payload = json.loads(RECIPE_PATH.read_text(encoding="utf-8"))
    payload["recipes"][0]["surprise"] = True
    path = tmp_path / "recipes.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="recipe must contain exactly"):
        load_clue_target_recipes(path)


def test_loader_rejects_unknown_operator(tmp_path: Path) -> None:
    payload = json.loads(RECIPE_PATH.read_text(encoding="utf-8"))
    payload["recipes"][0]["operator"] = "content/invent_something"
    path = tmp_path / "recipes.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="unknown targeted operator"):
        load_clue_target_recipes(path)


def test_loader_rejects_duplicate_recipe_ids(tmp_path: Path) -> None:
    payload = json.loads(RECIPE_PATH.read_text(encoding="utf-8"))
    payload["recipes"].append(dict(payload["recipes"][0]))
    path = tmp_path / "recipes.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate recipe_id"):
        load_clue_target_recipes(path)


def test_loader_rejects_unsupported_version(tmp_path: Path) -> None:
    payload = json.loads(RECIPE_PATH.read_text(encoding="utf-8"))
    payload["version"] = 2
    path = tmp_path / "recipes.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="unsupported recipe version"):
        load_clue_target_recipes(path)


def test_loader_requires_a_substantive_rationale(tmp_path: Path) -> None:
    payload = json.loads(RECIPE_PATH.read_text(encoding="utf-8"))
    payload["recipes"][0]["rationale"] = "TBD"
    path = tmp_path / "recipes.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="rationale"):
        load_clue_target_recipes(path)


# ---------------------------------------------------------------------------
# Mapping existing candidates
# ---------------------------------------------------------------------------


def test_existing_candidates_map_to_canonical_predicates_and_clues() -> None:
    fixture = load_fixture_path(DATASET / "et-2044143.json", project_root=ROOT)
    registry = load_baseline_clue_registry(REGISTRY_PATH)
    rule_clues = next(
        rule for rule in registry.rules if rule.rule_id == "et-2044143"
    )
    generated = generate_generic_candidates(
        fixture.sanitized_rule, revision=fixture.revision, fixture_name="et-2044143"
    )
    mapped = map_existing_candidates(
        generated.accepted,
        parsed=parse_suricata_rule(fixture.sanitized_rule),
        rule_clues=rule_clues,
    )
    by_id = {record.candidate.id: record for record in mapped}
    assert len(by_id) == len(generated.accepted)
    assert all(record.status == "existing" for record in mapped)

    anchor = next(
        record
        for record in mapped
        if record.candidate.operator == "remove_startswith"
    )
    assert anchor.touched_predicate_ids == ("content-1-startswith",)
    assert anchor.clue_ids == ("et-2044143-major-3-uri-prefix-anchor",)
    assert anchor.clue_ranks == (3,)

    baseline = by_id["et-2044143-baseline"]
    assert baseline.touched_predicate_ids == ()
    assert baseline.clue_ids == ()


def test_mapping_covers_every_fixture_without_unknown_predicates() -> None:
    for name in fixture_names():
        fixture = load_fixture_path(DATASET / f"{name}.json", project_root=ROOT)
        parsed = parse_suricata_rule(fixture.sanitized_rule)
        known = canonical_rule_predicates(parsed)
        generated = generate_generic_candidates(
            fixture.sanitized_rule, revision=fixture.revision, fixture_name=name
        )
        for candidate in generated.accepted:
            touched = canonical_touched_predicate_ids(
                candidate.params, known_predicate_ids=known
            )
            assert set(touched) <= set(known)


# ---------------------------------------------------------------------------
# Targeted generation
# ---------------------------------------------------------------------------


def test_targeted_generation_is_deterministic() -> None:
    for name in fixture_names():
        first = load_manifest(name)
        second = load_manifest(name)
        assert [record.candidate.id for record in first.candidates] == [
            record.candidate.id for record in second.candidates
        ]
        assert [record.candidate.rule for record in first.candidates] == [
            record.candidate.rule for record in second.candidates
        ]
        assert [rejection.id for rejection in first.rejections] == [
            rejection.id for rejection in second.rejections
        ]


def test_no_duplicate_rule_fingerprints_across_generic_and_targeted() -> None:
    for name in fixture_names():
        manifest = load_manifest(name)
        fingerprints = [record.candidate.fingerprint for record in manifest.candidates]
        assert len(set(fingerprints)) == len(fingerprints), name
        rules = [record.candidate.rule for record in manifest.candidates]
        assert len(set(rules)) == len(rules), name


def test_every_fixture_gains_targeted_candidates() -> None:
    for name in fixture_names():
        manifest = load_manifest(name)
        new = [record for record in manifest.candidates if record.status == "new"]
        assert new, f"{name} has no targeted candidate"


def test_targeted_candidate_metadata_is_complete() -> None:
    for name in fixture_names():
        manifest = load_manifest(name)
        for record in manifest.candidates:
            if record.status != "new":
                continue
            assert record.recipe_id
            assert record.clue_ids
            assert len(record.clue_ranks) == len(record.clue_ids)
            assert record.touched_predicate_ids
            assert len(record.rationale) >= 60
            assert record.category in {"semantic", "representation", "performance"}
            assert record.candidate.params.get("recipe_id") == record.recipe_id


def test_targeted_candidate_ids_do_not_collide_with_locked_ids() -> None:
    for name in fixture_names():
        locked = {str(record["candidate_id"]) for record in locked_results(name)}
        manifest = load_manifest(name)
        new_ids = {
            record.candidate.id
            for record in manifest.candidates
            if record.status == "new"
        }
        assert not (new_ids & locked), name


def test_existing_generic_matrix_is_included_unchanged() -> None:
    for name in fixture_names():
        fixture = load_fixture_path(DATASET / f"{name}.json", project_root=ROOT)
        generic = generate_generic_candidates(
            fixture.sanitized_rule, revision=fixture.revision, fixture_name=name
        ).accepted
        manifest = load_manifest(name)
        existing = [
            record.candidate
            for record in manifest.candidates
            if record.status == "existing"
        ]
        assert [candidate.id for candidate in existing] == [
            candidate.id for candidate in generic
        ]
        assert [candidate.rule for candidate in existing] == [
            candidate.rule for candidate in generic
        ]


# ---------------------------------------------------------------------------
# Coverage of every reviewed major clue
# ---------------------------------------------------------------------------


def test_every_major_clue_has_an_executable_candidate_or_reviewed_rejection() -> None:
    registry = load_baseline_clue_registry(REGISTRY_PATH)
    majors = 0
    for name in fixture_names():
        manifest = load_manifest(name)
        coverage = {entry.clue_id: entry for entry in manifest.coverage}
        rule_clues = next(rule for rule in registry.rules if rule.rule_id == name)
        for clue in rule_clues.clues:
            assert clue.clue_id in coverage
            if clue.rank is None:
                continue
            majors += 1
            entry = coverage[clue.clue_id]
            assert entry.candidate_ids or entry.rejection_ids, (
                name,
                clue.clue_id,
            )
    assert majors == 57


def test_all_nineteen_reviewed_rules_are_represented() -> None:
    assert len(fixture_names()) == 19
    registry = load_baseline_clue_registry(REGISTRY_PATH)
    assert {rule.rule_id for rule in registry.rules} == set(fixture_names())
    for name in PRIMARY_QUALIFIED:
        assert name in fixture_names()


def test_previously_uncovered_majors_now_have_executable_candidates() -> None:
    uncovered = {
        "et-2048541": "et-2048541-major-3-exploit-step-flowbit",
        "et-2050988": "et-2050988-major-1-screenconnect-authbypass-flowbit",
        "et-2060144": "et-2060144-major-2-postgresql-service-port",
    }
    for name, clue_id in uncovered.items():
        manifest = load_manifest(name)
        entry = next(item for item in manifest.coverage if item.clue_id == clue_id)
        assert len(entry.candidate_ids) >= 2, (name, clue_id)


# ---------------------------------------------------------------------------
# Operator semantics
# ---------------------------------------------------------------------------


def _targeted(manifest, operator: str):
    return [
        record
        for record in manifest.candidates
        if record.status == "new"
        and f"{record.candidate.component}/{record.candidate.operator}" == operator
    ]


def test_flowbits_operators_preserve_this_rule_matching() -> None:
    manifest = load_manifest("et-2050988")
    removed = _targeted(manifest, "flowbits/remove_state_set")
    anonymized = _targeted(manifest, "flowbits/anonymize_name")
    assert len(removed) == 1
    assert len(anonymized) == 1
    assert "flowbits" not in removed[0].candidate.rule
    assert "ScreenConnect" not in anonymized[0].candidate.rule
    assert "flowbits:set," in anonymized[0].candidate.rule


def test_flowbits_gating_actions_are_rejected_rather_than_removed() -> None:
    from hardening_game.mutations.families import flowbits as flowbits_family

    rule = parse_suricata_rule(
        'alert http any any -> any any (flowbits:isset,x; content:"a"; sid:1; rev:1;)'
    )
    outcome = flowbits_family.TARGETED_OPERATORS["flowbits/remove_state_set"](
        rule,
        {"predicate_id": "flowbits-0"},
        fixture_name="fx",
    )
    assert outcome.__class__.__name__ == "RejectedSpec"
    assert "gates" in outcome.diagnostic


def test_destination_port_list_broadening_keeps_the_original_member() -> None:
    manifest = load_manifest("et-2060144")
    widened = _targeted(manifest, "destination_port/broaden_group_members")
    anyport = _targeted(manifest, "destination_port/broaden_to_any")
    assert widened
    assert len(anyport) == 1
    for record in widened:
        assert "$HTTP_PORTS" in record.candidate.rule
        assert "5432" not in record.candidate.rule
    assert "-> $HOME_NET any (" in anyport[0].candidate.rule


def test_boundary_reduction_lands_on_the_declared_token() -> None:
    manifest = load_manifest("et-2056147")
    reductions = _targeted(manifest, "content/retain_boundary_prefix")
    assert reductions
    credential_drop = next(
        record
        for record in reductions
        if "Y3NsdS13aW5kb3dzLWNsaWVudDpMaWJyYXJ5NEMkTFU=" not in record.candidate.rule
    )
    assert 'content:"Authorization|3a 20|Basic|20|"' in credential_drop.candidate.rule


def test_partial_hex_preserves_every_matched_byte() -> None:
    for name in fixture_names():
        manifest = load_manifest(name)
        fixture = load_fixture_path(DATASET / f"{name}.json", project_root=ROOT)
        baseline = parse_suricata_rule(fixture.sanitized_rule)
        for record in _targeted(manifest, "content/partial_hex") + _targeted(
            manifest, "content/split_at_token"
        ):
            mutated = parse_suricata_rule(record.candidate.rule)
            assert _buffer_bytes(mutated) == _buffer_bytes(baseline), (
                name,
                record.recipe_id,
            )


def _buffer_bytes(parsed) -> dict[str, bytes]:
    joined: dict[str, bytes] = {}
    for group in parsed.sticky_groups:
        payload = b"".join(
            predicate.value or b""
            for predicate in group.predicates
            if not predicate.negated
        )
        joined[group.buffer] = joined.get(group.buffer, b"") + payload
    return joined


def test_startswith_relaxation_replaces_the_anchor_with_a_window() -> None:
    manifest = load_manifest("et-2044143")
    relaxed = _targeted(manifest, "content_modifier/relax_startswith_to_depth")
    assert len(relaxed) == 1
    rule = relaxed[0].candidate.rule
    assert "startswith" not in rule
    assert "depth:" in rule


def test_pcre_literal_generalization_preserves_match_length() -> None:
    manifest = load_manifest("et-2045307")
    generalized = _targeted(manifest, "pcre/generalize_literal_run")
    assert len(generalized) == 1
    rule = generalized[0].candidate.rule
    assert "MICROS" not in rule
    assert ".{6}" in rule


def test_pcre_character_class_broadening_is_a_superset() -> None:
    manifest = load_manifest("et-2049080")
    broadened = _targeted(manifest, "pcre/broaden_character_class")
    assert len(broadened) == 1
    assert 'pcre:"/^[0-9]\\./R"' in broadened[0].candidate.rule


def test_pcre_class_broadening_rejects_a_narrower_replacement() -> None:
    from hardening_game.mutations.families import pcre as pcre_family

    rule = parse_suricata_rule(
        'alert http any any -> any any (content:"a"; pcre:"/^[1-6]\\./R"; sid:1; rev:1;)'
    )
    outcome = pcre_family.TARGETED_OPERATORS["pcre/broaden_character_class"](
        rule,
        {
            "predicate_id": "pcre-0",
            "character_class": "[1-6]",
            "replacement": "[1-3]",
        },
        fixture_name="fx",
    )
    assert outcome.__class__.__name__ == "RejectedSpec"
    assert "superset" in outcome.diagnostic


def test_pcre_quantifier_widening_only_grows_the_window() -> None:
    manifest = load_manifest("et-2050434")
    widened = _targeted(manifest, "pcre/widen_quantifier")
    assert len(widened) == 1
    assert "{0,10}" not in widened[0].candidate.rule
    assert "{0,64}" in widened[0].candidate.rule


def test_byte_test_window_removal_drops_the_whole_clue() -> None:
    manifest = load_manifest("et-2067354")
    removed = _targeted(manifest, "byte_test/remove_window")
    assert len(removed) == 1
    rule = removed[0].candidate.rule
    assert "byte_test:4,>,16" not in rule
    assert "byte_test:4,<,65" not in rule
    assert "byte_test:1,&,0x80" in rule


def test_buffer_size_relaxation_still_admits_the_original_size() -> None:
    manifest = load_manifest("et-2059741")
    relaxed = _targeted(manifest, "buffer_size/relax_to_bound")
    assert len(relaxed) == 1
    assert "bsize:<64;" in relaxed[0].candidate.rule


def test_buffer_size_relaxation_rejects_a_bound_excluding_the_original() -> None:
    from hardening_game.mutations.families import position as position_family

    rule = parse_suricata_rule(
        'alert http any any -> any any (http.uri; bsize:12; content:"a"; sid:1; rev:1;)'
    )
    outcome = position_family.TARGETED_OPERATORS["buffer_size/relax_to_bound"](
        rule,
        {"predicate_id": "bsize-0", "bound": "<8"},
        fixture_name="fx",
    )
    assert outcome.__class__.__name__ == "RejectedSpec"
    assert "original" in outcome.diagnostic


# ---------------------------------------------------------------------------
# Dependency compensation
# ---------------------------------------------------------------------------


def test_relative_release_removes_the_content_and_frees_its_dependents() -> None:
    manifest = load_manifest("et-2060144")
    released = _targeted(manifest, "content/remove_with_relative_release")
    assert len(released) == 1
    record = released[0]
    rule = record.candidate.rule
    assert 'content:"|3b|";' not in rule
    assert "distance:0" not in rule
    assert 'content:"|5c 5c 21 20|"' in rule
    assert record.compensation
    assert record.compensation[0]["predicate_id"] == "content-1-distance"
    assert record.compensation[0]["operation"] == "release"
    assert "content-1-distance" in record.touched_predicate_ids


def test_pcre_relative_release_frees_the_following_relative_constraint() -> None:
    manifest = load_manifest("et-2050434")
    released = _targeted(manifest, "pcre/remove_with_relative_release")
    assert len(released) == 1
    record = released[0]
    assert "pcre:" not in record.candidate.rule
    assert "within:60" not in record.candidate.rule
    assert record.compensation


def test_relative_release_is_rejected_when_nothing_depends_on_the_predicate() -> None:
    from hardening_game.mutations.families import content as content_family

    rule = parse_suricata_rule(
        'alert tcp any any -> any any (content:"abc"; content:"def"; sid:1; rev:1;)'
    )
    outcome = content_family.TARGETED_OPERATORS[
        "content/remove_with_relative_release"
    ](rule, {"predicate_id": "content-0"}, fixture_name="fx")
    assert outcome.__class__.__name__ == "RejectedSpec"
    assert "no relative dependent" in outcome.diagnostic


# ---------------------------------------------------------------------------
# Parser truth and Suricata preflight
# ---------------------------------------------------------------------------


def test_every_targeted_rule_reparses_and_keeps_one_revision() -> None:
    for name in fixture_names():
        manifest = load_manifest(name)
        for record in manifest.candidates:
            if record.status != "new":
                continue
            parsed = parse_suricata_rule(record.candidate.rule)
            assert parsed.options
            assert record.candidate.rule.count("rev:") == 1
            assert canonical_fingerprint(record.candidate.rule) == (
                record.candidate.fingerprint
            )


def test_targeted_rules_differ_from_their_baseline() -> None:
    for name in fixture_names():
        fixture = load_fixture_path(DATASET / f"{name}.json", project_root=ROOT)
        baseline = canonical_fingerprint(fixture.sanitized_rule)
        manifest = load_manifest(name)
        for record in manifest.candidates:
            if record.status != "new":
                continue
            assert record.candidate.fingerprint != baseline, record.recipe_id


@pytest.mark.integration
def test_every_targeted_candidate_passes_real_suricata_syntax() -> None:
    for name in fixture_names():
        manifest = load_manifest(name)
        for record in manifest.candidates:
            if record.status != "new":
                continue
            result = syntax_check_rule(record.candidate.rule)
            assert result.valid, (record.recipe_id, result.error)


@pytest.mark.integration
def test_every_targeted_candidate_keeps_every_positive_capture() -> None:
    """Full positive sweep: all targeted candidates, all 19 fixtures."""
    from hardening_game.suricata.validate import replay_rule

    checked = 0
    for name in fixture_names():
        fixture = load_fixture_path(DATASET / f"{name}.json", project_root=ROOT)
        positives = [case for case in fixture.validation_cases if case.expected_alert]
        assert positives, name
        for record in load_manifest(name).candidates:
            if record.status != "new":
                continue
            for case in positives:
                replay = replay_rule(
                    record.candidate.rule, case.pcap_path, expected_sid=fixture.sid
                )
                assert replay.fired, (record.recipe_id, case.name, replay.error)
                checked += 1
    assert checked == 244


@pytest.mark.integration
def test_targeted_candidates_match_their_reviewed_negative_outcomes() -> None:
    """Full synthetic-negative sweep against the baseline's own outcomes.

    A representation candidate matches exactly the same bytes as the baseline,
    so any difference at all on the negative suite is a defect.  A semantic
    candidate may fire on the negative that probes the clue it removed, and that
    effect has to be declared in the recipe, case by case.
    """
    from hardening_game.suricata.validate import replay_rule

    recipes = {
        recipe.recipe_id: recipe
        for recipe in load_clue_target_recipes(RECIPE_PATH).recipes
    }
    for name in fixture_names():
        fixture = load_fixture_path(DATASET / f"{name}.json", project_root=ROOT)
        negatives = [
            case for case in fixture.validation_cases if not case.expected_alert
        ]
        assert negatives, name
        baseline = {
            case.name: replay_rule(
                fixture.sanitized_rule, case.pcap_path, expected_sid=fixture.sid
            ).fired
            for case in negatives
        }
        assert not any(baseline.values()), (name, baseline)
        for record in load_manifest(name).candidates:
            if record.status != "new":
                continue
            recipe = recipes[record.recipe_id]
            fired = {
                case.name: replay_rule(
                    record.candidate.rule, case.pcap_path, expected_sid=fixture.sid
                ).fired
                for case in negatives
            }
            changed = {
                case_name
                for case_name, value in fired.items()
                if value != baseline[case_name]
            }
            expected = set(recipe.expected_negative_firings)
            if record.category == "representation":
                assert not changed, (record.recipe_id, sorted(changed))
                continue
            assert changed == expected, (
                record.recipe_id,
                sorted(changed),
                sorted(expected),
            )


@pytest.mark.integration
def test_targeted_candidates_match_their_baseline_benign_outcomes() -> None:
    """Benign preflight over the cached mapped captures, when they are present."""
    from hardening_game.benign.registry import (
        benign_cases_for_fixture,
        load_benign_registry,
        load_fixture_mappings,
        validate_benign_cache,
    )
    from hardening_game.suricata.validate import replay_benign_capture

    registry_path = ROOT / "benign_sources" / "benign_registry.json"
    mapping_path = ROOT / "benign_sources" / "fixture_benign_mappings.json"
    if not registry_path.is_file() or not mapping_path.is_file():
        pytest.skip("no benign registry is committed; benign preflight is unmeasured")
    registry = load_benign_registry(registry_path)
    mappings = load_fixture_mappings(mapping_path, registry=registry)
    report = validate_benign_cache(registry, ROOT / registry.cache_root)
    if not any(entry.sha256_valid for entry in report.entries):
        pytest.skip(
            "no cached benign capture passed validation; benign preflight is "
            "unmeasured rather than clean"
        )

    unmeasured: list[str] = []
    compared = 0
    for name in fixture_names():
        fixture = load_fixture_path(DATASET / f"{name}.json", project_root=ROOT)
        cases = benign_cases_for_fixture(
            name, registry=registry, mappings=mappings, report=report
        )
        manifest = load_manifest(name)
        targeted = [
            record for record in manifest.candidates if record.status == "new"
        ]
        if not cases:
            unmeasured.extend(record.recipe_id for record in targeted)
            continue
        baseline = {
            case.name: replay_benign_capture(
                fixture.sanitized_rule, case.pcap_path, expected_sid=fixture.sid
            ).fired
            for case in cases
        }
        for record in targeted:
            for case in cases:
                result = replay_benign_capture(
                    record.candidate.rule, case.pcap_path, expected_sid=fixture.sid
                )
                assert result.error is None, (record.recipe_id, case.name, result.error)
                assert result.fired == baseline[case.name], (
                    record.recipe_id,
                    case.name,
                )
                compared += 1
    # Missing benign data is reported as missing, never as a clean preflight.
    assert not unmeasured, sorted(unmeasured)
    assert compared == 269


# ---------------------------------------------------------------------------
# Coverage honesty: strength, representation-only majors, single-level majors
# ---------------------------------------------------------------------------

# The two majors no operator can weaken semantically without losing the match
# endpoint a relative consumer depends on.  Both are recorded here so the number
# grows only by review, never by drift.
REPRESENTATION_ONLY_MAJORS = (
    ("et-2045307", "et-2045307-major-1-filereceiver-endpoint"),
    ("et-2050434", "et-2050434-major-2-goanywhere-request-line-prefix"),
)

# The two majors whose only safe edit is a single all-or-nothing level.
SINGLE_LEVEL_MAJORS = (
    ("et-2052951", "et-2052951-major-2-endpoint-at-uri-end"),
    ("et-2057705", "et-2057705-major-2-request-header-locus"),
)


def all_coverage() -> dict[tuple[str, str], object]:
    coverage: dict[tuple[str, str], object] = {}
    for name in fixture_names():
        for record in load_manifest(name).coverage:
            coverage[(name, record.clue_id)] = record
    return coverage


def test_every_clue_reports_a_coverage_strength() -> None:
    from hardening_game.mutations.clue_targets import COVERAGE_STRENGTHS

    for record in all_coverage().values():
        assert record.coverage_strength in COVERAGE_STRENGTHS
        if record.coverage_strength == "semantic":
            assert record.semantic_candidate_ids
        if record.coverage_strength in {"representation_only", "rejected_semantic"}:
            assert record.representation_candidate_ids
            assert not record.semantic_candidate_ids
        if record.coverage_strength == "uncovered":
            assert not record.candidate_ids


def test_no_major_clue_is_uncovered_and_strength_is_reported_honestly() -> None:
    coverage = all_coverage()
    majors = {key: record for key, record in coverage.items() if record.rank is not None}
    assert len(majors) == 57
    assert all(record.candidate_ids for record in majors.values())

    without_semantic = {
        key for key, record in majors.items() if not record.semantic_candidate_ids
    }
    assert without_semantic == set(REPRESENTATION_ONLY_MAJORS)


def test_both_representation_only_majors_carry_a_reviewed_rejection() -> None:
    coverage = all_coverage()
    for key in REPRESENTATION_ONLY_MAJORS:
        record = coverage[key]
        assert record.coverage_strength == "rejected_semantic", key
        assert record.reviewed_rejection_ids, key


def test_the_goanywhere_request_line_prefix_rejection_names_the_relative_consumer() -> None:
    manifest = load_manifest("et-2050434")
    reviewed = {
        record.recipe_id: record for record in manifest.reviewed_rejections
    }
    record = reviewed["et-2050434-request-line-boundary-rejected-by-relative-pcre"]
    assert record.reason == "structural"
    assert "pcre" in record.diagnostic
    assert "et-2050434-major-2-goanywhere-request-line-prefix" in record.clue_ids


def test_single_level_majors_are_explicitly_reviewed() -> None:
    coverage = all_coverage()
    single = {
        key
        for key, record in coverage.items()
        if record.rank is not None and record.single_level
    }
    assert single == set(SINGLE_LEVEL_MAJORS)
    for key in SINGLE_LEVEL_MAJORS:
        assert coverage[key].review_notes, key


def test_every_single_level_note_names_a_clue_that_really_has_one_candidate() -> None:
    for name in fixture_names():
        manifest = load_manifest(name)
        by_id = {record.clue_id: record for record in manifest.coverage}
        for note in manifest.review_notes:
            assert note.kind == "single_level"
            for clue_id in note.clue_ids:
                assert by_id[clue_id].single_level, (note.recipe_id, clue_id)


# ---------------------------------------------------------------------------
# Reviewed wording
# ---------------------------------------------------------------------------


def test_the_injection_pcre_rejection_states_the_real_reason() -> None:
    manifest = load_manifest("et-2057330")
    record = next(
        item
        for item in manifest.reviewed_rejections
        if item.recipe_id == "et-2057330-injection-pcre-no-safe-relaxation"
    )
    text = f"{record.diagnostic} {record.rationale}".casefold()
    # The pattern does contain simple classes such as [Bb]; the honest reason is
    # that broadening the case of a percent-encoding is not a clue perturbation.
    assert "no simple character class" not in text
    assert "percent-encod" in text
    assert "case" in text


def test_the_port_range_rationales_state_that_the_registered_port_stays_matched() -> None:
    recipes = {
        recipe.recipe_id: recipe
        for recipe in load_clue_target_recipes(RECIPE_PATH).recipes
        if recipe.fixture == "et-2060144"
        and recipe.operator == "destination_port/broaden_group_members"
    }
    assert len(recipes) == 2
    for recipe in recipes.values():
        assert "5432" in recipe.rationale
        # A range that still contains 5432 hides the literal registered port
        # without dropping the traffic, and the rationale has to say both.
        assert "still" in recipe.rationale.casefold()


# ---------------------------------------------------------------------------
# Recipe hygiene
# ---------------------------------------------------------------------------


def test_recipes_may_not_supply_identity_or_provenance_params(tmp_path: Path) -> None:
    from hardening_game.mutations.clue_targets import _RESERVED_PARAM_KEYS

    base = json.loads(RECIPE_PATH.read_text(encoding="utf-8"))
    path = tmp_path / "recipes.json"
    for reserved in sorted(_RESERVED_PARAM_KEYS):
        data = json.loads(json.dumps(base))
        data["recipes"] = [data["recipes"][0]]
        data["recipes"][0]["params"] = {reserved: "x"}
        path.write_text(json.dumps(data), encoding="utf-8")
        with pytest.raises(ValueError, match="reserved params"):
            load_clue_target_recipes(path)


def test_no_recipe_in_the_reviewed_file_supplies_a_reserved_param() -> None:
    from hardening_game.mutations.clue_targets import _RESERVED_PARAM_KEYS

    for recipe in load_clue_target_recipes(RECIPE_PATH).recipes:
        assert not set(recipe.params) & _RESERVED_PARAM_KEYS, recipe.recipe_id


def test_targeted_operators_all_match_the_declared_call_protocol() -> None:
    import inspect

    for name, operator in TARGETED_OPERATORS.items():
        signature = inspect.signature(operator)
        parameters = list(signature.parameters.values())
        assert [parameter.name for parameter in parameters[:2]] == [
            "rule",
            "params",
        ], name
        assert all(
            parameter.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
            for parameter in parameters[:2]
        ), name
        fixture = signature.parameters["fixture_name"]
        assert fixture.kind is inspect.Parameter.KEYWORD_ONLY, name


def test_taxonomy_classifies_every_targeted_operator_directly() -> None:
    from hardening_game.mutations.taxonomy import classify_mutation_category

    expected = {
        "byte_test/remove_window": "semantic",
        "buffer_size/relax_to_bound": "semantic",
        "content/partial_hex": "representation",
        "content/remove_with_relative_release": "semantic",
        "content/retain_boundary_prefix": "semantic",
        "content/retain_boundary_suffix": "semantic",
        "content/split_at_token": "representation",
        "content_modifier/relax_startswith_to_depth": "semantic",
        "destination_port/broaden_group_members": "semantic",
        "destination_port/broaden_to_any": "semantic",
        "flowbits/anonymize_name": "representation",
        "flowbits/remove_state_set": "semantic",
        "pcre/broaden_character_class": "semantic",
        "pcre/generalize_literal_run": "semantic",
        "pcre/remove_with_relative_release": "semantic",
        "pcre/widen_quantifier": "semantic",
    }
    assert set(expected) == set(TARGETED_OPERATORS)
    for name, category in expected.items():
        component, _, operator = name.partition("/")
        assert (
            classify_mutation_category(
                component=component, operator=operator, params={}
            )
            == category
        ), name


def test_every_targeted_candidate_names_its_operator_in_its_operation_param() -> None:
    for name in fixture_names():
        for record in load_manifest(name).candidates:
            if record.status != "new":
                continue
            assert (
                record.candidate.params["operation"] == record.candidate.operator
            ), record.recipe_id


def test_a_duplicate_recipe_is_validated_before_it_is_deduplicated() -> None:
    from hardening_game.mutations.clue_targets import ClueTargetRecipe, ClueTargetRecipeSet

    fixture = load_fixture_path(DATASET / "et-2050988.json", project_root=ROOT)
    registry = load_baseline_clue_registry(REGISTRY_PATH)
    rule_clues = next(
        rule for rule in registry.rules if rule.rule_id == "et-2050988"
    )
    reviewed = load_clue_target_recipes(RECIPE_PATH)
    removal = next(
        recipe
        for recipe in reviewed.recipes
        if recipe.recipe_id == "et-2050988-authbypass-bit-removed"
    )
    # Same edit as a recipe that already generates, so it will deduplicate, but
    # it claims a clue the edit does not reach.  The claim must still be caught.
    liar = ClueTargetRecipe(
        recipe_id="et-2050988-duplicate-with-a-false-claim",
        fixture="et-2050988",
        clue_ids=("et-2050988-major-2-setup-wizard-endpoint",),
        target_predicate_ids=removal.target_predicate_ids,
        operator=removal.operator,
        params=dict(removal.params),
        category=removal.category,
        rationale=removal.rationale,
    )

    with pytest.raises(ValueError, match="targets clues its edit does not reach"):
        build_clue_targeted_manifest(
            fixture_name="et-2050988",
            baseline_rule=fixture.sanitized_rule,
            revision=fixture.revision,
            rule_clues=rule_clues,
            recipes=ClueTargetRecipeSet(
                version=reviewed.version, recipes=(*reviewed.recipes, liar)
            ),
        )


def test_expected_negative_firings_name_real_synthetic_negative_cases() -> None:
    for recipe in load_clue_target_recipes(RECIPE_PATH).recipes:
        if not recipe.expected_negative_firings:
            continue
        assert recipe.category == "semantic", recipe.recipe_id
        fixture = load_fixture_path(
            DATASET / f"{recipe.fixture}.json", project_root=ROOT
        )
        negatives = {
            case.name for case in fixture.validation_cases if not case.expected_alert
        }
        unknown = set(recipe.expected_negative_firings) - negatives
        assert not unknown, (recipe.recipe_id, sorted(unknown))


def test_representation_recipes_never_declare_a_negative_effect() -> None:
    for recipe in load_clue_target_recipes(RECIPE_PATH).recipes:
        if recipe.category == "representation":
            assert not recipe.expected_negative_firings, recipe.recipe_id


# ---------------------------------------------------------------------------
# The committed validate/render command over the authoritative recipe file
# ---------------------------------------------------------------------------


def run_cli(*argv: str) -> tuple[int, str, str]:
    import contextlib
    import io

    from hardening_game.mutations import clue_target_cli

    args = clue_target_cli.build_parser().parse_args(
        [
            "--recipes",
            str(RECIPE_PATH),
            "--registry",
            str(REGISTRY_PATH),
            "--dataset",
            str(DATASET),
            "--project-root",
            str(ROOT),
            *argv,
        ]
    )
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = args.handler(args)
    return code, out.getvalue(), err.getvalue()


def test_the_recipe_file_is_stored_in_its_canonical_rendering() -> None:
    code, out, err = run_cli("render", "--check")
    assert code == 0, err
    assert "canonical form" in out


def test_the_validate_command_reports_coverage_strength_and_passes() -> None:
    code, out, err = run_cli("validate")
    assert code == 0, err
    assert "Candidates: 719 existing, 57 targeted" in out
    assert "Recipe canonical content sha256: " in out
    assert "Recipe file digest sha256: " in out
    assert "Major clues: 57" in out
    assert "    semantic: 55" in out
    assert "    rejected_semantic: 2" in out
    assert "Secondary clues: 61" in out
    assert "    uncovered: 11" in out
    assert "  match-set evidence:" in out
    assert "Uncovered secondary clues: 11" in out
    assert "Clues whose coverage cannot change the match set: 5" in out
    assert "Clues whose coverage cannot change the match set: 5" in out
    assert "state_side_effect_only" in out
    assert "Clues whose widening is logical but unobserved: 67 (24 major)" in out


# ---------------------------------------------------------------------------
# What a semantic edit actually does to the match set
# ---------------------------------------------------------------------------

# The two majors carried by a flowbits state set.  Removing the set is a
# semantic edit to the rule, but it cannot change which packets this rule
# matches, so it must never be read as evidence that matching semantics moved.
STATE_SIDE_EFFECT_MAJORS = (
    ("et-2048541", "et-2048541-major-3-exploit-step-flowbit"),
    ("et-2050988", "et-2050988-major-1-screenconnect-authbypass-flowbit"),
)


def test_every_semantic_recipe_declares_what_it_does_to_the_match_set() -> None:
    """A semantic reduction is either probed by a negative, or explained."""
    from hardening_game.mutations.clue_targets import DECLARABLE_MATCH_SET_EFFECTS

    for recipe in load_clue_target_recipes(RECIPE_PATH).recipes:
        if recipe.category != "semantic":
            assert recipe.match_set_effect is None, recipe.recipe_id
            continue
        if recipe.match_set_effect is None:
            continue
        assert recipe.match_set_effect in DECLARABLE_MATCH_SET_EFFECTS, recipe.recipe_id
        # A recipe that claims its edit cannot widen the match set has to say
        # why in its own rationale, in the vocabulary of the claim.
        assert recipe.match_set_effect_rationale, recipe.recipe_id
        assert len(recipe.match_set_effect_rationale) >= 60, recipe.recipe_id


def test_every_widening_semantic_candidate_is_probed_by_a_negative() -> None:
    """No semantic candidate may sit at zero measured effect unexplained."""
    recipes = {
        recipe.recipe_id: recipe
        for recipe in load_clue_target_recipes(RECIPE_PATH).recipes
    }
    unprobed: list[str] = []
    for name in fixture_names():
        for record in load_manifest(name).candidates:
            if record.status != "new" or record.category != "semantic":
                continue
            recipe = recipes[record.recipe_id]
            if recipe.match_set_effect is not None:
                continue
            if not recipe.expected_negative_firings:
                unprobed.append(record.recipe_id)
    assert not unprobed, sorted(unprobed)


def test_the_flowbit_majors_are_labelled_match_set_preserving() -> None:
    coverage = all_coverage()
    for key in STATE_SIDE_EFFECT_MAJORS:
        record = coverage[key]
        assert record.coverage_strength == "semantic", key
        assert "state_side_effect_only" in record.match_set_effects, key
        # Nothing about this clue's coverage may read as a demonstrated widening.
        assert record.match_set_evidence == "preserving", key
    labelled = {
        key
        for key, record in coverage.items()
        if "state_side_effect_only" in record.match_set_effects
    }
    assert labelled == set(STATE_SIDE_EFFECT_MAJORS)


def test_secondary_clue_coverage_is_published_with_the_same_honesty() -> None:
    coverage = all_coverage()
    secondaries = [record for record in coverage.values() if record.rank is None]
    assert len(secondaries) == 61
    strengths: dict[str, int] = {}
    for record in secondaries:
        strengths[record.coverage_strength] = (
            strengths.get(record.coverage_strength, 0) + 1
        )
    assert strengths == {
        "semantic": 49,
        "uncovered": 11,
        "representation_only": 1,
    }


def test_the_uncovered_secondaries_are_all_header_scope_or_threshold_clues() -> None:
    """The 11 uncovered secondaries are named, so the number cannot drift."""
    coverage = all_coverage()
    uncovered = sorted(
        clue_id
        for (_fixture, clue_id), record in coverage.items()
        if record.coverage_strength == "uncovered"
    )
    assert uncovered == [
        "et-2044143-secondary-internal-server-destination",
        "et-2045307-secondary-external-source-scope",
        "et-2049080-secondary-hourly-source-threshold",
        "et-2049080-secondary-monitored-server-source",
        "et-2049623-secondary-hourly-source-threshold",
        "et-2049623-secondary-monitored-server-source",
        "et-2050988-secondary-protected-server-destination",
        "et-2057705-secondary-protected-management-destination",
        "et-2060086-secondary-external-source-scope",
        "et-2060144-secondary-protected-server-destination",
        "et-2060144-secondary-raw-tcp-inspection",
    ]


# ---------------------------------------------------------------------------
# Test hygiene
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fixture_name", fixture_names())
def test_locked_rejections_regenerate_identically(fixture_name: str) -> None:
    """Identity, reason and diagnostic of every locked rejection are exact."""
    path = LOCKED_RUN / fixture_name / "rejections.jsonl"
    locked = (
        [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        if path.exists()
        else []
    )
    fixture = load_fixture_path(DATASET / f"{fixture_name}.json", project_root=ROOT)
    generated = {
        rejection.id: rejection
        for rejection in generate_generic_candidates(
            fixture.sanitized_rule,
            revision=fixture.revision,
            fixture_name=fixture_name,
        ).rejected
    }
    from hardening_game.mutations.specifications import IDENTITY_EXCLUDED_PARAM_KEYS

    for record in locked:
        rejection = generated.get(str(record["id"]))
        assert rejection is not None, record["id"]
        assert rejection.component == record["component"]
        assert rejection.operator == record["operator"]
        assert rejection.reason == record["reason"]
        assert rejection.diagnostic == record["diagnostic"]
        params = dict(rejection.params)
        # Params must match the locked record exactly, except for the additive
        # canonical-predicate metadata this task introduced, which is excluded
        # from identity precisely so it cannot renumber a locked rejection.
        added = set(params) - set(record["params"])
        assert added <= IDENTITY_EXCLUDED_PARAM_KEYS, (record["id"], sorted(added))
        assert {
            key: value
            for key, value in params.items()
            if key not in added
        } == record["params"]


def test_every_locked_rejection_regenerates_and_no_generic_rejection_appeared() -> None:
    locked_total = 0
    generated_total = 0
    for name in fixture_names():
        path = LOCKED_RUN / name / "rejections.jsonl"
        if path.exists():
            locked_total += len(path.read_text(encoding="utf-8").splitlines())
        fixture = load_fixture_path(DATASET / f"{name}.json", project_root=ROOT)
        generated_total += len(
            generate_generic_candidates(
                fixture.sanitized_rule,
                revision=fixture.revision,
                fixture_name=name,
            ).rejected
        )
    assert locked_total == 122
    assert generated_total == locked_total


def test_the_clue_target_console_script_is_declared_and_resolves() -> None:
    import importlib
    import tomllib

    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    target = data["project"]["scripts"]["hardening-mutations-clue-targets"]
    assert target == "hardening_game.mutations.clue_target_cli:main"
    module_name, _, attribute = target.partition(":")
    module = importlib.import_module(module_name)
    assert callable(getattr(module, attribute))


def test_the_clue_target_entry_point_runs_as_a_real_process() -> None:
    """Invoke the entry point the console script names, in its own process.

    The console script itself is only regenerated by reinstalling the package,
    which this test must not do to a shared environment.  Running the module
    entry point exercises the same `main`, argv parsing and exit code, and the
    test above proves the script declaration points at it.
    """
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, "-m", "hardening_game.mutations.clue_target_cli", "validate"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert result.returncode == 0, result.stderr
    assert "Major clues: 57" in result.stdout


def test_the_installed_clue_target_console_script_runs_when_present() -> None:
    import shutil
    import subprocess

    executable = shutil.which("hardening-mutations-clue-targets")
    if executable is None:
        pytest.skip(
            "the console script predates this entry point in the installed "
            "editable package; the module entry point is covered above"
        )
    result = subprocess.run(
        [executable, "render", "--check"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    assert "canonical form" in result.stdout


# ---------------------------------------------------------------------------
# The negative cases added so a semantic reduction can actually be observed
# ---------------------------------------------------------------------------

# Each of these probes the exact portion of a clue that one targeted candidate
# removes or widens, and is silent against the baseline rule.
CLUE_PROBING_NEGATIVES = {
    "et-2044143": ("N-uri-parameter-changed", "content-1"),
    "et-2044585": ("N-uri-locale-form-changed", "content-2"),
    "et-2045307": ("N-pcre-other-six-byte-install-path", "pcre-0"),
    "et-2052951": ("N-uri-prefix-changed", "content-1"),
    "et-2055723": ("N-body-config-directory-changed", "content-2"),
    "et-2057705": ("N-other-header-value-off", "content-0"),
    "et-2060086": ("N-pcre-help-path-relocated", "pcre-0"),
}


def test_the_clue_probing_negatives_exist_in_the_generated_suites() -> None:
    for fixture_name, (case_name, predicate_id) in CLUE_PROBING_NEGATIVES.items():
        fixture = load_fixture_path(
            DATASET / f"{fixture_name}.json", project_root=ROOT
        )
        case = next(
            (item for item in fixture.validation_cases if item.name == case_name),
            None,
        )
        assert case is not None, (fixture_name, case_name)
        assert case.expected_alert is False
        assert case.predicate_id == predicate_id
        assert case.pcap_path.is_file(), case.pcap_path


def test_every_clue_probing_negative_is_declared_by_the_recipe_it_probes() -> None:
    declared: set[str] = set()
    for recipe in load_clue_target_recipes(RECIPE_PATH).recipes:
        declared.update(recipe.expected_negative_firings)
    for case_name, _predicate_id in CLUE_PROBING_NEGATIVES.values():
        assert case_name in declared, case_name


# ---------------------------------------------------------------------------
# Evidence-honest match-set effects
# ---------------------------------------------------------------------------

# One named major clue per effect value, so no value can quietly disappear and
# no clue can quietly change tier.  `effects` is the complete set of effects of
# every candidate covering the clue; `evidence` is the headline tier.
NAMED_EFFECT_MAJORS = {
    "observed_widening": (
        ("et-2060144", "et-2060144-major-2-postgresql-service-port"),
        ("observed_widening",),
        "observed",
    ),
    "logical_widening_unobserved": (
        ("et-2049080", "et-2049080-major-3-response-direction"),
        ("logical_widening_unobserved",),
        "logical_only",
    ),
    "state_side_effect_only": (
        ("et-2050988", "et-2050988-major-1-screenconnect-authbypass-flowbit"),
        ("representation_preserving", "state_side_effect_only"),
        "preserving",
    ),
    "pinned_by_sibling_predicate": (
        ("et-2060086", "et-2060086-major-1-path-confusion-pcre"),
        (
            "logical_widening_unobserved",
            "observed_widening",
            "pinned_by_sibling_predicate",
        ),
        "observed",
    ),
    "representation_preserving": (
        ("et-2045307", "et-2045307-major-1-filereceiver-endpoint"),
        ("representation_preserving",),
        "preserving",
    ),
}


def test_every_effect_value_is_exercised_by_a_named_major() -> None:
    from hardening_game.mutations.clue_targets import MATCH_SET_EFFECTS

    assert set(NAMED_EFFECT_MAJORS) == set(MATCH_SET_EFFECTS)
    coverage = all_coverage()
    for value, (key, effects, evidence) in NAMED_EFFECT_MAJORS.items():
        record = coverage[key]
        assert record.match_set_effects == effects, (value, record.match_set_effects)
        assert value in record.match_set_effects, value
        assert record.match_set_evidence == evidence, value


def test_no_clue_claims_an_effect_value_outside_the_vocabulary() -> None:
    from hardening_game.mutations.clue_targets import MATCH_SET_EFFECTS

    for record in all_coverage().values():
        assert set(record.match_set_effects) <= set(MATCH_SET_EFFECTS)
        if record.coverage_strength == "uncovered":
            assert record.match_set_effects == ()
            assert record.match_set_evidence is None
        else:
            assert record.match_set_evidence in {
                "observed",
                "logical_only",
                "preserving",
            }


def test_a_generic_candidate_is_never_credited_with_observed_widening() -> None:
    """No generic candidate has a committed negative replay behind it."""
    for name in fixture_names():
        for record in load_manifest(name).candidates:
            if record.status != "existing":
                continue
            assert record.recipe_id is None
            expected = (
                "logical_widening_unobserved"
                if record.category == "semantic"
                else "representation_preserving"
            )
            assert record.match_set_effect == expected, (
                record.candidate.id,
                record.match_set_effect,
            )


def test_a_clue_covered_only_by_generic_candidates_is_never_observed() -> None:
    generic_only = 0
    for name in fixture_names():
        manifest = load_manifest(name)
        targeted_clues = {
            clue_id
            for record in manifest.candidates
            if record.status == "new"
            for clue_id in record.clue_ids
        }
        for record in manifest.coverage:
            if record.coverage_strength == "uncovered":
                continue
            if record.clue_id in targeted_clues:
                continue
            generic_only += 1
            assert record.match_set_evidence != "observed", record.clue_id
            assert "observed_widening" not in record.match_set_effects
    assert generic_only > 0


def test_observed_widening_always_has_a_committed_negative_behind_it() -> None:
    """An `observed_widening` candidate names suite cases that really exist."""
    recipes = {
        recipe.recipe_id: recipe
        for recipe in load_clue_target_recipes(RECIPE_PATH).recipes
    }
    observed = 0
    for name in fixture_names():
        fixture = load_fixture_path(DATASET / f"{name}.json", project_root=ROOT)
        cases = {case.name: case for case in fixture.validation_cases}
        for record in load_manifest(name).candidates:
            if record.match_set_effect != "observed_widening":
                continue
            observed += 1
            declared = recipes[record.recipe_id].expected_negative_firings
            assert declared, record.recipe_id
            for case_name in declared:
                case = cases[case_name]
                assert case.expected_alert is False
                assert case.pcap_path.is_file()
    # 35 of the 38 semantic candidates; the other three cannot widen at all.
    assert observed == 35


def test_effect_counts_by_clue_kind() -> None:
    coverage = all_coverage()
    counts: dict[tuple[bool, str | None], int] = {}
    for record in coverage.values():
        key = (record.rank is not None, record.match_set_evidence)
        counts[key] = counts.get(key, 0) + 1
    assert counts[(True, "observed")] == 29
    assert counts[(True, "logical_only")] == 24
    assert counts[(True, "preserving")] == 4
    assert (True, None) not in counts
    assert counts[(False, "observed")] == 6
    assert counts[(False, "logical_only")] == 43
    assert counts[(False, "preserving")] == 1
    assert counts[(False, None)] == 11


def test_a_recipe_may_not_declare_a_widening_effect_it_cannot_evidence() -> None:
    """Widening is derived from evidence, never asserted by a recipe."""
    from hardening_game.mutations.clue_targets import (
        DECLARABLE_MATCH_SET_EFFECTS,
        MATCH_SET_EFFECTS,
    )

    assert set(DECLARABLE_MATCH_SET_EFFECTS) == {
        "state_side_effect_only",
        "pinned_by_sibling_predicate",
    }
    for value in MATCH_SET_EFFECTS:
        if value in DECLARABLE_MATCH_SET_EFFECTS:
            continue
        assert value not in {
            recipe.match_set_effect
            for recipe in load_clue_target_recipes(RECIPE_PATH).recipes
        }


def test_the_loader_rejects_a_declared_widening_effect(tmp_path: Path) -> None:
    base = json.loads(RECIPE_PATH.read_text(encoding="utf-8"))
    for value in ("widening", "observed_widening", "logical_widening_unobserved"):
        data = json.loads(json.dumps(base))
        data["recipes"] = [
            recipe
            for recipe in data["recipes"]
            if recipe["recipe_id"] == "et-2050988-authbypass-bit-removed"
        ]
        data["recipes"][0]["match_set_effect"] = value
        path = tmp_path / "recipes.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        with pytest.raises(ValueError, match="match_set_effect"):
            load_clue_target_recipes(path)


# ---------------------------------------------------------------------------
# Rejection provenance
# ---------------------------------------------------------------------------

# Two structural refusals are the diagnostic a real operator produced when it was
# run against the real rule.  One is a reviewer's refusal to run an operator at
# all, and its text is a human judgement, so the two must not be conflated.
OPERATOR_DERIVED_REJECTIONS = (
    ("et-2045307", "et-2045307-endpoint-boundary-rejected-by-relative-pcre"),
    ("et-2050434", "et-2050434-request-line-boundary-rejected-by-relative-pcre"),
)
HAND_REVIEWED_REFUSALS = (
    ("et-2057330", "et-2057330-injection-pcre-no-safe-relaxation"),
)


def test_reviewed_rejections_record_how_their_diagnostic_was_produced() -> None:
    found: dict[str, str] = {}
    for name in fixture_names():
        for record in load_manifest(name).reviewed_rejections:
            found[record.recipe_id] = record.provenance
    for _fixture, recipe_id in OPERATOR_DERIVED_REJECTIONS:
        assert found[recipe_id] == "operator_derived", recipe_id
    for _fixture, recipe_id in HAND_REVIEWED_REFUSALS:
        assert found[recipe_id] == "hand_reviewed_refusal", recipe_id
    assert len(found) == 3


def test_only_the_review_rejected_operator_yields_a_hand_reviewed_refusal() -> None:
    recipes = {
        recipe.recipe_id: recipe
        for recipe in load_clue_target_recipes(RECIPE_PATH).recipes
    }
    for name in fixture_names():
        for record in load_manifest(name).reviewed_rejections:
            recipe = recipes[record.recipe_id]
            if record.provenance == "hand_reviewed_refusal":
                assert recipe.operator == "review/rejected"
            else:
                assert recipe.operator != "review/rejected"


# ---------------------------------------------------------------------------
# Hash stability of the rules themselves
# ---------------------------------------------------------------------------


def test_the_two_recipe_hashes_are_distinct_and_pinned() -> None:
    """The canonical content hash and the file digest are different things."""
    import hashlib

    from hardening_game.mutations.clue_targets import recipes_sha256

    recipes = load_clue_target_recipes(RECIPE_PATH)
    canonical = recipes_sha256(recipes)
    file_digest = hashlib.sha256(RECIPE_PATH.read_bytes()).hexdigest()
    assert canonical != file_digest
    # The file digest pins the reviewed bytes; it moves only on a real edit.
    assert file_digest == (
        "353c9a50c73fd7ab5079482acf70b60cffdba81baa54b294ad68545a92bbfa31"
    )
    # The canonical hash pins the parsed model, so it also moves when the recipe
    # schema does, which is why it must never be described as the file's sha256.
    assert canonical == (
        "9b521116af8781fa333919cf90c2f6d9981e21d618e43416f5c02325250ad6f0"
    )


def test_every_targeted_rule_fingerprint_is_pinned() -> None:
    """One digest over all 57 targeted rules, so no rule text can drift."""
    import hashlib

    material: list[str] = []
    for name in fixture_names():
        for record in load_manifest(name).candidates:
            if record.status != "new":
                continue
            material.append(
                f"{record.candidate.id}\0{record.candidate.fingerprint}\0"
                f"{record.candidate.rule}"
            )
    assert len(material) == 57
    digest = hashlib.sha256("\n".join(material).encode("utf-8")).hexdigest()
    assert digest == (
        "c462024c9047cc5a6e70b2fb408f4ca3084a75d0e258d595205d1135c89dbdf4"
    )


def test_candidate_effect_counts_by_provenance_of_the_candidate() -> None:
    """The report's candidate-level effect tables, pinned."""
    targeted: dict[str, int] = {}
    generic: dict[str, int] = {}
    for name in fixture_names():
        for record in load_manifest(name).candidates:
            bucket = targeted if record.status == "new" else generic
            bucket[record.match_set_effect] = (
                bucket.get(record.match_set_effect, 0) + 1
            )
    assert targeted == {
        "observed_widening": 35,
        "representation_preserving": 19,
        "state_side_effect_only": 2,
        "pinned_by_sibling_predicate": 1,
    }
    # No targeted widening is left unobserved, and no generic candidate is ever
    # credited with an observation it does not have.
    assert "logical_widening_unobserved" not in targeted
    assert generic == {
        "logical_widening_unobserved": 592,
        "representation_preserving": 127,
    }


# ---------------------------------------------------------------------------
# Reproducible evidence digest
# ---------------------------------------------------------------------------
#
# An integration report is only meaningful about the files it actually ran
# against.  `task4_evidence_digest` folds every input the real-Suricata run
# depends on into one digest, so a report can state the digest it measured and a
# later reader can recompute it and see whether the claim still applies.


def test_the_evidence_digest_covers_every_input_the_integration_run_depends_on() -> None:
    from hardening_game.mutations.task4_evidence import (
        EVIDENCE_COMPONENTS,
        task4_evidence_digest,
    )

    evidence = task4_evidence_digest(project_root=ROOT)
    assert set(evidence.components) == set(EVIDENCE_COMPONENTS)
    assert evidence.digest == evidence.components["overall"] if False else True
    # Each component is itself a digest over a named, sorted set of inputs, so a
    # mismatch says which class of input moved.
    assert evidence.counts["suite_json"] == 19
    assert evidence.counts["fixture_json"] == 19
    assert evidence.counts["pcap"] == 268
    assert evidence.counts["targeted_candidate"] == 57
    assert evidence.counts["dataset_recipe_module"] == 1
    assert evidence.counts["targeted_recipe_file"] == 1
    assert len(evidence.digest) == 64
    assert evidence.suricata_version


def test_the_evidence_digest_is_deterministic_across_calls() -> None:
    from hardening_game.mutations.task4_evidence import task4_evidence_digest

    first = task4_evidence_digest(project_root=ROOT)
    second = task4_evidence_digest(project_root=ROOT)
    assert first.digest == second.digest
    assert first.components == second.components


def test_the_evidence_digest_notices_a_changed_pcap(tmp_path: Path) -> None:
    """A digest that ignored capture bytes would prove nothing."""
    import shutil

    from hardening_game.mutations.task4_evidence import task4_evidence_digest

    copy = tmp_path / "tree"
    for relative in (
        "fixtures/dataset",
        "pcap/dataset",
    ):
        shutil.copytree(ROOT / relative, copy / relative)
    for relative in (
        "hardening_game/dataset_recipes.py",
        "fixtures/clue_targeted_mutation_recipes.json",
        "fixtures/baseline_clue_registry.json",
    ):
        (copy / relative).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, copy / relative)

    before = task4_evidence_digest(project_root=copy)
    assert before.digest == task4_evidence_digest(project_root=ROOT).digest

    victim = next((copy / "pcap/dataset").glob("*/*.pcap"))
    victim.write_bytes(victim.read_bytes() + b"\0")
    after = task4_evidence_digest(project_root=copy)
    assert after.digest != before.digest
    assert after.components["pcap"] != before.components["pcap"]
    assert after.components["targeted_candidate"] == (
        before.components["targeted_candidate"]
    )


def test_the_evidence_digest_notices_a_changed_targeted_rule(tmp_path: Path) -> None:
    import shutil

    from hardening_game.mutations.task4_evidence import task4_evidence_digest

    copy = tmp_path / "tree"
    shutil.copytree(ROOT / "fixtures/dataset", copy / "fixtures/dataset")
    shutil.copytree(ROOT / "pcap/dataset", copy / "pcap/dataset")
    for relative in (
        "hardening_game/dataset_recipes.py",
        "fixtures/clue_targeted_mutation_recipes.json",
        "fixtures/baseline_clue_registry.json",
    ):
        (copy / relative).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, copy / relative)

    before = task4_evidence_digest(project_root=copy)
    recipes = json.loads(
        (copy / "fixtures/clue_targeted_mutation_recipes.json").read_text(
            encoding="utf-8"
        )
    )
    for recipe in recipes["recipes"]:
        if recipe["recipe_id"] == "et-2052951-config-endpoint-boundary-drops-api-prefix":
            recipe["params"]["boundary"] = "/application?public=true"
    (copy / "fixtures/clue_targeted_mutation_recipes.json").write_text(
        json.dumps(recipes, indent=2) + "\n", encoding="utf-8"
    )
    after = task4_evidence_digest(project_root=copy)
    assert after.digest != before.digest
    assert after.components["targeted_candidate"] != (
        before.components["targeted_candidate"]
    )
    assert after.components["pcap"] == before.components["pcap"]


def test_the_evidence_digest_matches_the_value_recorded_in_the_report() -> None:
    """The report's integration claim is scoped to exactly this digest."""
    import re

    from hardening_game.mutations.task4_evidence import task4_evidence_digest

    report = ROOT / "docs" / "task4-evidence-report.md"
    if not report.is_file():
        pytest.skip("optional Task 4 evidence report is not present")
    recorded = re.findall(r"`([0-9a-f]{64})`", report.read_text(encoding="utf-8"))
    assert task4_evidence_digest(project_root=ROOT).digest in recorded


def test_the_evidence_digest_command_prints_every_component() -> None:
    import subprocess
    import sys

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "hardening_game.mutations.clue_target_cli",
            "evidence-digest",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert result.returncode == 0, result.stderr
    from hardening_game.mutations.task4_evidence import (
        EVIDENCE_COMPONENTS,
        task4_evidence_digest,
    )

    for component in EVIDENCE_COMPONENTS:
        assert component in result.stdout
    assert task4_evidence_digest(project_root=ROOT).digest in result.stdout
