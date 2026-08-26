import json
from pathlib import Path

import pytest

from hardening_game.attribution.clue_registry import (
    BaselineClue,
    BaselineRuleClues,
    load_baseline_clue_registry,
    registry_sha256,
    validate_completed_rule,
)
from hardening_game.attribution.clue_scoring import (
    TrialClueScore,
    aggregate_candidate_trials,
    map_attacker_evidence,
    score_trial,
    summarize_candidate_trials,
)
from hardening_game.attribution.registry import RelatedCveEntry, RelatedCveRegistry
from hardening_game.mutations.attacker_trials import AttackerTrial
from hardening_game.mutations.clue_review import _rule_predicates
from hardening_game.suricata.rule_model import parse_suricata_rule


TARGET = "CVE-2025-0108"
CLOSE = "CVE-2024-0012"
DISTINCT = "CVE-2099-0001"
UNKNOWN = "CVE-2099-0002"
TEST_RULE = (
    'alert tcp any any -> any 80 (content:"major-one"; fast_pattern; '
    'content:"major-two"; flow:established,to_server; pcre:"/secondary/";)'
)
RULE_PREDICATES = _rule_predicates(parse_suricata_rule(TEST_RULE))


def _clue(
    clue_id: str,
    *,
    rank: int | None,
    predicate_ids: list[str],
) -> dict[str, object]:
    return {
        "clue_id": clue_id,
        "rank": rank,
        "description": f"description for {clue_id}",
        "rationale": f"rationale for {clue_id}",
        "provenance": "manual review packet 1",
        "predicate_ids": predicate_ids,
        "targetable": True,
    }


def _rule(clues: list[dict[str, object]] | None = None) -> dict[str, object]:
    return {
        "rule_id": "fixture-a",
        "target_cve": TARGET,
        "clues": clues
        if clues is not None
        else [
            _clue("fixture-a-major-1", rank=1, predicate_ids=["content-0"]),
            _clue("fixture-a-major-2", rank=2, predicate_ids=["content-1"]),
            _clue("fixture-a-major-3", rank=3, predicate_ids=["flow-to_server"]),
            _clue("fixture-a-secondary-path", rank=None, predicate_ids=["pcre-0"]),
        ],
    }


def _write_registry(tmp_path: Path, payload: object) -> Path:
    path = tmp_path / "clues.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_committed_clue_registry_is_complete_and_hash_stable() -> None:
    path = Path(__file__).parents[1] / "fixtures/baseline_clue_registry.json"
    registry = load_baseline_clue_registry(path)
    assert registry.version == 1
    assert len(registry.rules) == 19
    for rule in registry.rules:
        validate_completed_rule(rule)
    assert registry_sha256(registry) == registry_sha256(
        load_baseline_clue_registry(path)
    )


def test_registry_hash_is_stable_across_json_formatting(tmp_path: Path) -> None:
    payload = {"version": 1, "rules": [_rule()]}
    first = _write_registry(tmp_path, payload)
    registry = load_baseline_clue_registry(first)
    first.write_text(json.dumps(payload, indent=4), encoding="utf-8")
    assert registry_sha256(registry) == registry_sha256(
        load_baseline_clue_registry(first)
    )


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ({"version": 2, "rules": []}, "unsupported clue registry version"),
        ({"version": 1, "rules": [_rule(), _rule()]}, "duplicate rule_id"),
        (
            {
                "version": 1,
                "rules": [
                    _rule(
                        [
                            _clue("duplicate-clue", rank=1, predicate_ids=["content-0"]),
                            _clue("duplicate-clue", rank=2, predicate_ids=["content-1"]),
                        ]
                    )
                ],
            },
            "duplicate clue_id",
        ),
        (
            {"version": 1, "rules": [_rule([_clue("bad id", rank=1, predicate_ids=["x"])])]},
            "invalid clue_id",
        ),
        (
            {"version": 1, "rules": [_rule([_clue("valid-id", rank=4, predicate_ids=["x"])])]},
            "rank must be 1, 2, 3, or null",
        ),
        (
            {"version": 1, "rules": [_rule([_clue("valid-id", rank=1, predicate_ids=[])])]},
            "predicate_ids must be a non-empty",
        ),
        (
            {
                "version": 1,
                "rules": [
                    _rule(
                        [
                            {
                                **_clue("valid-id", rank=1, predicate_ids=["x"]),
                                "provenance": "",
                            }
                        ]
                    )
                ],
            },
            "provenance must be a non-empty",
        ),
    ],
)
def test_registry_strictly_rejects_invalid_data(
    tmp_path: Path, payload: object, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        load_baseline_clue_registry(_write_registry(tmp_path, payload))


@pytest.mark.parametrize(
    "predicate_id",
    [
        "content-12",
        "content-12-fast_pattern",
        "flow-to_server",
        "header-dst-port",
        "pcre-0",
        "byte_test-2",
        "bsize-0",
    ],
)
def test_registry_accepts_current_parser_and_suite_predicate_ids(
    tmp_path: Path, predicate_id: str
) -> None:
    registry = load_baseline_clue_registry(
        _write_registry(
            tmp_path,
            {
                "version": 1,
                "rules": [
                    _rule([_clue("valid-clue", rank=1, predicate_ids=[predicate_id])])
                ],
            },
        )
    )
    assert registry.rules[0].clues[0].predicate_ids == (predicate_id,)


@pytest.mark.parametrize(
    "predicate_id",
    [
        "content 0",
        "content:0",
        "content/0",
        "../content-0",
        "content-0?",
        "Content-0",
        "-content-0",
    ],
)
def test_registry_rejects_noncanonical_predicate_ids(
    tmp_path: Path, predicate_id: str
) -> None:
    with pytest.raises(ValueError, match="invalid predicate_id"):
        load_baseline_clue_registry(
            _write_registry(
                tmp_path,
                {
                    "version": 1,
                    "rules": [
                        _rule(
                            [_clue("valid-clue", rank=1, predicate_ids=[predicate_id])]
                        )
                    ],
                },
            )
        )


def test_completed_rule_requires_exact_major_ranks_separately() -> None:
    incomplete = BaselineRuleClues(
        rule_id="fixture-a",
        target_cve=TARGET,
        clues=(
            BaselineClue(
                clue_id="only-major",
                rank=1,
                description="one",
                rationale="why",
                provenance="review",
                predicate_ids=("content-0",),
                targetable=True,
            ),
        ),
    )
    with pytest.raises(ValueError, match="exactly one clue at each major rank 1, 2, and 3"):
        validate_completed_rule(incomplete)


def _registry() -> RelatedCveRegistry:
    return RelatedCveRegistry(
        version=1,
        entries=(
            RelatedCveEntry(
                target_cve=TARGET,
                predicted_cve=CLOSE,
                tier="closely_related",
                vendor="vendor",
                product="product",
                rationale="close",
                provenance="review",
            ),
            RelatedCveEntry(
                target_cve=TARGET,
                predicted_cve=DISTINCT,
                tier="meaningfully_distinct",
                vendor="vendor",
                product="other product",
                rationale="reviewed as meaningfully distinct",
                provenance="review",
            ),
            RelatedCveEntry(
                target_cve=TARGET,
                predicted_cve="CVE-2099-0003",
                tier="same_ecosystem",
                vendor="vendor",
                product="ecosystem",
                rationale="legacy broad relationship",
                provenance="legacy review",
            ),
        ),
    )


def _trial(
    prediction: str | None,
    evidence: list[str] | None,
    *,
    status: str = "succeeded",
) -> AttackerTrial:
    if status == "failed":
        return AttackerTrial("candidate-a", 0, "failed", None, None, "timeout")
    clues: list[object]
    if evidence is None:
        clues = ["legacy clue"]
    else:
        clues = [{"description": "observed", "rule_evidence": evidence}]
    return AttackerTrial(
        "candidate-a",
        0,
        "succeeded",
        {
            "prompt": f"Infer the CVE.\n\nRule:\n{TEST_RULE}\n",
            "parsed_response": {
                "predicted_cve": prediction,
                "reasoning": "reason",
                "clues": clues,
            }
        },
        prediction,
        None,
    )


def test_evidence_mapping_is_explicit_and_ambiguous_evidence_is_unmeasured() -> None:
    assert map_attacker_evidence(
        ['content:"major-one";'],
        visible_rule=TEST_RULE,
        rule_predicates=RULE_PREDICATES,
    ).predicate_ids == (
        "content-0",
    )
    mapping = map_attacker_evidence(
        ["missing"], visible_rule=TEST_RULE, rule_predicates=RULE_PREDICATES
    )
    assert mapping.measured is False
    assert mapping.reason == "unmapped_evidence"
    assert map_attacker_evidence(
        ["any"], visible_rule=TEST_RULE, rule_predicates=RULE_PREDICATES
    ).reason == (
        "ambiguous_evidence"
    )
    assert (
        map_attacker_evidence(
            [], visible_rule=TEST_RULE, rule_predicates=RULE_PREDICATES
        ).reason
        == "missing_evidence"
    )


def test_same_ecosystem_is_reviewed_non_close_evidence(
    tmp_path: Path,
) -> None:
    rule = load_baseline_clue_registry(
        _write_registry(tmp_path, {"version": 1, "rules": [_rule()]})
    ).rules[0]
    result = score_trial(
        _trial(
            "CVE-2099-0003",
            ['content:"major-two";', "flow:established,to_server;", 'pcre:"/secondary/";'],
        ),
        target_cve=TARGET,
        related_cve_registry=_registry(),
        rule_clues=rule,
        touched_predicate_ids={"content-0"},
        rule_predicates=RULE_PREDICATES,
    )
    assert result.attribution_label == "non_close"
    assert result.outcome_label == "major_obscurity"


@pytest.mark.parametrize(
    ("prediction", "evidence", "touched", "attribution", "clue_effect", "outcome"),
    [
        (
            TARGET,
            ['content:"major-two";', "flow:established,to_server;", 'pcre:"/secondary/";'],
            {"content-0"},
            "exact",
            "major_disruption",
            "no_effective_obscurity",
        ),
        (
            CLOSE,
            ['content:"major-two";', "flow:established,to_server;", 'pcre:"/secondary/";'],
            {"content-0"},
            "close",
            "major_disruption",
            "no_effective_obscurity",
        ),
        (
            UNKNOWN,
            ['content:"major-two";', "flow:established,to_server;", 'pcre:"/secondary/";'],
            {"content-0"},
            "unreviewed",
            "unmeasured",
            "unmeasured",
        ),
        (
            DISTINCT,
            ['content:"major-two";', "flow:established,to_server;", 'pcre:"/secondary/";'],
            {"content-0"},
            "non_close",
            "major_disruption",
            "major_obscurity",
        ),
        (
            DISTINCT,
            ['content:"major-one";', 'content:"major-two";', "flow:established,to_server;"],
            {"pcre-0"},
            "non_close",
            "secondary_disruption",
            "weak_obscurity",
        ),
        (
            DISTINCT,
            ['content:"major-two";', "flow:established,to_server;", 'pcre:"/secondary/";'],
            {"header-dst-port"},
            "non_close",
            "unsupported",
            "unsupported_attribution_miss",
        ),
        (
            DISTINCT,
            [
                'content:"major-one";',
                'content:"major-two";',
                "flow:established,to_server;",
                'pcre:"/secondary/";',
            ],
            {"content-0"},
            "non_close",
            "unsupported",
            "unsupported_attribution_miss",
        ),
    ],
)
def test_trial_scoring_matrix(
    prediction: str,
    evidence: list[str],
    touched: set[str],
    attribution: str,
    clue_effect: str,
    outcome: str,
    tmp_path: Path,
) -> None:
    rule = load_baseline_clue_registry(
        _write_registry(tmp_path, {"version": 1, "rules": [_rule()]})
    ).rules[0]
    result = score_trial(
        _trial(prediction, evidence),
        target_cve=TARGET,
        related_cve_registry=_registry(),
        rule_clues=rule,
        touched_predicate_ids=touched,
        rule_predicates=RULE_PREDICATES,
    )
    assert (result.attribution_label, result.clue_effect_label, result.outcome_label) == (
        attribution,
        clue_effect,
        outcome,
    )


def test_multi_predicate_clue_requires_all_linked_predicates_for_presence(
    tmp_path: Path,
) -> None:
    rule = load_baseline_clue_registry(
        _write_registry(
            tmp_path,
            {
                "version": 1,
                "rules": [
                    _rule(
                        [
                            _clue(
                                "multi-major",
                                rank=1,
                                predicate_ids=["content-0", "content-0-fast_pattern"],
                            ),
                            _clue("major-two", rank=2, predicate_ids=["content-1"]),
                            _clue(
                                "major-three",
                                rank=3,
                                predicate_ids=["flow-to_server"],
                            ),
                        ]
                    )
                ],
            },
        )
    ).rules[0]
    common = {
        "target_cve": TARGET,
        "related_cve_registry": _registry(),
        "rule_clues": rule,
        "touched_predicate_ids": {"content-0"},
        "rule_predicates": RULE_PREDICATES,
    }
    full = score_trial(
        _trial(
            DISTINCT,
            [
                'content:"major-one";',
                "fast_pattern;",
                'content:"major-two";',
                "flow:established,to_server;",
            ],
        ),
        **common,
    )
    partial = score_trial(
        _trial(
            DISTINCT,
            [
                'content:"major-one";',
                'content:"major-two";',
                "flow:established,to_server;",
            ],
        ),
        **common,
    )
    unrelated = score_trial(
        _trial(
            DISTINCT,
            ["80", 'content:"major-two";', "flow:established,to_server;"],
        ),
        **common,
    )
    ambiguous = score_trial(
        _trial(
            DISTINCT,
            ["any", 'content:"major-two";', "flow:established,to_server;"],
        ),
        **common,
    )
    assert full.clue_effect_label == "unsupported"
    assert partial.clue_effect_label == "major_disruption"
    assert unrelated.clue_effect_label == "major_disruption"
    assert ambiguous.clue_effect_label == "unmeasured"


def test_failed_and_legacy_or_unmapped_evidence_are_unmeasured(tmp_path: Path) -> None:
    rule = load_baseline_clue_registry(
        _write_registry(tmp_path, {"version": 1, "rules": [_rule()]})
    ).rules[0]
    common = {
        "target_cve": TARGET,
        "related_cve_registry": _registry(),
        "rule_clues": rule,
        "touched_predicate_ids": {"content-0"},
        "rule_predicates": RULE_PREDICATES,
    }
    failed = score_trial(_trial(None, None, status="failed"), **common)
    legacy = score_trial(_trial(DISTINCT, None), **common)
    unmapped = score_trial(_trial(DISTINCT, ["missing"]), **common)
    assert failed.attribution_label == "failed"
    assert failed.clue_effect_label == "unmeasured"
    assert failed.outcome_label == "unmeasured"
    failed_summary = summarize_candidate_trials([failed], configured_trial_count=3)
    assert failed_summary.clue_effect_rates == {"unmeasured": 1.0}
    assert "major_disruption" not in failed_summary.clue_effect_rates
    assert legacy.clue_effect_label == "unmeasured"
    assert unmapped.clue_effect_label == "unmeasured"


def test_trial_scoring_rejects_unknown_touched_predicates_before_mapping(
    tmp_path: Path,
) -> None:
    rule = load_baseline_clue_registry(
        _write_registry(tmp_path, {"version": 1, "rules": [_rule()]})
    ).rules[0]

    with pytest.raises(ValueError, match="unknown predicate alias"):
        score_trial(
            _trial(DISTINCT, ["not present in the visible rule"]),
            target_cve=TARGET,
            related_cve_registry=_registry(),
            rule_clues=rule,
            touched_predicate_ids={"legacy-unknown-touch"},
            rule_predicates=RULE_PREDICATES,
        )


@pytest.mark.parametrize(
    ("outcomes", "expected"),
    [
        (["major_obscurity"] * 3, "durable_major"),
        (
            ["major_obscurity", "major_obscurity", "unsupported_attribution_miss"],
            "probable_major",
        ),
        (["weak_obscurity"] * 3, "durable_weak"),
        (["unsupported_attribution_miss"] * 3, "unsupported_miss"),
        (["no_effective_obscurity"] * 3, "no_effective_obscurity"),
        (
            ["major_obscurity", "weak_obscurity", "unsupported_attribution_miss"],
            "unstable",
        ),
        (
            ["major_obscurity", "no_effective_obscurity", "major_obscurity"],
            "unstable",
        ),
        (["major_obscurity", "major_obscurity"], "unmeasured"),
        (["major_obscurity", "major_obscurity", "unmeasured"], "unmeasured"),
    ],
)
def test_candidate_aggregate_matrix(outcomes: list[str], expected: str) -> None:
    assert aggregate_candidate_trials(outcomes, configured_trial_count=3) == expected


@pytest.mark.parametrize(
    "indexes",
    [
        (0, 0, 1),
        (0, 1),
        (0, 1, 2, 3),
    ],
)
def test_candidate_summary_requires_exact_distinct_trial_slots(
    indexes: tuple[int, ...],
) -> None:
    trials = [
        TrialClueScore(
            candidate_id="candidate-a",
            trial_index=index,
            attribution_label="non_close",
            clue_effect_label="major_disruption",
            outcome_label="major_obscurity",
        )
        for index in indexes
    ]
    assert (
        summarize_candidate_trials(trials, configured_trial_count=3).aggregate_label
        == "unmeasured"
    )
