import json
import hashlib
from dataclasses import replace
from pathlib import Path

import pytest

import hardening_game.agents as agents
import hardening_game.mutations.cli as mutation_cli
from hardening_game.agents import (
    ATTACKER_PROMPT_VERSION,
    ATTACKER_RULE_SANITIZER_VERSION,
    ATTACKER_RESPONSE_SCHEMA_VERSION,
)
from hardening_game.attribution import RelatedCveEntry, RelatedCveRegistry
from hardening_game.benign.registry import BenignCaptureCase
from hardening_game.config import configured_litellm_base_url, load_project_env
from hardening_game.fixture import GameFixture, ValidationCase, load_fixture_path
from hardening_game.mutations.engine import (
    generate_generic_candidates,
    generate_smart_install_candidates,
)
from hardening_game.mutations.attacker_trials import (
    completed_trial_indexes,
    load_attacker_trials,
)
from hardening_game.mutations.cli import (
    _persist_run_metadata,
    build_parser as build_mutation_parser,
    build_run_metadata,
    run_experiment,
    select_experiment_candidates,
)
from hardening_game.mutations.evaluator import MutationEvaluator
from hardening_game.suricata.validate import (
    BenignReplayResult,
    ReplayResult,
    SyntaxResult,
)


RULE = (
    'alert tcp any any -> $HOME_NET 4786 (flow:established,to_server; '
    'content:"|00 00 00 01 00 00 00 01 00 00 00 07|"; depth:12; '
    'content:"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; distance:12; within:36; '
    'content:"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"; distance:4; within:44; '
    'sid:2025472; rev:1;)'
)

GENERIC_RULE = (
    'alert http any any -> $HOME_NET 8080 (flow:established,to_server; '
    'http.method; content:"POST"; http.uri; content:"/example"; '
    'sid:4242; rev:7;)'
)

HTTP_REQUEST_BODY_RULE = (
    'alert http any any -> $HOME_NET 80 (http.method; content:"POST"; '
    'http.request_body; content:"operation=write"; content:"country=|24 28|"; '
    'sid:2044585; rev:1;)'
)

RAW_TCP_RULE = (
    'alert tcp any any -> $HOME_NET 873 (flow:established,to_server; '
    'content:"|40|RSYNCD|3a|"; fast_pattern; content:"--server"; '
    'content:"--sender"; content:"|00 00 07|"; content:"|0e|"; distance:0; '
    'sid:2067354; rev:1;)'
)


def test_base_url_is_explicit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LITELLM_BASE_URL", raising=False)

    assert configured_litellm_base_url() is None


def test_base_url_reads_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("LITELLM_BASE_URL", raising=False)
    env_path = tmp_path / ".env"
    env_path.write_text(
        "LITELLM_BASE_URL=https://example.test/v1\n",
        encoding="utf-8",
    )

    load_project_env(env_path)

    assert configured_litellm_base_url() == "https://example.test/v1"


def _fixture(tmp_path: Path) -> GameFixture:
    positive = ValidationCase("P0", tmp_path / "positive.pcap", True, "must fire")
    negative = ValidationCase("N0", tmp_path / "negative.pcap", False, "must stay silent")
    return GameFixture(
        name="smart_install",
        sid=2025472,
        revision=1,
        cve="CVE-2018-0171",
        pcap_path=positive.pcap_path,
        rule=RULE,
        validation_cases=(positive, negative),
    )


def test_a_shortening_compensates_b_distance() -> None:
    candidates = generate_smart_install_candidates(RULE, revision=1)
    candidate = next(
        item
        for item in candidates
        if item.component == "a_anchor" and item.params["length"] == 27
    )

    assert 'content:"AAAAAAAAAAAAAAAAAAAAAAAAAAA"; distance:12; within:27;' in candidate.rule
    assert (
        'content:"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"; distance:13; within:44;'
        in candidate.rule
    )


def test_candidate_ids_and_canonical_dedup_are_deterministic() -> None:
    first = generate_smart_install_candidates(RULE, revision=1)
    second = generate_smart_install_candidates(RULE, revision=1)

    assert [item.id for item in first] == [item.id for item in second]
    assert len({item.fingerprint for item in first}) == len(first)
    assert first[0].id == "smart-install-baseline"


def test_mutation_cli_defaults_to_three_trials_and_supports_baseline_only() -> None:
    defaults = build_mutation_parser().parse_args(["--attacker-model", "model-a"])
    baseline = build_mutation_parser().parse_args(
        ["--attacker-model", "model-a", "--attacker-trials", "5", "--baseline-only"]
    )

    assert defaults.attacker_trials == 3
    assert defaults.baseline_only is False
    assert defaults.base_url is None
    assert baseline.attacker_trials == 5
    assert baseline.baseline_only is True


def test_baseline_only_selects_the_baseline_even_with_no_mutation_family() -> None:
    candidates = generate_smart_install_candidates(RULE, revision=1)

    selected = select_experiment_candidates(
        candidates, families=["not-a-real-family"], baseline_only=True
    )

    assert [candidate.id for candidate in selected] == ["smart-install-baseline"]


def test_run_metadata_freezes_prompt_model_count_and_input_hashes(
    tmp_path: Path,
) -> None:
    clue_registry = tmp_path / "clues.json"
    related_registry = tmp_path / "related.json"
    clue_registry.write_bytes(b'{"version":1,"clues":[]}\n')
    related_registry.write_bytes(b'{"version":1,"entries":[]}\n')
    candidates = generate_smart_install_candidates(RULE, revision=1)

    metadata = build_run_metadata(
        attacker_model="model-a",
        attacker_trial_count=3,
        candidates=candidates,
        baseline_only=False,
        clue_registry_path=clue_registry,
        related_cve_registry_path=related_registry,
    )

    assert metadata["attacker_prompt_version"]
    assert metadata["attacker_response_schema_version"]
    assert metadata["attacker_prompt_version"] == ATTACKER_PROMPT_VERSION
    assert (
        metadata["attacker_response_schema_version"]
        == ATTACKER_RESPONSE_SCHEMA_VERSION
    )
    assert (
        metadata["attacker_rule_sanitizer_version"]
        == ATTACKER_RULE_SANITIZER_VERSION
    )
    assert metadata["attacker_model"] == "model-a"
    assert metadata["attacker_trial_count"] == 3
    assert metadata["clue_registry_hash"] == hashlib.sha256(
        clue_registry.read_bytes()
    ).hexdigest()
    assert metadata["related_cve_registry_hash"] == hashlib.sha256(
        related_registry.read_bytes()
    ).hexdigest()
    assert metadata["mutation_manifest_hash"]


def test_generic_candidates_apply_only_safe_text_level_mutations() -> None:
    candidates = generate_generic_candidates(
        GENERIC_RULE, revision=7, fixture_name="dataset-example"
    ).accepted
    by_operation = {(candidate.component, candidate.operator): candidate for candidate in candidates}

    assert by_operation[("baseline", "original")].rule == GENERIC_RULE
    assert "flow:to_server;" in by_operation[("flow", "remove_established")].rule
    assert "flow:established;" in by_operation[("flow", "remove_direction")].rule
    assert "flow:" not in by_operation[("flow", "remove")].rule
    assert "-> $HOME_NET any (" in by_operation[("destination_port", "any")].rule
    assert "-> $HOME_NET [8080,8081] (" in by_operation[
        ("destination_port", "small_list")
    ].rule
    assert 'content:"|50 4f 53 54|";' in next(
        candidate
        for candidate in candidates
        if candidate.component == "content"
        and candidate.operator == "literal_as_hex"
        and candidate.params["content_index"] == 0
    ).rule
    assert 'content:"|2f 65 78 61 6d 70 6c 65|";' in next(
        candidate
        for candidate in candidates
        if candidate.component == "content"
        and candidate.operator == "literal_as_hex"
        and candidate.params["content_index"] == 1
    ).rule
    assert [candidate.revision for candidate in candidates] == list(
        range(7, 7 + len(candidates))
    )


def test_generic_candidates_are_stable_deduplicated_and_label_components() -> None:
    first = generate_generic_candidates(
        GENERIC_RULE, revision=7, fixture_name="dataset-example"
    ).accepted
    second = generate_generic_candidates(
        GENERIC_RULE, revision=7, fixture_name="dataset-example"
    ).accepted

    assert [candidate.id for candidate in first] == [candidate.id for candidate in second]
    assert len({candidate.fingerprint for candidate in first}) == len(first)
    assert {"baseline", "flow", "destination_port", "sticky_buffer", "content"} >= {
        candidate.component for candidate in first
    }


def test_generic_candidates_skip_unsafe_header_and_literal_representations() -> None:
    rule = 'alert tcp any any -> $HOME_NET [80,443] (content:"|00 ff|"; sid:9; rev:1;)'

    generated = generate_generic_candidates(rule, revision=1, fixture_name="narrow")

    assert [
        (candidate.component, candidate.operator) for candidate in generated.accepted
    ] == [
        ("baseline", "original"),
        ("content", "shorten_prefix"),
        ("content", "shorten_suffix"),
        ("content", "split_adjacent"),
        ("content", "remove"),
    ]
    assert [
        (rejection.component, rejection.reason) for rejection in generated.rejected
    ] == [("destination_port", "unsupported")]


def test_rule_aware_candidates_mutate_each_http_request_body_content_group() -> None:
    candidates = generate_generic_candidates(
        HTTP_REQUEST_BODY_RULE, revision=1, fixture_name="http-body"
    ).accepted
    body_candidates = [
        candidate
        for candidate in candidates
        if candidate.component == "content"
        and candidate.params.get("buffer") == "http.request_body"
    ]

    assert {candidate.params["content_index"] for candidate in body_candidates} == {1, 2}
    assert {
        candidate.operator for candidate in body_candidates if candidate.params["content_index"] == 1
    } >= {"literal_as_hex", "shorten_prefix", "remove"}
    assert any(
        candidate.operator == "remove" and candidate.params["content_index"] == 2
        for candidate in body_candidates
    )
    assert all(
        {"buffer", "content_index", "option_index", "operation"} <= candidate.params.keys()
        for candidate in body_candidates
    )


def test_rule_aware_candidates_mutate_raw_tcp_content_groups_and_constraints() -> None:
    candidates = generate_generic_candidates(
        RAW_TCP_RULE, revision=1, fixture_name="raw-tcp"
    ).accepted

    assert {
        candidate.params["content_index"]
        for candidate in candidates
        if "content_index" in candidate.params
    } >= {0, 1, 2, 4}
    distance_candidates = [
        candidate
        for candidate in candidates
        if candidate.component == "relative_constraint"
        and candidate.params["constraint"] == "distance"
    ]
    assert distance_candidates
    assert all(candidate.params["content_index"] == 4 for candidate in distance_candidates)
    assert all(candidate.params["buffer"] == "payload" for candidate in distance_candidates)


def test_rule_aware_candidates_label_sticky_buffers_and_change_one_option() -> None:
    candidates = generate_generic_candidates(
        HTTP_REQUEST_BODY_RULE, revision=1, fixture_name="http-body"
    ).accepted
    shortened = next(
        candidate
        for candidate in candidates
        if candidate.operator == "shorten_prefix"
        and candidate.params["content_index"] == 1
        and candidate.params["retained_fraction"] == 0.5
    )

    assert shortened.component == "content"
    assert shortened.buffer == "http.request_body"
    assert shortened.option_index == 3
    assert shortened.params["buffer"] == "http.request_body"
    assert 'content:"operati";' in shortened.rule
    assert 'content:"country=|24 28|";' in shortened.rule


def test_representative_rule_aware_candidates_pass_suricata_syntax() -> None:
    root = Path(__file__).resolve().parents[1]
    selected = []
    for fixture_name, component in (
        ("et-2044585", "content"),
        ("et-2067354", "relative_constraint"),
    ):
        fixture = load_fixture_path(
            root / "fixtures" / "dataset" / f"{fixture_name}.json",
            project_root=root,
        )
        selected.append(
            next(
                candidate
                for candidate in generate_generic_candidates(
                    fixture.sanitized_rule,
                    revision=fixture.revision,
                    fixture_name=fixture.name,
                ).accepted
                if candidate.component == component
            )
        )

    from hardening_game.suricata.validate import syntax_check_rule

    for candidate in selected:
        syntax = syntax_check_rule(candidate.rule)
        assert syntax.valid, f"{candidate.id}: {syntax.error}"


def test_positive_failure_skips_attacker_and_is_persisted(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    attacker_calls: list[str] = []
    evaluator = MutationEvaluator(
        fixture=fixture,
        syntax_check=lambda _rule: SyntaxResult(True, None),
        replay=lambda _rule, case: ReplayResult(
            fired=not case.expected_alert, error=None, alerts=[]
        ),
        attacker=lambda rule: attacker_calls.append(rule) or "CVE-2018-0171",
        output_dir=tmp_path / "run",
    )

    result = evaluator.evaluate(
        [generate_smart_install_candidates(RULE, revision=1)[0]]
    )[0]

    assert result.status == "positive_recall_failed"
    assert result.attacker_prediction is None
    assert attacker_calls == []
    assert json.loads((tmp_path / "run" / "results.jsonl").read_text())["status"] == result.status


def test_attacker_provider_failure_has_distinct_status(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)

    def unavailable_attacker(_rule: str) -> str:
        raise RuntimeError("provider unavailable")

    evaluator = MutationEvaluator(
        fixture=fixture,
        syntax_check=lambda _rule: SyntaxResult(True, None),
        replay=lambda _rule, case: ReplayResult(
            fired=case.expected_alert, error=None, alerts=[]
        ),
        attacker=unavailable_attacker,
        output_dir=tmp_path / "run",
    )

    result = evaluator.evaluate(
        [generate_smart_install_candidates(RULE, revision=1)[0]]
    )[0]

    assert result.status == "attacker_provider_failed"
    assert result.attacker_prediction is None
    assert result.attacker_error == "provider unavailable"
    assert json.loads((tmp_path / "run" / "summary.json").read_text())[
        "attacker_provider_failed"
    ] == 1


def test_attacker_parse_failure_has_distinct_status(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)

    def malformed_attacker(_rule: str) -> str:
        raise ValueError("agent response was not valid JSON")

    evaluator = MutationEvaluator(
        fixture=fixture,
        syntax_check=lambda _rule: SyntaxResult(True, None),
        replay=lambda _rule, case: ReplayResult(
            fired=case.expected_alert, error=None, alerts=[]
        ),
        attacker=malformed_attacker,
        output_dir=tmp_path / "run",
    )

    result = evaluator.evaluate(
        [generate_smart_install_candidates(RULE, revision=1)[0]]
    )[0]

    assert result.status == "attacker_parse_failed"
    assert result.attacker_prediction is None


def test_attacker_empty_response_has_distinct_status(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)

    def empty_attacker(_rule: str) -> str:
        raise ValueError("model returned empty content after retry")

    evaluator = MutationEvaluator(
        fixture=fixture,
        syntax_check=lambda _rule: SyntaxResult(True, None),
        replay=lambda _rule, case: ReplayResult(
            fired=case.expected_alert, error=None, alerts=[]
        ),
        attacker=empty_attacker,
        output_dir=tmp_path / "run",
    )

    result = evaluator.evaluate(
        [generate_smart_install_candidates(RULE, revision=1)[0]]
    )[0]

    assert result.status == "attacker_empty_response"
    assert result.attacker_prediction is None


def test_attacker_empty_prediction_has_distinct_status(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    evaluator = MutationEvaluator(
        fixture=fixture,
        syntax_check=lambda _rule: SyntaxResult(True, None),
        replay=lambda _rule, case: ReplayResult(
            fired=case.expected_alert, error=None, alerts=[]
        ),
        attacker=lambda _rule: "",
        output_dir=tmp_path / "run",
    )

    result = evaluator.evaluate(
        [generate_smart_install_candidates(RULE, revision=1)[0]]
    )[0]

    assert result.status == "attacker_empty_prediction"
    assert result.attacker_prediction == ""


def test_negative_false_positive_rate_is_logged(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    evaluator = MutationEvaluator(
        fixture=fixture,
        syntax_check=lambda _rule: SyntaxResult(True, None),
        replay=lambda _rule, _case: ReplayResult(fired=True, error=None, alerts=[]),
        attacker=lambda _rule: "CVE-2018-0171",
        output_dir=tmp_path / "run",
    )

    result = evaluator.evaluate(
        [generate_smart_install_candidates(RULE, revision=1)[0]]
    )[0]

    assert result.status == "evaluated"
    assert result.positive_recall == 1.0
    assert result.negative_false_positive_rate == 1.0
    assert result.case_results["N0"]["fired"] is True


def test_unavailable_benign_corpus_is_distinct_from_zero_false_positives(
    tmp_path: Path,
) -> None:
    fixture = GameFixture(
        name="smart_install",
        sid=2025472,
        revision=1,
        cve="CVE-2018-0171",
        pcap_path=tmp_path / "positive.pcap",
        rule=RULE,
        validation_cases=(
            ValidationCase("P0", tmp_path / "positive.pcap", True, "must fire"),
        ),
    )
    evaluator = MutationEvaluator(
        fixture=fixture,
        syntax_check=lambda _rule: SyntaxResult(True, None),
        replay=lambda _rule, _case: ReplayResult(fired=True, error=None, alerts=[]),
        attacker=lambda _rule: "CVE-2018-0171",
        output_dir=tmp_path / "run",
    )

    result = evaluator.evaluate(
        [generate_smart_install_candidates(RULE, revision=1)[0]]
    )[0]

    assert result.benign_corpus_available is False
    assert result.negative_false_positive_rate is None


def test_evaluator_persists_capture_and_flow_aware_benign_metrics(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    benign_case = BenignCaptureCase(
        name="smart_install:HTTP_SIMPLE",
        pcap_path=tmp_path / "http.cap",
        source_id="HTTP_SIMPLE",
        coverage_tier="level1",
        relevance_note="HTTP protocol coverage",
    )
    evaluator = MutationEvaluator(
        fixture=fixture,
        syntax_check=lambda _rule: SyntaxResult(True, None),
        replay=lambda _rule, case: ReplayResult(
            fired=case.expected_alert, error=None, alerts=[]
        ),
        benign_replay=lambda _rule, _case: BenignReplayResult(
            fired=True,
            total_alerts=2,
            relevant_flow_count=4,
            alerting_relevant_flow_count=1,
            alerts_per_relevant_flow=0.5,
            error=None,
        ),
        attacker=lambda _rule: "CVE-2018-0171",
        output_dir=tmp_path / "run",
        benign_cases=(benign_case,),
        benign_requested=2,
        benign_cache_errors=("HTTP_GZIP: capture is missing",),
    )

    result = evaluator.evaluate(
        [generate_smart_install_candidates(RULE, revision=1)[0]]
    )[0]

    assert result.benign_capture_results["HTTP_SIMPLE"]["total_alerts"] == 2
    assert result.benign_aggregate == {
        "corpus_available": True,
        "captures_requested": 2,
        "captures_evaluated": 1,
        "captures_missing": 1,
        "capture_firing_rate": 1.0,
        "alerting_flow_rate": 0.25,
        "total_alert_count": 2,
        "coverage_tiers_present": {"level1": 1},
        "cache_errors": ("HTTP_GZIP: capture is missing",),
    }
    assert result.benign_false_positive_rate == 1.0
    assert result.benign_cache_errors == ("HTTP_GZIP: capture is missing",)


def test_positive_recall_failure_skips_benign_replay_and_rates(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    benign_calls: list[str] = []
    benign_case = BenignCaptureCase(
        name="smart_install:HTTP_SIMPLE",
        pcap_path=tmp_path / "http.cap",
        source_id="HTTP_SIMPLE",
        coverage_tier="level1",
        relevance_note="HTTP protocol coverage",
    )
    evaluator = MutationEvaluator(
        fixture=fixture,
        syntax_check=lambda _rule: SyntaxResult(True, None),
        replay=lambda _rule, case: ReplayResult(
            fired=not case.expected_alert, error=None, alerts=[]
        ),
        benign_replay=lambda rule, _case: benign_calls.append(rule)
        or BenignReplayResult(False, 0, 1, 0, 0.0, None),
        attacker=lambda _rule: "CVE-2018-0171",
        output_dir=tmp_path / "run",
        benign_cases=(benign_case,),
        benign_requested=1,
    )

    result = evaluator.evaluate(
        [generate_smart_install_candidates(RULE, revision=1)[0]]
    )[0]

    assert benign_calls == []
    assert result.benign_capture_results == {}
    assert result.benign_aggregate is None
    assert result.benign_false_positive_rate is None


def test_resume_skips_already_persisted_candidate(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    candidate = generate_smart_install_candidates(RULE, revision=1)[0]
    calls: list[str] = []
    evaluator = MutationEvaluator(
        fixture=fixture,
        syntax_check=lambda _rule: SyntaxResult(True, None),
        replay=lambda _rule, case: ReplayResult(
            fired=case.expected_alert, error=None, alerts=[]
        ),
        attacker=lambda rule: calls.append(rule) or "CVE-2018-0171",
        output_dir=tmp_path / "run",
    )

    assert len(evaluator.evaluate([candidate])) == 1
    assert evaluator.evaluate([candidate], resume=True) == []
    assert len(calls) == 1


def test_evaluator_records_three_attacker_trials_after_one_traffic_evaluation(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    replay_calls: list[str] = []
    attacker_calls: list[str] = []
    candidate = generate_smart_install_candidates(RULE, revision=1)[0]
    evaluator = MutationEvaluator(
        fixture=fixture,
        syntax_check=lambda _rule: SyntaxResult(True, None),
        replay=lambda rule, case: replay_calls.append(f"{rule}:{case.name}")
        or ReplayResult(fired=case.expected_alert, error=None, alerts=[]),
        attacker=lambda rule: attacker_calls.append(rule) or fixture.cve,
        output_dir=tmp_path / "run",
        attacker_trial_count=3,
    )

    evaluator.evaluate([candidate])

    trials = load_attacker_trials(
        tmp_path / "run" / "attacker_trials.jsonl", trial_count=3
    )
    assert completed_trial_indexes(trials, candidate.id, trial_count=3) == frozenset(
        {0, 1, 2}
    )
    assert len(attacker_calls) == 3
    assert len(replay_calls) == len(fixture.validation_cases)


def test_resume_retries_only_failed_attacker_slot_without_replaying_traffic(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    candidate = generate_smart_install_candidates(RULE, revision=1)[0]
    replay_calls: list[str] = []
    attempts = iter([fixture.cve, RuntimeError("provider unavailable"), fixture.cve])

    def flaky_attacker(_rule: str) -> str:
        outcome = next(attempts)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    first = MutationEvaluator(
        fixture=fixture,
        syntax_check=lambda _rule: SyntaxResult(True, None),
        replay=lambda rule, case: replay_calls.append(f"{rule}:{case.name}")
        or ReplayResult(fired=case.expected_alert, error=None, alerts=[]),
        attacker=flaky_attacker,
        output_dir=tmp_path / "run",
        attacker_trial_count=3,
    )
    first.evaluate([candidate])
    replay_count = len(replay_calls)

    resumed_calls: list[str] = []
    resumed = MutationEvaluator(
        fixture=fixture,
        syntax_check=lambda _rule: SyntaxResult(True, None),
        replay=lambda rule, case: replay_calls.append(f"{rule}:{case.name}")
        or ReplayResult(fired=case.expected_alert, error=None, alerts=[]),
        attacker=lambda rule: resumed_calls.append(rule) or fixture.cve,
        output_dir=tmp_path / "run",
        attacker_trial_count=3,
    )
    assert resumed.evaluate([candidate], resume=True) == []

    trials = load_attacker_trials(
        tmp_path / "run" / "attacker_trials.jsonl", trial_count=3
    )
    assert completed_trial_indexes(trials, candidate.id, trial_count=3) == frozenset(
        {0, 1, 2}
    )
    assert len(replay_calls) == replay_count
    assert resumed_calls == [candidate.rule]


def test_one_configured_trial_still_resumes_without_replaying_traffic(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    candidate = generate_smart_install_candidates(RULE, revision=1)[0]
    replay_calls: list[str] = []
    first = MutationEvaluator(
        fixture=fixture,
        syntax_check=lambda _rule: SyntaxResult(True, None),
        replay=lambda rule, case: replay_calls.append(f"{rule}:{case.name}")
        or ReplayResult(fired=case.expected_alert, error=None, alerts=[]),
        attacker=lambda _rule: (_ for _ in ()).throw(RuntimeError("unavailable")),
        output_dir=tmp_path / "run",
        attacker_trial_count=1,
    )
    first.evaluate([candidate])
    replay_count = len(replay_calls)

    resumed = MutationEvaluator(
        fixture=fixture,
        syntax_check=lambda _rule: SyntaxResult(True, None),
        replay=lambda rule, case: replay_calls.append(f"{rule}:{case.name}")
        or ReplayResult(fired=case.expected_alert, error=None, alerts=[]),
        attacker=lambda _rule: fixture.cve,
        output_dir=tmp_path / "run",
        attacker_trial_count=1,
    )
    assert resumed.evaluate([candidate], resume=True) == []

    assert len(replay_calls) == replay_count
    assert completed_trial_indexes(
        load_attacker_trials(
            tmp_path / "run" / "attacker_trials.jsonl", trial_count=1
        ),
        candidate.id,
        trial_count=1,
    ) == frozenset({0})


def test_resume_from_traffic_checkpoint_never_replays_validation(
    tmp_path: Path,
) -> None:
    class SimulatedProcessCrash(BaseException):
        pass

    fixture = _fixture(tmp_path)
    candidate = generate_smart_install_candidates(RULE, revision=1)[0]
    syntax_calls: list[str] = []
    replay_calls: list[str] = []
    benign_calls: list[str] = []
    benign_case = BenignCaptureCase(
        name="smart_install:HTTP_SIMPLE",
        pcap_path=tmp_path / "http.cap",
        source_id="HTTP_SIMPLE",
        coverage_tier="level1",
        relevance_note="HTTP coverage",
    )
    first = MutationEvaluator(
        fixture=fixture,
        syntax_check=lambda rule: syntax_calls.append(rule)
        or SyntaxResult(True, None),
        replay=lambda rule, case: replay_calls.append(f"{rule}:{case.name}")
        or ReplayResult(fired=case.expected_alert, error=None, alerts=[]),
        benign_replay=lambda rule, case: benign_calls.append(f"{rule}:{case.name}")
        or BenignReplayResult(False, 0, 1, 0, 0.0, None),
        attacker=lambda _rule: (_ for _ in ()).throw(SimulatedProcessCrash()),
        output_dir=tmp_path / "run",
        benign_cases=(benign_case,),
        benign_requested=1,
        attacker_trial_count=3,
    )

    with pytest.raises(SimulatedProcessCrash):
        first.evaluate([candidate])

    checkpoint = json.loads(
        (tmp_path / "run" / "results.jsonl").read_text(encoding="utf-8")
    )
    assert checkpoint["status"] == "traffic_complete"
    assert checkpoint["attacker_prediction"] is None
    observed_counts = (len(syntax_calls), len(replay_calls), len(benign_calls))

    resumed = MutationEvaluator(
        fixture=fixture,
        syntax_check=lambda _rule: (_ for _ in ()).throw(
            AssertionError("syntax replayed")
        ),
        replay=lambda _rule, _case: (_ for _ in ()).throw(
            AssertionError("traffic replayed")
        ),
        benign_replay=lambda _rule, _case: (_ for _ in ()).throw(
            AssertionError("benign replayed")
        ),
        attacker=lambda _rule: fixture.cve,
        output_dir=tmp_path / "run",
        benign_cases=(benign_case,),
        benign_requested=1,
        attacker_trial_count=3,
    )
    resumed.evaluate([candidate], resume=True)

    assert (len(syntax_calls), len(replay_calls), len(benign_calls)) == observed_counts
    records = [
        json.loads(line)
        for line in (tmp_path / "run" / "results.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert records[-1]["status"] == "evaluated"
    assert records[-1]["attacker_prediction"] == fixture.cve


def test_resume_migrates_true_legacy_results_only_slot_zero(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    candidate = generate_smart_install_candidates(RULE, revision=1)[0]
    legacy = MutationEvaluator(
        fixture=fixture,
        syntax_check=lambda _rule: SyntaxResult(True, None),
        replay=lambda _rule, case: ReplayResult(
            fired=case.expected_alert, error=None, alerts=[]
        ),
        attacker=lambda _rule: fixture.cve,
        output_dir=tmp_path / "run",
    )
    legacy.evaluate([candidate])
    results_path = tmp_path / "run" / "results.jsonl"
    legacy_record = json.loads(results_path.read_text(encoding="utf-8"))
    legacy_record["attacker_exchange"] = None
    results_path.write_text(json.dumps(legacy_record) + "\n", encoding="utf-8")
    assert not (tmp_path / "run" / "attacker_trials.jsonl").exists()

    attacker_calls: list[str] = []
    resumed = MutationEvaluator(
        fixture=fixture,
        syntax_check=lambda _rule: (_ for _ in ()).throw(
            AssertionError("legacy syntax replayed")
        ),
        replay=lambda _rule, _case: (_ for _ in ()).throw(
            AssertionError("legacy traffic replayed")
        ),
        attacker=lambda rule: attacker_calls.append(rule) or fixture.cve,
        output_dir=tmp_path / "run",
        attacker_trial_count=3,
    )
    assert resumed.evaluate([candidate], resume=True) == []

    trials = load_attacker_trials(
        tmp_path / "run" / "attacker_trials.jsonl", trial_count=3
    )
    assert completed_trial_indexes(trials, candidate.id, trial_count=3) == frozenset(
        {0, 1, 2}
    )
    assert attacker_calls == [candidate.rule, candidate.rule]


def test_partial_traffic_checkpoint_is_recomputed_not_treated_as_final(
    tmp_path: Path,
) -> None:
    class SimulatedProcessCrash(BaseException):
        pass

    fixture = _fixture(tmp_path)
    candidate = generate_smart_install_candidates(RULE, revision=1)[0]
    first = MutationEvaluator(
        fixture=fixture,
        syntax_check=lambda _rule: SyntaxResult(True, None),
        replay=lambda _rule, case: ReplayResult(
            fired=case.expected_alert, error=None, alerts=[]
        ),
        attacker=lambda _rule: (_ for _ in ()).throw(SimulatedProcessCrash()),
        output_dir=tmp_path / "run",
        attacker_trial_count=3,
    )
    with pytest.raises(SimulatedProcessCrash):
        first.evaluate([candidate])

    path = tmp_path / "run" / "results.jsonl"
    partial = json.loads(path.read_text(encoding="utf-8"))
    partial["case_results"] = {}
    path.write_text(json.dumps(partial) + "\n", encoding="utf-8")
    syntax_calls: list[str] = []
    resumed = MutationEvaluator(
        fixture=fixture,
        syntax_check=lambda rule: syntax_calls.append(rule)
        or SyntaxResult(True, None),
        replay=lambda _rule, case: ReplayResult(
            fired=case.expected_alert, error=None, alerts=[]
        ),
        attacker=lambda _rule: fixture.cve,
        output_dir=tmp_path / "run",
        attacker_trial_count=3,
    )

    results = resumed.evaluate([candidate], resume=True)

    assert syntax_calls == [candidate.rule]
    assert results[-1].status == "evaluated"


def test_run_metadata_hash_is_canonical_for_mapping_key_order(tmp_path: Path) -> None:
    candidate = generate_smart_install_candidates(RULE, revision=1)[0]
    first = replace(candidate, params={"alpha": 1, "beta": 2})
    second = replace(candidate, params={"beta": 2, "alpha": 1})

    first_metadata = build_run_metadata(
        attacker_model="model-a",
        attacker_trial_count=3,
        candidates=[first],
        baseline_only=False,
        clue_registry_path=None,
        related_cve_registry_path=None,
    )
    second_metadata = build_run_metadata(
        attacker_model="model-a",
        attacker_trial_count=3,
        candidates=[second],
        baseline_only=False,
        clue_registry_path=None,
        related_cve_registry_path=None,
    )

    assert (
        first_metadata["mutation_manifest_hash"]
        == second_metadata["mutation_manifest_hash"]
    )


def test_persisted_run_metadata_mismatch_is_rejected_without_overwrite(
    tmp_path: Path,
) -> None:
    path = tmp_path / "run" / "run_metadata.json"
    metadata = build_run_metadata(
        attacker_model="model-a",
        attacker_trial_count=3,
        candidates=generate_smart_install_candidates(RULE, revision=1),
        baseline_only=False,
        clue_registry_path=None,
        related_cve_registry_path=None,
    )
    _persist_run_metadata(path, metadata)
    before = path.read_text(encoding="utf-8")

    with pytest.raises(ValueError, match="metadata mismatch"):
        _persist_run_metadata(path, {**metadata, "attacker_model": "model-b"})

    assert path.read_text(encoding="utf-8") == before


@pytest.mark.parametrize(
    "artifact",
    [
        "results.jsonl",
        "attacker_trials.jsonl",
        "summary.json",
        "summary.md",
        "rejections.jsonl",
        "logs/attacker.log",
    ],
)
def test_single_mutation_refuses_missing_metadata_in_populated_run(
    tmp_path: Path, artifact: str
) -> None:
    run_dir = tmp_path / "run"
    artifact_path = run_dir / artifact
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    artifact_path.write_text("legacy artifact\n", encoding="utf-8")
    metadata_path = run_dir / "run_metadata.json"

    with pytest.raises(ValueError, match="missing run metadata"):
        _persist_run_metadata(metadata_path, {"attacker_model": "model-a"})

    assert artifact_path.read_text(encoding="utf-8") == "legacy artifact\n"
    assert not metadata_path.exists()


def test_single_mutation_creates_metadata_in_genuinely_empty_directory(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    metadata_path = run_dir / "run_metadata.json"
    metadata = {"attacker_model": "model-a"}

    _persist_run_metadata(metadata_path, metadata)

    assert json.loads(metadata_path.read_text(encoding="utf-8")) == metadata


@pytest.mark.parametrize(
    ("field", "incompatible"),
    [
        ("attacker_model", "other-model"),
        ("attacker_prompt_version", "other-prompt"),
        ("attacker_response_schema_version", 999),
        ("attacker_rule_sanitizer_version", "other-sanitizer"),
        ("attacker_trial_count", 9),
        ("related_cve_registry_hash", "0" * 64),
        ("clue_registry_hash", "0" * 64),
        ("mutation_manifest_hash", "0" * 64),
    ],
)
def test_single_mutation_metadata_rejects_every_locked_field_mismatch(
    tmp_path: Path, field: str, incompatible: object
) -> None:
    path = tmp_path / "run" / "run_metadata.json"
    metadata = build_run_metadata(
        attacker_model="model-a",
        attacker_trial_count=3,
        candidates=generate_smart_install_candidates(RULE, revision=1),
        baseline_only=False,
        clue_registry_path=None,
        related_cve_registry_path=None,
    )
    _persist_run_metadata(path, metadata)
    before = path.read_bytes()

    with pytest.raises(ValueError, match="metadata mismatch"):
        _persist_run_metadata(path, {**metadata, field: incompatible})

    assert path.read_bytes() == before


def test_old_prompt_metadata_is_rejected_without_overwrite(tmp_path: Path) -> None:
    path = tmp_path / "run" / "run_metadata.json"
    path.parent.mkdir(parents=True)
    old_metadata = build_run_metadata(
        attacker_model="model-a",
        attacker_trial_count=3,
        candidates=generate_smart_install_candidates(RULE, revision=1),
        baseline_only=False,
        clue_registry_path=None,
        related_cve_registry_path=None,
    )
    old_metadata["attacker_prompt_version"] = "ranked-clues-v1"
    old_metadata["attacker_response_schema_version"] = 2
    old_metadata.pop("attacker_rule_sanitizer_version", None)
    path.write_text(json.dumps(old_metadata, sort_keys=True) + "\n", encoding="utf-8")
    before = path.read_bytes()

    current_metadata = build_run_metadata(
        attacker_model="model-a",
        attacker_trial_count=3,
        candidates=generate_smart_install_candidates(RULE, revision=1),
        baseline_only=False,
        clue_registry_path=None,
        related_cve_registry_path=None,
    )
    with pytest.raises(ValueError, match="metadata mismatch"):
        _persist_run_metadata(path, current_metadata)

    assert path.read_bytes() == before


def test_run_experiment_baseline_only_evaluates_baseline_with_configured_trials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sanitizer_calls: list[str] = []
    real_sanitizer = agents.sanitize_attacker_rule

    def counting_sanitizer(rule: str) -> str:
        sanitizer_calls.append(rule)
        return real_sanitizer(rule)

    monkeypatch.setattr(agents, "sanitize_attacker_rule", counting_sanitizer)
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    fixture_path = fixtures / "dataset-example.json"
    fixture_path.write_text(
        json.dumps(
            {
                "name": "dataset-example",
                "sid": 1,
                "revision": 1,
                "cve": "CVE-2023-0001",
                "pcap": "positive.pcap",
                "rule": (
                    'alert tcp any any -> any 8080 (flow:established,to_server; '
                    'content:"POST"; sid:1; rev:1;)'
                ),
            }
        ),
        encoding="utf-8",
    )
    captured: dict[str, object] = {}
    prompts: list[str] = []

    class FakeClient:
        def complete(self, *, model: str, prompt: str) -> str:
            prompts.append(prompt)
            return json.dumps(
                {
                    "predicted_cve": "CVE-2023-0001",
                    "reasoning": "The POST marker is distinctive.",
                    "clues": [
                        {
                            "description": "Method marker",
                            "rule_evidence": ['content:"POST";'],
                        }
                    ],
                }
            )

    class FakeEvaluator:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)

        def persist_rejections(self, _rejections: object) -> None:
            pass

        def validate_baseline(self, candidate: object) -> None:
            captured["validated_baseline"] = candidate

        def evaluate(
            self, candidates: list[object], *, resume: bool
        ) -> list[object]:
            captured["selected"] = candidates
            captured["resume"] = resume
            return []

    monkeypatch.setattr(mutation_cli, "MutationEvaluator", FakeEvaluator)

    run_experiment(
        fixture_name="fixtures/dataset-example.json",
        attacker_model="model-a",
        api_key="unused",
        run_id="baseline-run",
        families=["not-a-real-family"],
        baseline_only=True,
        attacker_trial_count=3,
        skip_benign=True,
        project_root=tmp_path,
        client_factory=lambda **_kwargs: FakeClient(),
    )

    assert [candidate.component for candidate in captured["selected"]] == ["baseline"]
    assert captured["attacker_trial_count"] == 3
    attacker_exchange = captured["attacker"](
        'alert tcp any any -> any 8080 (content:"POST"; sid:1; rev:1;)'
    )
    assert attacker_exchange["parsed_response"] == {
        "predicted_cve": "CVE-2023-0001",
        "reasoning": "The POST marker is distinctive.",
        "clues": [
            {
                "description": "Method marker",
                "rule_evidence": ['content:"POST";'],
            }
        ],
    }
    assert len(prompts) == 1
    assert sanitizer_calls == [
        'alert tcp any any -> any 8080 (content:"POST"; sid:1; rev:1;)'
    ]
    assert 'content:"POST";' in prompts[0]
    assert "sid:1;" not in prompts[0]
    assert "rev:1;" not in prompts[0]
    metadata = json.loads(
        (
            tmp_path
            / "runs"
            / "mutations"
            / "baseline-run"
            / "run_metadata.json"
        ).read_text(encoding="utf-8")
    )
    assert metadata["baseline_only"] is True
    assert metadata["attacker_trial_count"] == 3


def test_baseline_only_never_generates_or_persists_mutation_rejections(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    fixture_path = fixtures / "dataset-example.json"
    fixture_path.write_text(
        json.dumps(
            {
                "name": "dataset-example",
                "sid": 1,
                "revision": 1,
                "cve": "CVE-2023-0001",
                "pcap": "positive.pcap",
                "rule": 'alert tcp any any -> any 8080 (content:"POST"; sid:1; rev:1;)',
            }
        ),
        encoding="utf-8",
    )

    def reject_generation(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("mutation families were generated")

    class FakeEvaluator:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def validate_baseline(self, candidate: object) -> None:
            assert candidate.component == "baseline"

        def evaluate(
            self, candidates: list[object], *, resume: bool
        ) -> list[object]:
            assert resume is False
            assert [candidate.component for candidate in candidates] == ["baseline"]
            return []

    monkeypatch.setattr(mutation_cli, "generate_generic_candidates", reject_generation)
    monkeypatch.setattr(mutation_cli, "MutationEvaluator", FakeEvaluator)

    run_experiment(
        fixture_name=str(fixture_path),
        attacker_model="model-a",
        api_key="unused",
        run_id="baseline-run",
        baseline_only=True,
        skip_benign=True,
        project_root=tmp_path,
        client_factory=lambda **_kwargs: object(),
    )

    assert not (
        tmp_path
        / "runs"
        / "mutations"
        / "baseline-run"
        / "rejections.jsonl"
    ).exists()


def test_evaluator_persists_attribution_and_mutation_category(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    registry = RelatedCveRegistry(
        version=1,
        entries=(
            RelatedCveEntry(
                target_cve=fixture.cve,
                predicted_cve="CVE-2024-0012",
                tier="closely_related",
                vendor="Example",
                product="Example",
                rationale="Test relationship.",
                provenance="Test fixture.",
            ),
        ),
    )
    evaluator = MutationEvaluator(
        fixture=fixture,
        syntax_check=lambda _rule: SyntaxResult(True, None),
        replay=lambda _rule, case: ReplayResult(
            fired=case.expected_alert, error=None, alerts=[]
        ),
        attacker=lambda _rule: "CVE-2024-0012",
        output_dir=tmp_path / "run",
        related_cve_registry=registry,
    )
    candidate = next(
        item
        for item in generate_generic_candidates(
            GENERIC_RULE,
            revision=1,
            fixture_name=fixture.name,
        ).accepted
        if item.component == "flow" and item.operator == "remove_established"
    )

    evaluator.evaluate([candidate])

    record = json.loads((tmp_path / "run" / "results.jsonl").read_text())
    assert record["target_cve"] == fixture.cve
    assert record["relationship_tier"] == "closely_related"
    assert record["meaningful_obscurity"] is False
    assert record["mutation_category"] == "semantic"


def test_evaluator_exact_attribution_needs_no_registry(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    evaluator = MutationEvaluator(
        fixture=fixture,
        syntax_check=lambda _rule: SyntaxResult(True, None),
        replay=lambda _rule, case: ReplayResult(
            fired=case.expected_alert, error=None, alerts=[]
        ),
        attacker=lambda _rule: fixture.cve,
        output_dir=tmp_path / "run",
    )

    result = evaluator.evaluate(
        [generate_smart_install_candidates(RULE, revision=1)[0]]
    )[0]

    assert result.relationship_tier == "exact_match"
    assert result.meaningful_obscurity is False


def test_non_evaluated_record_has_unknown_attribution(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    evaluator = MutationEvaluator(
        fixture=fixture,
        syntax_check=lambda _rule: SyntaxResult(False, "invalid"),
        replay=lambda _rule, _case: ReplayResult(False, None, []),
        attacker=lambda _rule: fixture.cve,
        output_dir=tmp_path / "run",
    )

    result = evaluator.evaluate(
        [generate_smart_install_candidates(RULE, revision=1)[0]]
    )[0]

    assert result.target_cve == fixture.cve
    assert result.relationship_tier is None
    assert result.meaningful_obscurity is None
    assert result.mutation_category == "semantic"


def test_evaluator_categorizes_legacy_smart_install_candidates(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    evaluator = MutationEvaluator(
        fixture=fixture,
        syntax_check=lambda _rule: SyntaxResult(True, None),
        replay=lambda _rule, case: ReplayResult(
            fired=case.expected_alert, error=None, alerts=[]
        ),
        attacker=lambda _rule: fixture.cve,
        output_dir=tmp_path / "run",
    )
    candidates = generate_smart_install_candidates(RULE, revision=1)
    selected = [
        next(
            candidate
            for candidate in candidates
            if (candidate.component, candidate.operator)
            == ("header", "split_4_4_4")
        ),
        next(
            candidate
            for candidate in candidates
            if (candidate.component, candidate.operator) == ("port", "any")
        ),
    ]

    results = evaluator.evaluate(selected)

    assert [result.mutation_category for result in results] == [
        "representation",
        "semantic",
    ]
