import json
from pathlib import Path

from hardening_game.fixture import GameFixture, ValidationCase
from hardening_game.fixture import load_fixture_path
from hardening_game.mutations.engine import generate_generic_candidates
from hardening_game.mutations.evaluator import MutationEvaluator
from hardening_game.suricata.validate import ReplayResult, SyntaxResult


def _fixture(tmp_path: Path) -> GameFixture:
    case = ValidationCase("P0", tmp_path / "positive.pcap", True, "must fire")
    return GameFixture(
        name="example",
        sid=1,
        revision=1,
        cve="CVE-2026-0001",
        pcap_path=case.pcap_path,
        rule='alert http any any -> any any (http.uri; content:"/x"; bsize:>3; sid:1; rev:1;)',
        validation_cases=(case,),
    )


def test_unsafe_sticky_buffer_removal_is_a_deterministic_rejection() -> None:
    rule = 'alert http any any -> any any (http.uri; content:"/x"; bsize:>3; sid:1; rev:1;)'

    first = generate_generic_candidates(rule, revision=1, fixture_name="example")
    second = generate_generic_candidates(rule, revision=1, fixture_name="example")

    assert [rejection.id for rejection in first.rejected] == [
        rejection.id for rejection in second.rejected
    ]
    rejection = next(
        rejection
        for rejection in first.rejected
        if rejection.component == "sticky_buffer" and rejection.operator == "remove"
    )
    assert rejection.reason == "structural"
    assert "bsize" in rejection.diagnostic


def test_rejections_are_persisted_without_evaluation_or_attacker_call(tmp_path: Path) -> None:
    generated = generate_generic_candidates(
        _fixture(tmp_path).sanitized_rule, revision=1, fixture_name="example"
    )
    attacker_calls: list[str] = []
    evaluator = MutationEvaluator(
        fixture=_fixture(tmp_path),
        syntax_check=lambda _rule: SyntaxResult(True, None),
        replay=lambda _rule, _case: ReplayResult(True, None, []),
        attacker=lambda rule: attacker_calls.append(rule) or "CVE-2026-0001",
        output_dir=tmp_path / "run",
    )

    evaluator.persist_rejections(generated.rejected)
    results = evaluator.evaluate(generated.accepted)

    assert attacker_calls == [candidate.rule for candidate in generated.accepted]
    assert results
    assert not any(
        rejection.id in (tmp_path / "run" / "results.jsonl").read_text()
        for rejection in generated.rejected
    )
    records = [
        json.loads(line)
        for line in (tmp_path / "run" / "rejections.jsonl").read_text().splitlines()
    ]
    assert [record["id"] for record in records] == [rejection.id for rejection in generated.rejected]
    assert json.loads((tmp_path / "run" / "summary.json").read_text())["rejected"] == len(
        generated.rejected
    )


def test_relative_pcre_prevents_removing_its_preceding_content() -> None:
    rule = (
        'alert http any any -> any any (http.response_body; content:"x"; '
        'pcre:"/x/R"; sid:1; rev:1;)'
    )

    candidate_set = generate_generic_candidates(rule, revision=1, fixture_name="example")

    assert not any(
        candidate.component == "content" and candidate.operator == "remove"
        for candidate in candidate_set.accepted
    )
    assert any(
        rejection.component == "content"
        and rejection.operator == "remove"
        and rejection.reason == "structural"
        for rejection in candidate_set.rejected
    )


def test_relative_byte_test_rejects_only_its_et_2067354_anchor() -> None:
    root = Path(__file__).resolve().parents[1]
    fixture = load_fixture_path(
        root / "fixtures" / "dataset" / "et-2067354.json",
        project_root=root,
    )
    candidate_set = generate_generic_candidates(
        fixture.sanitized_rule,
        revision=fixture.revision,
        fixture_name=fixture.name,
    )

    assert any(
        rejection.component == "content"
        and rejection.params["content_index"] == 3
        and "distance" in rejection.diagnostic
        for rejection in candidate_set.rejected
    )
    assert not any(
        candidate.component == "content"
        and candidate.operator == "remove"
        and candidate.params["content_index"] == 4
        for candidate in candidate_set.accepted
    )
    assert any(
        rejection.component == "content"
        and rejection.params["content_index"] == 4
        and rejection.reason == "structural"
        for rejection in candidate_set.rejected
    )


def test_relative_pcre_in_one_buffer_does_not_block_another_buffer() -> None:
    rule = (
        'alert http any any -> any any (http.uri; content:"/a"; pcre:"/a/R"; '
        'http.request_body; content:"body"; sid:1; rev:1;)'
    )

    candidate_set = generate_generic_candidates(rule, revision=1, fixture_name="example")

    assert any(
        candidate.component == "content"
        and candidate.operator == "shorten_prefix"
        and candidate.params["buffer"] == "http.request_body"
        for candidate in candidate_set.accepted
    )


def test_safe_sticky_removal_is_accepted_but_bsize_removal_is_rejected() -> None:
    safe = generate_generic_candidates(
        'alert http any any -> any any (http.uri; content:"/x"; sid:1; rev:1;)',
        revision=1,
        fixture_name="safe",
    )

    assert any(
        candidate.component == "sticky_buffer" and candidate.operator == "remove"
        for candidate in safe.accepted
    )


def test_sticky_removal_is_rejected_when_it_reassigns_content_to_prior_bsize() -> None:
    generated = generate_generic_candidates(
        'alert http any any -> any any (http.uri; bsize:3; content:"uri"; '
        'http.request_body; content:"body"; sid:1; rev:1;)',
        revision=1,
        fixture_name="example",
    )

    assert not any(
        candidate.component == "sticky_buffer"
        and candidate.params["buffer"] == "http.request_body"
        for candidate in generated.accepted
    )
    assert any(
        rejection.component == "sticky_buffer"
        and rejection.params["buffer"] == "http.request_body"
        and rejection.reason == "structural"
        for rejection in generated.rejected
    )


def test_downstream_distance_consumer_protects_upstream_endpoint() -> None:
    generated = generate_generic_candidates(
        'alert tcp any any -> any any (content:"upstream"; content:"downstream"; '
        "distance:0; within:10; byte_test:1,=,1,0,relative; sid:1; rev:1;)",
        revision=1,
        fixture_name="example",
    )

    assert not any(
        candidate.component == "content"
        and candidate.operator in {"remove", "shorten_prefix"}
        and candidate.params["content_index"] == 0
        for candidate in generated.accepted
    )
    assert any(
        rejection.component == "content"
        and rejection.params["content_index"] == 0
        and "distance" in rejection.diagnostic
        for rejection in generated.rejected
    )


def test_sticky_removal_rejects_buffer_bound_positional_modifier() -> None:
    generated = generate_generic_candidates(
        'alert http any any -> any any (http.uri; content:"/x"; startswith; '
        "sid:1; rev:1;)",
        revision=1,
        fixture_name="example",
    )

    assert not any(
        candidate.component == "sticky_buffer" for candidate in generated.accepted
    )
    assert any(
        rejection.component == "sticky_buffer"
        and "buffer-bound positional modifiers" in rejection.diagnostic
        for rejection in generated.rejected
    )


def test_sticky_removal_rejects_relocation_into_prior_positional_buffer() -> None:
    generated = generate_generic_candidates(
        'alert http any any -> any any (http.uri; content:"/x"; startswith; '
        'http.request_body; content:"body"; sid:1; rev:1;)',
        revision=1,
        fixture_name="example",
    )

    assert not any(
        candidate.component == "sticky_buffer"
        and candidate.params["buffer"] == "http.request_body"
        for candidate in generated.accepted
    )
