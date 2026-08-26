import json
from pathlib import Path

import pytest

from hardening_game.fixture import GameFixture, ValidationCase
from hardening_game.mutations.engine import MutationCandidate, canonical_fingerprint
from hardening_game.mutations.evaluator import (
    ManifestHashMismatch,
    MutationEvaluator,
    latest_records,
)
from hardening_game.suricata.validate import ReplayResult, SyntaxResult


MANIFEST_HASH = "25b628b697d244097ff76ab4961a924a746073d3336724bc341211c65cd6f91a"
OTHER_MANIFEST_HASH = "0" * 64
RULE = (
    'alert tcp any any -> $HOME_NET 80 ( flow:established,to_server; '
    'content:"/admin"; sid:1000001; rev:2;)'
)


def _raise(error: Exception):
    raise error


def _raising_attacker(error: Exception):
    return lambda _rule: _raise(error)


def _fixture(tmp_path: Path) -> GameFixture:
    positive = ValidationCase("P0", tmp_path / "positive.pcap", True, "must fire")
    negative = ValidationCase("N0", tmp_path / "negative.pcap", False, "must be silent")
    return GameFixture(
        name="et-2052951",
        sid=1000001,
        revision=1,
        cve="CVE-2024-0001",
        pcap_path=positive.pcap_path,
        rule=RULE,
        validation_cases=(positive, negative),
    )


def _combination_candidate(
    candidate_id: str,
    *,
    source_ids: tuple[str, ...],
    experiment_manifest_hash: str = MANIFEST_HASH,
    rule: str = RULE,
) -> MutationCandidate:
    return MutationCandidate(
        id=candidate_id,
        component="combination",
        operator=f"blocks_{len(source_ids)}",
        params={
            "source_candidate_ids": list(source_ids),
            "source_categories": ["semantic"] * len(source_ids),
        },
        description="Combine baseline-relative mutations.",
        rule=rule,
        revision=2,
        fingerprint=canonical_fingerprint(rule),
        experiment_manifest_hash=experiment_manifest_hash,
        source_candidate_ids=source_ids,
        block_count=len(source_ids),
    )


def _evaluator(
    tmp_path: Path,
    *,
    attacker_calls: list[str] | None = None,
    experiment_manifest_hash: str | None = MANIFEST_HASH,
    attacker=None,
) -> MutationEvaluator:
    calls = attacker_calls if attacker_calls is not None else []
    return MutationEvaluator(
        fixture=_fixture(tmp_path),
        syntax_check=lambda _rule: SyntaxResult(True, None),
        replay=lambda _rule, case: ReplayResult(
            fired=case.expected_alert, error=None, alerts=[]
        ),
        attacker=attacker or (lambda rule: calls.append(rule) or "CVE-2024-0001"),
        output_dir=tmp_path / "run",
        experiment_manifest_hash=experiment_manifest_hash,
    )


def _records(tmp_path: Path) -> list[dict[str, object]]:
    path = tmp_path / "run" / "results.jsonl"
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_result_persists_manifest_hash_ordered_sources_and_block_count(
    tmp_path: Path,
) -> None:
    expected_ids = ("et-2052951-content-a", "et-2052951-flow-b", "et-2052951-pcre-c")
    candidate = _combination_candidate("et-2052951-combination-3-aaa", source_ids=expected_ids)

    _evaluator(tmp_path).evaluate([candidate])

    record = _records(tmp_path)[0]
    assert record["experiment_manifest_hash"] == MANIFEST_HASH
    assert record["source_candidate_ids"] == list(expected_ids)
    assert record["block_count"] == len(expected_ids)


def test_single_mutation_candidates_persist_null_provenance(tmp_path: Path) -> None:
    candidate = MutationCandidate(
        id="et-2052951-flow-remove-abc",
        component="flow",
        operator="remove",
        params={},
        description="Remove the flow option.",
        rule=RULE,
        revision=2,
        fingerprint=canonical_fingerprint(RULE),
    )

    _evaluator(tmp_path, experiment_manifest_hash=None).evaluate([candidate])

    record = _records(tmp_path)[0]
    assert record["experiment_manifest_hash"] is None
    assert record["source_candidate_ids"] is None
    assert record["block_count"] is None


def test_resume_skips_only_terminally_persisted_candidate_ids(tmp_path: Path) -> None:
    calls: list[str] = []
    evaluator = _evaluator(tmp_path, attacker_calls=calls)
    first = _combination_candidate("et-2052951-combination-2-aaa", source_ids=("a", "b"))
    second = _combination_candidate(
        "et-2052951-combination-2-bbb",
        source_ids=("a", "c"),
        rule=RULE.replace("/admin", "/admin2"),
    )

    assert len(evaluator.evaluate([first])) == 1
    resumed = evaluator.evaluate([first, second], resume=True)

    assert [result.candidate_id for result in resumed] == [second.id]
    assert len(calls) == 2
    assert [record["candidate_id"] for record in _records(tmp_path)] == [
        first.id,
        second.id,
    ]


@pytest.mark.parametrize(
    ("attacker", "expected_status"),
    [
        (_raising_attacker(RuntimeError("provider 503")), "attacker_provider_failed"),
        (
            _raising_attacker(ValueError("model returned empty content after retry")),
            "attacker_empty_response",
        ),
        (_raising_attacker(ValueError("no JSON object")), "attacker_parse_failed"),
        (lambda _rule: "", "attacker_empty_prediction"),
    ],
)
def test_resume_retries_a_candidate_whose_attacker_step_never_completed(
    tmp_path: Path, attacker, expected_status: str
) -> None:
    candidate = _combination_candidate(
        "et-2052951-combination-2-aaa", source_ids=("a", "b")
    )
    _evaluator(tmp_path, attacker=attacker).evaluate([candidate])
    assert _records(tmp_path)[0]["status"] == expected_status

    calls: list[str] = []
    resumed = _evaluator(tmp_path, attacker_calls=calls).evaluate(
        [candidate], resume=True
    )

    assert [result.candidate_id for result in resumed] == [candidate.id]
    assert calls == [candidate.rule]
    assert [record["status"] for record in _records(tmp_path)] == [
        expected_status,
        "evaluated",
    ]


@pytest.mark.parametrize(
    "terminal_status", ["evaluated", "syntax_invalid", "positive_recall_failed"]
)
def test_completed_ids_hold_terminal_records_and_exclude_retryable_ones(
    tmp_path: Path, terminal_status: str
) -> None:
    terminal = _combination_candidate(
        "et-2052951-combination-2-terminal", source_ids=("a", "b")
    )
    retryable = _combination_candidate(
        "et-2052951-combination-2-retryable",
        source_ids=("a", "c"),
        rule=RULE.replace("/admin", "/admin2"),
    )
    evaluator = MutationEvaluator(
        fixture=_fixture(tmp_path),
        syntax_check=lambda rule: SyntaxResult(
            terminal_status != "syntax_invalid" or rule != terminal.rule,
            None if terminal_status != "syntax_invalid" else "simulated",
        ),
        replay=lambda rule, case: ReplayResult(
            fired=(
                case.expected_alert
                and not (
                    terminal_status == "positive_recall_failed"
                    and rule == terminal.rule
                )
            ),
            error=None,
            alerts=[],
        ),
        attacker=lambda rule: (
            "CVE-2024-0001"
            if rule == terminal.rule
            else _raise(RuntimeError("provider 503"))
        ),
        output_dir=tmp_path / "run",
        experiment_manifest_hash=MANIFEST_HASH,
    )

    evaluator.evaluate([terminal, retryable])

    assert {record["status"] for record in _records(tmp_path)} == {
        terminal_status,
        "attacker_provider_failed",
    }
    assert evaluator.completed_candidate_ids() == frozenset({terminal.id})


def test_summary_counts_the_latest_record_of_a_retried_candidate_once(
    tmp_path: Path,
) -> None:
    candidate = _combination_candidate(
        "et-2052951-combination-2-aaa", source_ids=("a", "b")
    )
    _evaluator(
        tmp_path, attacker=_raising_attacker(RuntimeError("provider 503"))
    ).evaluate([candidate])

    _evaluator(tmp_path).evaluate([candidate], resume=True)

    summary = json.loads((tmp_path / "run" / "summary.json").read_text(encoding="utf-8"))
    assert summary["records"] == 1
    assert summary["evaluated"] == 1
    assert summary["attacker_provider_failed"] == 0


def test_resume_does_not_skip_a_truncated_trailing_record(tmp_path: Path) -> None:
    candidate = _combination_candidate(
        "et-2052951-combination-2-aaa", source_ids=("a", "b")
    )
    results_path = tmp_path / "run" / "results.jsonl"
    results_path.parent.mkdir(parents=True)
    results_path.write_text(
        '{"candidate_id": "et-2052951-combination-2-aaa", "experiment_manifest_h',
        encoding="utf-8",
    )

    resumed = _evaluator(tmp_path).evaluate([candidate], resume=True)

    assert [result.candidate_id for result in resumed] == [candidate.id]


TORN_LINE = '{"candidate_id": "et-2052951-combination-2-aaa", "experiment_manifest_h'


def test_a_torn_trailing_line_cannot_merge_with_the_appended_record(
    tmp_path: Path,
) -> None:
    candidate = _combination_candidate(
        "et-2052951-combination-2-aaa", source_ids=("a", "b")
    )
    results_path = tmp_path / "run" / "results.jsonl"
    results_path.parent.mkdir(parents=True)
    results_path.write_text(TORN_LINE, encoding="utf-8")

    calls: list[str] = []
    _evaluator(tmp_path, attacker_calls=calls).evaluate([candidate], resume=True)

    contents = results_path.read_text(encoding="utf-8")
    assert contents.startswith(TORN_LINE + "\n")
    assert contents.endswith("\n")
    lines = contents.splitlines()
    assert lines[0] == TORN_LINE
    appended = json.loads(lines[-1])
    assert appended["candidate_id"] == candidate.id
    assert appended["status"] == "evaluated"
    assert appended["attacker_prediction"] == "CVE-2024-0001"
    assert calls == [candidate.rule]
    parsable = []
    for line in lines:
        try:
            parsable.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    assert latest_records(parsable) == [appended]


def test_summary_tolerates_a_persisted_row_without_a_status(tmp_path: Path) -> None:
    candidate = _combination_candidate(
        "et-2052951-combination-2-aaa", source_ids=("a", "b")
    )
    results_path = tmp_path / "run" / "results.jsonl"
    results_path.parent.mkdir(parents=True)
    results_path.write_text(
        json.dumps(
            {
                "candidate_id": "et-2052951-combination-2-legacy",
                "experiment_manifest_hash": MANIFEST_HASH,
            }
        )
        + "\n",
        encoding="utf-8",
    )

    _evaluator(tmp_path).evaluate([candidate], resume=True)

    summary = json.loads((tmp_path / "run" / "summary.json").read_text(encoding="utf-8"))
    assert summary["records"] == 2
    assert summary["evaluated"] == 1


def test_resume_refuses_a_stored_manifest_hash_mismatch_before_appending(
    tmp_path: Path,
) -> None:
    calls: list[str] = []
    evaluator = _evaluator(tmp_path, attacker_calls=calls)
    stale = _combination_candidate(
        "et-2052951-combination-2-old",
        source_ids=("a", "b"),
        experiment_manifest_hash=OTHER_MANIFEST_HASH,
    )
    _evaluator(
        tmp_path, experiment_manifest_hash=OTHER_MANIFEST_HASH
    ).evaluate([stale])
    before = (tmp_path / "run" / "results.jsonl").read_text(encoding="utf-8")
    calls.clear()

    with pytest.raises(ManifestHashMismatch) as error:
        evaluator.evaluate(
            [_combination_candidate("et-2052951-combination-2-new", source_ids=("a", "c"))],
            resume=True,
        )

    assert OTHER_MANIFEST_HASH in str(error.value)
    assert (tmp_path / "run" / "results.jsonl").read_text(encoding="utf-8") == before
    assert calls == []


def test_candidate_manifest_hash_mismatch_is_refused_before_appending(
    tmp_path: Path,
) -> None:
    calls: list[str] = []
    evaluator = _evaluator(tmp_path, attacker_calls=calls)
    foreign = _combination_candidate(
        "et-2052951-combination-2-foreign",
        source_ids=("a", "b"),
        experiment_manifest_hash=OTHER_MANIFEST_HASH,
    )

    with pytest.raises(ManifestHashMismatch):
        evaluator.evaluate([foreign])

    assert not (tmp_path / "run" / "results.jsonl").exists()
    assert calls == []
