import json
from pathlib import Path

import pytest

from hardening_game.mutations.attacker_trials import (
    AttackerTrial,
    DuplicateSuccessfulTrial,
    append_attacker_trial,
    completed_trial_indexes,
    load_attacker_trial_history,
    load_attacker_trials,
    successful_trial_slots,
    validate_trial_count,
)


def _trial(
    trial_index: int,
    *,
    status: str = "succeeded",
    prediction: str | None = "CVE-2025-0001",
    error: str | None = None,
) -> AttackerTrial:
    return AttackerTrial(
        candidate_id="candidate-a",
        trial_index=trial_index,
        status=status,
        exchange=(
            {"parsed_response": {"predicted_cve": prediction}}
            if prediction is not None
            else None
        ),
        prediction=prediction,
        error=error,
    )


def test_three_distinct_successful_trial_slots_are_completed(tmp_path: Path) -> None:
    path = tmp_path / "attacker_trials.jsonl"
    for trial_index in range(3):
        append_attacker_trial(path, _trial(trial_index), trial_count=3)

    loaded = load_attacker_trials(path, trial_count=3)

    assert [trial.trial_index for trial in loaded] == [0, 1, 2]
    assert completed_trial_indexes(loaded, "candidate-a", trial_count=3) == frozenset(
        {0, 1, 2}
    )


def test_failed_slot_is_retryable_and_success_completes_it(tmp_path: Path) -> None:
    path = tmp_path / "attacker_trials.jsonl"
    append_attacker_trial(
        path,
        _trial(1, status="failed", prediction=None, error="provider unavailable"),
        trial_count=3,
    )
    assert completed_trial_indexes(
        load_attacker_trials(path, trial_count=3),
        "candidate-a",
        trial_count=3,
    ) == frozenset()

    append_attacker_trial(path, _trial(1), trial_count=3)

    assert completed_trial_indexes(
        load_attacker_trials(path, trial_count=3),
        "candidate-a",
        trial_count=3,
    ) == frozenset({1})
    assert len(path.read_text(encoding="utf-8").splitlines()) == 2


def test_successful_trial_slots_collapse_retry_history_in_slot_order() -> None:
    trials = [
        _trial(0),
        _trial(1, status="failed", prediction=None, error="Request timed out."),
        _trial(2),
        _trial(1),
    ]

    selected = successful_trial_slots(
        trials, "candidate-a", trial_count=3
    )

    assert [trial.trial_index for trial in selected] == [0, 1, 2]


def test_successful_trial_slots_reject_missing_success() -> None:
    trials = [
        _trial(0),
        _trial(1, status="failed", prediction=None, error="provider unavailable"),
        _trial(2),
    ]

    with pytest.raises(ValueError, match="missing successful attacker trial slot 1"):
        successful_trial_slots(trials, "candidate-a", trial_count=3)


def test_successful_trial_slots_reject_conflicting_successes() -> None:
    trials = [
        _trial(0),
        _trial(1),
        AttackerTrial(
            candidate_id="candidate-a",
            trial_index=1,
            status="succeeded",
            exchange={"parsed_response": {"predicted_cve": "CVE-2025-9999"}},
            prediction="CVE-2025-9999",
            error=None,
        ),
        _trial(2),
    ]

    with pytest.raises(ValueError, match="conflicting successful attacker trial slot 1"):
        successful_trial_slots(trials, "candidate-a", trial_count=3)


def test_loader_ignores_a_torn_trailing_jsonl_line(tmp_path: Path) -> None:
    path = tmp_path / "attacker_trials.jsonl"
    append_attacker_trial(path, _trial(0), trial_count=3)
    with path.open("a", encoding="utf-8") as handle:
        handle.write('{"candidate_id":"candidate-a","trial_index":1')

    assert load_attacker_trials(path, trial_count=3) == [_trial(0)]


def test_loader_reports_a_tolerated_unterminated_torn_tail(tmp_path: Path) -> None:
    path = tmp_path / "attacker_trials.jsonl"
    append_attacker_trial(path, _trial(0), trial_count=3)
    with path.open("a", encoding="utf-8") as handle:
        handle.write('{"candidate_id":"candidate-a","trial_index":1')

    history = load_attacker_trial_history(path, trial_count=3)

    assert history.trials == (_trial(0),)
    assert history.torn_tail_count == 1
    assert history.torn_tail_diagnostics == (
        f"{path}:2: ignored malformed unterminated final JSONL record",
    )


def test_loader_rejects_malformed_interior_record_with_path_and_line(
    tmp_path: Path,
) -> None:
    path = tmp_path / "attacker_trials.jsonl"
    path.write_text(
        json.dumps(_trial(0).__dict__) + "\n" + '{"broken":\n' + json.dumps(_trial(1).__dict__),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=rf"{path}:2: malformed attacker trial JSONL"):
        load_attacker_trials(path, trial_count=3)


def test_loader_rejects_newline_terminated_final_malformed_record(
    tmp_path: Path,
) -> None:
    path = tmp_path / "attacker_trials.jsonl"
    path.write_text(json.dumps(_trial(0).__dict__) + "\n" + '{"broken":\n', encoding="utf-8")

    with pytest.raises(ValueError, match=rf"{path}:2: malformed attacker trial JSONL"):
        load_attacker_trials(path, trial_count=3)


def test_append_discards_a_torn_tail_before_writing_a_retry(tmp_path: Path) -> None:
    path = tmp_path / "attacker_trials.jsonl"
    path.write_text('{"candidate_id":"candidate-a"', encoding="utf-8")

    append_attacker_trial(path, _trial(0), trial_count=3)

    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["trial_index"] == 0
    assert load_attacker_trials(path, trial_count=3) == [_trial(0)]


def test_identical_successful_append_is_idempotent_but_conflict_is_rejected(
    tmp_path: Path,
) -> None:
    path = tmp_path / "attacker_trials.jsonl"
    original = _trial(0)
    append_attacker_trial(path, original, trial_count=3)
    append_attacker_trial(path, original, trial_count=3)

    with pytest.raises(DuplicateSuccessfulTrial):
        append_attacker_trial(
            path,
            AttackerTrial(
                candidate_id="candidate-a",
                trial_index=0,
                status="succeeded",
                exchange={"parsed_response": {"predicted_cve": "CVE-2025-9999"}},
                prediction="CVE-2025-9999",
                error=None,
            ),
            trial_count=3,
        )

    assert len(path.read_text(encoding="utf-8").splitlines()) == 1


@pytest.mark.parametrize("trial_count", [0, -1, True, 1.5])
def test_configured_trial_count_must_be_a_positive_integer(trial_count: object) -> None:
    with pytest.raises(ValueError, match="positive integer"):
        validate_trial_count(trial_count)


@pytest.mark.parametrize(
    "trial",
    [
        AttackerTrial("candidate-a", 0, "succeeded", None, "CVE-2025-0001", None),
        AttackerTrial(
            "candidate-a",
            0,
            "succeeded",
            {"parsed_response": {"predicted_cve": "CVE-2025-9999"}},
            "CVE-2025-0001",
            None,
        ),
        AttackerTrial(
            "candidate-a",
            0,
            "succeeded",
            {"parsed_response": {"predicted_cve": "not-a-cve"}},
            "not-a-cve",
            None,
        ),
        AttackerTrial(
            "candidate-a",
            0,
            "succeeded",
            {"parsed_response": {"predicted_cve": "CVE-2025-0001"}},
            "CVE-2025-0001",
            "unexpected error",
        ),
    ],
)
def test_invalid_success_is_rejected_before_serialization(
    tmp_path: Path, trial: AttackerTrial
) -> None:
    path = tmp_path / "attacker_trials.jsonl"

    with pytest.raises(ValueError, match="succeeded"):
        append_attacker_trial(path, trial, trial_count=3)

    assert not path.exists()


def test_loader_rejects_invalid_success_so_it_cannot_complete_a_slot(
    tmp_path: Path,
) -> None:
    path = tmp_path / "attacker_trials.jsonl"
    path.write_text(
        json.dumps(
            {
                "candidate_id": "candidate-a",
                "trial_index": 0,
                "status": "succeeded",
                "exchange": None,
                "prediction": "CVE-2025-0001",
                "error": None,
            }
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="succeeded"):
        load_attacker_trials(path, trial_count=3)


@pytest.mark.parametrize(
    "trial",
    [
        AttackerTrial("candidate-a", 0, "failed", None, None, None),
        AttackerTrial(
            "candidate-a",
            0,
            "failed",
            {"parsed_response": {"predicted_cve": "CVE-2025-0001"}},
            "CVE-2025-0001",
            "provider failed",
        ),
    ],
)
def test_failed_trial_requires_error_and_cannot_carry_success_shape(
    tmp_path: Path, trial: AttackerTrial
) -> None:
    with pytest.raises(ValueError, match="failed"):
        append_attacker_trial(
            tmp_path / "attacker_trials.jsonl", trial, trial_count=3
        )
