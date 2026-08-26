"""Append-only persistence for independently resumable attacker measurements."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import re
from typing import Iterable


_TRIAL_STATUSES = frozenset({"succeeded", "failed"})
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


class DuplicateSuccessfulTrial(ValueError):
    """A successful trial slot cannot be overwritten with different data."""


@dataclass(frozen=True)
class AttackerTrial:
    candidate_id: str
    trial_index: int
    status: str
    exchange: dict[str, object] | None
    prediction: str | None
    error: str | None


@dataclass(frozen=True)
class AttackerTrialHistory:
    trials: tuple[AttackerTrial, ...]
    torn_tail_count: int
    torn_tail_diagnostics: tuple[str, ...]


def validate_trial_count(trial_count: object) -> int:
    """Return a configured positive integer trial count."""
    if isinstance(trial_count, bool) or not isinstance(trial_count, int) or trial_count <= 0:
        raise ValueError("attacker trial count must be a positive integer")
    return trial_count


def _validate_trial(trial: AttackerTrial, *, trial_count: int | None) -> None:
    if not isinstance(trial.candidate_id, str) or not trial.candidate_id.strip():
        raise ValueError("candidate_id must be a non-empty string")
    if (
        isinstance(trial.trial_index, bool)
        or not isinstance(trial.trial_index, int)
        or trial.trial_index < 0
    ):
        raise ValueError("trial_index must be a non-negative integer")
    if trial_count is not None and trial.trial_index >= trial_count:
        raise ValueError(
            f"trial_index {trial.trial_index} is outside configured count {trial_count}"
        )
    if trial.status not in _TRIAL_STATUSES:
        raise ValueError(f"unsupported attacker trial status: {trial.status!r}")
    if trial.exchange is not None and not isinstance(trial.exchange, dict):
        raise ValueError("exchange must be an object or null")
    if trial.prediction is not None and not isinstance(trial.prediction, str):
        raise ValueError("prediction must be a string or null")
    if trial.error is not None and not isinstance(trial.error, str):
        raise ValueError("error must be a string or null")
    parsed_prediction: object = None
    if isinstance(trial.exchange, dict):
        parsed = trial.exchange.get("parsed_response")
        if isinstance(parsed, dict):
            parsed_prediction = parsed.get("predicted_cve")
    if trial.status == "succeeded":
        if (
            not isinstance(trial.prediction, str)
            or not _CVE.fullmatch(trial.prediction.strip())
            or trial.error is not None
            or not isinstance(parsed_prediction, str)
            or parsed_prediction.strip().upper() != trial.prediction.strip().upper()
        ):
            raise ValueError(
                "succeeded attacker trial requires a valid consistent CVE "
                "prediction/exchange and no error"
            )
    elif (
        not isinstance(trial.error, str)
        or not trial.error.strip()
        or trial.prediction is not None
        or (
            isinstance(parsed_prediction, str)
            and _CVE.fullmatch(parsed_prediction.strip())
        )
    ):
        raise ValueError(
            "failed attacker trial requires a non-empty error and no "
            "success-shaped prediction"
        )


def _trial_from_record(
    record: dict[str, object], *, trial_count: int | None
) -> AttackerTrial:
    expected = {
        "candidate_id",
        "trial_index",
        "status",
        "exchange",
        "prediction",
        "error",
    }
    if set(record) != expected:
        raise ValueError(
            "attacker trial record must contain exactly: "
            + ", ".join(sorted(expected))
        )
    trial = AttackerTrial(
        candidate_id=record["candidate_id"],  # type: ignore[arg-type]
        trial_index=record["trial_index"],  # type: ignore[arg-type]
        status=record["status"],  # type: ignore[arg-type]
        exchange=record["exchange"],  # type: ignore[arg-type]
        prediction=record["prediction"],  # type: ignore[arg-type]
        error=record["error"],  # type: ignore[arg-type]
    )
    _validate_trial(trial, trial_count=trial_count)
    return trial


def load_attacker_trial_history(
    path: Path, *, trial_count: int | None = None
) -> AttackerTrialHistory:
    """Load valid history, tolerating only one malformed unterminated tail."""
    validated_count = (
        validate_trial_count(trial_count) if trial_count is not None else None
    )
    if not path.exists():
        return AttackerTrialHistory((), 0, ())
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    trials: list[AttackerTrial] = []
    torn_tail_diagnostics: list[str] = []
    for line_number, line in enumerate(lines, start=1):
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            if line_number == len(lines) and not text.endswith("\n"):
                torn_tail_diagnostics.append(
                    f"{path}:{line_number}: ignored malformed unterminated "
                    "final JSONL record"
                )
                continue
            raise ValueError(
                f"{path}:{line_number}: malformed attacker trial JSONL: "
                f"{error.msg}"
            ) from error
        if not isinstance(record, dict):
            raise ValueError(
                f"{path}:{line_number}: malformed attacker trial JSONL: "
                "record must be an object"
            )
        try:
            trials.append(_trial_from_record(record, trial_count=validated_count))
        except ValueError as error:
            raise ValueError(
                f"{path}:{line_number}: malformed attacker trial JSONL: {error}"
            ) from error
    return AttackerTrialHistory(
        tuple(trials),
        len(torn_tail_diagnostics),
        tuple(torn_tail_diagnostics),
    )


def load_attacker_trials(
    path: Path, *, trial_count: int | None = None
) -> list[AttackerTrial]:
    """Load complete records from an integrity-checked append-only history."""
    return list(load_attacker_trial_history(path, trial_count=trial_count).trials)


def completed_trial_indexes(
    trials: Iterable[AttackerTrial],
    candidate_id: str,
    *,
    trial_count: int | None = None,
) -> frozenset[int]:
    """Return immutable successful slots for one candidate."""
    validated_count = (
        validate_trial_count(trial_count) if trial_count is not None else None
    )
    completed: set[int] = set()
    for trial in trials:
        _validate_trial(trial, trial_count=validated_count)
        if trial.candidate_id == candidate_id and trial.status == "succeeded":
            completed.add(trial.trial_index)
    return frozenset(completed)


def successful_trial_slots(
    trials: Iterable[AttackerTrial],
    candidate_id: str,
    *,
    trial_count: int,
) -> tuple[AttackerTrial, ...]:
    """Select one successful terminal record per configured slot in slot order."""
    validated_count = validate_trial_count(trial_count)
    successes: dict[int, AttackerTrial] = {}
    for trial in trials:
        _validate_trial(trial, trial_count=validated_count)
        if trial.candidate_id != candidate_id or trial.status != "succeeded":
            continue
        stored = successes.get(trial.trial_index)
        if stored is not None and stored != trial:
            raise ValueError(
                f"{candidate_id} has conflicting successful attacker trial "
                f"slot {trial.trial_index}"
            )
        successes[trial.trial_index] = trial
    for trial_index in range(validated_count):
        if trial_index not in successes:
            raise ValueError(
                f"{candidate_id} is missing successful attacker trial "
                f"slot {trial_index}"
            )
    return tuple(successes[trial_index] for trial_index in range(validated_count))


def append_attacker_trial(
    path: Path, trial: AttackerTrial, *, trial_count: int
) -> None:
    """Append one trial, preserving any successful record already in its slot."""
    validated_count = validate_trial_count(trial_count)
    _validate_trial(trial, trial_count=validated_count)
    history = load_attacker_trial_history(path, trial_count=validated_count)
    existing = history.trials
    successful = next(
        (
            stored
            for stored in existing
            if stored.candidate_id == trial.candidate_id
            and stored.trial_index == trial.trial_index
            and stored.status == "succeeded"
        ),
        None,
    )
    if successful is not None:
        if successful == trial:
            return
        raise DuplicateSuccessfulTrial(
            f"successful attacker trial already exists for "
            f"({trial.candidate_id!r}, {trial.trial_index})"
        )

    path.parent.mkdir(parents=True, exist_ok=True)
    if history.torn_tail_count:
        _discard_torn_trailing_line(path)
    serialized = json.dumps(asdict(trial), sort_keys=True) + "\n"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(serialized)
        handle.flush()
        os.fsync(handle.fileno())


def _discard_torn_trailing_line(path: Path) -> None:
    data = path.read_bytes()
    final_newline = data.rfind(b"\n")
    path.write_bytes(data[: final_newline + 1] if final_newline >= 0 else b"")
