"""Shared latest-record and attacker normalization helpers for explorers."""

from __future__ import annotations

from typing import Mapping


_ATTACKER_STATUSES = {
    "attacker_provider_failed": "provider",
    "attacker_parse_failed": "parse",
    "attacker_empty_response": "empty_response",
    "attacker_empty_prediction": "empty_prediction",
}


def latest_numbered_records(
    numbered: list[tuple[int, dict[str, object]]],
) -> list[tuple[int, dict[str, object]]]:
    """Collapse an append-only log to the last line per candidate ID."""
    latest: dict[str, tuple[int, dict[str, object]]] = {}
    for line, record in numbered:
        candidate_id = record.get("candidate_id")
        if isinstance(candidate_id, str):
            latest[candidate_id] = (line, record)
    return list(latest.values())


def normalized_attacker(record: Mapping[str, object]) -> dict[str, object]:
    """Normalize persisted and legacy attacker outcomes for explorer details."""
    persisted_status = record.get("status")
    exchange = record.get("attacker_exchange")
    exchange_object = exchange if isinstance(exchange, dict) else {}
    parsed = exchange_object.get("parsed_response")
    parsed_object = parsed if isinstance(parsed, dict) else {}
    clues = parsed_object.get("clues")
    raw_prediction = (
        parsed_object.get("predicted_cve")
        if isinstance(parsed_object.get("predicted_cve"), str)
        else record.get("attacker_prediction")
    )
    prediction = (
        raw_prediction
        if isinstance(raw_prediction, str) and raw_prediction.strip()
        else None
    )
    error = (
        record.get("attacker_error")
        if isinstance(record.get("attacker_error"), str)
        and record.get("attacker_error")
        else None
    )
    status = _ATTACKER_STATUSES.get(str(persisted_status))
    if status is None and persisted_status == "evaluated":
        if error is not None:
            status = "provider"
        elif prediction is None:
            status = "empty_prediction"
        else:
            status = "success"
    elif status is None:
        status = "validation"
    return {
        "status": status,
        "predicted_cve": prediction,
        "reasoning": (
            parsed_object.get("reasoning")
            if isinstance(parsed_object.get("reasoning"), str)
            else None
        ),
        "clues": (
            [clue for clue in clues if isinstance(clue, str)]
            if isinstance(clues, list)
            else []
        ),
        "prompt": (
            exchange_object.get("prompt")
            if isinstance(exchange_object.get("prompt"), str)
            else None
        ),
        "raw_response": (
            exchange_object.get("raw_response")
            if isinstance(exchange_object.get("raw_response"), str)
            else None
        ),
        "error": error,
    }
