"""Real-Suricata regression gate for committed predicate-complete suites."""

import json
from pathlib import Path

import pytest

from hardening_game.fixture import load_fixture_path
from hardening_game.suricata.validate import replay_suite


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.integration
def test_all_retained_dataset_suites_replay_with_predicate_metadata() -> None:
    manifest = json.loads((ROOT / "fixtures" / "dataset_manifest.json").read_text())
    validated = [record for record in manifest["records"] if record["status"] == "validated"]

    assert len(validated) == 19
    assert {record["sid"] for record in manifest["records"] if record["status"] == "excluded"} == {
        2044680
    }
    for record in validated:
        fixture = load_fixture_path(ROOT / record["fixture"], project_root=ROOT)
        assert fixture.validation_cases
        assert all(
            case.expected_alert or case.predicate_id is not None
            for case in fixture.validation_cases
        )
        replay = replay_suite(
            fixture.rule, fixture.validation_cases, expected_sid=fixture.sid
        )
        assert replay.fired, (fixture.name, replay.error, replay.cases)
