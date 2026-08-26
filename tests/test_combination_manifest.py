import json
from pathlib import Path

import pytest

from hardening_game.mutations.combination_manifest import (
    ControlFixture,
    load_combination_manifest,
    manifest_hash,
    resolve_selected_blocks,
)


PRIMARY_FIXTURES = (
    "et-2052951",
    "et-2059741",
    "et-2050340",
    "et-2057330",
    "et-2060144",
    "et-2067354",
)
CONTROL_FIXTURES = (
    {"name": "et-2060086", "role": "near_cve_confusion_control"},
)
METRICS = (
    "exact_cve",
    "effective_attribution",
    "positive_recall",
    "synthetic_precision",
    "benign_precision",
)
PROJECT_ROOT = Path(__file__).parents[1]
LOCKED_MANIFEST_HASH = (
    "25b628b697d244097ff76ab4961a924a746073d3336724bc341211c65cd6f91a"
)


def _manifest_payload() -> dict[str, object]:
    fixtures = (*PRIMARY_FIXTURES, *(item["name"] for item in CONTROL_FIXTURES))
    return {
        "version": 1,
        "experiment_id": "combination-hybrid-v1",
        "source_run": "runs/mutations/dataset-component-mutations-v2",
        "primary_fixtures": list(PRIMARY_FIXTURES),
        "control_fixtures": [dict(item) for item in CONTROL_FIXTURES],
        "selection": {
            "strategy": "hybrid_ranked_v1",
            "max_blocks": 8,
            "minimum_combination_size": 2,
            "selected_blocks_by_fixture": {
                fixture: [f"{fixture}-block-a", f"{fixture}-block-b"]
                for fixture in fixtures
            },
        },
        "metrics": list(METRICS),
    }


def _write_manifest(
    tmp_path: Path,
    *,
    payload: dict[str, object] | None = None,
    indent: int | None = 2,
) -> Path:
    payload = payload or _manifest_payload()
    source_run = tmp_path / str(payload["source_run"])
    selection = payload["selection"]
    assert isinstance(selection, dict)
    selected = selection["selected_blocks_by_fixture"]
    assert isinstance(selected, dict)
    for fixture, candidate_ids in selected.items():
        fixture_dir = source_run / fixture
        fixture_dir.mkdir(parents=True, exist_ok=True)
        fixture_dir.joinpath("results.jsonl").write_text(
            "".join(
                json.dumps({"candidate_id": candidate_id}) + "\n"
                for candidate_id in candidate_ids
            )
        )
    path = tmp_path / "experiments/combination-hybrid-v1/manifest.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(payload, indent=indent))
    return path


def test_manifest_hash_ignores_json_whitespace(tmp_path: Path) -> None:
    left_path = _write_manifest(tmp_path / "left", indent=2)
    right_path = _write_manifest(tmp_path / "right", indent=None)
    left = load_combination_manifest(left_path, project_root=tmp_path / "left")
    right = load_combination_manifest(right_path, project_root=tmp_path / "right")
    assert manifest_hash(left) == manifest_hash(right)


def test_manifest_has_six_primary_rules_and_control(tmp_path: Path) -> None:
    manifest = load_combination_manifest(
        _write_manifest(tmp_path), project_root=tmp_path
    )
    assert manifest.primary_fixtures == PRIMARY_FIXTURES
    assert manifest.control_fixtures == (
        ControlFixture("et-2060086", "near_cve_confusion_control"),
    )
    assert manifest.selected_blocks("et-2052951") == (
        "et-2052951-block-a",
        "et-2052951-block-b",
    )


@pytest.mark.parametrize(
    "change",
    [
        "primary",
        "control_name",
        "control_role",
    ],
)
def test_v1_experiment_rejects_wrong_fixture_contract(
    tmp_path: Path, change: str
) -> None:
    payload = _manifest_payload()
    selection = payload["selection"]
    assert isinstance(selection, dict)
    selected = selection["selected_blocks_by_fixture"]
    assert isinstance(selected, dict)
    if change == "primary":
        payload["primary_fixtures"] = [
            *PRIMARY_FIXTURES[:-1],
            "et-future-primary",
        ]
        selected["et-future-primary"] = selected.pop(PRIMARY_FIXTURES[-1])
    else:
        controls = payload["control_fixtures"]
        assert isinstance(controls, list)
        control = controls[0]
        assert isinstance(control, dict)
        if change == "control_name":
            control["name"] = "et-future-control"
            selected["et-future-control"] = selected.pop("et-2060086")
        else:
            control["role"] = "future_control"

    with pytest.raises(ValueError, match="combination-hybrid-v1 fixture contract"):
        load_combination_manifest(
            _write_manifest(tmp_path, payload=payload), project_root=tmp_path
        )


def test_future_experiment_id_uses_generic_fixture_validation(
    tmp_path: Path,
) -> None:
    payload = _manifest_payload()
    payload["experiment_id"] = "combination-hybrid-v2"
    payload["primary_fixtures"] = ["et-future-primary"]
    payload["control_fixtures"] = []
    selection = payload["selection"]
    assert isinstance(selection, dict)
    selection["selected_blocks_by_fixture"] = {
        "et-future-primary": ["et-future-primary-block-a"]
    }

    manifest = load_combination_manifest(
        _write_manifest(tmp_path, payload=payload), project_root=tmp_path
    )
    assert manifest.experiment_id == "combination-hybrid-v2"
    assert manifest.primary_fixtures == ("et-future-primary",)
    assert manifest.control_fixtures == ()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("version", True),
        ("version", 1.0),
        ("max_blocks", True),
        ("max_blocks", 8.0),
        ("minimum_combination_size", True),
        ("minimum_combination_size", 2.0),
    ],
)
def test_manifest_integer_fields_require_exact_json_integers(
    tmp_path: Path, field: str, value: object
) -> None:
    payload = _manifest_payload()
    if field == "version":
        payload[field] = value
    else:
        selection = payload["selection"]
        assert isinstance(selection, dict)
        selection[field] = value
    with pytest.raises(ValueError, match=f"{field} must be an integer"):
        load_combination_manifest(
            _write_manifest(tmp_path, payload=payload), project_root=tmp_path
        )


def test_locked_manifest_resolves_all_fixture_sources() -> None:
    manifest = load_combination_manifest(
        PROJECT_ROOT / "experiments/combination-hybrid-v1/manifest.json",
        project_root=PROJECT_ROOT,
    )
    assert {
        fixture: len(blocks)
        for fixture, blocks in (
            manifest.selection.selected_blocks_by_fixture.items()
        )
    } == {
        "et-2052951": 5,
        "et-2059741": 7,
        "et-2050340": 7,
        "et-2057330": 6,
        "et-2060144": 4,
        "et-2067354": 6,
        "et-2060086": 6,
    }
    assert manifest_hash(manifest) == LOCKED_MANIFEST_HASH


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda payload: payload["primary_fixtures"].append("et-2052951"),
            "duplicate primary fixture",
        ),
        (
            lambda payload: payload["control_fixtures"].append(
                {"name": "et-2052951", "role": "control"}
            ),
            "overlap",
        ),
        (
            lambda payload: payload["metrics"].append("unknown_metric"),
            "unknown metric",
        ),
        (
            lambda payload: payload["selection"][
                "selected_blocks_by_fixture"
            ].__setitem__(
                "et-2052951",
                ["et-2052951-block-a", "et-2052951-block-a"],
            ),
            "duplicate block",
        ),
        (
            lambda payload: payload["selection"][
                "selected_blocks_by_fixture"
            ].__setitem__(
                "et-2052951",
                [f"et-2052951-block-{index}" for index in range(9)],
            ),
            "more than 8 blocks",
        ),
    ],
)
def test_manifest_rejects_invalid_structure(
    tmp_path: Path, mutate, message: str
) -> None:
    payload = _manifest_payload()
    mutate(payload)
    path = _write_manifest(tmp_path, payload=payload)
    with pytest.raises(ValueError, match=message):
        load_combination_manifest(path, project_root=tmp_path)


def test_manifest_rejects_absent_source_run(tmp_path: Path) -> None:
    payload = _manifest_payload()
    path = _write_manifest(tmp_path, payload=payload)
    source_run = tmp_path / str(payload["source_run"])
    for results_path in source_run.glob("*/results.jsonl"):
        results_path.unlink()
        results_path.parent.rmdir()
    source_run.rmdir()
    with pytest.raises(ValueError, match="source run does not exist"):
        load_combination_manifest(path, project_root=tmp_path)


def test_manifest_rejects_selected_id_absent_from_fixture_results(
    tmp_path: Path,
) -> None:
    path = _write_manifest(tmp_path)
    results_path = (
        tmp_path
        / "runs/mutations/dataset-component-mutations-v2"
        / "et-2052951/results.jsonl"
    )
    results_path.write_text(
        json.dumps({"candidate_id": "et-2052951-block-a"}) + "\n"
    )
    with pytest.raises(ValueError, match="selected block not found"):
        load_combination_manifest(path, project_root=tmp_path)


def _record(candidate_id: str, **overrides: object) -> dict[str, object]:
    record: dict[str, object] = {
        "candidate_id": candidate_id,
        "component": "flow",
        "status": "evaluated",
        "positive_recall": 1.0,
        "meaningful_obscurity": None,
        "relationship_tier": "unclassified",
        "attacker_correct": True,
        "negative_false_positive_rate": 0.0,
        "benign_false_positive_rate": 0.0,
        "params": {},
    }
    record.update(overrides)
    return record


def test_resolver_excludes_ineligible_records() -> None:
    records = [
        _record("baseline", component="baseline"),
        _record("not-evaluated", status="positive_recall_failed"),
        _record("partial-recall", positive_recall=0.75),
        _record("eligible"),
    ]
    assert resolve_selected_blocks(records) == ("eligible",)


def test_resolver_prefers_meaningful_then_unrelated_miss_then_other() -> None:
    records = [
        _record("other"),
        _record(
            "unrelated-miss",
            attacker_correct=False,
            relationship_tier="unclassified",
        ),
        _record("meaningful", meaningful_obscurity=True),
    ]
    assert resolve_selected_blocks(records) == ("meaningful",)


def test_resolver_never_prioritizes_close_miss_as_meaningful() -> None:
    records = [
        _record(
            "close-miss",
            attacker_correct=False,
            relationship_tier="closely_related",
        ),
        _record("meaningful", meaningful_obscurity=True),
    ]
    assert resolve_selected_blocks(records) == ("meaningful",)


def test_resolver_uses_rates_and_candidate_id_as_stable_tiebreakers() -> None:
    records = [
        _record("z", negative_false_positive_rate=0.1),
        _record("b"),
        _record("a"),
    ]
    assert resolve_selected_blocks(records) == ("a",)


@pytest.mark.parametrize(
    "field", ["negative_false_positive_rate", "benign_false_positive_rate"]
)
def test_resolver_ranks_an_unmeasured_rate_behind_a_worse_measured_one(
    field: str,
) -> None:
    # The unmeasured record wins every other tiebreaker, including the
    # candidate ID, so only the rate ordering can decide this.
    records = [
        _record("a-unmeasured", **{field: None}),
        _record("z-measured", **{field: 0.5}),
    ]

    assert resolve_selected_blocks(records) == ("z-measured",)


def test_resolver_ranks_records_missing_false_positive_fields_last() -> None:
    bare = {
        "candidate_id": "bare",
        "component": "flow",
        "status": "evaluated",
        "positive_recall": 1.0,
        "params": {},
    }

    assert resolve_selected_blocks([bare, _record("measured")]) == ("measured",)


def test_resolver_still_selects_a_block_when_no_rate_was_measured() -> None:
    records = [
        _record("b", negative_false_positive_rate=None, benign_false_positive_rate=None),
        _record("a", negative_false_positive_rate=None, benign_false_positive_rate=None),
    ]

    assert resolve_selected_blocks(records) == ("a",)


def test_resolver_selects_three_distinct_content_slots_then_components() -> None:
    records = [
        _record("uri-best", component="content", buffer="http.uri"),
        _record(
            "uri-second",
            component="content",
            buffer="http.uri",
            negative_false_positive_rate=0.1,
        ),
        _record("header", component="content", buffer="http.header"),
        _record("body", component="content", buffer="http.request_body"),
        _record("payload", component="content", buffer="payload"),
        _record("flow", component="flow"),
        _record("pcre", component="pcre"),
        _record("sticky", component="sticky_buffer"),
        _record("port", component="destination_port"),
        _record("relative", component="relative_constraint"),
        _record("size", component="buffer_size"),
    ]
    assert resolve_selected_blocks(records) == (
        "body",
        "header",
        "payload",
        "flow",
        "pcre",
        "sticky",
        "port",
        "relative",
    )


def test_resolver_honors_cap_below_three_content_slots() -> None:
    records = [
        _record("uri", component="content", buffer="http.uri"),
        _record("header", component="content", buffer="http.header"),
        _record("body", component="content", buffer="http.request_body"),
        _record("flow", component="flow"),
    ]
    assert resolve_selected_blocks(records, max_blocks=1) == ("body",)
    assert resolve_selected_blocks(records, max_blocks=2) == ("body", "header")


@pytest.mark.parametrize("max_blocks", [True, False, 1.0, 8.0, 0, -1, 9])
def test_resolver_rejects_invalid_max_blocks(max_blocks: object) -> None:
    with pytest.raises(
        ValueError, match="max_blocks must be an integer from 1 through 8"
    ):
        resolve_selected_blocks([], max_blocks=max_blocks)  # type: ignore[arg-type]


def test_content_slot_falls_back_to_option_identity_without_collapsing() -> None:
    records = [
        _record(
            "uri-best",
            component="content",
            buffer=None,
            option_index=2,
            params={"content_index": 0},
        ),
        _record(
            "uri-second",
            component="content",
            buffer=None,
            option_index=2,
            params={"content_index": 0},
            negative_false_positive_rate=0.1,
        ),
        _record(
            "header",
            component="content",
            buffer=None,
            option_index=4,
            params={"content_index": 1},
        ),
        _record(
            "body",
            component="content",
            buffer=None,
            option_index=7,
            params={"content_index": 2},
        ),
    ]
    assert resolve_selected_blocks(records) == ("body", "header", "uri-best")
