"""Strict loading and deterministic resolution for combination manifests."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping

from hardening_game.mutations.path_safety import assert_safe_path


_METRICS = (
    "exact_cve",
    "effective_attribution",
    "positive_recall",
    "synthetic_precision",
    "benign_precision",
)
_V1_PRIMARY_FIXTURES = (
    "et-2052951",
    "et-2059741",
    "et-2050340",
    "et-2057330",
    "et-2060144",
    "et-2067354",
)
_COMPONENT_PRIORITY = (
    "flow",
    "pcre",
    "sticky_buffer",
    "destination_port",
    "relative_constraint",
    "buffer_size",
    "byte_test",
    "content_modifier",
    "negated_content",
)
_ROOT_KEYS = {
    "version",
    "experiment_id",
    "source_run",
    "primary_fixtures",
    "control_fixtures",
    "selection",
    "metrics",
}
_SELECTION_KEYS = {
    "strategy",
    "max_blocks",
    "minimum_combination_size",
    "selected_blocks_by_fixture",
}


@dataclass(frozen=True)
class ControlFixture:
    name: str
    role: str


_V1_CONTROL_FIXTURES = (
    ControlFixture("et-2060086", "near_cve_confusion_control"),
)


@dataclass(frozen=True)
class CombinationSelection:
    strategy: str
    max_blocks: int
    minimum_combination_size: int
    selected_blocks_by_fixture: Mapping[str, tuple[str, ...]]


@dataclass(frozen=True)
class CombinationManifest:
    version: int
    experiment_id: str
    source_run: str
    primary_fixtures: tuple[str, ...]
    control_fixtures: tuple[ControlFixture, ...]
    selection: CombinationSelection
    metrics: tuple[str, ...]

    def selected_blocks(self, fixture: str) -> tuple[str, ...]:
        """Return locked IDs directly; runtime callers must not rerank."""
        return self.selection.selected_blocks_by_fixture[fixture]


def _require_json_integer(value: object, context: str) -> int:
    if type(value) is not int:
        raise ValueError(f"{context} must be an integer")
    return value


def _require_exact_keys(
    data: Mapping[str, object], expected: set[str], context: str
) -> None:
    keys = set(data)
    if keys != expected:
        missing = sorted(expected - keys)
        unknown = sorted(keys - expected)
        raise ValueError(
            f"{context} keys differ: missing={missing}, unknown={unknown}"
        )


def _require_string(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{context} must be a nonempty string")
    return value


def _require_string_list(value: object, context: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError(f"{context} must be a list")
    return tuple(
        _require_string(item, f"{context} entry") for item in value
    )


def _parse_controls(value: object) -> tuple[ControlFixture, ...]:
    if not isinstance(value, list):
        raise ValueError("control_fixtures must be a list")
    controls: list[ControlFixture] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {"name", "role"}:
            raise ValueError("control fixture must contain only name and role")
        controls.append(
            ControlFixture(
                _require_string(item["name"], "control fixture name"),
                _require_string(item["role"], "control fixture role"),
            )
        )
    return tuple(controls)


def _parse_selection(value: object) -> CombinationSelection:
    if not isinstance(value, dict):
        raise ValueError("selection must be an object")
    _require_exact_keys(value, _SELECTION_KEYS, "selection")
    strategy = _require_string(value["strategy"], "selection strategy")
    max_blocks = _require_json_integer(value["max_blocks"], "max_blocks")
    minimum_size = _require_json_integer(
        value["minimum_combination_size"], "minimum_combination_size"
    )
    if strategy != "hybrid_ranked_v1":
        raise ValueError(f"unsupported selection strategy: {strategy}")
    if max_blocks != 8:
        raise ValueError("selection max_blocks must be 8")
    if minimum_size != 2:
        raise ValueError("selection minimum_combination_size must be 2")

    raw_selected = value["selected_blocks_by_fixture"]
    if not isinstance(raw_selected, dict):
        raise ValueError("selected_blocks_by_fixture must be an object")
    selected: dict[str, tuple[str, ...]] = {}
    all_blocks: set[str] = set()
    for fixture, raw_blocks in raw_selected.items():
        fixture_name = _require_string(fixture, "selected fixture")
        blocks = _require_string_list(
            raw_blocks, f"selected blocks for {fixture_name}"
        )
        if len(blocks) != len(set(blocks)):
            raise ValueError(f"duplicate block for fixture {fixture_name}")
        if len(blocks) > max_blocks:
            raise ValueError(f"more than 8 blocks for fixture {fixture_name}")
        duplicate_across_fixtures = all_blocks.intersection(blocks)
        if duplicate_across_fixtures:
            raise ValueError(
                "duplicate block across fixtures: "
                f"{sorted(duplicate_across_fixtures)}"
            )
        all_blocks.update(blocks)
        selected[fixture_name] = blocks
    return CombinationSelection(
        strategy=strategy,
        max_blocks=max_blocks,
        minimum_combination_size=minimum_size,
        selected_blocks_by_fixture=selected,
    )


def _project_root_for(manifest_path: Path, source_run: str) -> Path:
    for parent in manifest_path.resolve().parents:
        if parent.joinpath(source_run).is_dir():
            return parent
    if len(manifest_path.resolve().parents) >= 3:
        return manifest_path.resolve().parents[2]
    return manifest_path.resolve().parent


def _validate_source_records(
    manifest: CombinationManifest, project_root: Path
) -> None:
    source_run = project_root / manifest.source_run
    if not source_run.is_dir():
        raise ValueError(f"source run does not exist: {source_run}")
    for fixture, blocks in manifest.selection.selected_blocks_by_fixture.items():
        results_path = source_run / fixture / "results.jsonl"
        assert_safe_path(
            project_root,
            results_path,
            label="fixture source results",
        )
        if not results_path.is_file():
            raise ValueError(
                f"fixture source results do not exist: {results_path}"
            )
        available: set[str] = set()
        for line_number, line in enumerate(
            results_path.read_text().splitlines(), start=1
        ):
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(
                    f"invalid JSON at {results_path}:{line_number}"
                ) from error
            candidate_id = record.get("candidate_id")
            if isinstance(candidate_id, str):
                available.add(candidate_id)
        for block in blocks:
            if block not in available:
                raise ValueError(
                    f"selected block not found in {results_path}: {block}"
                )


def load_combination_manifest(
    path: str | Path, *, project_root: str | Path | None = None
) -> CombinationManifest:
    """Load and fully validate a locked combination manifest."""
    manifest_path = Path(path)
    try:
        data = json.loads(manifest_path.read_text())
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid manifest JSON: {manifest_path}") from error
    if not isinstance(data, dict):
        raise ValueError("manifest must be an object")
    _require_exact_keys(data, _ROOT_KEYS, "manifest")

    version = _require_json_integer(data["version"], "version")
    if version != 1:
        raise ValueError(f"unsupported manifest version: {version}")
    experiment_id = _require_string(data["experiment_id"], "experiment_id")
    source_run = _require_string(data["source_run"], "source_run")
    if source_run != "runs/mutations/dataset-component-mutations-v2":
        raise ValueError(f"unexpected source_run: {source_run}")

    primary = _require_string_list(
        data["primary_fixtures"], "primary_fixtures"
    )
    if len(primary) != len(set(primary)):
        raise ValueError("duplicate primary fixture")
    controls = _parse_controls(data["control_fixtures"])
    control_names = tuple(control.name for control in controls)
    if len(control_names) != len(set(control_names)):
        raise ValueError("duplicate control fixture")
    overlap = set(primary).intersection(control_names)
    if overlap:
        raise ValueError(f"primary/control fixture overlap: {sorted(overlap)}")
    if experiment_id == "combination-hybrid-v1" and (
        primary != _V1_PRIMARY_FIXTURES or controls != _V1_CONTROL_FIXTURES
    ):
        raise ValueError(
            "combination-hybrid-v1 fixture contract requires the exact six "
            "primary fixtures and sole near-CVE confusion control"
        )

    metrics = _require_string_list(data["metrics"], "metrics")
    unknown_metrics = set(metrics) - set(_METRICS)
    if unknown_metrics:
        raise ValueError(f"unknown metric: {sorted(unknown_metrics)}")
    if len(metrics) != len(set(metrics)):
        raise ValueError("duplicate metric")
    if metrics != _METRICS:
        raise ValueError(f"metrics must be exactly {_METRICS}")

    selection = _parse_selection(data["selection"])
    fixture_names = (*primary, *control_names)
    selected_names = tuple(selection.selected_blocks_by_fixture)
    if set(selected_names) != set(fixture_names):
        raise ValueError(
            "selected fixture keys must exactly match primary and control fixtures"
        )

    manifest = CombinationManifest(
        version=version,
        experiment_id=experiment_id,
        source_run=source_run,
        primary_fixtures=primary,
        control_fixtures=controls,
        selection=selection,
        metrics=metrics,
    )
    root = (
        Path(project_root)
        if project_root is not None
        else _project_root_for(manifest_path, source_run)
    )
    _validate_source_records(manifest, root)
    return manifest


def _manifest_data(manifest: CombinationManifest) -> dict[str, object]:
    return {
        "version": manifest.version,
        "experiment_id": manifest.experiment_id,
        "source_run": manifest.source_run,
        "primary_fixtures": list(manifest.primary_fixtures),
        "control_fixtures": [
            {"name": control.name, "role": control.role}
            for control in manifest.control_fixtures
        ],
        "selection": {
            "strategy": manifest.selection.strategy,
            "max_blocks": manifest.selection.max_blocks,
            "minimum_combination_size": (
                manifest.selection.minimum_combination_size
            ),
            "selected_blocks_by_fixture": {
                fixture: list(blocks)
                for fixture, blocks in (
                    manifest.selection.selected_blocks_by_fixture.items()
                )
            },
        },
        "metrics": list(manifest.metrics),
    }


def manifest_hash(manifest: CombinationManifest) -> str:
    """Return the SHA-256 of canonical, whitespace-independent JSON."""
    canonical = json.dumps(
        _manifest_data(manifest),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def _false_positive_rank(value: object) -> tuple[int, float]:
    """Rank a measured rate ahead of an unmeasured one, never comparing None.

    A block whose false-positive rate was never measured is not a clean zero
    and is not orderable against a float, so it sorts after every measured
    rate instead of raising when the resolver ranks a mixed record set.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return (1, 0.0)
    return (0, float(value))


def _candidate_rank(record: Mapping[str, object]) -> tuple[object, ...]:
    if record.get("meaningful_obscurity") is True:
        attribution_rank = 0
    elif (
        record.get("attacker_correct") is False
        and record.get("relationship_tier") != "closely_related"
    ):
        attribution_rank = 1
    else:
        attribution_rank = 2
    return (
        attribution_rank,
        _false_positive_rank(record.get("negative_false_positive_rate")),
        _false_positive_rank(record.get("benign_false_positive_rate")),
        str(record.get("candidate_id", "")),
    )


def _content_slot(record: Mapping[str, object]) -> tuple[object, ...]:
    params = record.get("params")
    params = params if isinstance(params, dict) else {}
    for value in (record.get("buffer"), params.get("buffer")):
        if isinstance(value, str) and value.strip():
            return ("buffer", value.strip())

    buffer_identity = {
        key: value
        for key, value in params.items()
        if "buffer" in key and value not in (None, "")
    }
    if buffer_identity:
        return (
            "buffer_params",
            json.dumps(
                buffer_identity,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ),
        )

    option_index = record.get("option_index", params.get("option_index"))
    content_index = params.get("content_index")
    if option_index is not None or content_index is not None:
        return ("option", option_index, content_index)
    return (
        "params",
        json.dumps(
            params, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ),
    )


def resolve_selected_blocks(
    records: Iterable[Mapping[str, object]], *, max_blocks: int = 8
) -> tuple[str, ...]:
    """Resolve deterministic winners from enriched single-mutation records."""
    if type(max_blocks) is not int or not 1 <= max_blocks <= 8:
        raise ValueError("max_blocks must be an integer from 1 through 8")
    eligible = [
        record
        for record in records
        if record.get("status") == "evaluated"
        and record.get("positive_recall") == 1.0
        and record.get("component") != "baseline"
    ]

    content_by_slot: dict[
        tuple[object, ...], list[Mapping[str, object]]
    ] = {}
    by_component: dict[str, list[Mapping[str, object]]] = {}
    for record in eligible:
        component = record.get("component")
        if component == "content":
            content_by_slot.setdefault(_content_slot(record), []).append(record)
        elif isinstance(component, str):
            by_component.setdefault(component, []).append(record)

    content_winners = sorted(
        (min(slot_records, key=_candidate_rank) for slot_records in content_by_slot.values()),
        key=_candidate_rank,
    )[: min(3, max_blocks)]
    selected = [str(record["candidate_id"]) for record in content_winners]

    for component in _COMPONENT_PRIORITY:
        if len(selected) >= max_blocks:
            break
        candidates = by_component.get(component)
        if candidates:
            selected.append(str(min(candidates, key=_candidate_rank)["candidate_id"]))
    return tuple(selected)
