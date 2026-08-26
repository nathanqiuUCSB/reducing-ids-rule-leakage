"""Pure provenance joins and comparisons for combination explorer records."""

from __future__ import annotations

import math
from pathlib import Path
import re
from typing import Literal, Mapping, Sequence, cast

from hardening_game.attribution.registry import RelatedCveRegistry
from hardening_game.mutations.combination_manifest import (
    CombinationManifest,
    load_combination_manifest,
    manifest_hash,
)
from hardening_game.mutations.evaluator import ManifestHashMismatch
from hardening_game.mutations.explorer_records import (
    latest_numbered_records,
    normalized_attacker,
)
from hardening_game.mutations.path_safety import (
    load_json_object,
    safe_directory,
    safe_file,
)
from hardening_game.mutations.reporting import (
    enrich_record,
    read_numbered_jsonl_records,
)


ComparisonLabel = Literal[
    "improved_obscurity",
    "reinforced_obscurity",
    "lost_obscurity",
    "no_obscurity_change",
    "unmeasured",
]
PrecisionChangeLabel = Literal[
    "precision_only_cost", "no_precision_cost", "unmeasured"
]
ComparisonMeasure = Literal["exact", "effective"]

_ATTRIBUTION_TIERS = frozenset(
    {"exact_match", "closely_related", "same_ecosystem", "unclassified"}
)
_PRECISION_FIELDS = (
    "negative_false_positive_rate",
    "benign_false_positive_rate",
)
_BLOCKS_OPERATOR = re.compile(r"blocks_(\d+)")


def _finite_unit_interval(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    measurement = float(value)
    if not math.isfinite(measurement) or not 0.0 <= measurement <= 1.0:
        return None
    return measurement


def _obscurity_miss(
    record: Mapping[str, object], measure: ComparisonMeasure
) -> bool | None:
    prediction = record.get("attacker_prediction")
    tier = record.get("relationship_tier")
    if (
        record.get("status") != "evaluated"
        or _finite_unit_interval(record.get("positive_recall")) != 1.0
        or record.get("attacker_error") is not None
        or not isinstance(prediction, str)
        or not prediction.strip()
        or tier not in _ATTRIBUTION_TIERS
    ):
        return None
    if measure == "exact":
        return tier != "exact_match"
    return tier not in {"exact_match", "closely_related"}


def classify_obscurity_comparison(
    *,
    measure: ComparisonMeasure,
    combination: Mapping[str, object],
    constituents: Sequence[Mapping[str, object]],
) -> ComparisonLabel:
    """Compare one combination with all constituents under one attribution measure."""
    if measure not in {"exact", "effective"}:
        raise ValueError(f"unknown obscurity comparison measure: {measure!r}")
    outcomes = [
        _obscurity_miss(record, measure)
        for record in (combination, *constituents)
    ]
    if not constituents or any(outcome is None for outcome in outcomes):
        return "unmeasured"
    combination_miss = cast(bool, outcomes[0])
    constituent_misses = cast(list[bool], outcomes[1:])
    if combination_miss and not any(constituent_misses):
        return "improved_obscurity"
    if combination_miss and any(constituent_misses):
        return "reinforced_obscurity"
    if not combination_miss and any(constituent_misses):
        return "lost_obscurity"
    return "no_obscurity_change"


def _measured_rate(record: Mapping[str, object], field: str) -> float | None:
    return _finite_unit_interval(record.get(field))


def classify_precision_change(
    *,
    combination: Mapping[str, object],
    constituents: Sequence[Mapping[str, object]],
    exact_comparison: ComparisonLabel,
    effective_comparison: ComparisonLabel,
) -> PrecisionChangeLabel:
    """Report a pure precision cost only when every required rate was measured."""
    records = (combination, *constituents)
    rates = {
        field: [_measured_rate(record, field) for record in records]
        for field in _PRECISION_FIELDS
    }
    if (
        not constituents
        or exact_comparison == "unmeasured"
        or effective_comparison == "unmeasured"
        or any(rate is None for values in rates.values() for rate in values)
    ):
        return "unmeasured"
    if "improved_obscurity" in {exact_comparison, effective_comparison}:
        return "no_precision_cost"
    for values in rates.values():
        measured = cast(list[float], values)
        if all(measured[0] > rate for rate in measured[1:]):
            return "precision_only_cost"
    return "no_precision_cost"


def _declared_manifest_path(project_root: Path, stored: object) -> Path:
    if not isinstance(stored, str) or not stored:
        raise ValueError("run metadata requires a nonempty manifest_path")
    relative = Path(stored)
    if relative.is_absolute():
        try:
            relative = relative.relative_to(project_root)
        except ValueError as error:
            raise ValueError("combination manifest must be inside project root") from error
    if ".." in relative.parts:
        raise ValueError("combination manifest path must not contain ..")
    return safe_file(
        project_root, project_root / relative, label="combination manifest"
    )


def resolve_combination_provenance(
    project_root: str | Path, run_root: str | Path
) -> dict[str, object]:
    """Validate a run's declared locked manifest and return join provenance."""
    root = Path(project_root).absolute()
    supplied_run = Path(run_root)
    run = supplied_run if supplied_run.is_absolute() else root / supplied_run
    safe_directory(root, run, label="combination run")
    metadata = load_json_object(
        root, run / "run_metadata.json", label="run metadata"
    )
    manifest_path = _declared_manifest_path(root, metadata.get("manifest_path"))
    manifest = load_combination_manifest(manifest_path, project_root=root)
    canonical_hash = manifest_hash(manifest)
    stored_hash = metadata.get("experiment_manifest_hash")
    if stored_hash != canonical_hash:
        raise ManifestHashMismatch(
            f"run metadata records manifest hash {stored_hash!r}, "
            f"not canonical hash {canonical_hash!r}"
        )
    if metadata.get("source_run") != manifest.source_run:
        raise ValueError(
            f"run metadata records source run {metadata.get('source_run')!r}, "
            f"not manifest source run {manifest.source_run!r}"
        )
    if metadata.get("experiment_id") != manifest.experiment_id:
        raise ValueError(
            f"run metadata records experiment {metadata.get('experiment_id')!r}, "
            f"not manifest experiment {manifest.experiment_id!r}"
        )
    roles = {fixture: "primary" for fixture in manifest.primary_fixtures}
    roles.update(
        {control.name: control.role for control in manifest.control_fixtures}
    )
    return {
        "manifest": manifest,
        "manifest_path": manifest_path,
        "manifest_hash": canonical_hash,
        "source_run": manifest.source_run,
        "roles": roles,
    }


def _dataset_targets(project_root: Path) -> dict[str, str]:
    manifest = load_json_object(
        project_root,
        project_root / "fixtures/dataset_manifest.json",
        label="dataset manifest",
    )
    records = manifest.get("records")
    if not isinstance(records, list):
        raise ValueError("dataset manifest records must be a list")
    targets: dict[str, str] = {}
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("dataset manifest records must be objects")
        fixture = record.get("name")
        target = record.get("cve")
        if isinstance(fixture, str) and isinstance(target, str):
            targets[fixture] = target
    return targets


def load_source_records(
    project_root: str | Path,
    provenance: Mapping[str, object],
    registry: RelatedCveRegistry,
) -> dict[str, object]:
    """Load one latest-record index for each manifest fixture."""
    root = Path(project_root).absolute()
    manifest = provenance.get("manifest")
    if not isinstance(manifest, CombinationManifest):
        raise ValueError("provenance is missing a validated combination manifest")
    targets = _dataset_targets(root)
    by_fixture: dict[str, dict[str, dict[str, object]]] = {}
    owners: dict[str, str] = {}
    diagnostics: list[dict[str, object]] = []
    diagnostics_by_fixture: dict[str, list[dict[str, object]]] = {}
    baselines: dict[str, str | None] = {}
    for fixture in manifest.selection.selected_blocks_by_fixture:
        fixture_diagnostics: list[dict[str, object]] = []
        target = targets.get(fixture)
        if target is None:
            raise ValueError(f"fixture missing from dataset manifest: {fixture}")
        path = safe_file(
            root,
            root / manifest.source_run / fixture / "results.jsonl",
            label="source results JSONL",
        )
        numbered, errors = read_numbered_jsonl_records(
            path, label=f"{fixture}/results.jsonl"
        )
        diagnostics.extend(errors)
        fixture_diagnostics.extend(errors)
        fixture_records: dict[str, dict[str, object]] = {}
        for line, record in latest_numbered_records(numbered):
            candidate_id = record.get("candidate_id")
            if not isinstance(candidate_id, str):
                diagnostic = {
                    "file": f"{fixture}/results.jsonl",
                    "line": line,
                    "error": "source record has no string candidate_id",
                }
                diagnostics.append(diagnostic)
                fixture_diagnostics.append(diagnostic)
                continue
            owner = owners.get(candidate_id)
            if owner is not None and owner != fixture:
                raise ValueError(
                    f"duplicate source candidate ID across fixtures: "
                    f"{candidate_id} ({owner}, {fixture})"
                )
            owners[candidate_id] = fixture
            try:
                enriched = enrich_record(
                    record, target_cve=target, registry=registry
                )
            except (KeyError, TypeError, ValueError) as error:
                diagnostic = {
                    "file": f"{fixture}/results.jsonl",
                    "line": line,
                    "error": f"source record unavailable: {error}",
                }
                diagnostics.append(diagnostic)
                fixture_diagnostics.append(diagnostic)
                continue
            fixture_records[candidate_id] = enriched
        baseline_id = f"{fixture}-baseline"
        baseline = fixture_records.get(baseline_id)
        baseline_rule = baseline.get("rule") if isinstance(baseline, dict) else None
        if not isinstance(baseline_rule, str):
            diagnostic = {
                "file": f"{fixture}/results.jsonl",
                "line": 0,
                "error": f"source baseline rule is unavailable: {baseline_id}",
            }
            diagnostics.append(diagnostic)
            fixture_diagnostics.append(diagnostic)
            baselines[fixture] = None
        else:
            baselines[fixture] = baseline_rule
        by_fixture[fixture] = fixture_records
        diagnostics_by_fixture[fixture] = fixture_diagnostics
    return {
        "by_fixture": by_fixture,
        "owners": owners,
        "diagnostics": diagnostics,
        "diagnostics_by_fixture": diagnostics_by_fixture,
        "baselines": baselines,
    }


def _valid_source_ids(raw: object) -> list[str] | None:
    if (
        not isinstance(raw, list)
        or not raw
        or any(not isinstance(item, str) or not item for item in raw)
    ):
        return None
    return cast(list[str], raw)


def _record_source_contract(
    record: Mapping[str, object],
) -> tuple[list[str] | None, list[dict[str, object]]]:
    diagnostics: list[dict[str, object]] = []
    params = record.get("params")
    params = params if isinstance(params, dict) else {}
    raw_top_ids = record.get("source_candidate_ids")
    raw_param_ids = params.get("source_candidate_ids")
    top_ids = _valid_source_ids(raw_top_ids)
    param_ids = _valid_source_ids(raw_param_ids)
    if top_ids is None:
        diagnostics.append(
            _diagnostic(None, "top-level source IDs are missing or malformed")
        )
    if param_ids is None:
        diagnostics.append(
            _diagnostic(None, "params source IDs are missing or malformed")
        )
    source_ids = top_ids or param_ids
    if source_ids is None:
        diagnostics.append(
            _diagnostic(None, "combination has no usable source IDs")
        )
        return None, diagnostics
    if top_ids is not None and param_ids is not None and top_ids != param_ids:
        diagnostics.append(
            _diagnostic(
                None,
                "top-level and params source IDs do not match",
            )
        )
    if len(source_ids) != len(set(source_ids)):
        diagnostics.append(_diagnostic(None, "combination repeats a source ID"))

    block_count = record.get("block_count")
    if (
        isinstance(block_count, bool)
        or not isinstance(block_count, int)
        or block_count != len(source_ids)
    ):
        diagnostics.append(
            _diagnostic(
                None,
                f"block_count {block_count!r} does not match "
                f"source ID count {len(source_ids)}",
            )
        )
    operator = record.get("operator")
    operator_match = (
        _BLOCKS_OPERATOR.fullmatch(operator) if isinstance(operator, str) else None
    )
    if operator_match is None or int(operator_match.group(1)) != len(source_ids):
        diagnostics.append(
            _diagnostic(
                None,
                f"operator {operator!r} does not match source ID count "
                f"{len(source_ids)}",
            )
        )
    for field in ("components", "operators", "source_categories"):
        value = params.get(field)
        if not isinstance(value, list) or len(value) != len(source_ids):
            count = len(value) if isinstance(value, list) else "non-list"
            diagnostics.append(
                _diagnostic(
                    None,
                    f"{field} count {count} does not match source ID count "
                    f"{len(source_ids)}",
                )
            )
    return source_ids, diagnostics


def _diagnostic(candidate_id: str | None, error: str) -> dict[str, object]:
    return {"source_candidate_id": candidate_id, "error": error}


def _unique(values: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _join_sources(
    record: Mapping[str, object],
    *,
    fixture: str,
    provenance: Mapping[str, object],
    source_records: Mapping[str, object],
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    expected_hash = provenance.get("manifest_hash")
    if record.get("experiment_manifest_hash") != expected_hash:
        return [], [
            _diagnostic(
                None,
                f"combination record manifest hash "
                f"{record.get('experiment_manifest_hash')!r} does not match "
                f"{expected_hash!r}",
            )
        ]
    manifest = provenance.get("manifest")
    if not isinstance(manifest, CombinationManifest):
        return [], [_diagnostic(None, "validated manifest is unavailable")]
    if fixture not in manifest.selection.selected_blocks_by_fixture:
        return [], [_diagnostic(None, f"fixture is not in manifest: {fixture}")]
    requested, contract_diagnostics = _record_source_contract(record)
    if requested is None:
        return [], contract_diagnostics

    raw_by_fixture = source_records.get("by_fixture")
    raw_owners = source_records.get("owners")
    by_fixture = raw_by_fixture if isinstance(raw_by_fixture, dict) else {}
    owners = raw_owners if isinstance(raw_owners, dict) else {}
    fixture_records = by_fixture.get(fixture)
    fixture_records = fixture_records if isinstance(fixture_records, dict) else {}
    selected = manifest.selected_blocks(fixture)
    requested_set = set(requested)
    joined: list[dict[str, object]] = []
    raw_fixture_diagnostics = source_records.get("diagnostics_by_fixture")
    diagnostics_by_fixture = (
        raw_fixture_diagnostics
        if isinstance(raw_fixture_diagnostics, dict)
        else {}
    )
    fixture_diagnostics = diagnostics_by_fixture.get(fixture)
    diagnostics: list[dict[str, object]] = [
        {**diagnostic, "source_candidate_id": None}
        for diagnostic in (
            fixture_diagnostics if isinstance(fixture_diagnostics, list) else []
        )
        if isinstance(diagnostic, dict)
    ]
    diagnostics.extend(contract_diagnostics)

    for candidate_id in selected:
        if candidate_id not in requested_set:
            continue
        source = fixture_records.get(candidate_id)
        if isinstance(source, dict):
            joined.append(source)
        else:
            diagnostics.append(
                _diagnostic(candidate_id, f"missing source ID: {candidate_id}")
            )
    for candidate_id in requested:
        if candidate_id in selected:
            continue
        owner = owners.get(candidate_id)
        if owner is not None and owner != fixture:
            error = (
                f"source ID belongs to a different fixture: "
                f"{candidate_id} ({owner})"
            )
        elif owner == fixture:
            error = f"source ID is not selected by the manifest: {candidate_id}"
        else:
            error = f"missing source ID: {candidate_id}"
        diagnostics.append(_diagnostic(candidate_id, error))
    return joined, diagnostics


def _base_extensions(
    record: Mapping[str, object],
    *,
    fixture: str,
    provenance: Mapping[str, object],
    source_records: Mapping[str, object],
) -> tuple[dict[str, object], list[dict[str, object]], list[dict[str, object]]]:
    constituents, diagnostics = _join_sources(
        record,
        fixture=fixture,
        provenance=provenance,
        source_records=source_records,
    )
    if diagnostics:
        exact: ComparisonLabel = "unmeasured"
        effective: ComparisonLabel = "unmeasured"
    else:
        exact = classify_obscurity_comparison(
            measure="exact", combination=record, constituents=constituents
        )
        effective = classify_obscurity_comparison(
            measure="effective", combination=record, constituents=constituents
        )
    components = [str(source.get("component", "")) for source in constituents]
    operators = [str(source.get("operator", "")) for source in constituents]
    roles = provenance.get("roles")
    role = roles.get(fixture) if isinstance(roles, dict) else None
    extension = {
        "experiment_role": role,
        "included_components": components,
        "included_operators": operators,
        "included_families": _unique(components),
        "included_block_labels": [
            f"{component}/{operator}"
            for component, operator in zip(components, operators)
        ],
        "exact_obscurity_comparison": exact,
        "effective_obscurity_comparison": effective,
        "source_join_status": "complete" if not diagnostics else "unavailable",
        "source_join_diagnostic_count": len(diagnostics),
        "precision_change": classify_precision_change(
            combination=record,
            constituents=constituents,
            exact_comparison=exact,
            effective_comparison=effective,
        ),
    }
    return extension, constituents, diagnostics


def build_combination_index_extensions(
    record: Mapping[str, object],
    *,
    fixture: str,
    provenance: Mapping[str, object],
    source_records: Mapping[str, object],
) -> dict[str, object]:
    """Return lightweight combination-only fields for an index record."""
    extension, _, _ = _base_extensions(
        record,
        fixture=fixture,
        provenance=provenance,
        source_records=source_records,
    )
    return extension


def _attribution_state(
    source: Mapping[str, object], measure: ComparisonMeasure
) -> str:
    miss = _obscurity_miss(source, measure)
    if miss is None:
        return "unmeasured"
    return "miss" if miss else "hit"


def _building_block(
    source: Mapping[str, object], *, baseline_rule: str | None
) -> dict[str, object]:
    normalized = normalized_attacker(source)
    mutated_rule = source.get("rule")
    return {
        "candidate_id": source.get("candidate_id"),
        "join_status": "available",
        "component": source.get("component"),
        "operator": source.get("operator"),
        "description": source.get("description"),
        "buffer": source.get("buffer"),
        "params": source.get("params"),
        "mutation_category": source.get("mutation_category"),
        "positive_recall": source.get("positive_recall"),
        "negative_false_positive_rate": source.get(
            "negative_false_positive_rate"
        ),
        "benign_false_positive_rate": source.get("benign_false_positive_rate"),
        "attacker": {
            key: normalized.get(key)
            for key in ("status", "predicted_cve", "reasoning", "clues", "error")
        },
        "attacker_prediction": source.get("attacker_prediction"),
        "attacker_correct": source.get("attacker_correct"),
        "relationship_tier": source.get("relationship_tier"),
        "meaningful_obscurity": source.get("meaningful_obscurity"),
        "baseline_rule": baseline_rule,
        "mutated_rule": (
            mutated_rule if isinstance(mutated_rule, str) else None
        ),
        "exact_attribution": _attribution_state(source, "exact"),
        "effective_attribution": _attribution_state(source, "effective"),
    }


def build_combination_detail_extensions(
    record: Mapping[str, object],
    *,
    fixture: str,
    provenance: Mapping[str, object],
    source_records: Mapping[str, object],
) -> dict[str, object]:
    """Return comparisons plus an ordered, explicitly projected source summary."""
    extension, constituents, diagnostics = _base_extensions(
        record,
        fixture=fixture,
        provenance=provenance,
        source_records=source_records,
    )
    raw_baselines = source_records.get("baselines")
    baselines = raw_baselines if isinstance(raw_baselines, dict) else {}
    stored_baseline = baselines.get(fixture)
    baseline_rule = stored_baseline if isinstance(stored_baseline, str) else None
    blocks = [
        _building_block(source, baseline_rule=baseline_rule)
        for source in constituents
    ]
    blocks.extend(
        {
            "candidate_id": diagnostic["source_candidate_id"],
            "join_status": "unavailable",
            "component": None,
            "operator": None,
            "description": None,
            "buffer": None,
            "params": None,
            "mutation_category": None,
            "positive_recall": None,
            "negative_false_positive_rate": None,
            "benign_false_positive_rate": None,
            "attacker": {
                "status": "unavailable",
                "predicted_cve": None,
                "reasoning": None,
                "clues": [],
                "error": None,
            },
            "attacker_prediction": None,
            "attacker_correct": None,
            "relationship_tier": None,
            "meaningful_obscurity": None,
            "baseline_rule": baseline_rule,
            "mutated_rule": None,
            "exact_attribution": "unmeasured",
            "effective_attribution": "unmeasured",
        }
        for diagnostic in diagnostics
        if diagnostic["source_candidate_id"] is not None
    )
    manifest = provenance.get("manifest")
    if isinstance(manifest, CombinationManifest) and fixture in (
        manifest.selection.selected_blocks_by_fixture
    ):
        source_order = {
            candidate_id: position
            for position, candidate_id in enumerate(manifest.selected_blocks(fixture))
        }
        blocks.sort(
            key=lambda block: source_order.get(
                str(block.get("candidate_id")), len(source_order)
            )
        )
    extension.update(
        {
            "building_blocks": blocks,
            "join_diagnostics": diagnostics,
        }
    )
    return extension
