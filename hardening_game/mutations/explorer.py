"""Read-only access to completed single-mutation experiment records."""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Mapping

from hardening_game.attribution.registry import (
    RelatedCveRegistry,
    load_related_cve_registry,
)
from hardening_game.mutations.combination_explorer import (
    build_combination_detail_extensions,
    build_combination_index_extensions,
    load_source_records,
    resolve_combination_provenance,
)
from hardening_game.mutations.evaluator import ManifestHashMismatch
from hardening_game.mutations.reporting import (
    enrich_record,
    read_numbered_jsonl_records,
)
from hardening_game.mutations.path_safety import (
    SAFE_ID,
    assert_safe_path as _assert_safe_path,
    load_json_object as _load_json_object,
    safe_directory as _safe_directory,
    safe_file as _safe_file,
    validate_id as _validate_id,
)
from hardening_game.mutations.explorer_records import (
    latest_numbered_records as _latest_numbered_records,
    normalized_attacker as _normalized_attacker,
)


MUTATION_FAMILY_ORDER = (
    "flow",
    "pcre",
    "sticky_buffer",
    "destination_port",
    "relative_constraint",
    "buffer_size",
    "byte_test",
    "content_modifier",
    "negated_content",
    "content",
    "baseline",
)
_FAMILY_RANK = {
    family: position for position, family in enumerate(MUTATION_FAMILY_ORDER)
}
_LARGE_INDEX_FIELDS = frozenset(
    {"rule", "attacker_exchange", "case_results", "benign_capture_results"}
)
_UNKNOWN_FIXTURE_DIAGNOSTIC = (
    "directory holds results but is not a fixture in the dataset manifest, "
    "so its records were skipped"
)
_PENDING_FIXTURE_DIAGNOSTIC = (
    "fixture directory has no results JSONL, so it contributed no records; "
    "an evaluation that is still running or that rejected every mutation "
    "looks like this"
)
_FLAT_LAYOUT_DIAGNOSTIC = (
    "run stores results at the run root instead of one directory per fixture, "
    "which is not a layout the explorer reads"
)
# A record can be individually unreadable without the run being broken, so the
# reader keeps the readable remainder and publishes the hole it stepped over.
_RECORD_ERRORS = (ValueError, KeyError, TypeError)
# One unreadable run must not take the whole listing down with it, so scanning
# failures are reported per run instead of raised.
_RUN_ERRORS = (ValueError, KeyError, TypeError, OSError)


class UnknownMutationCandidate(ValueError):
    """Raised when a safe candidate ID is absent from a readable run."""


class _ExplorerRequestCache:
    """Share immutable combination joins within one explorer request."""

    def __init__(self) -> None:
        self.provenance: dict[tuple[str, str, str, str], dict[str, object]] = {}
        self.sources: dict[tuple[str, str], dict[str, object]] = {}


def _runs_root(project_root: Path) -> Path:
    return project_root / "runs" / "mutations"


def _manifest_records(project_root: Path) -> dict[str, dict[str, object]]:
    manifest = _load_json_object(
        project_root,
        project_root / "fixtures" / "dataset_manifest.json",
        label="dataset manifest",
    )
    raw_records = manifest.get("records")
    if not isinstance(raw_records, list):
        raise ValueError("dataset manifest records must be a list")
    records: dict[str, dict[str, object]] = {}
    for raw in raw_records:
        if not isinstance(raw, dict):
            raise ValueError("dataset manifest records must be JSON objects")
        name = raw.get("name")
        target = raw.get("cve")
        if not isinstance(name, str) or not isinstance(target, str):
            raise ValueError("dataset manifest records require string name and cve")
        _validate_id(name, kind="fixture")
        if name in records:
            raise ValueError(f"duplicate fixture in dataset manifest: {name}")
        records[name] = raw
    return records


def _run_directory(project_root: Path, run_id: str) -> Path:
    _validate_id(run_id, kind="run")
    return _safe_directory(
        project_root, _runs_root(project_root) / run_id, label="run"
    )


def _explorer_fixture_directories(
    project_root: Path,
    run_root: Path,
    manifest_fixtures: Mapping[str, object],
) -> tuple[list[Path], list[dict[str, object]]]:
    """Return the run's readable fixture directories plus data-quality notes.

    A run tree also holds nested preflight groups and one-off sibling
    directories, so membership needs positive evidence: either the manifest
    knows the fixture, or the directory itself holds a results JSONL. Discovery
    and scanning share this function so a listed run is always readable.
    """
    fixtures: list[Path] = []
    diagnostics: list[dict[str, object]] = []
    for path in sorted(run_root.iterdir(), key=lambda entry: entry.name):
        if path.is_symlink():
            raise ValueError(f"fixture must not be a symlink: {path}")
        if not path.is_dir():
            continue
        _validate_id(path.name, kind="fixture")
        _safe_directory(project_root, path, label="fixture")
        results_path = path / "results.jsonl"
        has_direct_results = results_path.exists() or results_path.is_symlink()
        known = path.name in manifest_fixtures
        if known and has_direct_results:
            fixtures.append(path)
        elif known or has_direct_results:
            diagnostics.append(
                {
                    "file": f"{path.name}/results.jsonl",
                    "line": 0,
                    "error": (
                        _PENDING_FIXTURE_DIAGNOSTIC
                        if known
                        else _UNKNOWN_FIXTURE_DIAGNOSTIC
                    ),
                }
            )
    root_results = run_root / "results.jsonl"
    if not fixtures and (root_results.exists() or root_results.is_symlink()):
        diagnostics.append(
            {"file": "results.jsonl", "line": 0, "error": _FLAT_LAYOUT_DIAGNOSTIC}
        )
    return fixtures, diagnostics


def build_index_entry(
    record: Mapping[str, object],
    *,
    fixture: str,
    target_cve: str,
    baseline_exact: bool,
) -> dict[str, object]:
    """Return a small record plus exact-CVE miss and precision classifications."""
    entry = {
        key: value for key, value in record.items() if key not in _LARGE_INDEX_FIELDS
    }
    prediction = record.get("attacker_prediction")
    valid_prediction = isinstance(prediction, str) and bool(prediction.strip())
    eligible = (
        record.get("component") != "baseline"
        and baseline_exact
        and record.get("status") == "evaluated"
        and record.get("positive_recall") == 1.0
        and valid_prediction
        and record.get("attacker_error") is None
    )
    emergent = eligible and prediction != target_cve
    synthetic_rate = record.get("negative_false_positive_rate")
    benign_rate = record.get("benign_false_positive_rate")
    precision_measured = (
        isinstance(synthetic_rate, (int, float))
        and not isinstance(synthetic_rate, bool)
        and isinstance(benign_rate, (int, float))
        and not isinstance(benign_rate, bool)
    )
    balanced = (
        emergent
        and precision_measured
        and synthetic_rate == 0
        and benign_rate == 0
    )
    unbalanced = emergent and not balanced
    entry.update(
        {
            "fixture": fixture,
            "target_cve": target_cve,
            "baseline_exact": baseline_exact,
            "is_emergent_miss": emergent,
            "is_balanced_emergent_miss": balanced,
            "is_unbalanced_emergent_miss": unbalanced,
            "is_closely_related_guess": (
                emergent and record.get("relationship_tier") == "closely_related"
            ),
        }
    )
    return entry


def _explorer_configuration(
    project_root: Path,
) -> tuple[dict[str, dict[str, object]], RelatedCveRegistry]:
    """Load the committed manifest and registry every run scan needs.

    Listing reads this once so a broken committed configuration still fails
    loudly instead of being reported as every run being individually broken.
    """
    manifest = _manifest_records(project_root)
    registry = load_related_cve_registry(
        _safe_file(
            project_root,
            project_root / "fixtures" / "related_cve_registry.json",
            label="related-CVE registry",
        )
    )
    return manifest, registry


def _combination_metadata(
    project_root: Path, run_root: Path
) -> dict[str, object] | None:
    """Return only metadata that explicitly declares combination provenance."""
    path = run_root / "run_metadata.json"
    if not (path.exists() or path.is_symlink()):
        return None
    _safe_file(project_root, path, label="run metadata")
    text = path.read_text(encoding="utf-8")
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(value, dict):
        return None
    fields = {
        field: value.get(field)
        for field in (
            "experiment_id",
            "experiment_manifest_hash",
            "manifest_path",
            "source_run",
        )
    }
    if any(
        not isinstance(stored, str) or not stored
        for stored in fields.values()
    ):
        return None
    if fields["source_run"] != "runs/mutations/dataset-component-mutations-v2":
        return None
    stored_hash = fields["experiment_manifest_hash"]
    if (
        not isinstance(stored_hash, str)
        or re.fullmatch(r"[0-9a-f]{64}", stored_hash) is None
    ):
        return None
    return value


def _provenance_cache_key(
    metadata: Mapping[str, object],
) -> tuple[str, str, str, str] | None:
    values = tuple(
        metadata.get(field)
        for field in (
            "experiment_id",
            "experiment_manifest_hash",
            "manifest_path",
            "source_run",
        )
    )
    if not all(isinstance(value, str) for value in values):
        return None
    experiment_id, stored_hash, manifest_path, source_run = values
    return (
        str(experiment_id),
        str(stored_hash),
        str(manifest_path),
        str(source_run),
    )


def _scan_run(
    project_root: Path,
    run_id: str,
    configuration: tuple[dict[str, dict[str, object]], RelatedCveRegistry]
    | None = None,
    request_cache: _ExplorerRequestCache | None = None,
) -> tuple[
    list[dict[str, object]],
    list[dict[str, object]],
    dict[str, dict[str, object]],
]:
    run_root = _run_directory(project_root, run_id)
    manifest, registry = configuration or _explorer_configuration(project_root)
    fixture_dirs, diagnostics = _explorer_fixture_directories(
        project_root, run_root, manifest
    )
    cache = request_cache or _ExplorerRequestCache()
    combination_provenance: dict[str, object] | None = None
    combination_sources: dict[str, object] | None = None
    combination_metadata = _combination_metadata(project_root, run_root)
    if combination_metadata is not None:
        provenance_key = _provenance_cache_key(combination_metadata)
        try:
            combination_provenance = (
                cache.provenance.get(provenance_key)
                if provenance_key is not None
                else None
            )
            if combination_provenance is None:
                combination_provenance = resolve_combination_provenance(
                    project_root, run_root
                )
                if provenance_key is not None:
                    cache.provenance[provenance_key] = combination_provenance
        except ManifestHashMismatch as error:
            diagnostics.append(
                {
                    "file": "run_metadata.json",
                    "line": 0,
                    "error": (
                        "combination provenance unavailable: "
                        f"{_redacted_reason(project_root, error)}"
                    ),
                }
            )
        else:
            sources_key = (
                str(combination_provenance.get("manifest_hash")),
                str(combination_provenance.get("source_run")),
            )
            combination_sources = cache.sources.get(sources_key)
            if combination_sources is None:
                combination_sources = load_source_records(
                    project_root, combination_provenance, registry
                )
                cache.sources[sources_key] = combination_sources
    by_fixture: dict[str, dict[str, object]] = {}
    candidate_owners: dict[str, str] = {}
    entries: list[dict[str, object]] = []

    for fixture_dir in fixture_dirs:
        fixture = fixture_dir.name
        manifest_record = manifest[fixture]
        _project_data_path(
            project_root, manifest_record.get("fixture"), label="fixture"
        )
        _project_data_path(project_root, manifest_record.get("suite"), label="suite")
        target_cve = manifest_record["cve"]
        if not isinstance(target_cve, str):
            raise ValueError(f"fixture {fixture} has no target CVE")
        label = f"{fixture}/results.jsonl"
        results_path = _safe_file(
            project_root,
            fixture_dir / "results.jsonl", label="results JSONL"
        )
        numbered, errors = read_numbered_jsonl_records(results_path, label=label)
        diagnostics.extend(errors)
        enriched: list[tuple[int, dict[str, object]]] = []
        for line, record in _latest_numbered_records(numbered):
            try:
                enriched.append(
                    (
                        line,
                        enrich_record(
                            record, target_cve=target_cve, registry=registry
                        ),
                    )
                )
            except _RECORD_ERRORS as error:
                diagnostics.append(
                    {"file": label, "line": line, "error": f"record skipped: {error}"}
                )
        baseline = next(
            (
                record
                for _, record in enriched
                if record.get("component") == "baseline"
            ),
            None,
        )
        baseline_exact = (
            baseline is not None
            and baseline.get("relationship_tier") == "exact_match"
        )
        fixture_records: dict[str, dict[str, object]] = {}
        for line, record in enriched:
            candidate_id = record.get("candidate_id")
            if not isinstance(candidate_id, str):
                continue
            _validate_id(candidate_id, kind="candidate")
            owner = candidate_owners.get(candidate_id)
            if owner is not None and owner != fixture:
                raise ValueError(
                    f"duplicate candidate ID across fixtures: {candidate_id} "
                    f"({owner}, {fixture})"
                )
            candidate_owners[candidate_id] = fixture
            try:
                entry = build_index_entry(
                    record,
                    fixture=fixture,
                    target_cve=target_cve,
                    baseline_exact=baseline_exact,
                )
                if (
                    record.get("component") == "combination"
                    and combination_provenance is not None
                    and combination_sources is not None
                ):
                    combination_extension = build_combination_index_extensions(
                        record,
                        fixture=fixture,
                        provenance=combination_provenance,
                        source_records=combination_sources,
                    )
                    entry.update(combination_extension)
                    diagnostic_count = combination_extension.get(
                        "source_join_diagnostic_count"
                    )
                    if (
                        isinstance(diagnostic_count, int)
                        and not isinstance(diagnostic_count, bool)
                        and diagnostic_count > 0
                    ):
                        diagnostics.append(
                            {
                                "file": label,
                                "line": line,
                                "error": (
                                    "combination source join unavailable for "
                                    f"{candidate_id}: {diagnostic_count} "
                                    "diagnostic(s); inspect record detail"
                                ),
                            }
                        )
            except _RECORD_ERRORS as error:
                diagnostics.append(
                    {"file": label, "line": line, "error": f"record skipped: {error}"}
                )
                continue
            fixture_records[candidate_id] = record
            entries.append(entry)
        by_fixture[fixture] = {
            "manifest": manifest_record,
            "target_cve": target_cve,
            "baseline": baseline,
            "records": fixture_records,
            "combination_provenance": combination_provenance,
            "combination_sources": combination_sources,
        }

    entries.sort(
        key=(
            _combination_index_sort_key
            if combination_provenance is not None
            else _index_sort_key
        )
    )
    return entries, diagnostics, by_fixture


def _combination_index_sort_key(
    entry: Mapping[str, object],
) -> tuple[str, int, tuple[str, ...], str]:
    """Order valid combination records by their explorer analysis dimensions."""
    raw_block_count = entry.get("block_count")
    block_count = (
        raw_block_count
        if isinstance(raw_block_count, int) and not isinstance(raw_block_count, bool)
        else 0
    )
    raw_families = entry.get("included_families")
    families = (
        tuple(str(family) for family in raw_families)
        if isinstance(raw_families, list)
        else ()
    )
    return (
        str(entry.get("fixture")),
        block_count,
        families,
        str(entry.get("candidate_id")),
    )


def _index_sort_key(entry: Mapping[str, object]) -> tuple[int, str, str, str, str]:
    """Order by family, then by name within unlisted families, as the UI does."""
    component = str(entry.get("component"))
    rank = _FAMILY_RANK.get(component, len(_FAMILY_RANK))
    return (
        rank,
        component if rank == len(_FAMILY_RANK) else "",
        str(entry.get("operator")),
        str(entry.get("fixture")),
        str(entry.get("candidate_id")),
    )


def _redacted_reason(project_root: Path, error: Exception) -> str:
    """Describe a failure without leaking where the server keeps its files."""
    text = str(error) or type(error).__name__
    for root in {str(project_root), str(project_root.absolute())}:
        text = text.replace(root, "<project root>")
    return text


def list_mutation_runs(project_root: Path) -> dict[str, object]:
    """List readable mutation runs with record and data-quality summaries.

    A run is listed only when the same scan the index endpoint performs yields
    at least one usable record, so the listing can never advertise a run whose
    records cannot be served. A run that cannot be scanned at all is omitted
    with a reason rather than taking every other run down with it.
    """
    root = _runs_root(project_root)
    _assert_safe_path(project_root, root, label="mutation runs root")
    if not root.is_dir():
        return {"runs": [], "omitted_run_count": 0, "omitted_runs": []}
    configuration = _explorer_configuration(project_root)
    request_cache = _ExplorerRequestCache()
    runs: list[dict[str, object]] = []
    omitted: list[dict[str, object]] = []
    for path in sorted(root.iterdir(), key=lambda candidate: candidate.name):
        if SAFE_ID.fullmatch(path.name) is None:
            continue
        if not path.is_dir():
            continue
        try:
            if path.is_symlink():
                # Never followed: the link is reported and left alone.
                raise ValueError(f"run directory is a symlink: {path}")
            entries, diagnostics, by_fixture = _scan_run(
                project_root, path.name, configuration, request_cache
            )
        except _RUN_ERRORS as error:
            omitted.append(
                {
                    "run_id": path.name,
                    "error": _redacted_reason(project_root, error),
                }
            )
            continue
        if not entries:
            continue
        runs.append(
            {
                "run_id": path.name,
                "fixture_count": len(by_fixture),
                "record_count": len(entries),
                "malformed_line_count": sum(
                    1
                    for diagnostic in diagnostics
                    if isinstance(diagnostic.get("line"), int)
                    and diagnostic["line"] > 0
                ),
                "diagnostics": diagnostics,
            }
        )
    return {
        "runs": runs,
        "omitted_run_count": len(omitted),
        "omitted_runs": omitted,
    }


def load_mutation_run_index(
    project_root: Path, run_id: str
) -> dict[str, object]:
    """Load enriched, sorted, lightweight records for one mutation run."""
    records, diagnostics, by_fixture = _scan_run(project_root, run_id)
    return {
        "run_id": run_id,
        "fixture_count": len(by_fixture),
        "record_count": len(records),
        "records": records,
        "diagnostics": diagnostics,
    }


def _project_data_path(
    project_root: Path, relative: object, *, label: str
) -> Path | None:
    if relative is None:
        return None
    if not isinstance(relative, str):
        raise ValueError(f"{label} path must be a string")
    path = Path(relative)
    if path.is_absolute():
        raise ValueError(f"{label} path must be relative: {relative!r}")
    if ".." in path.parts:
        raise ValueError(f"{label} path must not contain ..: {relative!r}")
    return _safe_file(project_root, project_root / path, label=label)


def _load_suite_cases(
    project_root: Path, manifest: Mapping[str, object]
) -> dict[str, dict[str, object]]:
    path = _project_data_path(project_root, manifest.get("suite"), label="suite")
    if path is None:
        return {}
    suite = _load_json_object(project_root, path, label="suite")
    raw_cases = suite.get("cases")
    if not isinstance(raw_cases, list):
        raise ValueError(f"{path} cases must be a list")
    cases: dict[str, dict[str, object]] = {}
    for raw in raw_cases:
        if not isinstance(raw, dict):
            raise ValueError(f"{path} cases must be JSON objects")
        name = raw.get("name")
        if not isinstance(name, str):
            raise ValueError(f"{path} case has no string name")
        cases[name] = raw
    return cases


def _case_groups(
    record: Mapping[str, object],
    *,
    suite_cases: Mapping[str, Mapping[str, object]],
) -> dict[str, list[dict[str, object]]]:
    groups: dict[str, list[dict[str, object]]] = {
        "positive": [],
        "negative": [],
        "benign": [],
    }
    raw_results = record.get("case_results")
    if isinstance(raw_results, dict):
        for name, result in raw_results.items():
            if not isinstance(name, str) or not isinstance(result, dict):
                continue
            suite_case = suite_cases.get(name, {})
            item = {"name": name, **result}
            for field in ("reason", "predicate_id", "pcap"):
                value = suite_case.get(field)
                if value is not None:
                    item[field] = value
            pcap = suite_case.get("pcap")
            if isinstance(pcap, str):
                item["pcap_name"] = Path(pcap).name
            group = (
                "positive"
                if suite_case.get("expected_alert") is True
                else "negative"
            )
            groups[group].append(item)
    raw_benign = record.get("benign_capture_results")
    if isinstance(raw_benign, dict):
        for source_id, result in raw_benign.items():
            if not isinstance(result, dict):
                continue
            item = dict(result)
            item.setdefault("source_id", source_id)
            groups["benign"].append(item)
    return groups


def load_mutation_record_detail(
    project_root: Path,
    run_id: str,
    candidate_id: str,
) -> dict[str, object]:
    """Load large fields for one candidate only."""
    _validate_id(candidate_id, kind="candidate")
    _, diagnostics, by_fixture = _scan_run(project_root, run_id)
    for fixture, fixture_data in by_fixture.items():
        records = fixture_data["records"]
        if not isinstance(records, dict) or candidate_id not in records:
            continue
        record = records[candidate_id]
        manifest = fixture_data["manifest"]
        baseline = fixture_data["baseline"]
        if not isinstance(record, dict) or not isinstance(manifest, dict):
            raise ValueError(f"invalid stored record for candidate {candidate_id}")
        _project_data_path(project_root, manifest.get("fixture"), label="fixture")
        suite_cases = _load_suite_cases(project_root, manifest)
        baseline_rule = (
            baseline.get("rule") if isinstance(baseline, dict) else None
        )
        detail = dict(record)
        detail.update(
            {
                "fixture": fixture,
                "target_cve": fixture_data["target_cve"],
                "baseline_rule": baseline_rule,
                "mutated_rule": record.get("rule"),
                "case_groups": _case_groups(record, suite_cases=suite_cases),
                "suite_reason": manifest.get("reason"),
                "attacker": _normalized_attacker(record),
                "diagnostics": diagnostics,
            }
        )
        provenance = fixture_data.get("combination_provenance")
        sources = fixture_data.get("combination_sources")
        if (
            record.get("component") == "combination"
            and isinstance(provenance, dict)
            and isinstance(sources, dict)
        ):
            detail.update(
                build_combination_detail_extensions(
                    record,
                    fixture=fixture,
                    provenance=provenance,
                    source_records=sources,
                )
            )
        return detail
    raise UnknownMutationCandidate(f"unknown candidate: {candidate_id}")
