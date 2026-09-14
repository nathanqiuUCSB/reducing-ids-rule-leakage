"""Analyze a whole dataset's experiment tree into one attribution report.

A thin wrapper over `reanalyze_run_tree`: the analysis itself is the same code
the published 19-rule experiment was reported with, pointed at this dataset's
run tree, its own manifest, and its own related-CVE registry. Using the same
analyzer rather than a parallel one is deliberate - a new dataset's numbers
mean the same thing as the published ones.
"""

from __future__ import annotations

from pathlib import Path

from hardening_game.attribution import load_related_cve_registry
from hardening_game.dataset_pipeline.manifest import dataset_root, manifest_path
from hardening_game.dataset_pipeline.run import experiment_run_root
from hardening_game.mutations.reporting import (
    reanalyze_run_tree,
    render_data_quality_lines,
    render_precision_lines,
)


def registry_path(dataset_id: str, *, project_root: Path) -> Path:
    return (
        dataset_root(dataset_id, project_root=project_root)
        / "related_cve_registry.json"
    )


def report_for_dataset(dataset_id: str, *, project_root: Path) -> dict[str, object]:
    """Write `attribution_report.{json,md}` for the dataset's experiment tree."""
    run_root = experiment_run_root(dataset_id, project_root=project_root)
    if not run_root.is_dir():
        raise FileNotFoundError(
            f"no experiment runs at {run_root}; run "
            f"`hardening-experiment run {dataset_id}` first"
        )
    return reanalyze_run_tree(
        run_root,
        registry=load_related_cve_registry(
            registry_path(dataset_id, project_root=project_root)
        ),
        dataset_manifest=manifest_path(dataset_id, project_root=project_root),
    )


def report_lines(report: dict[str, object], *, run_root: Path) -> list[str]:
    """The same console summary `hardening-mutations-report` prints."""
    totals = report["totals"]
    assert isinstance(totals, dict)
    quality = report["data_quality"]
    assert isinstance(quality, dict)
    lines = [
        f"Rules analyzed: {totals['analyzed_rule_count']}",
        f"Contributing rules: {totals['contributing_rule_count']}",
        f"Exact emergent misses: {totals['exact_miss_count']}",
        f"Effective emergent misses: {totals['effective_miss_count']}",
        "Closely related predictions discounted: "
        f"{totals['closely_related_miss_count']}",
    ]
    lines.extend(line.removeprefix("- ") for line in render_precision_lines(totals))
    # A skipped line is missing data, so it is reported on the console too and
    # never left only in the artifacts.
    lines.extend(
        line.removeprefix("- ").replace("`", "")
        for line in render_data_quality_lines(quality)
    )
    lines.append(f"Artifacts: {run_root}")
    return lines
