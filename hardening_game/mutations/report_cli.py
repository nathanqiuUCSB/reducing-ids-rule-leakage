"""CLI for backward-compatible mutation attribution reports."""

from __future__ import annotations

import argparse
from pathlib import Path

from hardening_game.attribution import load_related_cve_registry
from hardening_game.mutations.reporting import (
    reanalyze_run_tree,
    render_data_quality_lines,
    render_precision_lines,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Reanalyze a mutation run tree with related-CVE attribution."
    )
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--registry", type=Path, required=True)
    parser.add_argument("--dataset-manifest", type=Path, required=True)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    report = reanalyze_run_tree(
        args.run_root,
        registry=load_related_cve_registry(args.registry),
        dataset_manifest=args.dataset_manifest,
    )
    totals = report["totals"]
    assert isinstance(totals, dict)
    print(f"Rules analyzed: {totals['analyzed_rule_count']}")
    print(f"Contributing rules: {totals['contributing_rule_count']}")
    print(f"Exact emergent misses: {totals['exact_miss_count']}")
    print(f"Effective emergent misses: {totals['effective_miss_count']}")
    print(
        "Closely related predictions discounted: "
        f"{totals['closely_related_miss_count']}"
    )
    for line in render_precision_lines(totals):
        print(line.removeprefix("- "))
    quality = report["data_quality"]
    assert isinstance(quality, dict)
    # A skipped line is missing data, so it is reported on the console too and
    # never left only in the artifacts.
    for line in render_data_quality_lines(quality):
        print(line.removeprefix("- ").replace("`", ""))
    print(f"Artifacts: {args.run_root}")


if __name__ == "__main__":
    main()
