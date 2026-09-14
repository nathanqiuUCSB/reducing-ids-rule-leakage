"""`hardening-experiment` - the one path through an experiment.

    add-dataset -> baseline -> generate -> run -> report

Each subcommand reads the dataset manifest, acts only on the records that are
ready for its stage, and writes the manifest back, so the whole sequence is
safe to interrupt and re-run. `run-all` chains the four stages for a user who
has already been through the flow once.

The published 19-rule dataset is deliberately not driven from here: it is
hash-locked and is reproduced with the existing `hardening-mutations
--experiment-manifest ...` commands. `list` says so rather than leaving it
looking absent.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys

from hardening_game.config import configured_litellm_base_url, load_project_env
from hardening_game.dataset_pipeline.assist import explain_rule
from hardening_game.dataset_pipeline.baseline_gate import run_baseline_gate
from hardening_game.dataset_pipeline.generate import (
    apply_manual_suite,
    generate_for_dataset,
)
from hardening_game.dataset_pipeline.ingest import add_dataset
from hardening_game.dataset_pipeline.manifest import (
    DatasetManifest,
    list_datasets,
    load_manifest,
)
from hardening_game.dataset_pipeline.report import report_for_dataset, report_lines
from hardening_game.dataset_pipeline.run import (
    experiment_run_root,
    pending_rules,
    run_dataset_experiment,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]

LEGACY_NOTE = (
    "legacy: the published 19-rule dataset (fixtures/dataset/) is hash-locked "
    "and is run with `hardening-mutations --experiment-manifest "
    "experiments/single-clue-targeted-v1/manifest.json --dataset-fixtures`; "
    "see docs/reproducibility.md. It is not re-qualified through this pipeline."
)


class UsageError(Exception):
    """A problem with what the user asked for, not with the pipeline."""


def _api_key(args: argparse.Namespace) -> str:
    load_project_env(PROJECT_ROOT / ".env")
    key = os.environ.get(args.api_key_env, "").strip()
    if not key:
        raise UsageError(
            f"no attacker API key in ${args.api_key_env}. Export it, or put it "
            f"in {PROJECT_ROOT / '.env'}, or pass --api-key-env with the name "
            "of the variable that holds it."
        )
    args.base_url = args.base_url or configured_litellm_base_url()
    return key


def _status_counts(manifest: DatasetManifest) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in manifest.records:
        counts[record.status] = counts.get(record.status, 0) + 1
    return counts


def _summarize(manifest: DatasetManifest) -> str:
    counts = _status_counts(manifest)
    detail = ", ".join(f"{count} {status}" for status, count in sorted(counts.items()))
    return f"{manifest.dataset_id}: {len(manifest.records)} rules ({detail})"


def command_list(args: argparse.Namespace) -> int:
    ids = list_datasets(project_root=args.project_root)
    if not ids:
        print("No datasets added yet. Start with:")
        print("  hardening-experiment add-dataset path/to/rules.jsonl --dataset-id my-set")
    for dataset_id in ids:
        print(_summarize(load_manifest(dataset_id, project_root=args.project_root)))
    print()
    print(LEGACY_NOTE)
    return 0


def command_add_dataset(args: argparse.Namespace) -> int:
    manifest = add_dataset(
        args.source,
        dataset_id=args.dataset_id,
        project_root=args.project_root,
        overwrite=args.overwrite,
    )
    print(f"Added {len(manifest.records)} rules as dataset {manifest.dataset_id!r}.")
    print(
        "Next: hardening-experiment baseline "
        f"{manifest.dataset_id} --attacker-model <model>"
    )
    return 0


def command_baseline(args: argparse.Namespace) -> int:
    api_key = _api_key(args)
    manifest = run_baseline_gate(
        args.dataset_id,
        attacker_model=args.attacker_model,
        api_key=api_key,
        base_url=args.base_url,
        attacker_trials=args.attacker_trials,
        project_root=args.project_root,
        resume=not args.no_resume,
    )
    qualified = [r for r in manifest.records if r.status == "baseline_qualified"]
    rejected = [r for r in manifest.records if r.status == "baseline_rejected"]
    later = [
        r
        for r in manifest.records
        if r.status in {"suite_needs_manual_pcap", "mutations_generated", "experiment_complete"}
    ]
    print(
        f"{len(qualified) + len(later)} / {len(manifest.records)} rules qualified "
        f"({args.attacker_trials}/{args.attacker_trials} exact baseline). "
        f"{len(rejected)} rejected."
    )
    for record in rejected:
        predictions = (
            ", ".join(str(p) for p in record.baseline.predictions)
            if record.baseline
            else "no trials"
        )
        print(f"  rejected {record.name} ({record.cve}): predicted {predictions}")
    if not qualified and not later:
        print(
            "No rule qualified, so there is nothing to mutate. A rule the "
            "attacker cannot identify unmutated cannot show a hardening effect."
        )
        return 1
    print(f"Next: hardening-experiment generate {args.dataset_id}")
    return 0


def command_generate(args: argparse.Namespace) -> int:
    manifest = generate_for_dataset(
        args.dataset_id,
        project_root=args.project_root,
        resume=not args.no_resume,
    )
    ready = [r for r in manifest.records if r.status in {"mutations_generated", "experiment_complete"}]
    blocked = [r for r in manifest.records if r.status == "suite_needs_manual_pcap"]
    total = len(ready) + len(blocked)
    candidates = sum(
        r.mutations.candidate_count for r in ready if r.mutations is not None
    )
    print(f"{len(ready)} / {total} prepared rules have a validated suite.")
    print(f"{candidates} mutation candidates to evaluate.")
    for record in blocked:
        print(f"  needs a manual PCAP: {record.name} - {record.reason}")
        print(
            f"    hardening-experiment explain {args.dataset_id} {record.name}"
        )
    if not ready:
        print("Nothing is ready to run yet.")
        return 1
    print(
        f"Next: hardening-experiment run {args.dataset_id} --attacker-model <model>"
    )
    return 0


def command_explain(args: argparse.Namespace) -> int:
    manifest = load_manifest(args.dataset_id, project_root=args.project_root)
    print(explain_rule(manifest.record(args.rule_name), dataset_id=args.dataset_id))
    return 0


def _fill_bytes(args: argparse.Namespace) -> bytes:
    if (args.fill_text is None) == (args.fill_hex is None):
        raise UsageError("pass exactly one of --fill-text or --fill-hex")
    if args.fill_text is not None:
        return args.fill_text.encode("utf-8").decode("unicode_escape").encode("latin-1")
    cleaned = "".join(args.fill_hex.split()).replace("|", "")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as error:
        raise UsageError(f"--fill-hex is not valid hex: {error}") from error


def command_complete_pcap(args: argparse.Namespace) -> int:
    _manifest, result = apply_manual_suite(
        args.dataset_id,
        args.rule_name,
        fill=_fill_bytes(args),
        project_root=args.project_root,
        insert_after=args.insert_after,
    )
    print(result.reason)
    if result.status != "generated":
        return 1
    print(f"Next: hardening-experiment generate {args.dataset_id}  # picks up the rest")
    return 0


def command_run(args: argparse.Namespace) -> int:
    api_key = _api_key(args)
    manifest = load_manifest(args.dataset_id, project_root=args.project_root)
    pending = pending_rules(manifest, resume=not args.no_resume)
    if not pending:
        raise UsageError(
            f"no rule in {args.dataset_id!r} has a generated mutation matrix "
            f"yet; run `hardening-experiment generate {args.dataset_id}` first"
        )
    print(f"Running {len(pending)} rules: {', '.join(pending)}")
    run_dataset_experiment(
        args.dataset_id,
        attacker_model=args.attacker_model,
        api_key=api_key,
        base_url=args.base_url,
        attacker_trials=args.attacker_trials,
        project_root=args.project_root,
        resume=not args.no_resume,
        skip_benign=not args.benign,
    )
    print(f"Next: hardening-experiment report {args.dataset_id}")
    return 0


def command_report(args: argparse.Namespace) -> int:
    report = report_for_dataset(args.dataset_id, project_root=args.project_root)
    run_root = experiment_run_root(args.dataset_id, project_root=args.project_root)
    for line in report_lines(report, run_root=run_root):
        print(line)
    return 0


def command_run_all(args: argparse.Namespace) -> int:
    for step in (command_baseline, command_generate, command_run):
        code = step(args)
        if code != 0:
            return code
    return command_report(args)


def _add_attacker_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--attacker-model", required=True, help="LiteLLM attacker model ID."
    )
    parser.add_argument(
        "--attacker-trials",
        type=int,
        default=3,
        help="Independent attacker measurements per rule or candidate (default: 3).",
    )
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--api-key-env", default="LITELLM_API_KEY")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hardening-experiment",
        description=(
            "Run one IDS-rule-hardening experiment end to end: add a dataset, "
            "qualify it against the attacker, generate mutations and PCAP "
            "suites, run, report."
        ),
        epilog=LEGACY_NOTE,
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=PROJECT_ROOT,
        help="Repository root holding datasets/ and runs/ (default: this checkout).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="Show every dataset and where each rule stands.")

    add = sub.add_parser("add-dataset", help="Validate and ingest a rules JSONL file.")
    add.add_argument("source", type=Path, help="JSONL file of {name, sid, cve, rule}.")
    add.add_argument("--dataset-id", required=True)
    add.add_argument(
        "--overwrite",
        action="store_true",
        help="Replace an existing dataset of this id whose source differs.",
    )

    baseline = sub.add_parser(
        "baseline", help="Keep only rules the attacker identifies every time."
    )
    baseline.add_argument("dataset_id")
    _add_attacker_flags(baseline)
    baseline.add_argument(
        "--no-resume",
        action="store_true",
        help="Re-run rules already decided, spending attacker calls again.",
    )

    generate = sub.add_parser(
        "generate", help="Write the mutation matrix and a validated PCAP suite."
    )
    generate.add_argument("dataset_id")
    generate.add_argument(
        "--no-resume", action="store_true", help="Regenerate rules already prepared."
    )

    explain = sub.add_parser(
        "explain", help="Say what a rule needing a manual PCAP is waiting for."
    )
    explain.add_argument("dataset_id")
    explain.add_argument("rule_name")

    complete = sub.add_parser(
        "complete-pcap", help="Supply the bytes a pcre/byte_test rule needs."
    )
    complete.add_argument("dataset_id")
    complete.add_argument("rule_name")
    complete.add_argument(
        "--fill-text", default=None, help='Bytes as text; \\xNN escapes allowed.'
    )
    complete.add_argument(
        "--fill-hex", default=None, help='Bytes as hex, e.g. "41 41 00 00 00 05".'
    )
    complete.add_argument(
        "--insert-after",
        default=None,
        help="Predicate id to place the bytes after (default: the anchor "
        "`explain` names).",
    )

    run = sub.add_parser("run", help="Evaluate every mutation of every prepared rule.")
    run.add_argument("dataset_id")
    _add_attacker_flags(run)
    run.add_argument(
        "--no-resume",
        action="store_true",
        help="Re-evaluate candidates already in results.jsonl.",
    )
    run.add_argument(
        "--benign",
        action="store_true",
        help="Also replay mapped benign captures (needs benign_sources/ "
        "mappings for these fixture names).",
    )

    report = sub.add_parser("report", help="Write the attribution report.")
    report.add_argument("dataset_id")

    run_all = sub.add_parser(
        "run-all", help="baseline -> generate -> run -> report in one go."
    )
    run_all.add_argument("dataset_id")
    _add_attacker_flags(run_all)
    run_all.add_argument("--no-resume", action="store_true")
    run_all.add_argument("--benign", action="store_true")

    return parser


_COMMANDS = {
    "list": command_list,
    "add-dataset": command_add_dataset,
    "baseline": command_baseline,
    "generate": command_generate,
    "explain": command_explain,
    "complete-pcap": command_complete_pcap,
    "run": command_run,
    "report": command_report,
    "run-all": command_run_all,
}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return _COMMANDS[args.command](args)
    except (UsageError, FileNotFoundError, KeyError, ValueError) as error:
        # These all mean "what you asked for isn't there or isn't valid" - a
        # missing dataset, an unknown rule name, a malformed source file, a
        # report before a run. Each already carries a message naming what to
        # do, so a traceback would only bury it.
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
