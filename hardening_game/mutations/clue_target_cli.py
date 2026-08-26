"""CLI for validating and rendering the reviewed clue-target recipe file.

The recipe JSON is the authoritative reviewed source: it is edited by hand and
read back by everything else.  `validate` proves that the file still loads, that
every recipe still resolves against its fixture, and that no major clue lost its
coverage.  `render` rewrites the same content in the canonical order and spacing
the loader expects, so keeping the file tidy never needs a private script.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import sys

from hardening_game.attribution import load_baseline_clue_registry
from hardening_game.fixture import load_fixture_path
from hardening_game.mutations.clue_targets import (
    ClueTargetedManifest,
    build_clue_targeted_manifest,
    load_clue_target_recipes,
    recipes_sha256,
)


def _manifests(
    *, recipes_path: Path, registry_path: Path, dataset: Path, project_root: Path
) -> tuple[ClueTargetedManifest, ...]:
    recipes = load_clue_target_recipes(recipes_path)
    registry = load_baseline_clue_registry(registry_path)
    return tuple(
        build_clue_targeted_manifest(
            fixture_name=rule.rule_id,
            baseline_rule=load_fixture_path(
                dataset / f"{rule.rule_id}.json", project_root=project_root
            ).sanitized_rule,
            revision=load_fixture_path(
                dataset / f"{rule.rule_id}.json", project_root=project_root
            ).revision,
            rule_clues=rule,
            recipes=recipes,
        )
        for rule in registry.rules
    )


def validate(args: argparse.Namespace) -> int:
    recipes = load_clue_target_recipes(args.recipes)
    manifests = _manifests(
        recipes_path=args.recipes,
        registry_path=args.registry,
        dataset=args.dataset,
        project_root=args.project_root,
    )
    print(f"Recipes: {len(recipes.recipes)}")
    # Two different hashes, never interchangeable: the canonical hash covers the
    # parsed recipe model and moves when that model gains a field, while the file
    # digest covers the reviewed bytes on disk and moves only when someone edits
    # the file.
    print(f"Recipe canonical content sha256: {recipes_sha256(recipes)}")
    print(
        "Recipe file digest sha256: "
        + hashlib.sha256(args.recipes.read_bytes()).hexdigest()
    )

    existing = sum(
        1
        for manifest in manifests
        for record in manifest.candidates
        if record.status == "existing"
    )
    new = sum(
        1
        for manifest in manifests
        for record in manifest.candidates
        if record.status == "new"
    )
    rejections = sum(len(manifest.rejections) for manifest in manifests)
    reviewed = sum(len(manifest.reviewed_rejections) for manifest in manifests)
    print(f"Candidates: {existing} existing, {new} targeted")
    print(f"Rejections: {rejections} total, {reviewed} reviewed")

    majors = [
        (manifest.fixture, record)
        for manifest in manifests
        for record in manifest.coverage
        if record.rank is not None
    ]
    secondaries = [
        (manifest.fixture, record)
        for manifest in manifests
        for record in manifest.coverage
        if record.rank is None
    ]
    # Coverage strength says whether the edit reaching a clue is semantic.
    # Evidence says whether anything committed demonstrates the effect.  They are
    # printed side by side so neither can be mistaken for the other.
    for label, group in (("Major clues", majors), ("Secondary clues", secondaries)):
        strengths: dict[str, int] = {}
        evidence: dict[str, int] = {}
        for _fixture, record in group:
            strengths[record.coverage_strength] = (
                strengths.get(record.coverage_strength, 0) + 1
            )
            key = record.match_set_evidence or "none"
            evidence[key] = evidence.get(key, 0) + 1
        print(f"{label}: {len(group)}")
        print("  coverage strength:")
        for strength in sorted(strengths):
            print(f"    {strength}: {strengths[strength]}")
        print("  match-set evidence:")
        for tier in sorted(evidence):
            print(f"    {tier}: {evidence[tier]}")

    # A clue no committed capture distinguishes must never be counted as a
    # demonstrated widening, so both weaker tiers are named in full.
    preserving = [
        (fixture, record)
        for fixture, record in majors + secondaries
        if record.match_set_evidence == "preserving"
    ]
    print(f"Clues whose coverage cannot change the match set: {len(preserving)}")
    for fixture, record in preserving:
        print(f"  {fixture} {record.clue_id}: {', '.join(record.match_set_effects)}")

    logical_only = [
        (fixture, record)
        for fixture, record in majors + secondaries
        if record.match_set_evidence == "logical_only"
    ]
    print(
        "Clues whose widening is logical but unobserved: "
        f"{len(logical_only)} "
        f"({sum(1 for _fixture, record in logical_only if record.rank is not None)} "
        "major)"
    )

    uncovered_secondaries = [
        (fixture, record)
        for fixture, record in secondaries
        if record.coverage_strength == "uncovered"
    ]
    print(f"Uncovered secondary clues: {len(uncovered_secondaries)}")
    for fixture, record in uncovered_secondaries:
        print(f"  {fixture} {record.clue_id}")

    failures: list[str] = []
    for fixture, record in majors:
        if record.coverage_strength == "uncovered":
            failures.append(f"{fixture} {record.clue_id} has no candidate")
        if record.coverage_strength == "representation_only":
            failures.append(
                f"{fixture} {record.clue_id} is representation-only with no "
                "reviewed rejection explaining why"
            )
        if record.single_level and not record.review_notes:
            failures.append(
                f"{fixture} {record.clue_id} has one candidate and no reviewed "
                "single-level note"
            )
    duplicates = [
        f"{manifest.fixture} {recipe_id}"
        for manifest in manifests
        for recipe_id in manifest.duplicate_recipe_ids
    ]
    for line in duplicates:
        print(f"Duplicate (deduplicated by fingerprint): {line}")
    for line in failures:
        print(f"FAIL: {line}", file=sys.stderr)
    return 1 if failures else 0


def render(args: argparse.Namespace) -> int:
    recipes = load_clue_target_recipes(args.recipes)
    ordered = sorted(
        (asdict(recipe) for recipe in recipes.recipes),
        key=lambda record: (record["fixture"], record["recipe_id"]),
    )
    for record in ordered:
        for key in ("clue_ids", "target_predicate_ids", "expected_negative_firings"):
            record[key] = list(record[key])
        # Optional fields are written only when they carry a decision, so the
        # file reads as the reviewed content rather than a schema dump.
        if not record["expected_negative_firings"]:
            del record["expected_negative_firings"]
        if record["match_set_effect"] is None:
            del record["match_set_effect"]
        if not record["match_set_effect_rationale"]:
            del record["match_set_effect_rationale"]
    text = (
        json.dumps(
            {"version": recipes.version, "recipes": ordered},
            indent=2,
            ensure_ascii=True,
        )
        + "\n"
    )
    if args.check:
        current = args.recipes.read_text(encoding="utf-8")
        if current != text:
            print(f"FAIL: {args.recipes} is not in canonical form", file=sys.stderr)
            return 1
        print(f"{args.recipes} is in canonical form")
        return 0
    args.recipes.write_text(text, encoding="utf-8")
    print(f"Rendered {len(ordered)} recipes to {args.recipes}")
    return 0


def evidence_digest(args: argparse.Namespace) -> int:
    """Print the digest a Task 4 integration claim has to be scoped to."""
    from hardening_game.mutations.task4_evidence import (
        render_evidence_report,
        task4_evidence_digest,
    )

    print(render_evidence_report(task4_evidence_digest(project_root=args.project_root)))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate or canonically render clue-target mutation recipes."
    )
    parser.add_argument(
        "--recipes",
        type=Path,
        default=Path("fixtures/clue_targeted_mutation_recipes.json"),
    )
    parser.add_argument(
        "--registry", type=Path, default=Path("fixtures/baseline_clue_registry.json")
    )
    parser.add_argument("--dataset", type=Path, default=Path("fixtures/dataset"))
    parser.add_argument("--project-root", type=Path, default=Path("."))
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("validate").set_defaults(handler=validate)
    rendered = commands.add_parser("render")
    rendered.add_argument(
        "--check",
        action="store_true",
        help="fail instead of writing when the file is not canonical",
    )
    rendered.set_defaults(handler=render)
    commands.add_parser(
        "evidence-digest",
        help="print the digest an integration report must be read against",
    ).set_defaults(handler=evidence_digest)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    raise SystemExit(args.handler(args))


if __name__ == "__main__":
    main()
