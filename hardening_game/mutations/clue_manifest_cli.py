"""CLI for validating and rendering the hash-locked clue-targeted manifest.

`validate` rebuilds the manifest from current inputs and compares it against
the committed `experiments/single-clue-targeted-v1/manifest.json`, printing
counts and the manifest hash. `render` writes the manifest and its companion
`review.md` in their canonical form; `render --check` verifies both are
already current without writing.

`--project-root` defaults to this package's own location, not the current
working directory, so running this from any directory produces the same
manifest and the same rendered review text.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from hardening_game.mutations.clue_manifest import (
    EXPECTED_EXPERIMENT_ID,
    build_manifest,
    live_disk_space_report,
    load_manifest,
    render_review,
    write_manifest,
)


_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_MANIFEST_PATH = Path("experiments/single-clue-targeted-v1/manifest.json")
_REVIEW_PATH = Path("experiments/single-clue-targeted-v1/review.md")


def validate(args: argparse.Namespace) -> int:
    manifest = build_manifest(project_root=args.project_root)
    print(f"Experiment: {manifest['experiment_id']}")
    print(f"Manifest hash: {manifest['manifest_hash']}")
    counts = manifest["counts"]
    print(f"Selected candidates: {counts['selected_candidates']}")
    print(f"  baseline: {counts['baseline_candidates']}")
    print(f"  generic (existing): {counts['generic_candidates']}")
    print(f"  targeted (new): {counts['targeted_candidates']}")
    print(f"Expected max attacker calls: {counts['expected_max_attacker_calls']}")
    print(f"Disk space: {live_disk_space_report(project_root=args.project_root)}")

    manifest_path = args.project_root / _MANIFEST_PATH
    if not manifest_path.is_file():
        print(f"FAIL: no committed manifest at {manifest_path}", file=sys.stderr)
        return 1
    try:
        load_manifest(manifest_path, project_root=args.project_root)
    except ValueError as error:
        print(f"FAIL: committed manifest does not match current inputs: {error}", file=sys.stderr)
        return 1
    print(f"{manifest_path} matches current inputs.")
    return 0


def render(args: argparse.Namespace) -> int:
    manifest = build_manifest(project_root=args.project_root)
    manifest_path = args.project_root / _MANIFEST_PATH
    review_path = args.project_root / _REVIEW_PATH
    manifest_text = (
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    )
    review_text = render_review(manifest, project_root=args.project_root) + "\n"

    if args.check:
        failures = []
        if not manifest_path.is_file() or manifest_path.read_text(encoding="utf-8") != manifest_text:
            failures.append(str(manifest_path))
        if not review_path.is_file() or review_path.read_text(encoding="utf-8") != review_text:
            failures.append(str(review_path))
        if failures:
            print(f"FAIL: not in canonical form: {failures}", file=sys.stderr)
            return 1
        print("manifest.json and review.md are both in canonical form.")
        return 0

    write_manifest(manifest_path, manifest)
    review_path.parent.mkdir(parents=True, exist_ok=True)
    review_path.write_text(review_text, encoding="utf-8")
    print(f"Wrote {manifest_path}")
    print(f"Wrote {review_path}")
    print(f"Manifest hash: {manifest['manifest_hash']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            f"Validate or render the {EXPECTED_EXPERIMENT_ID} hash-locked manifest "
            "and review."
        )
    )
    parser.add_argument("--project-root", type=Path, default=_PROJECT_ROOT)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("validate").set_defaults(handler=validate)
    rendered = commands.add_parser("render")
    rendered.add_argument(
        "--check",
        action="store_true",
        help="fail instead of writing when manifest.json or review.md is stale",
    )
    rendered.set_defaults(handler=render)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    args.project_root = args.project_root.resolve()
    raise SystemExit(args.handler(args))


if __name__ == "__main__":
    main()
