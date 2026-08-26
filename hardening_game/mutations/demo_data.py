"""Copy sanitized example mutation results into a local runs/ directory."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path


_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_SOURCE = (
    _PROJECT_ROOT / "examples" / "results" / "dataset-clue-targeted-singles-v1"
)
_DEFAULT_DESTINATION = (
    _PROJECT_ROOT / "runs" / "mutations" / "example-clue-targeted"
)


def install_demo_results(
    *,
    source: Path,
    destination: Path,
) -> Path:
    """Copy example results into a discoverable mutation-run directory.

    Refuses to overwrite a non-empty destination so user experiment output is
    never clobbered by the demo installer.
    """
    source = source.resolve()
    destination = destination.resolve()
    if not source.is_dir():
        raise FileNotFoundError(f"demo source directory does not exist: {source}")
    if destination.exists():
        if not destination.is_dir():
            raise NotADirectoryError(
                f"demo destination exists and is not a directory: {destination}"
            )
        if any(destination.iterdir()):
            raise FileExistsError(
                f"demo destination is not empty: {destination}"
            )
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, destination, dirs_exist_ok=destination.exists())
    return destination


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Install the sanitized mutation-explorer demo results under "
            "runs/mutations/."
        )
    )
    parser.add_argument(
        "--source",
        type=Path,
        default=_DEFAULT_SOURCE,
        help="Directory containing the sanitized example run.",
    )
    parser.add_argument(
        "--destination",
        type=Path,
        default=_DEFAULT_DESTINATION,
        help="Destination run directory under runs/mutations/.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    installed = install_demo_results(
        source=args.source,
        destination=args.destination,
    )
    print(f"Installed demo results at {installed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
