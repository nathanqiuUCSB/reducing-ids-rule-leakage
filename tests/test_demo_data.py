from __future__ import annotations

from pathlib import Path

import pytest

from hardening_game.mutations.demo_data import install_demo_results
from hardening_game.mutations.explorer import list_mutation_runs, load_mutation_run_index


def test_install_demo_results_copies_sanitized_example(tmp_path: Path) -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "examples"
        / "results"
        / "dataset-clue-targeted-singles-v1"
    )
    destination = tmp_path / "runs" / "mutations" / "example-clue-targeted"
    installed = install_demo_results(source=source, destination=destination)
    assert installed == destination
    assert (destination / "run_metadata.json").is_file()
    assert (destination / "et-2050340" / "results.jsonl").is_file()
    text = (destination / "et-2050340" / "results.jsonl").read_text(encoding="utf-8")
    assert '"prompt"' not in text
    assert '"raw_response"' not in text


def test_install_demo_results_refuses_nonempty_destination(tmp_path: Path) -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "examples"
        / "results"
        / "dataset-clue-targeted-singles-v1"
    )
    destination = tmp_path / "example"
    destination.mkdir()
    (destination / "marker.txt").write_text("keep\n", encoding="utf-8")
    with pytest.raises(FileExistsError, match="not empty"):
        install_demo_results(source=source, destination=destination)


def test_installed_demo_is_discoverable_by_explorer(tmp_path: Path) -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "examples"
        / "results"
        / "dataset-clue-targeted-singles-v1"
    )
    project_root = tmp_path / "project"
    # Minimal project layout expected by the explorer.
    for relative in (
        "fixtures/dataset_manifest.json",
        "fixtures/related_cve_registry.json",
        "fixtures/dataset",
    ):
        src = Path(__file__).resolve().parents[1] / relative
        dest = project_root / relative
        dest.parent.mkdir(parents=True, exist_ok=True)
        if src.is_dir():
            import shutil

            shutil.copytree(src, dest)
        else:
            dest.write_bytes(src.read_bytes())
    destination = project_root / "runs" / "mutations" / "example-clue-targeted"
    install_demo_results(source=source, destination=destination)
    listing = list_mutation_runs(project_root)
    run_ids = {run["run_id"] for run in listing["runs"]}
    assert "example-clue-targeted" in run_ids
    index = load_mutation_run_index(project_root, "example-clue-targeted")
    assert index["record_count"] >= 7
