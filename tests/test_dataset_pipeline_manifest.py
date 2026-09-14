from pathlib import Path

import pytest

from hardening_game.dataset_pipeline.manifest import (
    BaselineEvidence,
    DatasetManifest,
    DatasetRecord,
    list_datasets,
    load_manifest,
    save_manifest,
    validate_dataset_id,
)


def _record(name: str = "rule-1", **overrides: object) -> DatasetRecord:
    base = dict(name=name, sid=1, cve="CVE-2025-0001", rule="alert tcp any any -> any any (sid:1;)")
    base.update(overrides)
    return DatasetRecord(**base)


@pytest.mark.parametrize(
    "dataset_id",
    ["", ".", "..", "a/b", "a\\b", "-leading-dash", "has space"],
)
def test_validate_dataset_id_rejects_unsafe_ids(dataset_id: str) -> None:
    with pytest.raises(ValueError, match="invalid dataset id"):
        validate_dataset_id(dataset_id)


def test_validate_dataset_id_accepts_ordinary_ids() -> None:
    assert validate_dataset_id("acme-2026") == "acme-2026"


def test_save_and_load_round_trips_records(tmp_path: Path) -> None:
    manifest = DatasetManifest(
        dataset_id="acme-2026",
        source="datasets/acme-2026/source.jsonl",
        records=(_record(),),
    )

    save_manifest(manifest, project_root=tmp_path)
    loaded = load_manifest("acme-2026", project_root=tmp_path)

    assert loaded == manifest


def test_save_is_atomic_and_never_leaves_a_tmp_file(tmp_path: Path) -> None:
    manifest = DatasetManifest(dataset_id="acme-2026", source="src.jsonl", records=(_record(),))

    path = save_manifest(manifest, project_root=tmp_path)

    assert path.is_file()
    assert not path.with_suffix(".json.tmp").exists()


def test_with_record_replaces_only_the_named_record() -> None:
    manifest = DatasetManifest(
        dataset_id="acme-2026",
        source="src.jsonl",
        records=(_record("rule-1"), _record("rule-2")),
    )

    updated = manifest.with_record(_record("rule-1", status="baseline_rejected"))

    assert updated.record("rule-1").status == "baseline_rejected"
    assert updated.record("rule-2").status == "ingested"


def test_with_record_rejects_an_unknown_name() -> None:
    manifest = DatasetManifest(dataset_id="acme-2026", source="src.jsonl", records=(_record(),))

    with pytest.raises(ValueError, match="no record named"):
        manifest.with_record(_record("does-not-exist"))


def test_evidence_round_trips_through_json(tmp_path: Path) -> None:
    record = _record(
        status="baseline_qualified",
        baseline=BaselineEvidence(
            trial_count=3, exact_trial_count=3, predictions=("CVE-2025-0001",) * 3
        ),
    )
    manifest = DatasetManifest(dataset_id="acme-2026", source="src.jsonl", records=(record,))

    save_manifest(manifest, project_root=tmp_path)
    loaded = load_manifest("acme-2026", project_root=tmp_path)

    assert loaded.record("rule-1").baseline == record.baseline


def test_load_manifest_rejects_unsupported_version(tmp_path: Path) -> None:
    manifest = DatasetManifest(dataset_id="acme-2026", source="src.jsonl", records=(_record(),))
    path = save_manifest(manifest, project_root=tmp_path)
    payload = path.read_text(encoding="utf-8").replace('"version": 1', '"version": 99')
    path.write_text(payload, encoding="utf-8")

    with pytest.raises(ValueError, match="unsupported dataset manifest version"):
        load_manifest("acme-2026", project_root=tmp_path)


def test_list_datasets_finds_only_directories_with_a_manifest(tmp_path: Path) -> None:
    save_manifest(
        DatasetManifest(dataset_id="acme-2026", source="src.jsonl", records=(_record(),)),
        project_root=tmp_path,
    )
    (tmp_path / "datasets" / "no-manifest-here").mkdir(parents=True)

    assert list_datasets(project_root=tmp_path) == ("acme-2026",)


def test_list_datasets_returns_empty_tuple_when_no_datasets_directory(tmp_path: Path) -> None:
    assert list_datasets(project_root=tmp_path) == ()
