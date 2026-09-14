import json
from pathlib import Path

import pytest

from hardening_game.dataset_pipeline.ingest import add_dataset, parse_dataset_source
from hardening_game.dataset_pipeline.manifest import load_manifest


RULE = (
    'alert http any any -> any 80 (flow:established,to_server; http.method; '
    'content:"GET"; http.uri; content:"/vulnerable"; sid:9000001; rev:1;)'
)


def _row(**overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "name": "acme-rule-001",
        "sid": 9000001,
        "cve": "CVE-2025-12345",
        "rule": RULE,
    }
    row.update(overrides)
    return row


def _write_source(tmp_path: Path, *rows: dict[str, object]) -> Path:
    path = tmp_path / "rules.jsonl"
    path.write_text(
        "\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8"
    )
    return path


def test_parses_a_well_formed_dataset(tmp_path: Path) -> None:
    source = _write_source(tmp_path, _row(), _row(name="acme-rule-002", sid=9000002))

    records = parse_dataset_source(source)

    assert [record.name for record in records] == ["acme-rule-001", "acme-rule-002"]
    assert records[0].status == "ingested"
    assert records[0].cve == "CVE-2025-12345"


def test_cve_is_upper_cased_on_ingest(tmp_path: Path) -> None:
    source = _write_source(tmp_path, _row(cve="cve-2025-12345"))

    assert parse_dataset_source(source)[0].cve == "CVE-2025-12345"


@pytest.mark.parametrize("field", ["name", "sid", "cve", "rule"])
def test_missing_required_field_is_rejected_with_the_line_number(
    tmp_path: Path, field: str
) -> None:
    row = _row()
    del row[field]
    source = _write_source(tmp_path, row)

    with pytest.raises(ValueError, match=rf"dataset line 1: missing required field '{field}'"):
        parse_dataset_source(source)


@pytest.mark.parametrize(
    "cve",
    ["not-a-cve", "CVE-2025", "CVE-2025-12345,CVE-2025-12346", ""],
)
def test_a_malformed_or_multi_cve_value_is_rejected(tmp_path: Path, cve: str) -> None:
    source = _write_source(tmp_path, _row(cve=cve))

    with pytest.raises(ValueError, match="exactly one identifier"):
        parse_dataset_source(source)


def test_a_list_of_cves_is_rejected_with_a_specific_hint(tmp_path: Path) -> None:
    source = _write_source(tmp_path, _row(cve=["CVE-2025-12345", "CVE-2025-12346"]))

    with pytest.raises(ValueError, match="a list of CVEs is not supported"):
        parse_dataset_source(source)


def test_an_unsanitized_rule_is_rejected_rather_than_silently_stripped(
    tmp_path: Path,
) -> None:
    leaky = (
        'alert http any any -> any 80 (msg:"ACME RCE CVE-2025-12345"; '
        'http.uri; content:"/vulnerable"; sid:9000001; rev:1;)'
    )
    source = _write_source(tmp_path, _row(rule=leaky))

    with pytest.raises(ValueError, match="rule is not sanitized"):
        parse_dataset_source(source)


def test_duplicate_rule_names_are_rejected(tmp_path: Path) -> None:
    source = _write_source(tmp_path, _row(), _row(sid=9000002))

    with pytest.raises(ValueError, match="duplicate rule name .* first seen on line 1"):
        parse_dataset_source(source)


def test_duplicate_sids_are_rejected(tmp_path: Path) -> None:
    source = _write_source(tmp_path, _row(), _row(name="acme-rule-002"))

    with pytest.raises(ValueError, match="duplicate sid 9000001"):
        parse_dataset_source(source)


def test_malformed_json_names_the_offending_line(tmp_path: Path) -> None:
    path = tmp_path / "rules.jsonl"
    path.write_text(json.dumps(_row()) + "\n{not json}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="dataset line 2: malformed JSON"):
        parse_dataset_source(path)


def test_an_empty_dataset_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "rules.jsonl"
    path.write_text("\n\n", encoding="utf-8")

    with pytest.raises(ValueError, match="contains no rule records"):
        parse_dataset_source(path)


def test_add_dataset_writes_source_manifest_and_empty_registry(tmp_path: Path) -> None:
    source = _write_source(tmp_path, _row())

    manifest = add_dataset(source, dataset_id="acme-2026", project_root=tmp_path)

    root = tmp_path / "datasets" / "acme-2026"
    assert (root / "source.jsonl").is_file()
    assert (root / "manifest.json").is_file()
    registry = json.loads((root / "related_cve_registry.json").read_text())
    assert registry == {"version": 1, "entries": []}
    assert manifest.dataset_id == "acme-2026"
    assert manifest.source == "datasets/acme-2026/source.jsonl"
    assert load_manifest("acme-2026", project_root=tmp_path) == manifest


def test_re_adding_identical_content_is_a_no_op(tmp_path: Path) -> None:
    source = _write_source(tmp_path, _row())
    first = add_dataset(source, dataset_id="acme-2026", project_root=tmp_path)

    again = add_dataset(source, dataset_id="acme-2026", project_root=tmp_path)

    assert again == first


def test_re_adding_different_content_refuses_without_overwrite(tmp_path: Path) -> None:
    add_dataset(_write_source(tmp_path, _row()), dataset_id="acme-2026", project_root=tmp_path)
    changed = _write_source(tmp_path, _row(name="acme-rule-002", sid=9000002))

    with pytest.raises(ValueError, match="already exists with different rules"):
        add_dataset(changed, dataset_id="acme-2026", project_root=tmp_path)

    replaced = add_dataset(
        changed, dataset_id="acme-2026", project_root=tmp_path, overwrite=True
    )
    assert [record.name for record in replaced.records] == ["acme-rule-002"]


def test_a_registry_the_user_has_curated_is_not_clobbered_by_overwrite(
    tmp_path: Path,
) -> None:
    add_dataset(_write_source(tmp_path, _row()), dataset_id="acme-2026", project_root=tmp_path)
    registry_path = tmp_path / "datasets" / "acme-2026" / "related_cve_registry.json"
    curated = {"version": 1, "entries": [{"curated": True}]}
    registry_path.write_text(json.dumps(curated), encoding="utf-8")

    add_dataset(
        _write_source(tmp_path, _row(name="acme-rule-002", sid=9000002)),
        dataset_id="acme-2026",
        project_root=tmp_path,
        overwrite=True,
    )

    assert json.loads(registry_path.read_text()) == curated
