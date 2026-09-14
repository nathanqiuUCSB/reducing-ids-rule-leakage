"""Validate and register a new rule dataset for the unified pipeline.

A dataset is a JSONL file with one object per rule. Ingest is strict on
purpose: the whole experiment rests on the assumption that each rule maps to
exactly one known CVE and that the rule text is already stripped of anything
that names the vulnerability. Rather than silently sanitizing, ingest rejects
a rule whose text would change under the sanitizer, so drift is visible at the
point it enters the pipeline instead of surfacing as a confusing result later.
"""

from __future__ import annotations

import json
from pathlib import Path
import re

from hardening_game.fixture import sanitize_l5_rule
from hardening_game.dataset_pipeline.manifest import (
    DatasetManifest,
    DatasetRecord,
    dataset_root,
    load_manifest,
    save_manifest,
    validate_dataset_id,
)


_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_RULE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_EMPTY_RELATED_REGISTRY = {"version": 1, "entries": []}


def _fail(line_number: int, message: str) -> None:
    raise ValueError(f"dataset line {line_number}: {message}")


def _parse_record(raw: object, *, line_number: int) -> DatasetRecord:
    if not isinstance(raw, dict):
        _fail(line_number, "record must be a JSON object")
    assert isinstance(raw, dict)

    for field in ("name", "sid", "cve", "rule"):
        if field not in raw:
            _fail(line_number, f"missing required field {field!r}")

    name = raw["name"]
    if not isinstance(name, str) or not _RULE_NAME_RE.fullmatch(name):
        _fail(
            line_number,
            f"name must be a filename-safe string, got {name!r}",
        )

    sid = raw["sid"]
    if isinstance(sid, bool) or not isinstance(sid, int):
        _fail(line_number, f"sid must be an integer, got {sid!r}")

    cve = raw["cve"]
    if not isinstance(cve, str):
        _fail(
            line_number,
            f"cve must be a single CVE identifier string, got {cve!r}"
            + (" (a list of CVEs is not supported)" if isinstance(cve, list) else ""),
        )
    assert isinstance(cve, str)
    if not _CVE_RE.fullmatch(cve.upper()):
        _fail(
            line_number,
            f"cve must be exactly one identifier matching CVE-YYYY-NNNN, got {cve!r}",
        )

    rule = raw["rule"]
    if not isinstance(rule, str) or not rule.strip():
        _fail(line_number, "rule must be a non-empty string")
    assert isinstance(rule, str)
    if sanitize_l5_rule(rule) != rule:
        _fail(
            line_number,
            "rule is not sanitized: it still carries msg/reference/classtype/"
            "metadata options that name the vulnerability. Strip them before "
            "ingesting so the attacker only ever sees detection logic.",
        )

    return DatasetRecord(
        name=name, sid=sid, cve=cve.upper(), rule=rule, status="ingested"
    )


def parse_dataset_source(source_path: Path) -> tuple[DatasetRecord, ...]:
    """Parse and validate every record, rejecting the file as a whole on error."""
    text = source_path.read_text(encoding="utf-8")
    records: list[DatasetRecord] = []
    seen_names: dict[str, int] = {}
    seen_sids: dict[int, int] = {}
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as error:
            _fail(line_number, f"malformed JSON: {error.msg}")
            raise  # unreachable, keeps type checkers honest
        record = _parse_record(raw, line_number=line_number)
        if record.name in seen_names:
            _fail(
                line_number,
                f"duplicate rule name {record.name!r}, first seen on line "
                f"{seen_names[record.name]}",
            )
        if record.sid in seen_sids:
            _fail(
                line_number,
                f"duplicate sid {record.sid}, first seen on line "
                f"{seen_sids[record.sid]}",
            )
        seen_names[record.name] = line_number
        seen_sids[record.sid] = line_number
        records.append(record)
    if not records:
        raise ValueError(f"dataset {source_path} contains no rule records")
    return tuple(records)


def _serialize_source(records: tuple[DatasetRecord, ...]) -> str:
    return (
        "\n".join(
            json.dumps(
                {
                    "name": record.name,
                    "sid": record.sid,
                    "cve": record.cve,
                    "rule": record.rule,
                },
                sort_keys=True,
            )
            for record in records
        )
        + "\n"
    )


def add_dataset(
    source_path: Path,
    *,
    dataset_id: str,
    project_root: Path,
    overwrite: bool = False,
) -> DatasetManifest:
    """Validate a rule JSONL and register it as `datasets/<dataset-id>/`.

    Re-adding a dataset whose source is byte-identical is a no-op that returns
    the existing manifest, so re-running the command is safe. Re-adding with
    different content raises unless `overwrite` is set, because a manifest can
    already hold baseline-qualification results that cost real attacker calls.
    """
    validate_dataset_id(dataset_id)
    records = parse_dataset_source(source_path)
    root = dataset_root(dataset_id, project_root=project_root)
    stored_source = root / "source.jsonl"
    serialized = _serialize_source(records)

    if stored_source.is_file():
        unchanged = stored_source.read_text(encoding="utf-8") == serialized
        if unchanged and not overwrite:
            return load_manifest(dataset_id, project_root=project_root)
        if not unchanged and not overwrite:
            raise ValueError(
                f"dataset {dataset_id!r} already exists with different rules. "
                "Re-adding would discard any baseline qualification already "
                "paid for; pass overwrite=True (--overwrite) to replace it."
            )

    root.mkdir(parents=True, exist_ok=True)
    stored_source.write_text(serialized, encoding="utf-8")

    registry_path = root / "related_cve_registry.json"
    if not registry_path.is_file():
        registry_path.write_text(
            json.dumps(_EMPTY_RELATED_REGISTRY, indent=2) + "\n", encoding="utf-8"
        )

    manifest = DatasetManifest(
        dataset_id=dataset_id,
        source=str(stored_source.relative_to(project_root)),
        records=records,
    )
    save_manifest(manifest, project_root=project_root)
    return manifest
