"""Per-dataset manifest: the resumable status record for the unified pipeline.

One dataset added through `hardening-experiment add-dataset` gets exactly one
manifest at `datasets/<dataset-id>/manifest.json`, listing every rule and the
stage it has reached. Every pipeline stage (baseline, generate, run) reads the
current status per record and only advances records that are ready for that
stage, so the whole pipeline is safe to interrupt and re-run.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
import re
from typing import Literal


_MANIFEST_VERSION = 1
_DATASET_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")

RecordStatus = Literal[
    "ingested",
    "baseline_qualified",
    "baseline_rejected",
    "suite_needs_manual_pcap",
    "mutations_generated",
    "experiment_complete",
]

_STATUSES: frozenset[str] = frozenset(
    {
        "ingested",
        "baseline_qualified",
        "baseline_rejected",
        "suite_needs_manual_pcap",
        "mutations_generated",
        "experiment_complete",
    }
)


@dataclass(frozen=True)
class BaselineEvidence:
    trial_count: int
    exact_trial_count: int
    predictions: tuple[str | None, ...]


@dataclass(frozen=True)
class SuiteEvidence:
    kind: str  # "auto_http" | "auto_raw_tcp" | "manual"
    case_count: int


@dataclass(frozen=True)
class MutationEvidence:
    generated: bool
    candidate_count: int


@dataclass(frozen=True)
class DatasetRecord:
    name: str
    sid: int
    cve: str
    rule: str
    status: RecordStatus = "ingested"
    baseline: BaselineEvidence | None = None
    suite: SuiteEvidence | None = None
    mutations: MutationEvidence | None = None
    reason: str | None = None


@dataclass(frozen=True)
class DatasetManifest:
    dataset_id: str
    source: str
    records: tuple[DatasetRecord, ...]

    def record(self, name: str) -> DatasetRecord:
        for candidate in self.records:
            if candidate.name == name:
                return candidate
        raise KeyError(f"no record named {name!r} in dataset {self.dataset_id!r}")

    def with_record(self, updated: DatasetRecord) -> "DatasetManifest":
        """Return a new manifest with one record replaced by name."""
        names = {record.name for record in self.records}
        if updated.name not in names:
            raise ValueError(
                f"no record named {updated.name!r} in dataset {self.dataset_id!r}"
            )
        records = tuple(
            updated if record.name == updated.name else record
            for record in self.records
        )
        return DatasetManifest(
            dataset_id=self.dataset_id, source=self.source, records=records
        )


def validate_dataset_id(dataset_id: str) -> str:
    if not _DATASET_ID_RE.fullmatch(dataset_id):
        raise ValueError(
            f"invalid dataset id {dataset_id!r}: must match "
            f"{_DATASET_ID_RE.pattern!r} (no slashes, no leading punctuation)"
        )
    return dataset_id


def dataset_root(dataset_id: str, *, project_root: Path) -> Path:
    validate_dataset_id(dataset_id)
    return project_root / "datasets" / dataset_id


def manifest_path(dataset_id: str, *, project_root: Path) -> Path:
    return dataset_root(dataset_id, project_root=project_root) / "manifest.json"


def _evidence_to_dict(value: object) -> dict[str, object] | None:
    return asdict(value) if value is not None else None


def _record_to_dict(record: DatasetRecord) -> dict[str, object]:
    return {
        "name": record.name,
        "sid": record.sid,
        "cve": record.cve,
        "rule": record.rule,
        "status": record.status,
        "baseline": _evidence_to_dict(record.baseline),
        "suite": _evidence_to_dict(record.suite),
        "mutations": _evidence_to_dict(record.mutations),
        "reason": record.reason,
    }


def _record_from_dict(raw: dict[str, object]) -> DatasetRecord:
    status = raw.get("status", "ingested")
    if status not in _STATUSES:
        raise ValueError(f"unsupported dataset record status: {status!r}")
    baseline_raw = raw.get("baseline")
    suite_raw = raw.get("suite")
    mutations_raw = raw.get("mutations")
    return DatasetRecord(
        name=str(raw["name"]),
        sid=int(raw["sid"]),
        cve=str(raw["cve"]),
        rule=str(raw["rule"]),
        status=status,  # type: ignore[arg-type]
        baseline=(
            BaselineEvidence(
                trial_count=int(baseline_raw["trial_count"]),
                exact_trial_count=int(baseline_raw["exact_trial_count"]),
                predictions=tuple(baseline_raw["predictions"]),
            )
            if baseline_raw is not None
            else None
        ),
        suite=(
            SuiteEvidence(
                kind=str(suite_raw["kind"]), case_count=int(suite_raw["case_count"])
            )
            if suite_raw is not None
            else None
        ),
        mutations=(
            MutationEvidence(
                generated=bool(mutations_raw["generated"]),
                candidate_count=int(mutations_raw["candidate_count"]),
            )
            if mutations_raw is not None
            else None
        ),
        reason=raw.get("reason"),
    )


def load_manifest(dataset_id: str, *, project_root: Path) -> DatasetManifest:
    path = manifest_path(dataset_id, project_root=project_root)
    if not path.is_file():
        raise FileNotFoundError(f"no dataset manifest at {path}")
    raw = json.loads(path.read_text(encoding="utf-8"))
    if raw.get("version") != _MANIFEST_VERSION:
        raise ValueError(
            f"unsupported dataset manifest version at {path}: {raw.get('version')!r}"
        )
    return DatasetManifest(
        dataset_id=str(raw["dataset_id"]),
        source=str(raw["source"]),
        records=tuple(_record_from_dict(item) for item in raw["records"]),
    )


def save_manifest(manifest: DatasetManifest, *, project_root: Path) -> Path:
    """Atomically write the manifest; never leaves a torn file on failure."""
    path = manifest_path(manifest.dataset_id, project_root=project_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": _MANIFEST_VERSION,
        "dataset_id": manifest.dataset_id,
        "source": manifest.source,
        "records": [_record_to_dict(record) for record in manifest.records],
    }
    temporary = path.with_suffix(path.suffix + ".tmp")
    try:
        temporary.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        temporary.replace(path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return path


def list_datasets(*, project_root: Path) -> tuple[str, ...]:
    """Every dataset previously added through the unified pipeline, sorted."""
    root = project_root / "datasets"
    if not root.is_dir():
        return ()
    return tuple(
        sorted(
            child.name
            for child in root.iterdir()
            if child.is_dir() and (child / "manifest.json").is_file()
        )
    )
