"""Load public benign provenance and validate the local capture cache."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
from typing import Literal, cast


CoverageTier = Literal["level1", "level2", "level3", "proxy"]
_COVERAGE_TIERS = frozenset({"level1", "level2", "level3", "proxy"})
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class BenignSourceRecord:
    source_id: str
    url: str
    relative_path: str
    sha256: str
    license_note: str
    capture_format: str
    inspection_status: str
    protocol: str


@dataclass(frozen=True)
class BenignRegistry:
    version: int
    cache_root: str
    sources: tuple[BenignSourceRecord, ...]


@dataclass(frozen=True)
class BenignFixtureMapping:
    fixture_name: str
    source_id: str
    coverage_tier: CoverageTier
    relevance_note: str


@dataclass(frozen=True)
class CacheEntryStatus:
    source_id: str
    path: Path
    present: bool
    sha256_valid: bool | None
    error: str | None


@dataclass(frozen=True)
class BenignCacheReport:
    cache_root: Path
    entries: tuple[CacheEntryStatus, ...]


@dataclass(frozen=True)
class BenignCaptureCase:
    name: str
    pcap_path: Path
    source_id: str
    coverage_tier: CoverageTier
    relevance_note: str


def _validated_relative_path(value: str, *, field: str) -> str:
    posix_path = PurePosixPath(value)
    windows_path = PureWindowsPath(value)
    if (
        posix_path.is_absolute()
        or windows_path.is_absolute()
        or windows_path.drive
        or windows_path.root
    ):
        raise ValueError(f"{field} must be relative")
    if ".." in posix_path.parts or ".." in windows_path.parts:
        raise ValueError(f"{field} must not contain '..'")
    return value


def load_benign_registry(path: Path) -> BenignRegistry:
    """Load and validate a JSON provenance registry."""
    data = json.loads(path.read_text())
    sources = tuple(BenignSourceRecord(**source) for source in data["sources"])
    seen: set[str] = set()
    for source in sources:
        if source.source_id in seen:
            raise ValueError(f"duplicate source_id: {source.source_id}")
        seen.add(source.source_id)
        if not _SHA256_RE.fullmatch(source.sha256):
            raise ValueError(
                f"{source.source_id} must have a 64-character lowercase SHA-256"
            )
        _validated_relative_path(
            source.relative_path,
            field=f"{source.source_id} relative_path",
        )
    _validated_relative_path(data["cache_root"], field="cache_root")
    return BenignRegistry(
        version=data["version"],
        cache_root=data["cache_root"],
        sources=sources,
    )


def load_fixture_mappings(
    path: Path, *, registry: BenignRegistry
) -> tuple[BenignFixtureMapping, ...]:
    """Load fixture mappings and check their registry references."""
    data = json.loads(path.read_text())
    source_ids = {source.source_id for source in registry.sources}
    mappings: list[BenignFixtureMapping] = []
    for record in data["mappings"]:
        source_id = record["source_id"]
        coverage_tier = record["coverage_tier"]
        if source_id not in source_ids:
            raise ValueError(f"unknown source_id: {source_id}")
        if coverage_tier not in _COVERAGE_TIERS:
            raise ValueError(f"invalid coverage tier: {coverage_tier}")
        mappings.append(
            BenignFixtureMapping(
                fixture_name=record["fixture_name"],
                source_id=source_id,
                coverage_tier=cast(CoverageTier, coverage_tier),
                relevance_note=record["relevance_note"],
            )
        )
    return tuple(mappings)


def validate_benign_cache(
    registry: BenignRegistry, cache_root: Path
) -> BenignCacheReport:
    """Report presence and hash validity for every registered capture."""
    entries: list[CacheEntryStatus] = []
    for source in registry.sources:
        path = cache_root / source.relative_path
        try:
            present = path.is_file()
        except OSError as error:
            entries.append(
                CacheEntryStatus(
                    source_id=source.source_id,
                    path=path,
                    present=False,
                    sha256_valid=None,
                    error=f"capture could not be inspected: {error}",
                )
            )
            continue
        if not present:
            entries.append(
                CacheEntryStatus(
                    source_id=source.source_id,
                    path=path,
                    present=False,
                    sha256_valid=None,
                    error="capture is missing",
                )
            )
            continue
        try:
            actual_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as error:
            entries.append(
                CacheEntryStatus(
                    source_id=source.source_id,
                    path=path,
                    present=True,
                    sha256_valid=None,
                    error=f"capture could not be read: {error}",
                )
            )
            continue
        valid = actual_hash == source.sha256
        entries.append(
            CacheEntryStatus(
                source_id=source.source_id,
                path=path,
                present=True,
                sha256_valid=valid,
                error=None if valid else "SHA-256 mismatch",
            )
        )
    return BenignCacheReport(cache_root=cache_root, entries=tuple(entries))


@dataclass(frozen=True)
class BenignCorpusDigest:
    """Reproducible evidence of exactly which benign captures a run used.

    Folds the registry file, the fixture-mapping file, and the bytes of every
    cached capture that validated, so a later reader can recompute the same
    value and learn whether the corpus a locked manifest refers to is still
    the one on disk. Sources that failed validation are named, never merely
    counted, so a launch can refuse to proceed on a corpus that is silently
    smaller than it was locked against.
    """

    digest: str
    registry_sha256: str
    mappings_sha256: str
    total_sources: int
    available_sources: int
    missing_sources: tuple[str, ...]
    mapped_fixtures: tuple[str, ...]


def benign_corpus_digest(
    *, registry_path: Path, mappings_path: Path, cache_root: Path
) -> BenignCorpusDigest:
    """Compute a stable digest over the registry, mappings, and valid captures."""
    registry = load_benign_registry(registry_path)
    mappings = load_fixture_mappings(mappings_path, registry=registry)
    report = validate_benign_cache(registry, cache_root)
    statuses = {entry.source_id: entry for entry in report.entries}
    missing = tuple(
        sorted(
            source.source_id
            for source in registry.sources
            if statuses[source.source_id].sha256_valid is not True
        )
    )
    capture_fold = hashlib.sha256()
    for source in sorted(registry.sources, key=lambda item: item.source_id):
        status = statuses[source.source_id]
        if status.sha256_valid is not True:
            continue
        capture_fold.update(source.source_id.encode("utf-8"))
        capture_fold.update(b"\0")
        capture_fold.update(hashlib.sha256(status.path.read_bytes()).digest())
        capture_fold.update(b"\n")

    registry_bytes = registry_path.read_bytes()
    mappings_bytes = mappings_path.read_bytes()
    overall = hashlib.sha256()
    overall.update(hashlib.sha256(registry_bytes).digest())
    overall.update(hashlib.sha256(mappings_bytes).digest())
    overall.update(capture_fold.digest())

    return BenignCorpusDigest(
        digest=overall.hexdigest(),
        registry_sha256=hashlib.sha256(registry_bytes).hexdigest(),
        mappings_sha256=hashlib.sha256(mappings_bytes).hexdigest(),
        total_sources=len(registry.sources),
        available_sources=len(registry.sources) - len(missing),
        missing_sources=missing,
        mapped_fixtures=tuple(
            sorted({mapping.fixture_name for mapping in mappings})
        ),
    )


def benign_cases_for_fixture(
    fixture_name: str,
    *,
    registry: BenignRegistry,
    mappings: tuple[BenignFixtureMapping, ...],
    report: BenignCacheReport,
) -> tuple[BenignCaptureCase, ...]:
    """Return only mapped captures whose cache entries passed validation."""
    sources = {source.source_id: source for source in registry.sources}
    statuses = {entry.source_id: entry for entry in report.entries}
    cases: list[BenignCaptureCase] = []
    for mapping in mappings:
        if mapping.fixture_name != fixture_name:
            continue
        source = sources.get(mapping.source_id)
        status = statuses.get(mapping.source_id)
        if source is None or status is None or status.sha256_valid is not True:
            continue
        cases.append(
            BenignCaptureCase(
                name=f"{fixture_name}:{source.source_id}",
                pcap_path=status.path,
                source_id=source.source_id,
                coverage_tier=mapping.coverage_tier,
                relevance_note=mapping.relevance_note,
            )
        )
    return tuple(cases)
