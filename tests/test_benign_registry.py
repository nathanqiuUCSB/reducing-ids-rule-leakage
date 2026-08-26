import hashlib
import json
from pathlib import Path

import pytest

from hardening_game.benign.registry import (
    BenignFixtureMapping,
    BenignRegistry,
    BenignSourceRecord,
    benign_cases_for_fixture,
    benign_corpus_digest,
    load_benign_registry,
    load_fixture_mappings,
    validate_benign_cache,
)


PROJECT_ROOT = Path(__file__).parents[1]


def _registry() -> BenignRegistry:
    return BenignRegistry(
        version=1,
        cache_root="cache",
        sources=(
            BenignSourceRecord(
                source_id="HTTP_SIMPLE",
                url="https://example.invalid/http.cap",
                relative_path="level1/http/http.cap",
                sha256="0" * 64,
                license_note="test fixture",
                capture_format="pcap",
                inspection_status="pending",
                protocol="http",
            ),
        ),
    )


def _mappings() -> tuple[BenignFixtureMapping, ...]:
    return (
        BenignFixtureMapping(
            fixture_name="et-2044143",
            source_id="HTTP_SIMPLE",
            coverage_tier="level1",
            relevance_note="HTTP protocol coverage",
        ),
    )


def _write_registry(tmp_path: Path, sources: list[dict[str, object]]) -> Path:
    path = tmp_path / "registry.json"
    path.write_text(
        json.dumps({"version": 1, "cache_root": "cache", "sources": sources})
    )
    return path


def _source(**overrides: object) -> dict[str, object]:
    source = {
        "source_id": "HTTP_SIMPLE",
        "url": "https://example.invalid/http.cap",
        "relative_path": "level1/http/http.cap",
        "sha256": "0" * 64,
        "license_note": "test fixture",
        "capture_format": "pcap",
        "inspection_status": "pending",
        "protocol": "http",
    }
    source.update(overrides)
    return source


def test_missing_benign_capture_is_unavailable_not_valid(tmp_path: Path) -> None:
    registry = _registry()
    report = validate_benign_cache(registry, tmp_path / "cache")
    assert report.entries[0].present is False
    assert report.entries[0].sha256_valid is None
    assert report.entries[0].error == "capture is missing"


def test_hash_mismatch_excludes_capture(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    (cache / "level1/http").mkdir(parents=True)
    (cache / "level1/http/http.cap").write_bytes(b"wrong")
    registry = _registry()
    report = validate_benign_cache(registry, cache)
    assert report.entries[0].present is True
    assert report.entries[0].sha256_valid is False
    assert benign_cases_for_fixture(
        "et-2044143",
        registry=registry,
        mappings=_mappings(),
        report=report,
    ) == ()


@pytest.mark.parametrize(
    "read_error",
    [
        PermissionError("permission denied"),
        FileNotFoundError("capture disappeared"),
    ],
)
def test_unreadable_capture_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    read_error: OSError,
) -> None:
    cache = tmp_path / "cache"
    capture = cache / "level1/http/http.cap"
    capture.parent.mkdir(parents=True)
    capture.write_bytes(b"capture")
    original_read_bytes = Path.read_bytes

    def fail_capture_read(path: Path) -> bytes:
        if path == capture:
            raise read_error
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", fail_capture_read)

    entry = validate_benign_cache(_registry(), cache).entries[0]

    assert entry.present is True
    assert entry.sha256_valid is None
    assert entry.error == f"capture could not be read: {read_error}"


def test_valid_capture_produces_fixture_case(tmp_path: Path) -> None:
    payload = b"valid capture"
    cache = tmp_path / "cache"
    capture = cache / "level1/http/http.cap"
    capture.parent.mkdir(parents=True)
    capture.write_bytes(payload)
    source = _registry().sources[0]
    registry = BenignRegistry(
        version=1,
        cache_root="cache",
        sources=(
            BenignSourceRecord(
                **{
                    **source.__dict__,
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
            ),
        ),
    )

    report = validate_benign_cache(registry, cache)

    assert report.entries[0].sha256_valid is True
    assert benign_cases_for_fixture(
        "et-2044143",
        registry=registry,
        mappings=_mappings(),
        report=report,
    )[0].pcap_path == capture


@pytest.mark.parametrize(
    ("sources", "message"),
    [
        ([_source(), _source()], "duplicate source_id"),
        ([_source(sha256="A" * 64)], "lowercase SHA-256"),
        ([_source(relative_path="../escape.cap")], "must not contain '..'"),
        ([_source(relative_path=r"level1\..\escape.cap")], "must not contain '..'"),
        ([_source(relative_path="/absolute/capture.pcap")], "must be relative"),
        ([_source(relative_path=r"C:\captures\capture.pcap")], "must be relative"),
        (
            [_source(relative_path=r"\\server\share\capture.pcap")],
            "must be relative",
        ),
    ],
)
def test_registry_rejects_invalid_sources(
    tmp_path: Path, sources: list[dict[str, object]], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        load_benign_registry(_write_registry(tmp_path, sources))


@pytest.mark.parametrize(
    ("source_id", "coverage_tier", "message"),
    [
        ("UNKNOWN", "level1", "unknown source_id"),
        ("HTTP_SIMPLE", "candidate", "invalid coverage tier"),
    ],
)
def test_mapping_loader_rejects_invalid_records(
    tmp_path: Path, source_id: str, coverage_tier: str, message: str
) -> None:
    path = tmp_path / "mappings.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "mappings": [
                    {
                        "fixture_name": "et-2044143",
                        "source_id": source_id,
                        "coverage_tier": coverage_tier,
                        "relevance_note": "HTTP protocol coverage",
                    }
                ],
            }
        )
    )
    with pytest.raises(ValueError, match=message):
        load_fixture_mappings(path, registry=_registry())


def test_corpus_digest_reports_availability_and_is_stable(tmp_path: Path) -> None:
    payload = b"valid capture"
    cache = tmp_path / "cache"
    capture = cache / "level1/http/http.cap"
    capture.parent.mkdir(parents=True)
    capture.write_bytes(payload)
    registry_path = _write_registry(
        tmp_path, [_source(sha256=hashlib.sha256(payload).hexdigest())]
    )
    mappings_path = tmp_path / "mappings.json"
    mappings_path.write_text(
        json.dumps(
            {
                "version": 1,
                "mappings": [
                    {
                        "fixture_name": "et-2044143",
                        "source_id": "HTTP_SIMPLE",
                        "coverage_tier": "level1",
                        "relevance_note": "HTTP protocol coverage",
                    }
                ],
            }
        )
    )

    first = benign_corpus_digest(
        registry_path=registry_path, mappings_path=mappings_path, cache_root=cache
    )
    second = benign_corpus_digest(
        registry_path=registry_path, mappings_path=mappings_path, cache_root=cache
    )

    assert first.digest == second.digest
    assert first.total_sources == 1
    assert first.available_sources == 1
    assert first.missing_sources == ()
    assert first.mapped_fixtures == ("et-2044143",)


def test_corpus_digest_reports_missing_sources_by_id(tmp_path: Path) -> None:
    registry_path = _write_registry(tmp_path, [_source()])
    mappings_path = tmp_path / "mappings.json"
    mappings_path.write_text(json.dumps({"version": 1, "mappings": []}))

    digest = benign_corpus_digest(
        registry_path=registry_path,
        mappings_path=mappings_path,
        cache_root=tmp_path / "empty-cache",
    )

    assert digest.available_sources == 0
    assert digest.missing_sources == ("HTTP_SIMPLE",)


def test_corpus_digest_changes_when_a_capture_byte_changes(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    capture = cache / "level1/http/http.cap"
    capture.parent.mkdir(parents=True)
    capture.write_bytes(b"valid capture")
    registry_path = _write_registry(
        tmp_path,
        [_source(sha256=hashlib.sha256(b"valid capture").hexdigest())],
    )
    mappings_path = tmp_path / "mappings.json"
    mappings_path.write_text(json.dumps({"version": 1, "mappings": []}))
    before = benign_corpus_digest(
        registry_path=registry_path, mappings_path=mappings_path, cache_root=cache
    )

    capture.write_bytes(b"valid captureX")
    registry_path.write_text(
        json.dumps(
            {
                "version": 1,
                "cache_root": "cache",
                "sources": [
                    _source(sha256=hashlib.sha256(b"valid captureX").hexdigest())
                ],
            }
        )
    )
    after = benign_corpus_digest(
        registry_path=registry_path, mappings_path=mappings_path, cache_root=cache
    )

    assert before.digest != after.digest


def test_committed_registry_and_mappings_are_complete() -> None:
    registry = load_benign_registry(
        PROJECT_ROOT / "benign_sources/benign_registry.json"
    )
    mappings = load_fixture_mappings(
        PROJECT_ROOT / "benign_sources/fixture_benign_mappings.json",
        registry=registry,
    )
    mapped_fixtures = {mapping.fixture_name for mapping in mappings}
    mappings_by_fixture = {
        fixture_name: {
            (mapping.source_id, mapping.coverage_tier)
            for mapping in mappings
            if mapping.fixture_name == fixture_name
        }
        for fixture_name in mapped_fixtures
    }
    expected_http_sources = {
        ("HTTP_SIMPLE", "level1"),
        ("HTTP_GZIP", "level1"),
        ("HTTP_CHUNKED", "level1"),
        ("HTTP_LARGE_POST", "level1"),
        ("HTTP_REDIRECTS", "level1"),
    }
    http_fixtures = {
        "et-2044143",
        "et-2044585",
        "et-2050434",
        "et-2055723",
        "et-2057330",
        "et-2057705",
        "et-2059741",
        "et-2060086",
        "et-2045307",
        "et-2048541",
        "et-2049007",
        "et-2049080",
        "et-2049623",
        "et-2050340",
        "et-2050988",
        "et-2052951",
        "et-2056147",
    }

    assert len(registry.sources) == 12
    assert all(source.sha256 for source in registry.sources)
    assert {source.source_id for source in registry.sources} == {
        "HTTP_SIMPLE",
        "HTTP_GZIP",
        "HTTP_CHUNKED",
        "HTTP_LARGE_POST",
        "HTTP_REDIRECTS",
        "SMTP_SIMPLE",
        "SMTP_IMF",
        "SMTP_TNEF",
        "RSYNC_EMERGE",
        "PGSQL_BRIEF",
        "PGSQL_JDBC",
        "PGSQL_SSL",
    }
    assert "et-2044680" not in mapped_fixtures
    assert mapped_fixtures == http_fixtures | {
        "et-2067354",
        "et-2060144",
    }
    assert all(
        mappings_by_fixture[fixture_name] == expected_http_sources
        for fixture_name in http_fixtures
    )
    assert mappings_by_fixture["et-2067354"] == {
        ("RSYNC_EMERGE", "level2")
    }
    assert mappings_by_fixture["et-2060144"] == {
        ("PGSQL_BRIEF", "level2"),
        ("PGSQL_JDBC", "level2"),
        ("PGSQL_SSL", "level2"),
    }


def test_committed_benign_corpus_is_fully_present_and_valid() -> None:
    """All 19 clue-registry fixtures depend on this corpus for their mapped
    benign preflight. A launch must never silently run with a missing or
    corrupted capture, so this is asserted here as a standing regression, not
    only checked ad hoc before a launch."""
    digest = benign_corpus_digest(
        registry_path=PROJECT_ROOT / "benign_sources/benign_registry.json",
        mappings_path=PROJECT_ROOT / "benign_sources/fixture_benign_mappings.json",
        cache_root=PROJECT_ROOT / "online_benign_pcaps",
    )

    assert digest.missing_sources == ()
    assert digest.available_sources == digest.total_sources == 12
    assert len(digest.mapped_fixtures) == 19
