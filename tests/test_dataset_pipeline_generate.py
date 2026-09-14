import json
from pathlib import Path

import pytest

from hardening_game.dataset_pipeline import generate as generate_module
from hardening_game.dataset_pipeline.auto_suite import AutoSuiteResult
from hardening_game.dataset_pipeline.generate import (
    candidates_path,
    generate_for_dataset,
    suite_path,
    write_candidates,
)
from hardening_game.dataset_pipeline.ingest import add_dataset
from hardening_game.dataset_pipeline.manifest import (
    BaselineEvidence,
    DatasetRecord,
    load_manifest,
    save_manifest,
)
from hardening_game.fixture import ValidationCase, load_fixture_path


RULE = (
    'alert http any any -> $HOME_NET any (flow:established,to_server; '
    'http.method; content:"POST"; http.uri; content:"/acme/{name}"; '
    'sid:{sid}; rev:1;)'
)


def _dataset(tmp_path: Path, *names: str) -> None:
    source = tmp_path / "rules.jsonl"
    source.write_text(
        "\n".join(
            json.dumps(
                {
                    "name": name,
                    "sid": 9000001 + index,
                    "cve": f"CVE-2025-1000{index}",
                    "rule": RULE.format(name=name, sid=9000001 + index),
                }
            )
            for index, name in enumerate(names)
        )
        + "\n",
        encoding="utf-8",
    )
    add_dataset(source, dataset_id="acme", project_root=tmp_path)


def _qualify(tmp_path: Path, *names: str) -> None:
    """Mark records baseline_qualified without spending attacker calls."""
    manifest = load_manifest("acme", project_root=tmp_path)
    for name in names:
        record = manifest.record(name)
        manifest = manifest.with_record(
            DatasetRecord(
                name=record.name,
                sid=record.sid,
                cve=record.cve,
                rule=record.rule,
                status="baseline_qualified",
                baseline=BaselineEvidence(
                    trial_count=3, exact_trial_count=3, predictions=(record.cve,) * 3
                ),
            )
        )
    save_manifest(manifest, project_root=tmp_path)


def _fake_suite(tmp_path: Path):
    """Stand in for auto_suite: write real files, skip real Suricata."""

    def fake(rule, *, rule_name, sid, output_dir, project_root):
        output_dir.mkdir(parents=True, exist_ok=True)
        cases = []
        for label, expected in (("P0-auto-canonical", True), ("N0-auto-broken", False)):
            path = output_dir / f"{label}.pcap"
            path.write_bytes(b"\xd4\xc3\xb2\xa1")
            cases.append(
                ValidationCase(
                    name=label,
                    pcap_path=path,
                    expected_alert=expected,
                    reason="fake",
                    predicate_id=None,
                )
            )
        return AutoSuiteResult("generated", tuple(cases), "fake", kind="auto_http")

    return fake


def test_write_candidates_records_the_matrix_without_spending_a_call(
    tmp_path: Path,
) -> None:
    _dataset(tmp_path, "acme-rule-001")
    record = load_manifest("acme", project_root=tmp_path).record("acme-rule-001")

    count = write_candidates(record, dataset_id="acme", project_root=tmp_path)
    payload = json.loads(
        candidates_path("acme", "acme-rule-001", project_root=tmp_path).read_text()
    )

    assert count == len(payload["accepted"]) > 1
    assert payload["fixture_name"] == "acme-rule-001"
    # the unmodified rule is always in the matrix; it is what the attacker's
    # mutated answers are compared against
    assert any(item["component"] == "baseline" for item in payload["accepted"])


def test_only_qualified_rules_are_prepared(tmp_path: Path, monkeypatch) -> None:
    _dataset(tmp_path, "qualified", "never-qualified")
    _qualify(tmp_path, "qualified")
    monkeypatch.setattr(generate_module, "generate_auto_suite", _fake_suite(tmp_path))

    manifest = generate_for_dataset("acme", project_root=tmp_path)

    assert manifest.record("qualified").status == "mutations_generated"
    assert manifest.record("never-qualified").status == "ingested"
    assert not candidates_path(
        "acme", "never-qualified", project_root=tmp_path
    ).exists()


def test_the_fixture_it_writes_loads_with_its_suite_attached(
    tmp_path: Path, monkeypatch
) -> None:
    """The fixture must resolve through the real loader: a fixture whose suite
    does not load leaves every mutation candidate silently rejected."""
    _dataset(tmp_path, "acme-rule-001")
    _qualify(tmp_path, "acme-rule-001")
    monkeypatch.setattr(generate_module, "generate_auto_suite", _fake_suite(tmp_path))

    generate_for_dataset("acme", project_root=tmp_path)
    fixture = load_fixture_path(
        tmp_path / "datasets/acme/fixtures/acme-rule-001.json", project_root=tmp_path
    )

    assert len(fixture.validation_cases) == 2
    assert any(case.expected_alert for case in fixture.validation_cases)
    assert fixture.pcap_path.is_file()
    assert suite_path("acme", "acme-rule-001", project_root=tmp_path).is_file()


def test_a_blocked_rule_is_retained_with_the_reason_not_dropped(
    tmp_path: Path, monkeypatch
) -> None:
    _dataset(tmp_path, "acme-rule-001")
    _qualify(tmp_path, "acme-rule-001")

    def refuse(rule, *, rule_name, sid, output_dir, project_root):
        return AutoSuiteResult(
            "needs_manual_pcap", (), "pcre is load-bearing", ("pcre",)
        )

    monkeypatch.setattr(generate_module, "generate_auto_suite", refuse)

    manifest = generate_for_dataset("acme", project_root=tmp_path)
    record = manifest.record("acme-rule-001")

    assert record.status == "suite_needs_manual_pcap"
    assert record.reason == "pcre is load-bearing"
    assert record.suite is None
    # the mutation matrix is still written: it costs nothing and the rule is
    # one hand-supplied PCAP away from being runnable
    assert record.mutations is not None and record.mutations.candidate_count > 1
    assert not suite_path("acme", "acme-rule-001", project_root=tmp_path).exists()


def test_resume_skips_prepared_rules_and_retries_blocked_ones(
    tmp_path: Path, monkeypatch
) -> None:
    _dataset(tmp_path, "prepared", "blocked")
    _qualify(tmp_path, "prepared", "blocked")
    seen: list[str] = []
    fake = _fake_suite(tmp_path)

    def first_pass(rule, *, rule_name, sid, output_dir, project_root):
        seen.append(rule_name)
        if rule_name == "blocked":
            return AutoSuiteResult("needs_manual_pcap", (), "pcre", ("pcre",))
        return fake(
            rule,
            rule_name=rule_name,
            sid=sid,
            output_dir=output_dir,
            project_root=project_root,
        )

    monkeypatch.setattr(generate_module, "generate_auto_suite", first_pass)
    generate_for_dataset("acme", project_root=tmp_path)
    seen.clear()

    generate_for_dataset("acme", project_root=tmp_path)

    assert seen == ["blocked"]


def test_no_resume_regenerates_everything_prepared(tmp_path: Path, monkeypatch) -> None:
    _dataset(tmp_path, "prepared")
    _qualify(tmp_path, "prepared")
    seen: list[str] = []
    fake = _fake_suite(tmp_path)

    def counting(rule, **kwargs):
        seen.append(kwargs["rule_name"])
        return fake(rule, **kwargs)

    monkeypatch.setattr(generate_module, "generate_auto_suite", counting)
    generate_for_dataset("acme", project_root=tmp_path)

    generate_for_dataset("acme", project_root=tmp_path, resume=False)

    assert seen == ["prepared", "prepared"]


def test_a_suite_without_a_positive_is_refused(tmp_path: Path) -> None:
    _dataset(tmp_path, "acme-rule-001")
    record = load_manifest("acme", project_root=tmp_path).record("acme-rule-001")
    negative = ValidationCase(
        name="N0",
        pcap_path=tmp_path / "n0.pcap",
        expected_alert=False,
        reason="only a negative",
        predicate_id=None,
    )

    with pytest.raises(ValueError, match="no positive case"):
        generate_module.write_suite_and_fixture(
            record, (negative,), dataset_id="acme", project_root=tmp_path
        )
