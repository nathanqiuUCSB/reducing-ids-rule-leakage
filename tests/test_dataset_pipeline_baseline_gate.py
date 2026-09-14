import json
from pathlib import Path

import pytest

from hardening_game.dataset_pipeline import baseline_gate
from hardening_game.dataset_pipeline.baseline_gate import (
    exact_trial_count,
    qualifies,
    run_baseline_gate,
    write_baseline_fixture,
)
from hardening_game.dataset_pipeline.ingest import add_dataset
from hardening_game.dataset_pipeline.manifest import load_manifest
from hardening_game.mutations.attacker_trials import AttackerTrial
from hardening_game.mutations.clue_review import _qualification


RULE = (
    'alert http any any -> $HOME_NET any (flow:established,to_server; '
    'http.method; content:"POST"; http.uri; content:"/acme/endpoint"; '
    'sid:9000001; rev:1;)'
)


def _trial(index: int, prediction: str | None, status: str = "succeeded") -> AttackerTrial:
    return AttackerTrial(
        candidate_id="acme-rule-001-baseline",
        trial_index=index,
        status=status,
        exchange={"parsed_response": {"predicted_cve": prediction}} if prediction else None,
        prediction=prediction if status == "succeeded" else None,
        error=None if status == "succeeded" else "boom",
    )


@pytest.mark.parametrize(
    ("predictions", "expected"),
    [
        (["CVE-2025-12345"] * 3, True),
        (["CVE-2025-12345", "CVE-2025-12345", "CVE-2019-0001"], False),
        (["CVE-2019-0001"] * 3, False),
        (["cve-2025-12345"] * 3, True),  # case-insensitive match
    ],
)
def test_qualification_requires_every_trial_to_be_exact(
    predictions: list[str], expected: bool
) -> None:
    trials = [_trial(index, cve) for index, cve in enumerate(predictions)]

    assert qualifies(trials, target_cve="CVE-2025-12345") is expected


def test_a_failed_trial_never_counts_as_exact() -> None:
    trials = [
        _trial(0, "CVE-2025-12345"),
        _trial(1, "CVE-2025-12345"),
        _trial(2, None, status="failed"),
    ]

    assert exact_trial_count(trials, target_cve="CVE-2025-12345") == 2
    assert qualifies(trials, target_cve="CVE-2025-12345") is False


@pytest.mark.parametrize(
    "predictions",
    [
        ["CVE-2025-12345"] * 3,
        ["CVE-2025-12345", "CVE-2025-12345", "CVE-2019-0001"],
        ["CVE-2019-0001"] * 3,
    ],
)
def test_it_agrees_with_the_clue_review_qualification_it_duplicates(
    predictions: list[str],
) -> None:
    """The gate deliberately duplicates clue_review's private predicate rather
    than importing it; this pins the two to identical behaviour so they cannot
    drift apart silently."""
    trials = [_trial(index, cve) for index, cve in enumerate(predictions)]
    target = "CVE-2025-12345"

    mine = "primary_qualified" if qualifies(trials, target_cve=target) else "control_or_unstable"

    assert mine == _qualification(trials, target_cve=target)


def test_the_baseline_fixture_has_no_suite_and_points_at_the_future_pcap(
    tmp_path: Path,
) -> None:
    source = tmp_path / "rules.jsonl"
    source.write_text(
        json.dumps(
            {"name": "acme-rule-001", "sid": 9000001, "cve": "CVE-2025-12345", "rule": RULE}
        )
        + "\n",
        encoding="utf-8",
    )
    manifest = add_dataset(source, dataset_id="acme", project_root=tmp_path)

    path = write_baseline_fixture(
        manifest.records[0], dataset_id="acme", project_root=tmp_path
    )
    payload = json.loads(path.read_text())

    assert "suite" not in payload  # baseline-only never replays a suite
    assert payload["cve"] == "CVE-2025-12345"
    assert payload["pcap"] == "datasets/acme/pcap/acme-rule-001/P0-auto-canonical.pcap"


def _dataset(tmp_path: Path, *rules: tuple[str, str]) -> None:
    """Each rule gets its own URI literal: the attacker-visible rule has sid
    and rev stripped, so rules must differ in detection logic to be told apart
    from the prompt alone."""
    source = tmp_path / "rules.jsonl"
    source.write_text(
        "\n".join(
            json.dumps(
                {
                    "name": name,
                    "sid": 9000001 + index,
                    "cve": cve,
                    "rule": RULE.replace("9000001", str(9000001 + index)).replace(
                        "/acme/endpoint", f"/acme/{name}"
                    ),
                }
            )
            for index, (name, cve) in enumerate(rules)
        )
        + "\n",
        encoding="utf-8",
    )
    add_dataset(source, dataset_id="acme", project_root=tmp_path)


@pytest.mark.integration
def test_the_gate_splits_qualified_from_rejected_and_records_evidence(
    tmp_path: Path, monkeypatch
) -> None:
    """Real Suricata syntax-checks the baseline; the attacker is faked so the
    gate's own decision logic is what is under test, not a live model."""
    _dataset(
        tmp_path,
        ("always-right", "CVE-2025-12345"),
        ("sometimes-right", "CVE-2025-22222"),
    )
    scripted = {
        "always-right": ["CVE-2025-12345"] * 3,
        "sometimes-right": ["CVE-2025-22222", "CVE-2019-0001", "CVE-2025-22222"],
    }
    calls: dict[str, int] = {}

    class FakeClient:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def complete(self, *, model: str, prompt: str) -> str:
            name = (
                "always-right" if "/acme/always-right" in prompt else "sometimes-right"
            )
            index = calls.get(name, 0)
            calls[name] = index + 1
            return json.dumps(
                {
                    "predicted_cve": scripted[name][index],
                    "reasoning": "fake",
                    "clues": [
                        {
                            "description": "uri literal",
                            "rule_evidence": [f"/acme/{name}"],
                        }
                    ],
                }
            )

    manifest = run_baseline_gate(
        "acme",
        attacker_model="fake",
        api_key="unused",
        project_root=tmp_path,
        client_factory=FakeClient,
    )

    qualified = manifest.record("always-right")
    rejected = manifest.record("sometimes-right")
    assert qualified.status == "baseline_qualified"
    assert qualified.baseline.exact_trial_count == 3
    assert rejected.status == "baseline_rejected"
    assert rejected.baseline.exact_trial_count == 2
    assert "2 of 3 baseline trials" in rejected.reason
    # persisted, not just returned
    assert load_manifest("acme", project_root=tmp_path) == manifest


@pytest.mark.integration
def test_the_gate_skips_rules_it_already_decided(tmp_path: Path) -> None:
    _dataset(tmp_path, ("already-done", "CVE-2025-12345"))
    calls: list[str] = []

    class FakeClient:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def complete(self, *, model: str, prompt: str) -> str:
            calls.append(prompt)
            return json.dumps(
                {
                    "predicted_cve": "CVE-2025-12345",
                    "reasoning": "fake",
                    "clues": [
                        {"description": "uri", "rule_evidence": ["/acme/already-done"]}
                    ],
                }
            )

    run_baseline_gate(
        "acme",
        attacker_model="fake",
        api_key="unused",
        project_root=tmp_path,
        client_factory=FakeClient,
    )
    first_round = len(calls)

    run_baseline_gate(
        "acme",
        attacker_model="fake",
        api_key="unused",
        project_root=tmp_path,
        client_factory=FakeClient,
    )

    assert first_round > 0
    assert len(calls) == first_round  # no further attacker spend on a re-run
