import json
from pathlib import Path

import pytest

from hardening_game.dataset_pipeline import cli
from hardening_game.dataset_pipeline.cli import build_parser, main
from hardening_game.dataset_pipeline.ingest import add_dataset
from hardening_game.dataset_pipeline.manifest import (
    BaselineEvidence,
    DatasetRecord,
    MutationEvidence,
    load_manifest,
    save_manifest,
)


RULE = (
    'alert http any any -> $HOME_NET any (flow:established,to_server; '
    'http.uri; content:"/acme/endpoint"; sid:9000001; rev:1;)'
)
PCRE_RULE = (
    'alert http any any -> $HOME_NET any (flow:established,to_server; '
    'http.uri; content:"/acme/"; pcre:"/^[a-z]{3}\\x2f/R"; sid:9000002; rev:1;)'
)


def _source(tmp_path: Path, *records: dict[str, object]) -> Path:
    path = tmp_path / "rules.jsonl"
    path.write_text(
        "".join(json.dumps(record) + "\n" for record in records), encoding="utf-8"
    )
    return path


def _added(tmp_path: Path) -> None:
    add_dataset(
        _source(
            tmp_path,
            {"name": "rule-a", "sid": 9000001, "cve": "CVE-2025-10000", "rule": RULE},
        ),
        dataset_id="acme",
        project_root=tmp_path,
    )


def _run(tmp_path: Path, *argv: str) -> int:
    return main(["--project-root", str(tmp_path), *argv])


def test_a_missing_subcommand_is_an_argparse_error() -> None:
    with pytest.raises(SystemExit):
        build_parser().parse_args([])


@pytest.mark.parametrize(
    "argv",
    [
        ["baseline", "acme"],  # --attacker-model is required
        ["run", "acme"],
        ["add-dataset", "rules.jsonl"],  # --dataset-id is required
        ["explain", "acme"],  # rule name is required
    ],
)
def test_required_flags_are_enforced(argv: list[str]) -> None:
    with pytest.raises(SystemExit):
        build_parser().parse_args(argv)


def test_list_names_the_legacy_dataset_even_with_nothing_added(
    tmp_path: Path, capsys
) -> None:
    assert _run(tmp_path, "list") == 0

    out = capsys.readouterr().out
    assert "No datasets added yet" in out
    assert "hash-locked" in out  # the 19-rule set is accounted for, not absent


def test_list_summarises_each_dataset_by_status(tmp_path: Path, capsys) -> None:
    _added(tmp_path)

    _run(tmp_path, "list")

    assert "acme: 1 rules (1 ingested)" in capsys.readouterr().out


def test_add_dataset_reports_the_count_and_the_next_command(
    tmp_path: Path, capsys
) -> None:
    source = _source(
        tmp_path,
        {"name": "rule-a", "sid": 9000001, "cve": "CVE-2025-10000", "rule": RULE},
    )

    assert _run(tmp_path, "add-dataset", str(source), "--dataset-id", "acme") == 0

    out = capsys.readouterr().out
    assert "Added 1 rules" in out
    assert "hardening-experiment baseline acme" in out


def test_a_missing_api_key_is_a_usage_error_not_a_traceback(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    _added(tmp_path)
    monkeypatch.delenv("LITELLM_API_KEY", raising=False)
    monkeypatch.setattr(cli, "load_project_env", lambda path: None)

    code = _run(tmp_path, "baseline", "acme", "--attacker-model", "fake")

    assert code == 2
    assert "no attacker API key in $LITELLM_API_KEY" in capsys.readouterr().err


def test_baseline_routes_through_the_gate_and_reports_rejections(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    _added(tmp_path)
    monkeypatch.setenv("LITELLM_API_KEY", "key")
    monkeypatch.setattr(cli, "load_project_env", lambda path: None)
    captured: dict[str, object] = {}

    def fake_gate(dataset_id, **kwargs):
        captured["dataset_id"] = dataset_id
        captured.update(kwargs)
        manifest = load_manifest("acme", project_root=tmp_path)
        record = manifest.record("rule-a")
        return manifest.with_record(
            DatasetRecord(
                name=record.name,
                sid=record.sid,
                cve=record.cve,
                rule=record.rule,
                status="baseline_rejected",
                baseline=BaselineEvidence(
                    trial_count=3,
                    exact_trial_count=1,
                    predictions=("CVE-2025-10000", "CVE-2099-9999", None),
                ),
            )
        )

    monkeypatch.setattr(cli, "run_baseline_gate", fake_gate)

    code = _run(
        tmp_path, "baseline", "acme", "--attacker-model", "gpt-x", "--attacker-trials", "3"
    )

    out = capsys.readouterr().out
    assert captured["attacker_model"] == "gpt-x"
    assert captured["api_key"] == "key"
    assert captured["resume"] is True
    assert "0 / 1 rules qualified" in out
    assert "rejected rule-a" in out
    assert "CVE-2099-9999" in out
    # nothing qualified, so there is nothing to mutate - a nonzero exit so a
    # `run-all` chain stops here instead of running an empty experiment
    assert code == 1


def test_generate_lists_blocked_rules_with_the_explain_command(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    add_dataset(
        _source(
            tmp_path,
            {"name": "rule-a", "sid": 9000001, "cve": "CVE-2025-10000", "rule": RULE},
            {
                "name": "rule-b",
                "sid": 9000002,
                "cve": "CVE-2025-10001",
                "rule": PCRE_RULE,
            },
        ),
        dataset_id="acme",
        project_root=tmp_path,
    )

    def fake_generate(dataset_id, *, project_root, resume):
        manifest = load_manifest(dataset_id, project_root=project_root)
        ready = manifest.record("rule-a")
        manifest = manifest.with_record(
            DatasetRecord(
                name=ready.name,
                sid=ready.sid,
                cve=ready.cve,
                rule=ready.rule,
                status="mutations_generated",
                mutations=MutationEvidence(generated=True, candidate_count=12),
            )
        )
        blocked = manifest.record("rule-b")
        return manifest.with_record(
            DatasetRecord(
                name=blocked.name,
                sid=blocked.sid,
                cve=blocked.cve,
                rule=blocked.rule,
                status="suite_needs_manual_pcap",
                reason="pcre is load-bearing",
            )
        )

    monkeypatch.setattr(cli, "generate_for_dataset", fake_generate)

    assert _run(tmp_path, "generate", "acme") == 0

    out = capsys.readouterr().out
    assert "1 / 2 prepared rules have a validated suite" in out
    assert "12 mutation candidates" in out
    assert "needs a manual PCAP: rule-b - pcre is load-bearing" in out
    assert "hardening-experiment explain acme rule-b" in out


def test_explain_prints_the_breakdown_for_one_rule(tmp_path: Path, capsys) -> None:
    add_dataset(
        _source(
            tmp_path,
            {
                "name": "rule-b",
                "sid": 9000002,
                "cve": "CVE-2025-10001",
                "rule": PCRE_RULE,
            },
        ),
        dataset_id="acme",
        project_root=tmp_path,
    )

    assert _run(tmp_path, "explain", "acme", "rule-b") == 0

    out = capsys.readouterr().out
    assert "pcre" in out
    assert "complete-pcap" in out


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["--fill-text", "abc/"], b"abc/"),
        (["--fill-text", "a\\x00b"], b"a\x00b"),
        (["--fill-hex", "41 41 00 00 00 05"], b"AA\x00\x00\x00\x05"),
        (["--fill-hex", "|41 42|"], b"AB"),
    ],
)
def test_fill_bytes_accepts_text_escapes_and_hex(
    argv: list[str], expected: bytes
) -> None:
    args = build_parser().parse_args(
        ["complete-pcap", "acme", "rule-b", *argv]
    )

    assert cli._fill_bytes(args) == expected


@pytest.mark.parametrize(
    "argv",
    [
        [],  # neither
        ["--fill-text", "a", "--fill-hex", "41"],  # both
        ["--fill-hex", "zz"],  # not hex
    ],
)
def test_an_ambiguous_or_invalid_fill_is_a_usage_error(argv: list[str]) -> None:
    args = build_parser().parse_args(["complete-pcap", "acme", "rule-b", *argv])

    with pytest.raises(cli.UsageError):
        cli._fill_bytes(args)


def test_complete_pcap_reports_failure_with_a_nonzero_exit(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    from hardening_game.dataset_pipeline.auto_suite import AutoSuiteResult

    _added(tmp_path)
    monkeypatch.setattr(
        cli,
        "apply_manual_suite",
        lambda *a, **k: (
            None,
            AutoSuiteResult("needs_manual_pcap", (), "those bytes did not fire"),
        ),
    )

    code = _run(
        tmp_path, "complete-pcap", "acme", "rule-a", "--fill-text", "nope"
    )

    assert code == 1
    assert "those bytes did not fire" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("argv", "fragment"),
    [
        (["report", "acme"], "hardening-experiment run acme"),
        (["explain", "acme", "no-such-rule"], "no record named 'no-such-rule'"),
        (["list"], ""),  # a control: this one must not be an error
    ],
)
def test_a_missing_artifact_is_a_message_not_a_traceback(
    tmp_path: Path, capsys, argv: list[str], fragment: str
) -> None:
    _added(tmp_path)

    code = _run(tmp_path, *argv)

    captured = capsys.readouterr()
    if fragment:
        assert code == 2
        assert fragment in captured.err
        assert "Traceback" not in captured.err
    else:
        assert code == 0


def test_run_refuses_before_generate_rather_than_running_nothing(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    _added(tmp_path)
    monkeypatch.setenv("LITELLM_API_KEY", "key")
    monkeypatch.setattr(cli, "load_project_env", lambda path: None)

    code = _run(tmp_path, "run", "acme", "--attacker-model", "fake")

    assert code == 2
    assert "generate acme" in capsys.readouterr().err


def test_run_passes_the_benign_flag_through_inverted(
    tmp_path: Path, monkeypatch
) -> None:
    _added(tmp_path)
    manifest = load_manifest("acme", project_root=tmp_path)
    record = manifest.record("rule-a")
    save_manifest(
        manifest.with_record(
            DatasetRecord(
                name=record.name,
                sid=record.sid,
                cve=record.cve,
                rule=record.rule,
                status="mutations_generated",
            )
        ),
        project_root=tmp_path,
    )
    monkeypatch.setenv("LITELLM_API_KEY", "key")
    monkeypatch.setattr(cli, "load_project_env", lambda path: None)
    captured: dict[str, object] = {}

    def fake_run(dataset_id, **kwargs):
        captured.update(kwargs)
        return load_manifest(dataset_id, project_root=tmp_path)

    monkeypatch.setattr(cli, "run_dataset_experiment", fake_run)

    _run(tmp_path, "run", "acme", "--attacker-model", "fake")
    default = captured["skip_benign"]
    _run(tmp_path, "run", "acme", "--attacker-model", "fake", "--benign")

    assert default is True
    assert captured["skip_benign"] is False


def test_run_all_stops_at_the_first_failing_stage(
    tmp_path: Path, monkeypatch
) -> None:
    _added(tmp_path)
    monkeypatch.setenv("LITELLM_API_KEY", "key")
    monkeypatch.setattr(cli, "load_project_env", lambda path: None)
    reached: list[str] = []

    monkeypatch.setattr(cli, "command_baseline", lambda args: (reached.append("baseline"), 1)[1])
    monkeypatch.setattr(cli, "command_generate", lambda args: reached.append("generate") or 0)
    monkeypatch.setattr(cli, "command_run", lambda args: reached.append("run") or 0)
    monkeypatch.setattr(cli, "command_report", lambda args: reached.append("report") or 0)

    code = _run(tmp_path, "run-all", "acme", "--attacker-model", "fake")

    assert code == 1
    assert reached == ["baseline"]
