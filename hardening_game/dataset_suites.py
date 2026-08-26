"""Generate predicate-complete deterministic PCAP suites for the dataset."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Literal

from hardening_game.dataset_recipes import RuleRecipe, SuiteCaseSpec, recipes
from hardening_game.fixture import ValidationCase, sanitize_l5_rule
from hardening_game.pcap.suite_builders import (
    build_established_tcp_stream,
    http_request,
    render_payload,
    segment_sizes_for,
    write_case_pcap,
)
from hardening_game.suricata.validate import replay_suite, syntax_check_rule

_SID = re.compile(r"\bsid\s*:\s*\d+\s*;", re.IGNORECASE)
_REV = re.compile(r"\brev\s*:\s*\d+\s*;", re.IGNORECASE)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
EXCLUDED_SIDS = frozenset({2044680})


@dataclass(frozen=True)
class DatasetRecord:
    name: str
    sid: int
    cve: str
    rule: str


@dataclass(frozen=True)
class SuitePlan:
    name: str
    sid: int
    suite_type: str | None
    status: Literal["planned", "unsupported", "excluded"]
    reason: str


@dataclass(frozen=True)
class BuiltSuiteCase:
    """Fully rendered case; fingerprint detects duplicate-equivalent fixtures."""

    spec: SuiteCaseSpec
    payload: bytes
    port: int
    direction: Literal["to_server", "to_client"]
    client_ip: str | None
    server_ip: str | None
    preamble: bytes | None
    segment_sizes: tuple[int, ...] | None

    @property
    def fingerprint(self) -> str:
        material = (
            self.payload,
            str(self.port).encode(),
            self.direction.encode(),
            (self.client_ip or "").encode(),
            (self.server_ip or "").encode(),
            self.preamble or b"",
            repr(self.segment_sizes).encode(),
            str(self.spec.retransmit_segment).encode(),
            str(self.spec.established).encode(),
        )
        return hashlib.sha256(b"\0".join(material)).hexdigest()


def load_dataset_records(path: Path) -> tuple[DatasetRecord, ...]:
    """Read the narrow dataset schema without trusting benchmark metadata."""
    records: list[DatasetRecord] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        raw = json.loads(line)
        try:
            records.append(
                DatasetRecord(
                    name=str(raw["name"]),
                    sid=int(raw["sid"]),
                    cve=str(raw["cve"]).upper(),
                    rule=str(raw["rule"]),
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"{path}:{line_number}: invalid dataset record") from exc
    return tuple(records)


def ensure_sid_and_revision(rule: str, *, sid: int, revision: int = 1) -> str:
    """Add required rule identity while retaining all detection semantics."""
    result = rule.strip()
    if not result.endswith(")"):
        raise ValueError("Suricata rule must end with ')'")
    if not _SID.search(result):
        result = result[:-1].rstrip() + f" sid:{sid};)"
    if not _REV.search(result):
        result = result[:-1].rstrip() + f" rev:{revision};)"
    return result


def plan_dataset_suites(records: tuple[DatasetRecord, ...]) -> tuple[SuitePlan, ...]:
    """Give every record a recipe, an explicit exclusion, or unsupported status."""
    catalog = recipes()
    plans: list[SuitePlan] = []
    for record in records:
        if record.sid in EXCLUDED_SIDS:
            plans.append(
                SuitePlan(
                    record.name,
                    record.sid,
                    None,
                    "excluded",
                    "Explicitly excluded: the SMTP base64 predicate has no retained "
                    "predicate-complete deterministic recipe.",
                )
            )
        elif record.sid in catalog:
            recipe = catalog[record.sid]
            plans.append(SuitePlan(record.name, record.sid, recipe.suite_type, "planned", recipe.reason))
        else:
            plans.append(
                SuitePlan(
                    record.name,
                    record.sid,
                    None,
                    "unsupported",
                    "No protocol-valid deterministic recipe is defined for this rule.",
                )
            )
    return tuple(plans)


def _as_optional_string(value: object | None) -> str | None:
    return str(value) if value is not None else None


def _response_preamble(recipe: RuleRecipe, mutation: dict[str, object]) -> bytes | None:
    if recipe.suite_type != "http" or recipe.direction != "to_client":
        return None
    target = str(mutation.get("request_target", recipe.canonical.get("request_target", "/")))
    return http_request("GET", target)


def build_suite_cases(recipe: RuleRecipe) -> tuple[BuiltSuiteCase, ...]:
    """Render all declarative cases without writing artifacts."""
    rendered: list[BuiltSuiteCase] = []
    for spec in recipe.cases:
        mutation = dict(spec.mutation)
        direction = mutation.get("direction", recipe.direction)
        if direction not in {"to_server", "to_client"}:
            raise ValueError(f"{recipe.sid}/{spec.name}: invalid direction {direction!r}")
        # Direction mutations alter the transport flow, not the protocol message.
        # A reversed HTTP response is still response-shaped bytes, just sent in
        # the wrong direction so Suricata must not populate response buffers.
        payload = render_payload(
            recipe.suite_type, recipe.direction, recipe.canonical, mutation
        )
        sizes = segment_sizes_for(
            payload,
            segment_sizes=spec.segment_sizes,
            split_after=spec.split_after,
            uniform_segment_size=spec.uniform_segment_size,
        )
        rendered.append(
            BuiltSuiteCase(
                spec=spec,
                payload=payload,
                port=int(mutation.get("port", recipe.port)),
                direction=direction,
                client_ip=_as_optional_string(mutation.get("client_ip")),
                server_ip=_as_optional_string(mutation.get("server_ip")),
                preamble=_response_preamble(recipe, mutation),
                segment_sizes=sizes,
            )
        )
    fingerprints = [case.fingerprint for case in rendered]
    if len(fingerprints) != len(set(fingerprints)):
        raise ValueError(f"{recipe.sid}: recipe contains duplicate-equivalent cases")
    return tuple(rendered)


def _write_suite_cases(
    recipe: RuleRecipe, *, suite_dir: Path, project_root: Path
) -> tuple[ValidationCase, ...]:
    cases: list[ValidationCase] = []
    for built in build_suite_cases(recipe):
        path = write_case_pcap(
            build_established_tcp_stream(
                built.payload,
                port=built.port,
                direction=built.direction,
                segment_sizes=built.segment_sizes,
                retransmit_segment=built.spec.retransmit_segment,
                established=built.spec.established,
                preamble=built.preamble,
                **(
                    {"client_ip": built.client_ip}
                    if built.client_ip is not None
                    else {}
                ),
                **(
                    {"server_ip": built.server_ip}
                    if built.server_ip is not None
                    else {}
                ),
            ),
            suite_dir / f"{built.spec.name}.pcap",
        )
        cases.append(
            ValidationCase(
                built.spec.name,
                path,
                built.spec.expected_alert,
                built.spec.reason,
                predicate_id=built.spec.predicate_id,
            )
        )
    return tuple(cases)


def _case_to_dict(case: ValidationCase) -> dict[str, object]:
    result: dict[str, object] = {
        "name": case.name,
        "pcap": str(case.pcap_path),
        "expected_alert": case.expected_alert,
        "reason": case.reason,
    }
    if case.predicate_id is not None:
        result["predicate_id"] = case.predicate_id
    return result


def _replay_case_to_dict(case: object) -> dict[str, object]:
    return {
        "name": case.name,
        "expected_alert": case.expected_alert,
        "fired": case.fired,
        "passed": case.passed,
        "error": case.error,
    }


def _generated_fixture_paths(
    *, project_root: Path, fixture_name: str
) -> tuple[Path, Path, Path]:
    """Return only the generated paths owned by one dataset fixture."""
    pcap_root = (project_root / "pcap" / "dataset").resolve()
    fixture_root = (project_root / "fixtures" / "dataset").resolve()
    suite_dir = (pcap_root / fixture_name).resolve()
    fixture_path = (fixture_root / f"{fixture_name}.json").resolve()
    suite_path = (fixture_root / f"{fixture_name}_suite.json").resolve()
    for path, root in (
        (suite_dir, pcap_root),
        (fixture_path, fixture_root),
        (suite_path, fixture_root),
    ):
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise ValueError(f"unsafe dataset fixture name: {fixture_name!r}") from exc
    return suite_dir, fixture_path, suite_path


def _remove_generated_fixture_artifacts(
    *, project_root: Path, fixture_name: str
) -> tuple[Path, Path, Path]:
    """Remove prior generated PCAPs and JSON for one dataset fixture only."""
    suite_dir, fixture_path, suite_path = _generated_fixture_paths(
        project_root=project_root, fixture_name=fixture_name
    )
    if suite_dir.is_dir():
        for pcap_path in suite_dir.glob("*.pcap"):
            pcap_path.unlink()
        try:
            suite_dir.rmdir()
        except OSError:
            pass
    fixture_path.unlink(missing_ok=True)
    suite_path.unlink(missing_ok=True)
    return suite_dir, fixture_path, suite_path


def _atomic_write_json(path: Path, value: object) -> None:
    """Atomically replace one generated JSON artifact."""
    temporary = path.with_suffix(path.suffix + ".tmp")
    try:
        temporary.write_text(
            json.dumps(value, indent=2) + "\n", encoding="utf-8"
        )
        temporary.replace(path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def generate_dataset_suites(*, dataset_path: Path, project_root: Path) -> dict[str, object]:
    """Generate only syntax-checked, all-case Suricata replay-validated suites."""
    catalog = recipes()
    output: list[dict[str, object]] = []
    for record in load_dataset_records(dataset_path):
        base = {"name": record.name, "sid": record.sid, "cve": record.cve}
        suite_dir, fixture_path, suite_path = _remove_generated_fixture_artifacts(
            project_root=project_root, fixture_name=record.name
        )
        if record.sid in EXCLUDED_SIDS:
            output.append(
                {
                    **base,
                    "suite_type": None,
                    "status": "excluded",
                    "reason": "Explicitly excluded from predicate-complete suites.",
                }
            )
            continue
        recipe = catalog.get(record.sid)
        if recipe is None:
            output.append(
                {
                    **base,
                    "suite_type": None,
                    "status": "unsupported",
                    "reason": "No protocol-valid deterministic recipe is defined for this rule.",
                }
            )
            continue
        rule = ensure_sid_and_revision(sanitize_l5_rule(record.rule), sid=record.sid)
        syntax = syntax_check_rule(rule)
        if not syntax.valid:
            output.append(
                {
                    **base,
                    "suite_type": recipe.suite_type,
                    "status": "baseline_invalid",
                    "reason": syntax.error,
                    "rule": rule,
                }
            )
            continue
        try:
            cases = _write_suite_cases(recipe, suite_dir=suite_dir, project_root=project_root)
            replay = replay_suite(rule, cases, expected_sid=record.sid)
        except Exception:
            _remove_generated_fixture_artifacts(
                project_root=project_root, fixture_name=record.name
            )
            raise
        if not replay.fired:
            _remove_generated_fixture_artifacts(
                project_root=project_root, fixture_name=record.name
            )
            output.append(
                {
                    **base,
                    "suite_type": recipe.suite_type,
                    "status": "replay_failed",
                    "reason": replay.error or "one or more predicate suite cases did not meet expectations",
                    "rule": rule,
                    "cases": [_replay_case_to_dict(case) for case in replay.cases],
                    "unsupported_predicates": [
                        {"id": item.id, "reason": item.reason} for item in recipe.unsupported
                    ],
                }
            )
            continue
        fixture_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            _atomic_write_json(
                suite_path,
                {
                    "cases": [
                        {
                            **_case_to_dict(case),
                            "pcap": str(case.pcap_path.relative_to(project_root)),
                        }
                        for case in cases
                    ]
                },
            )
            _atomic_write_json(
                fixture_path,
                {
                    "name": record.name,
                    "sid": record.sid,
                    "revision": 1,
                    "cve": record.cve,
                    "pcap": str(cases[0].pcap_path.relative_to(project_root)),
                    "suite": str(suite_path.relative_to(project_root)),
                    "rule": rule,
                },
            )
        except Exception:
            _remove_generated_fixture_artifacts(
                project_root=project_root, fixture_name=record.name
            )
            raise
        output.append(
            {
                **base,
                "suite_type": recipe.suite_type,
                "status": "validated",
                "reason": recipe.reason,
                "fixture": str(fixture_path.relative_to(project_root)),
                "suite": str(suite_path.relative_to(project_root)),
                "case_counts": {
                    "signature_positive": sum(case.expected_alert for case in cases),
                    "negative": sum(not case.expected_alert for case in cases),
                    "unsupported": len(recipe.unsupported),
                },
                "unsupported_predicates": [
                    {"id": item.id, "reason": item.reason} for item in recipe.unsupported
                ],
            }
        )
    try:
        dataset_ref = str(dataset_path.relative_to(project_root))
    except ValueError:
        dataset_ref = str(dataset_path)
    manifest = {"dataset": dataset_ref, "records": output}
    (project_root / "fixtures" / "dataset_manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    return manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate and replay-validate predicate-complete dataset suites."
    )
    parser.add_argument("--dataset", default="datasets/gpt55_exact_cve_l5_2023plus_20.jsonl")
    parser.add_argument("--project-root", default=str(_PROJECT_ROOT))
    return parser


def main() -> None:
    args = build_parser().parse_args()
    project_root = Path(args.project_root).resolve()
    dataset_path = Path(args.dataset)
    if not dataset_path.is_absolute():
        dataset_path = project_root / dataset_path
    manifest = generate_dataset_suites(dataset_path=dataset_path, project_root=project_root)
    records = manifest["records"]
    validated = sum(record["status"] == "validated" for record in records)
    print(f"Validated {validated} of {len(records)} dataset records.")
    print(f"Manifest: {project_root / 'fixtures' / 'dataset_manifest.json'}")


if __name__ == "__main__":
    main()
