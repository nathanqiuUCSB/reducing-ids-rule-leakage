"""Evaluate deterministic candidates with injected validation dependencies."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
from typing import TYPE_CHECKING, Callable, Iterable

from hardening_game.attribution import (
    RelatedCveRegistry,
    classify_cve_attribution,
)
from hardening_game.benign.metrics import (
    BenignCaptureResult,
    aggregate_benign_metrics,
)
from hardening_game.benign.registry import BenignCaptureCase
from hardening_game.fixture import GameFixture, ValidationCase
from hardening_game.mutations.attacker_trials import (
    AttackerTrial,
    append_attacker_trial,
    completed_trial_indexes,
    load_attacker_trials,
    validate_trial_count,
)
from hardening_game.mutations.engine import MutationCandidate
from hardening_game.mutations.specifications import RejectedSpec
from hardening_game.mutations.taxonomy import classify_mutation_category
from hardening_game.suricata.validate import (
    BenignReplayResult,
    ReplayResult,
    SyntaxResult,
)

if TYPE_CHECKING:
    from hardening_game.mutations.combiner import CombinationRejection


SyntaxCheck = Callable[[str], SyntaxResult]
Replay = Callable[[str, ValidationCase], ReplayResult]
BenignReplay = Callable[[str, BenignCaptureCase], BenignReplayResult]
Attacker = Callable[[str], object]
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


class ManifestHashMismatch(RuntimeError):
    """A run directory or candidate belongs to a different locked manifest."""


# A terminal record is a measurement: the candidate was carried as far as it can
# go. Every other status means the attacker step never produced an answer, so
# the candidate is still owed one and a resume must run it again.
TERMINAL_STATUSES = frozenset(
    {"evaluated", "syntax_invalid", "positive_recall_failed"}
)


def latest_records(records: Iterable[dict[str, object]]) -> list[dict[str, object]]:
    """Collapse an append-only log to the last record per candidate ID."""
    latest: dict[str, dict[str, object]] = {}
    for record in records:
        candidate_id = record.get("candidate_id")
        if isinstance(candidate_id, str):
            latest[candidate_id] = record
    return list(latest.values())


@dataclass(frozen=True)
class MutationResult:
    candidate_id: str
    component: str
    operator: str
    params: dict[str, object]
    description: str
    revision: int
    fingerprint: str
    rule: str
    status: str
    syntax_valid: bool
    syntax_error: str | None
    positive_recall: float | None
    negative_false_positive_rate: float | None
    benign_corpus_available: bool
    benign_false_positive_rate: float | None
    benign_capture_results: dict[str, dict[str, object]]
    benign_aggregate: dict[str, object] | None
    benign_cache_errors: tuple[str, ...]
    case_results: dict[str, dict[str, object]]
    attacker_prediction: str | None
    attacker_correct: bool | None
    attacker_exchange: dict[str, object] | None
    attacker_error: str | None
    target_cve: str
    relationship_tier: str | None
    meaningful_obscurity: bool | None
    mutation_category: str
    evaluated_at: str
    buffer: str | None
    option_index: int | None
    experiment_manifest_hash: str | None = None
    source_candidate_ids: tuple[str, ...] | None = None
    block_count: int | None = None


class MutationEvaluator:
    """Persistable candidate evaluator without controller/game dependencies."""

    def __init__(
        self,
        *,
        fixture: GameFixture,
        syntax_check: SyntaxCheck,
        replay: Replay,
        attacker: Attacker,
        output_dir: Path,
        benign_cases: Iterable[BenignCaptureCase] = (),
        benign_replay: BenignReplay | None = None,
        benign_requested: int | None = None,
        benign_cache_errors: Iterable[str] = (),
        benign_enabled: bool = True,
        related_cve_registry: RelatedCveRegistry | None = None,
        experiment_manifest_hash: str | None = None,
        attacker_trial_count: int | None = None,
    ) -> None:
        self.fixture = fixture
        self.syntax_check = syntax_check
        self.replay = replay
        self.attacker = attacker
        self.output_dir = output_dir
        self.benign_cases = tuple(benign_cases)
        self.benign_replay = benign_replay
        self.benign_requested = (
            len(self.benign_cases) if benign_requested is None else benign_requested
        )
        self.benign_cache_errors = tuple(benign_cache_errors)
        self.benign_enabled = benign_enabled
        self.related_cve_registry = related_cve_registry
        self.experiment_manifest_hash = experiment_manifest_hash
        self._trial_storage_enabled = attacker_trial_count is not None
        self.attacker_trial_count = (
            validate_trial_count(attacker_trial_count)
            if attacker_trial_count is not None
            else 1
        )

    @property
    def results_path(self) -> Path:
        return self.output_dir / "results.jsonl"

    @property
    def rejections_path(self) -> Path:
        return self.output_dir / "rejections.jsonl"

    @property
    def attacker_trials_path(self) -> Path:
        return self.output_dir / "attacker_trials.jsonl"

    def completed_candidate_ids(self) -> frozenset[str]:
        """Return candidate IDs whose latest persisted record is terminal.

        A candidate whose last record is an attacker failure is deliberately
        absent, so resuming retries it instead of leaving it unmeasured.
        """
        return frozenset(self._completed_candidate_ids())

    def persist_rejections(
        self, rejections: Iterable[RejectedSpec | CombinationRejection]
    ) -> None:
        """Persist non-executable rejected specs outside experiment results."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        contents = "".join(
            json.dumps(asdict(rejection), sort_keys=True) + "\n"
            for rejection in rejections
        )
        self._atomic_write(self.rejections_path, contents)
        self._write_summaries()

    def evaluate(
        self, candidates: Iterable[MutationCandidate], *, resume: bool = False
    ) -> list[MutationResult]:
        candidates = tuple(candidates)
        self.require_manifest_agreement(candidates)
        if self._trial_storage_enabled:
            return self._evaluate_with_attacker_trials(candidates, resume=resume)
        seen = self._completed_candidate_ids() if resume else set()
        results: list[MutationResult] = []
        for candidate in candidates:
            if candidate.id in seen:
                continue
            result = self._evaluate_one(candidate)
            self._append(result)
            results.append(result)
        self._write_summaries()
        return results

    def _evaluate_with_attacker_trials(
        self, candidates: tuple[MutationCandidate, ...], *, resume: bool
    ) -> list[MutationResult]:
        persisted = {
            str(record["candidate_id"]): record
            for record in latest_records(self._persisted_records())
            if isinstance(record.get("candidate_id"), str)
        }
        results: list[MutationResult] = []
        for candidate in candidates:
            record = persisted.get(candidate.id) if resume else None
            if record is not None:
                if record.get("status") in {
                    "syntax_invalid",
                    "positive_recall_failed",
                }:
                    continue
                if record.get("status") == "traffic_complete":
                    if not self._valid_traffic_checkpoint(record, candidate):
                        record = None
                    else:
                        checkpoint = MutationResult(**record)  # type: ignore[arg-type]
                        result = self._complete_traffic_checkpoint(checkpoint)
                        self._append(result)
                        results.append(result)
                        self._append_result_trial(result)
                        self._run_attacker_trials(
                            candidate,
                            range(1, self.attacker_trial_count),
                        )
                        continue
            if record is not None:
                self._seed_trial_from_result_record(record)
                self._run_attacker_trials(
                    candidate,
                    range(self.attacker_trial_count),
                )
                continue

            checkpoint = self._evaluate_one(candidate, include_attacker=False)
            self._append(checkpoint)
            if checkpoint.status in {"syntax_invalid", "positive_recall_failed"}:
                results.append(checkpoint)
                continue
            result = self._complete_traffic_checkpoint(checkpoint)
            self._append(result)
            results.append(result)
            self._append_result_trial(result)
            self._run_attacker_trials(
                candidate,
                range(1, self.attacker_trial_count),
            )
        self._write_summaries()
        return results

    def _valid_traffic_checkpoint(
        self, record: dict[str, object], candidate: MutationCandidate
    ) -> bool:
        required = {field.name for field in MutationResult.__dataclass_fields__.values()}
        case_results = record.get("case_results")
        expected_cases = {
            case.name: case.expected_alert for case in self.fixture.validation_cases
        }
        cases_complete = (
            isinstance(case_results, dict)
            and set(case_results) == set(expected_cases)
            and all(
                isinstance(case_results[name], dict)
                and case_results[name].get("expected_alert") is expected_alert
                and (
                    not expected_alert
                    or case_results[name].get("passed") is True
                )
                for name, expected_alert in expected_cases.items()
            )
        )
        return (
            set(record) == required
            and record.get("status") == "traffic_complete"
            and record.get("candidate_id") == candidate.id
            and record.get("component") == candidate.component
            and record.get("operator") == candidate.operator
            and record.get("params") == candidate.params
            and record.get("description") == candidate.description
            and record.get("revision") == candidate.revision
            and record.get("rule") == candidate.rule
            and record.get("fingerprint") == candidate.fingerprint
            and record.get("experiment_manifest_hash")
            == candidate.experiment_manifest_hash
            and record.get("syntax_valid") is True
            and record.get("syntax_error") is None
            and record.get("positive_recall") == 1.0
            and cases_complete
            and isinstance(record.get("benign_capture_results"), dict)
            and (
                record.get("benign_aggregate") is None
                or isinstance(record.get("benign_aggregate"), dict)
            )
            and record.get("attacker_prediction") is None
            and record.get("attacker_correct") is None
            and record.get("attacker_exchange") is None
            and record.get("attacker_error") is None
            and record.get("relationship_tier") is None
            and record.get("meaningful_obscurity") is None
        )

    def _seed_trial_from_result_record(self, record: dict[str, object]) -> None:
        trials = load_attacker_trials(
            self.attacker_trials_path,
            trial_count=self.attacker_trial_count,
        )
        candidate_id = str(record["candidate_id"])
        if any(
            trial.candidate_id == candidate_id and trial.trial_index == 0
            for trial in trials
        ):
            return
        exchange = record.get("attacker_exchange")
        self._append_trial(
            candidate_id=candidate_id,
            trial_index=0,
            status=str(record.get("status")),
            prediction=(
                record.get("attacker_prediction")
                if isinstance(record.get("attacker_prediction"), str)
                else None
            ),
            exchange=exchange if isinstance(exchange, dict) else None,
            error=(
                record.get("attacker_error")
                if isinstance(record.get("attacker_error"), str)
                else None
            ),
        )

    def _append_result_trial(self, result: MutationResult) -> None:
        self._append_trial(
            candidate_id=result.candidate_id,
            trial_index=0,
            status=result.status,
            prediction=result.attacker_prediction,
            exchange=result.attacker_exchange,
            error=result.attacker_error,
        )

    def _run_attacker_trials(
        self,
        candidate: MutationCandidate,
        trial_indexes: Iterable[int],
    ) -> None:
        trials = load_attacker_trials(
            self.attacker_trials_path,
            trial_count=self.attacker_trial_count,
        )
        completed = completed_trial_indexes(
            trials,
            candidate.id,
            trial_count=self.attacker_trial_count,
        )
        for trial_index in trial_indexes:
            if trial_index in completed:
                continue
            prediction, exchange, error, status = self._measure_attacker(candidate.rule)
            self._append_trial(
                candidate_id=candidate.id,
                trial_index=trial_index,
                status=status,
                prediction=prediction,
                exchange=exchange,
                error=error,
            )

    def _append_trial(
        self,
        *,
        candidate_id: str,
        trial_index: int,
        status: str,
        prediction: str | None,
        exchange: dict[str, object] | None,
        error: str | None,
    ) -> None:
        succeeded = (
            status == "evaluated"
            and isinstance(prediction, str)
            and _CVE.fullmatch(prediction.strip()) is not None
        )
        if succeeded and exchange is None:
            exchange = {"parsed_response": {"predicted_cve": prediction}}
        append_attacker_trial(
            self.attacker_trials_path,
            AttackerTrial(
                candidate_id=candidate_id,
                trial_index=trial_index,
                status="succeeded" if succeeded else "failed",
                exchange=exchange,
                prediction=prediction if succeeded else None,
                error=error or (None if succeeded else status),
            ),
            trial_count=self.attacker_trial_count,
        )

    def validate_baseline(self, candidate: MutationCandidate) -> None:
        """Require the fixture baseline to parse and meet every suite expectation."""
        syntax = self.syntax_check(candidate.rule)
        if not syntax.valid:
            raise RuntimeError(f"baseline syntax validation failed: {syntax.error}")
        failures: list[str] = []
        for case in self.fixture.validation_cases:
            result = self.replay(candidate.rule, case)
            if result.error is not None:
                failures.append(f"{case.name}: {result.error}")
            elif result.fired is not case.expected_alert:
                expected = "alert" if case.expected_alert else "silence"
                observed = "alert" if result.fired else "silence"
                failures.append(f"{case.name}: expected {expected}, observed {observed}")
        if failures:
            raise RuntimeError("baseline replay validation failed: " + "; ".join(failures))

    def _evaluate_one(
        self, candidate: MutationCandidate, *, include_attacker: bool = True
    ) -> MutationResult:
        syntax = self.syntax_check(candidate.rule)
        mutation_category = classify_mutation_category(
            component=candidate.component,
            operator=candidate.operator,
            params=candidate.params,
        )
        base = dict(
            candidate_id=candidate.id,
            component=candidate.component,
            operator=candidate.operator,
            params=candidate.params,
            description=candidate.description,
            revision=candidate.revision,
            fingerprint=candidate.fingerprint,
            rule=candidate.rule,
            buffer=candidate.buffer,
            option_index=candidate.option_index,
            experiment_manifest_hash=candidate.experiment_manifest_hash,
            source_candidate_ids=candidate.source_candidate_ids,
            block_count=candidate.block_count,
            syntax_valid=syntax.valid,
            syntax_error=syntax.error,
            attacker_prediction=None,
            attacker_correct=None,
            attacker_exchange=None,
            attacker_error=None,
            target_cve=self.fixture.cve,
            relationship_tier=None,
            meaningful_obscurity=None,
            mutation_category=mutation_category,
            evaluated_at=datetime.now(timezone.utc).isoformat(),
        )
        if not syntax.valid:
            return MutationResult(
                status="syntax_invalid",
                positive_recall=None,
                negative_false_positive_rate=None,
                benign_corpus_available=bool(self.benign_cases),
                benign_false_positive_rate=None,
                benign_capture_results={},
                benign_aggregate=None,
                benign_cache_errors=self.benign_cache_errors,
                case_results={},
                **base,
            )

        positives = [case for case in self.fixture.validation_cases if case.expected_alert]
        negatives = [case for case in self.fixture.validation_cases if not case.expected_alert]
        case_results: dict[str, dict[str, object]] = {}
        positive_fires = 0
        for case in positives:
            result = self.replay(candidate.rule, case)
            case_results[case.name] = self._case_result(case, result)
            if result.error is None and result.fired:
                positive_fires += 1
        positive_recall = positive_fires / len(positives) if positives else 0.0
        if positive_recall != 1.0:
            return MutationResult(
                status="positive_recall_failed",
                positive_recall=positive_recall,
                negative_false_positive_rate=None,
                benign_corpus_available=bool(self.benign_cases),
                benign_false_positive_rate=None,
                benign_capture_results={},
                benign_aggregate=None,
                benign_cache_errors=self.benign_cache_errors,
                case_results=case_results,
                **base,
            )

        negative_fires = 0
        for case in negatives:
            result = self.replay(candidate.rule, case)
            case_results[case.name] = self._case_result(case, result)
            if result.error is None and result.fired:
                negative_fires += 1
        fp_rate = negative_fires / len(negatives) if negatives else None
        benign_capture_results: dict[str, dict[str, object]] = {}
        benign_results: list[BenignCaptureResult] = []
        if self.benign_enabled:
            for case in self.benign_cases:
                if self.benign_replay is None:
                    replay_result = BenignReplayResult(
                        fired=False,
                        total_alerts=0,
                        relevant_flow_count=None,
                        alerting_relevant_flow_count=None,
                        alerts_per_relevant_flow=None,
                        error="benign replay not configured",
                    )
                else:
                    replay_result = self.benign_replay(candidate.rule, case)
                capture_result = BenignCaptureResult(
                    source_id=case.source_id,
                    coverage_tier=case.coverage_tier,
                    capture_name=case.pcap_path.name,
                    fired=replay_result.fired,
                    total_alerts=replay_result.total_alerts,
                    relevant_flow_count=replay_result.relevant_flow_count,
                    alerting_relevant_flow_count=(
                        replay_result.alerting_relevant_flow_count
                    ),
                    alerts_per_relevant_flow=replay_result.alerts_per_relevant_flow,
                    error=replay_result.error,
                )
                benign_results.append(capture_result)
                benign_capture_results[case.source_id] = asdict(capture_result)
            aggregate = aggregate_benign_metrics(
                benign_results,
                requested=self.benign_requested,
                cache_errors=self.benign_cache_errors,
            )
            benign_aggregate: dict[str, object] | None = asdict(aggregate)
            benign_fp_rate = aggregate.capture_firing_rate
            benign_available = aggregate.corpus_available
        else:
            benign_aggregate = None
            benign_fp_rate = None
            benign_available = False
        if include_attacker:
            prediction, attacker_exchange, attacker_error, status = (
                self._measure_attacker(candidate.rule)
            )
        else:
            prediction = None
            attacker_exchange = None
            attacker_error = None
            status = "traffic_complete"
        attribution = None
        if prediction:
            registry = self.related_cve_registry or RelatedCveRegistry(
                version=1,
                entries=(),
            )
            attribution = classify_cve_attribution(
                target_cve=self.fixture.cve,
                predicted_cve=prediction,
                registry=registry,
            )
        return MutationResult(
            status=status,
            positive_recall=positive_recall,
            negative_false_positive_rate=fp_rate,
            benign_corpus_available=benign_available,
            benign_false_positive_rate=benign_fp_rate,
            benign_capture_results=benign_capture_results,
            benign_aggregate=benign_aggregate,
            benign_cache_errors=self.benign_cache_errors,
            case_results=case_results,
            attacker_prediction=prediction,
            attacker_correct=prediction == self.fixture.cve if prediction else None,
            attacker_exchange=attacker_exchange,
            attacker_error=attacker_error,
            relationship_tier=(
                attribution.relationship_tier if attribution is not None else None
            ),
            meaningful_obscurity=(
                attribution.meaningful_obscurity if attribution is not None else None
            ),
            **{
                key: value
                for key, value in base.items()
                if not key.startswith("attacker_")
                and key not in {"relationship_tier", "meaningful_obscurity"}
            },
        )

    def _complete_traffic_checkpoint(
        self, checkpoint: MutationResult
    ) -> MutationResult:
        prediction, exchange, error, status = self._measure_attacker(checkpoint.rule)
        attribution = None
        if prediction:
            registry = self.related_cve_registry or RelatedCveRegistry(
                version=1,
                entries=(),
            )
            attribution = classify_cve_attribution(
                target_cve=self.fixture.cve,
                predicted_cve=prediction,
                registry=registry,
            )
        return replace(
            checkpoint,
            status=status,
            attacker_prediction=prediction,
            attacker_correct=prediction == self.fixture.cve if prediction else None,
            attacker_exchange=exchange,
            attacker_error=error,
            relationship_tier=(
                attribution.relationship_tier if attribution is not None else None
            ),
            meaningful_obscurity=(
                attribution.meaningful_obscurity if attribution is not None else None
            ),
        )

    def _measure_attacker(
        self, rule: str
    ) -> tuple[
        str | None,
        dict[str, object] | None,
        str | None,
        str,
    ]:
        prediction: str | None = None
        attacker_exchange: dict[str, object] | None = None
        attacker_error: str | None = None
        status = "evaluated"
        try:
            response = self.attacker(rule)
            if isinstance(response, str):
                prediction = response
            elif isinstance(response, dict):
                attacker_exchange = response
                parsed = response.get("parsed_response")
                if isinstance(parsed, dict):
                    predicted = parsed.get("predicted_cve")
                    prediction = predicted if isinstance(predicted, str) else None
            else:
                raise TypeError("attacker must return a CVE string or exchange object")
        except ValueError as exc:
            attacker_error = str(exc)
            status = (
                "attacker_empty_response"
                if attacker_error == "model returned empty content after retry"
                else "attacker_parse_failed"
            )
        except Exception as exc:  # Persist provider failures as experimental data.
            attacker_error = str(exc)
            status = "attacker_provider_failed"
        if status == "evaluated" and not prediction:
            status = "attacker_empty_prediction"
        elif status == "evaluated" and (
            not isinstance(prediction, str)
            or _CVE.fullmatch(prediction.strip()) is None
        ):
            attacker_error = "attacker prediction was not a valid CVE identifier"
            prediction = None
            status = "attacker_invalid_prediction"
        return prediction, attacker_exchange, attacker_error, status

    @staticmethod
    def _case_result(
        case: ValidationCase, result: ReplayResult
    ) -> dict[str, object]:
        return {
            "expected_alert": case.expected_alert,
            "fired": result.fired,
            "error": result.error,
            "passed": result.error is None and result.fired is case.expected_alert,
        }

    def _persisted_records(self) -> list[dict[str, object]]:
        """Return only whole records; a torn trailing line is not yet a result."""
        if not self.results_path.exists():
            return []
        records: list[dict[str, object]] = []
        for line in self.results_path.read_text(encoding="utf-8").splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(record, dict):
                records.append(record)
        return records

    def _completed_candidate_ids(self) -> set[str]:
        return {
            str(record["candidate_id"])
            for record in latest_records(self._persisted_records())
            if record.get("status") in TERMINAL_STATUSES
        }

    def require_manifest_agreement(
        self, candidates: Iterable[MutationCandidate] = ()
    ) -> None:
        """Refuse the whole batch before any evaluation or append can happen."""
        expected = self.experiment_manifest_hash
        for record in self._persisted_records():
            stored = record.get("experiment_manifest_hash")
            if stored != expected:
                raise ManifestHashMismatch(
                    f"{self.results_path} was written under manifest hash "
                    f"{stored!r}, not {expected!r}"
                )
        for candidate in candidates:
            if candidate.experiment_manifest_hash != expected:
                raise ManifestHashMismatch(
                    f"candidate {candidate.id} carries manifest hash "
                    f"{candidate.experiment_manifest_hash!r}, not {expected!r}"
                )

    def _append(self, result: MutationResult) -> None:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        serialized = json.dumps(asdict(result), sort_keys=True) + "\n"
        with self.results_path.open("a", encoding="utf-8") as handle:
            # A crash can leave a partial trailing line. Close it with its own
            # newline instead of truncating it, so the torn bytes stay auditable
            # and cannot swallow this record into one unparseable line.
            if self._has_torn_trailing_line():
                handle.write("\n")
            handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())

    def _has_torn_trailing_line(self) -> bool:
        try:
            size = self.results_path.stat().st_size
        except FileNotFoundError:
            return False
        if size == 0:
            return False
        with self.results_path.open("rb") as handle:
            handle.seek(-1, os.SEEK_END)
            return handle.read(1) != b"\n"

    def _write_summaries(self) -> None:
        records = latest_records(self._persisted_records())
        rejection_count = (
            sum(1 for line in self.rejections_path.read_text(encoding="utf-8").splitlines() if line.strip())
            if self.rejections_path.exists()
            else 0
        )
        statuses = [record.get("status") for record in records]
        summary = {
            "fixture": self.fixture.name,
            "records": len(records),
            "evaluated": statuses.count("evaluated"),
            "syntax_invalid": statuses.count("syntax_invalid"),
            "rejected": rejection_count,
            "positive_recall_failed": statuses.count("positive_recall_failed"),
            "attacker_provider_failed": statuses.count("attacker_provider_failed"),
            "attacker_parse_failed": statuses.count("attacker_parse_failed"),
            "attacker_empty_response": statuses.count("attacker_empty_response"),
            "attacker_empty_prediction": statuses.count("attacker_empty_prediction"),
            "benign_corpus_available": bool(self.benign_cases),
        }
        if self.experiment_manifest_hash is not None:
            summary["experiment_manifest_hash"] = self.experiment_manifest_hash
        self._atomic_write(
            self.output_dir / "summary.json",
            json.dumps(summary, indent=2, sort_keys=True) + "\n",
        )
        markdown = "\n".join(
            [
                "# Smart Install mutation experiment",
                "",
                f"- Fixture: `{summary['fixture']}`",
                f"- Candidate records: {summary['records']}",
                f"- Fully evaluated: {summary['evaluated']}",
                f"- Syntax-invalid: {summary['syntax_invalid']}",
                f"- Rejected specifications: {summary['rejected']}",
                f"- Positive-recall failures: {summary['positive_recall_failed']}",
                f"- Attacker provider failures: {summary['attacker_provider_failed']}",
                f"- Attacker parse failures: {summary['attacker_parse_failed']}",
                f"- Attacker empty responses: {summary['attacker_empty_response']}",
                f"- Attacker empty predictions: {summary['attacker_empty_prediction']}",
                f"- Benign corpus available: {summary['benign_corpus_available']}",
                "",
            ]
        )
        self._atomic_write(self.output_dir / "summary.md", markdown)

    @staticmethod
    def _atomic_write(path: Path, contents: str) -> None:
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(contents, encoding="utf-8")
        os.replace(temporary, path)
