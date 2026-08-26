"""Dependency-safe composition of baseline-relative single-mutation blocks.

Every combined rule is built by applying edits derived from the *baseline* rule,
never by mutating an already-mutated rule.  Edits are snapped to parser-derived
option spans so that two blocks touching the same option always collide, and any
edit whose attribution to a rule option is not unique is rejected instead of
guessed.

Span attribution is deliberately conservative, so a rejection does not imply that
two mutations are semantically incompatible.  The locked `et-2057330` pairing of
`content-retain_alternating` with `content_modifier-remove_fast_pattern` is the
worked example: `retain_alternating` splits one content into fragments that are
emitted *after* the unchanged `fast_pattern;` option, and `difflib` reports the
new text as an insertion at an offset inside that unchanged option.  Neither the
text nor the meaning of `fast_pattern;` changes - the replacement reproduces it
verbatim - but no contiguous option-aligned span can exclude it, so the two
blocks collide and the subset is rejected rather than guessed.

`structural_preflight` checks rule structure only.  It deliberately does not
model buffer-scoped semantics: a surviving `bsize` whose buffer no longer holds
any content is structurally valid here and is left for Task 5 replay to measure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from difflib import SequenceMatcher
from itertools import combinations
import hashlib
import json
from pathlib import Path
import re
from typing import Mapping, Sequence

from hardening_game.mutations.combination_manifest import (
    CombinationManifest,
    manifest_hash,
)
from hardening_game.mutations.engine import canonical_fingerprint
from hardening_game.mutations.families import apply_edits
from hardening_game.mutations.taxonomy import classify_mutation_category
from hardening_game.suricata.rule_model import (
    CONTENT_MODIFIERS,
    CONTENT_OPTION,
    ParsedRule,
    decode_content,
    is_relative_consumer,
    parse_suricata_rule,
)


MIN_COMBINATION_BLOCKS = 2
MAX_COMBINATION_BLOCKS = 8

_REVISION = re.compile(r"\brev\s*:\s*\d+\s*;", re.IGNORECASE)
_NORMALIZED_REVISION = 0
_ESCAPE = re.compile(r"\\.", re.DOTALL)
_DETECTION_OPTIONS = frozenset({"content", "pcre", "byte_test", "byte_jump"})
_PREFLIGHT_CHECKS = (
    "rule_parses",
    "quotes_balanced",
    "options_terminated",
    "sid_present_once",
    "revision_present_once",
    "sid_preserved",
    "content_values_valid",
    "modifiers_bound_to_content",
    "relative_options_bound_to_content",
    "detection_predicate_present",
)


class CombinationConflict(Exception):
    """A subset of mutation blocks cannot be combined safely."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class OptionEdit:
    """One baseline-relative replacement aligned to whole rule-option spans."""

    start: int
    end: int
    replacement: str


@dataclass(frozen=True)
class CombinationBlock:
    """One evaluated single-mutation candidate used as a combination block."""

    candidate_id: str
    component: str
    operator: str
    description: str
    rule: str
    params: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class CombinationCandidate:
    id: str
    fixture_name: str
    source_candidate_ids: tuple[str, ...]
    block_count: int
    experiment_manifest_hash: str
    component: str
    operator: str
    params: dict[str, object]
    description: str
    rule: str
    revision: int
    fingerprint: str
    preflight_checks: tuple[str, ...]


@dataclass(frozen=True)
class CombinationRejection:
    id: str
    fixture_name: str
    source_candidate_ids: tuple[str, ...]
    block_count: int
    experiment_manifest_hash: str
    reason: str
    diagnostic: str


@dataclass(frozen=True)
class CombinationSet:
    fixture_name: str
    experiment_manifest_hash: str
    accepted: tuple[CombinationCandidate, ...]
    rejected: tuple[CombinationRejection, ...]


@dataclass(frozen=True)
class FixtureSources:
    fixture_name: str
    baseline_candidate_id: str
    baseline_rule: str
    baseline_revision: int
    blocks: tuple[CombinationBlock, ...]
    # Measured once in the locked source run; carried forward so a combination
    # run never has to spend another attacker call to re-establish it.
    baseline_attacker_prediction: str | None = None
    baseline_attacker_correct: bool | None = None


@dataclass(frozen=True)
class PreflightResult:
    passed: bool
    checks: tuple[str, ...]
    failures: tuple[str, ...]


def normalize_revision(rule: str) -> str:
    """Return the rule with its revision fixed so diffs ignore revision drift."""
    if not _REVISION.search(rule):
        raise ValueError("combination composition requires a rule revision")
    return _REVISION.sub(f"rev:{_NORMALIZED_REVISION};", rule, count=1)


def set_revision(rule: str, revision: int) -> str:
    """Set the single deterministic revision carried by a combined rule."""
    if type(revision) is not int or revision < 0:
        raise ValueError("revision must be a non-negative integer")
    if not _REVISION.search(rule):
        raise ValueError("combination composition requires a rule revision")
    return _REVISION.sub(f"rev:{revision};", rule, count=1)


def region_boundaries(rule: str) -> tuple[int, ...]:
    """Return parser-derived offsets that delimit independently editable spans."""
    parsed = parse_suricata_rule(rule)
    opening = rule.find("(")
    marks = {0, len(rule), opening + 1}
    marks.add(parsed.header.destination_port_span.start)
    marks.add(parsed.header.destination_port_span.end)
    for option in parsed.options:
        marks.add(option.span.start)
        marks.add(option.span.end)
    return tuple(sorted(marks))


def _common_prefix(left: str, right: str) -> int:
    limit = min(len(left), len(right))
    index = 0
    while index < limit and left[index] == right[index]:
        index += 1
    return index


def _common_suffix(left: str, right: str) -> int:
    limit = min(len(left), len(right))
    index = 0
    while index < limit and left[-1 - index] == right[-1 - index]:
        index += 1
    return index


def _unique_minimal_edit(
    baseline: str,
    candidate: str,
    marks: Sequence[int],
    window: tuple[int, int],
    candidate_window: tuple[int, int],
) -> OptionEdit:
    """Return the one smallest option-aligned edit explaining a window.

    Every candidate attribution is enumerated over parser boundaries.  When more
    than one smallest attribution reproduces the same text - which happens when a
    rule repeats an option verbatim - the edit is ambiguous and is rejected.
    Replacing the whole window is always a valid attribution, so the enumeration
    can never come back empty; `derive_edits` is what decides whether the
    smallest attribution is localized enough to compose with.
    """
    low, high = window
    candidate_low, candidate_high = candidate_window
    baseline_segment = baseline[low:high]
    candidate_segment = candidate[candidate_low:candidate_high]
    prefix = _common_prefix(baseline_segment, candidate_segment)
    suffix = _common_suffix(baseline_segment, candidate_segment)
    inner = [mark for mark in marks if low <= mark <= high]

    attributions: list[tuple[int, int]] = []
    for start in inner:
        if start - low > prefix:
            continue
        for end in inner:
            if end < start or high - end > suffix:
                continue
            replacement_length = (
                (candidate_high - candidate_low) - (start - low) - (high - end)
            )
            if replacement_length >= 0:
                attributions.append((start, end))
    smallest = min(end - start for start, end in attributions)
    minimal = [span for span in attributions if span[1] - span[0] == smallest]
    if len(minimal) > 1:
        spans = ", ".join(f"[{start}:{end}]" for start, end in minimal)
        raise CombinationConflict(
            "ambiguous_edit",
            f"repeated rule text allows {len(minimal)} equivalent edits: {spans}",
        )
    start, end = minimal[0]
    return OptionEdit(
        start,
        end,
        candidate[candidate_low + (start - low) : candidate_high - (high - end)],
    )


def _changed_windows(
    baseline: str, candidate: str, marks: Sequence[int]
) -> tuple[tuple[int, int], ...]:
    """Snap character-level opcodes onto option spans and merge touching runs."""
    opcodes = SequenceMatcher(a=baseline, b=candidate, autojunk=False).get_opcodes()
    windows: list[tuple[int, int]] = []
    for tag, start, end, _, _ in opcodes:
        if tag == "equal":
            continue
        if start == end and start in marks:
            low = max((mark for mark in marks if mark < start), default=0)
            high = min((mark for mark in marks if mark > start), default=len(baseline))
        else:
            low = max(mark for mark in marks if mark <= start)
            high = min(mark for mark in marks if mark >= end)
        if windows and low <= windows[-1][1]:
            windows[-1] = (windows[-1][0], max(windows[-1][1], high))
        else:
            windows.append((low, high))
    return tuple(windows)


def _multi_window_edits(
    baseline: str,
    candidate: str,
    marks: Sequence[int],
    windows: Sequence[tuple[int, int]],
) -> tuple[OptionEdit, ...]:
    """Locate each unchanged gap once, then solve every window independently."""
    head = windows[0][0]
    tail = len(baseline) - windows[-1][1]
    if baseline[:head] != candidate[:head] or (
        tail and baseline[-tail:] != candidate[-tail:]
    ):
        raise CombinationConflict(
            "underivable_edit", "candidate does not preserve unchanged rule text"
        )
    limit = len(candidate) - tail
    cursor = head
    gaps: list[tuple[int, int]] = []
    for index in range(len(windows) - 1):
        segment = baseline[windows[index][1] : windows[index + 1][0]]
        found = candidate.find(segment, cursor, limit)
        if found < 0:
            raise CombinationConflict(
                "underivable_edit", "unchanged rule text is missing from the candidate"
            )
        if candidate.find(segment, found + 1, limit) >= 0:
            raise CombinationConflict(
                "ambiguous_edit",
                "repeated rule text allows more than one window alignment",
            )
        gaps.append((found, found + len(segment)))
        cursor = found + len(segment)

    edits: list[OptionEdit] = []
    for index, window in enumerate(windows):
        candidate_low = head if index == 0 else gaps[index - 1][1]
        candidate_high = limit if index == len(windows) - 1 else gaps[index][0]
        edits.append(
            _unique_minimal_edit(
                baseline, candidate, marks, window, (candidate_low, candidate_high)
            )
        )
    return tuple(edits)


def apply_option_edits(baseline: str, edits: Sequence[OptionEdit]) -> str:
    """Apply option-aligned edits from the highest baseline offset downwards."""
    return apply_edits(
        baseline, [(edit.start, edit.end, edit.replacement) for edit in edits]
    )


def verify_edits(
    baseline_rule: str, candidate_rule: str, edits: Sequence[OptionEdit]
) -> None:
    """Raise unless the edits rebuild the candidate from the baseline exactly.

    This is the postcondition every derivation must satisfy before its edits are
    allowed to take part in composition.  `derive_edits` enforces it on its own
    output, and callers that build edits by other means should enforce it too.
    """
    if apply_option_edits(
        normalize_revision(baseline_rule), edits
    ) != normalize_revision(candidate_rule):
        raise CombinationConflict(
            "underivable_edit", "edits do not reproduce the candidate rule"
        )


def derive_edits(baseline_rule: str, candidate_rule: str) -> tuple[OptionEdit, ...]:
    """Derive option-aligned edits that turn the baseline into one candidate."""
    baseline = normalize_revision(baseline_rule)
    candidate = normalize_revision(candidate_rule)
    if baseline == candidate:
        raise CombinationConflict(
            "no_effect", "candidate rule is identical to the baseline rule"
        )
    marks = region_boundaries(baseline)
    windows = _changed_windows(baseline, candidate, marks)
    if len(windows) <= 1:
        edits = (
            _unique_minimal_edit(
                baseline,
                candidate,
                marks,
                (0, len(baseline)),
                (0, len(candidate)),
            ),
        )
    else:
        edits = _multi_window_edits(baseline, candidate, marks, windows)
    verify_edits(baseline_rule, candidate_rule, edits)
    return edits


def _require_block_count(blocks: Sequence[CombinationBlock]) -> None:
    if not MIN_COMBINATION_BLOCKS <= len(blocks) <= MAX_COMBINATION_BLOCKS:
        raise CombinationConflict(
            "block_count",
            f"combinations need {MIN_COMBINATION_BLOCKS} through "
            f"{MAX_COMBINATION_BLOCKS} blocks, received {len(blocks)}",
        )


def _owned_edits(
    baseline_rule: str, blocks: Sequence[CombinationBlock]
) -> list[tuple[OptionEdit, str]]:
    owned: list[tuple[OptionEdit, str]] = []
    seen: set[str] = set()
    for block in blocks:
        if block.candidate_id in seen:
            raise CombinationConflict(
                "duplicate_block", f"block repeated in subset: {block.candidate_id}"
            )
        seen.add(block.candidate_id)
        for edit in derive_edits(baseline_rule, block.rule):
            owned.append((edit, block.candidate_id))
    return owned


def _require_compatible(
    owned: Sequence[tuple[OptionEdit, str]]
) -> tuple[OptionEdit, ...]:
    ordered = sorted(
        owned, key=lambda item: (item[0].start, item[0].end, item[0].replacement, item[1])
    )
    for index, (edit, owner) in enumerate(ordered):
        for other, other_owner in ordered[index + 1 :]:
            if owner == other_owner or edit == other:
                continue
            if edit.start == edit.end or other.start == other.end:
                if other.start <= edit.end and edit.start <= other.end:
                    raise CombinationConflict(
                        "competing_insertion",
                        f"{owner} and {other_owner} both edit offset "
                        f"{max(edit.start, other.start)}",
                    )
                continue
            if edit.start == other.start and edit.end == other.end:
                raise CombinationConflict(
                    "competing_edit",
                    f"{owner} and {other_owner} replace baseline span "
                    f"[{edit.start}:{edit.end}] differently",
                )
            if other.start < edit.end and edit.start < other.end:
                raise CombinationConflict(
                    "overlapping_edit",
                    f"{owner} span [{edit.start}:{edit.end}] overlaps "
                    f"{other_owner} span [{other.start}:{other.end}]",
                )
    unique: dict[tuple[int, int, str], OptionEdit] = {}
    for edit, _ in ordered:
        unique[(edit.start, edit.end, edit.replacement)] = edit
    return tuple(unique[key] for key in sorted(unique))


def compose_rule(
    baseline_rule: str, blocks: Sequence[CombinationBlock], *, revision: int
) -> str:
    """Compose one baseline-relative, order-independent multi-block rule."""
    blocks = tuple(blocks)
    _require_block_count(blocks)
    edits = _require_compatible(_owned_edits(baseline_rule, blocks))
    composed = apply_option_edits(normalize_revision(baseline_rule), edits)
    return set_revision(composed, revision)


def _relative_option_indexes(parsed: ParsedRule) -> set[int]:
    return {
        consumer.option_index
        for group in parsed.sticky_groups
        for predicate in group.predicates
        for consumer in predicate.relative_consumers
    }


def _content_value_failures(rule: str, parsed: ParsedRule) -> bool:
    """Return whether any content option is structurally unusable.

    Hex-block validity is delegated to the parser's decoder so there is one
    definition of a decodable content value.  The parser refuses to decode
    escaped values at all (`representation="mixed"`, `value=None`), but escapes
    are legal Suricata syntax, so escape sequences are removed before decoding
    and only the surrounding structure is checked.  Unbalanced `|` delimiters
    are also rejected here; the decoder treats a lone pipe as literal text.
    """
    for option in parsed.options:
        if option.name != "content":
            continue
        match = CONTENT_OPTION.fullmatch(rule[option.span.start : option.span.end])
        if match is None:
            return True
        value = match.group("value")
        if not value:
            return True
        unescaped = _ESCAPE.sub("", value)
        if len(unescaped.split("|")) % 2 == 0:
            return True
        if decode_content(unescaped)[0] is None:
            return True
    return False


def structural_preflight(rule: str, *, expected_sid: str | None = None) -> PreflightResult:
    """Check a composed rule for structural defects without invoking Suricata."""
    try:
        parsed = parse_suricata_rule(rule)
    except ValueError:
        return PreflightResult(
            passed=False, checks=_PREFLIGHT_CHECKS, failures=("rule_parses",)
        )

    failures: list[str] = []
    if (rule.count('"') - rule.count('\\"')) % 2:
        failures.append("quotes_balanced")

    closing = rule.rfind(")")
    last_option_end = parsed.options[-1].span.end if parsed.options else -1
    if not parsed.options or rule[last_option_end:closing].strip():
        failures.append("options_terminated")

    names = [option.name for option in parsed.options]
    if names.count("sid") != 1:
        failures.append("sid_present_once")
    if names.count("rev") != 1:
        failures.append("revision_present_once")
    if expected_sid is not None:
        sids = [
            option.value for option in parsed.options if option.name == "sid"
        ]
        if sids != [expected_sid]:
            failures.append("sid_preserved")
    if _content_value_failures(rule, parsed):
        failures.append("content_values_valid")
    if any(option.name in CONTENT_MODIFIERS for option in parsed.other_options):
        failures.append("modifiers_bound_to_content")

    attached = _relative_option_indexes(parsed)
    if any(
        is_relative_consumer(option) and option.option_index not in attached
        for option in parsed.options
    ):
        failures.append("relative_options_bound_to_content")
    if not any(name in _DETECTION_OPTIONS for name in names):
        failures.append("detection_predicate_present")
    return PreflightResult(
        passed=not failures, checks=_PREFLIGHT_CHECKS, failures=tuple(failures)
    )


def _combination_digest(fixture_name: str, source_candidate_ids: Sequence[str]) -> str:
    identity = json.dumps(
        {
            "fixture_name": fixture_name,
            "source_candidate_ids": list(source_candidate_ids),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(identity.encode()).hexdigest()[:12]


def combination_candidate_id(
    fixture_name: str, source_candidate_ids: Sequence[str]
) -> str:
    """Return the stable ID for one ordered set of source candidate IDs."""
    return (
        f"{fixture_name}-combination-{len(source_candidate_ids)}-"
        f"{_combination_digest(fixture_name, source_candidate_ids)}"
    )


def combination_rejection_id(
    fixture_name: str, source_candidate_ids: Sequence[str]
) -> str:
    """Return the stable ID for one rejected set of source candidate IDs."""
    return (
        f"{fixture_name}-combination-rejected-{len(source_candidate_ids)}-"
        f"{_combination_digest(fixture_name, source_candidate_ids)}"
    )


def _ordered_source_ids(blocks: Sequence[CombinationBlock]) -> tuple[str, ...]:
    return tuple(sorted(block.candidate_id for block in blocks))


def combination_rejection(
    blocks: Sequence[CombinationBlock],
    conflict: CombinationConflict,
    *,
    fixture_name: str,
    experiment_manifest_hash: str,
) -> CombinationRejection:
    """Record one conflicting subset so it is never evaluated."""
    source_candidate_ids = _ordered_source_ids(blocks)
    return CombinationRejection(
        id=combination_rejection_id(fixture_name, source_candidate_ids),
        fixture_name=fixture_name,
        source_candidate_ids=source_candidate_ids,
        block_count=len(source_candidate_ids),
        experiment_manifest_hash=experiment_manifest_hash,
        reason=conflict.reason,
        diagnostic=conflict.detail,
    )


def compose_combination(
    baseline_rule: str,
    blocks: Sequence[CombinationBlock],
    *,
    fixture_name: str,
    revision: int,
    experiment_manifest_hash: str,
    known_fingerprints: Mapping[str, str] | None = None,
) -> CombinationCandidate:
    """Compose, validate, and identify one dependency-safe combination."""
    blocks = tuple(blocks)
    rule = compose_rule(baseline_rule, blocks, revision=revision)
    parsed_baseline = parse_suricata_rule(baseline_rule)
    expected_sid = next(
        (
            option.value
            for option in parsed_baseline.options
            if option.name == "sid" and option.value
        ),
        None,
    )
    preflight = structural_preflight(rule, expected_sid=expected_sid)
    if not preflight.passed:
        raise CombinationConflict(
            "preflight_failed",
            "structural preflight failed: " + ", ".join(preflight.failures),
        )
    fingerprint = canonical_fingerprint(rule)
    owner = (known_fingerprints or {}).get(fingerprint)
    if owner is not None:
        raise CombinationConflict(
            "duplicate_fingerprint", f"rule fingerprint already produced by {owner}"
        )

    source_candidate_ids = _ordered_source_ids(blocks)
    by_id = {block.candidate_id: block for block in blocks}
    ordered = [by_id[candidate_id] for candidate_id in source_candidate_ids]
    return CombinationCandidate(
        id=combination_candidate_id(fixture_name, source_candidate_ids),
        fixture_name=fixture_name,
        source_candidate_ids=source_candidate_ids,
        block_count=len(source_candidate_ids),
        experiment_manifest_hash=experiment_manifest_hash,
        component="combination",
        operator=f"blocks_{len(source_candidate_ids)}",
        params={
            "source_candidate_ids": list(source_candidate_ids),
            "components": [block.component for block in ordered],
            "operators": [block.operator for block in ordered],
            "source_categories": [
                classify_mutation_category(
                    component=block.component,
                    operator=block.operator,
                    params=dict(block.params),
                )
                for block in ordered
            ],
        },
        description=(
            f"Combine {len(source_candidate_ids)} baseline-relative mutations: "
            + ", ".join(f"{block.component}/{block.operator}" for block in ordered)
        ),
        rule=rule,
        revision=revision,
        fingerprint=fingerprint,
        preflight_checks=preflight.checks,
    )


def load_fixture_sources(
    fixture_name: str,
    *,
    manifest: CombinationManifest,
    project_root: str | Path,
) -> FixtureSources:
    """Load the exact baseline and locked source candidates for one fixture."""
    results_path = (
        Path(project_root) / manifest.source_run / fixture_name / "results.jsonl"
    )
    records: dict[str, Mapping[str, object]] = {}
    for line in results_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        candidate_id = record.get("candidate_id")
        if isinstance(candidate_id, str):
            records[candidate_id] = record

    baseline_id = f"{fixture_name}-baseline"
    baseline = records.get(baseline_id)
    if baseline is None or not isinstance(baseline.get("rule"), str):
        raise ValueError(f"baseline record is missing from {results_path}")
    revision = baseline.get("revision")
    if type(revision) is not int:
        raise ValueError(f"baseline revision is missing from {results_path}")

    blocks: list[CombinationBlock] = []
    for candidate_id in manifest.selected_blocks(fixture_name):
        record = records.get(candidate_id)
        if record is None or not isinstance(record.get("rule"), str):
            raise ValueError(f"selected block is missing a rule: {candidate_id}")
        blocks.append(
            CombinationBlock(
                candidate_id=candidate_id,
                component=str(record.get("component", "")),
                operator=str(record.get("operator", "")),
                description=str(record.get("description", "")),
                rule=str(record["rule"]),
                params=dict(record.get("params") or {}),
            )
        )
    prediction = baseline.get("attacker_prediction")
    correct = baseline.get("attacker_correct")
    return FixtureSources(
        fixture_name=fixture_name,
        baseline_candidate_id=baseline_id,
        baseline_rule=str(baseline["rule"]),
        baseline_revision=revision,
        blocks=tuple(blocks),
        baseline_attacker_prediction=(
            prediction if isinstance(prediction, str) else None
        ),
        baseline_attacker_correct=correct if isinstance(correct, bool) else None,
    )


def generate_combinations(
    sources: FixtureSources,
    *,
    experiment_manifest_hash: str,
    revision: int | None = None,
    max_blocks: int = MAX_COMBINATION_BLOCKS,
) -> CombinationSet:
    """Generate every conflict-free subset and persist conflicts as rejections."""
    if type(max_blocks) is not int or not 1 <= max_blocks <= MAX_COMBINATION_BLOCKS:
        raise ValueError(
            f"max_blocks must be an integer from 1 through {MAX_COMBINATION_BLOCKS}"
        )
    blocks = sources.blocks
    combined_revision = (
        sources.baseline_revision + 1 if revision is None else revision
    )
    known_fingerprints: dict[str, str] = {
        canonical_fingerprint(sources.baseline_rule): sources.baseline_candidate_id
    }
    for block in blocks:
        known_fingerprints.setdefault(
            canonical_fingerprint(block.rule), block.candidate_id
        )

    accepted: list[CombinationCandidate] = []
    rejected: list[CombinationRejection] = []
    for size in range(MIN_COMBINATION_BLOCKS, min(len(blocks), max_blocks) + 1):
        for subset in combinations(blocks, size):
            try:
                candidate = compose_combination(
                    sources.baseline_rule,
                    subset,
                    fixture_name=sources.fixture_name,
                    revision=combined_revision,
                    experiment_manifest_hash=experiment_manifest_hash,
                    known_fingerprints=known_fingerprints,
                )
            except CombinationConflict as conflict:
                rejected.append(
                    combination_rejection(
                        subset,
                        conflict,
                        fixture_name=sources.fixture_name,
                        experiment_manifest_hash=experiment_manifest_hash,
                    )
                )
            else:
                known_fingerprints[candidate.fingerprint] = candidate.id
                accepted.append(candidate)
    return CombinationSet(
        fixture_name=sources.fixture_name,
        experiment_manifest_hash=experiment_manifest_hash,
        accepted=tuple(accepted),
        rejected=tuple(rejected),
    )


def generate_fixture_combinations(
    fixture_name: str,
    *,
    manifest: CombinationManifest,
    project_root: str | Path,
    revision: int | None = None,
) -> CombinationSet:
    """Generate one fixture's combinations directly from the locked manifest."""
    sources = load_fixture_sources(
        fixture_name, manifest=manifest, project_root=project_root
    )
    return generate_combinations(
        sources,
        experiment_manifest_hash=manifest_hash(manifest),
        revision=revision,
        max_blocks=manifest.selection.max_blocks,
    )


def generate_manifest_combinations(
    *,
    manifest: CombinationManifest,
    project_root: str | Path,
    revision: int | None = None,
) -> tuple[CombinationSet, ...]:
    """Generate combinations for every fixture the locked manifest names."""
    fixtures = (
        *manifest.primary_fixtures,
        *(control.name for control in manifest.control_fixtures),
    )
    return tuple(
        generate_fixture_combinations(
            fixture,
            manifest=manifest,
            project_root=project_root,
            revision=revision,
        )
        for fixture in fixtures
    )
