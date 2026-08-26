"""Strict, hash-stable baseline clue registry."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Mapping


_SUPPORTED_VERSION = 1
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]*$")
# Parser/suite predicate IDs are lowercase symbolic segments separated by
# hyphens. Segments may contain digits and underscores (for example
# ``content-1-fast_pattern``, ``flow-to_server``, and ``byte_test-0``).
# Excluding dots, slashes, colons, whitespace, and leading hyphens keeps these
# identifiers distinct from paths, snippets, and free-form option syntax.
_PREDICATE_ID_RE = re.compile(r"^[a-z][a-z0-9_]*(?:-[a-z0-9_]+)*$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_TOP_LEVEL_FIELDS = {"version", "rules"}
_RULE_FIELDS = {"rule_id", "target_cve", "clues"}
_CLUE_FIELDS = {
    "clue_id",
    "rank",
    "description",
    "rationale",
    "provenance",
    "predicate_ids",
    "targetable",
}


@dataclass(frozen=True)
class BaselineClue:
    clue_id: str
    rank: int | None
    description: str
    rationale: str
    provenance: str
    predicate_ids: tuple[str, ...]
    targetable: bool


@dataclass(frozen=True)
class BaselineRuleClues:
    rule_id: str
    target_cve: str
    clues: tuple[BaselineClue, ...]


@dataclass(frozen=True)
class BaselineClueRegistry:
    version: int
    rules: tuple[BaselineRuleClues, ...]


def _object(value: object, *, field: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object")
    return value


def _exact_fields(
    value: Mapping[str, object], expected: set[str], *, field: str
) -> None:
    if set(value) != expected:
        raise ValueError(f"{field} must contain exactly: {', '.join(sorted(expected))}")


def _text(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value.strip()


def _identifier(value: object, *, field: str) -> str:
    text = _text(value, field=field)
    if not _ID_RE.fullmatch(text):
        raise ValueError(f"invalid {field}: {text!r}")
    return text


def _parse_clue(value: object) -> BaselineClue:
    record = _object(value, field="clue")
    _exact_fields(record, _CLUE_FIELDS, field="clue")
    clue_id = _identifier(record["clue_id"], field="clue_id")
    rank = record["rank"]
    if rank is not None and (
        isinstance(rank, bool) or not isinstance(rank, int) or rank not in {1, 2, 3}
    ):
        raise ValueError("rank must be 1, 2, 3, or null")
    raw_predicates = record["predicate_ids"]
    if (
        not isinstance(raw_predicates, list)
        or not raw_predicates
        or any(
            not isinstance(item, str) or not _PREDICATE_ID_RE.fullmatch(item)
            for item in raw_predicates
        )
    ):
        raise ValueError(
            "predicate_ids must be a non-empty array of valid predicate IDs; "
            "invalid predicate_id"
        )
    predicates = tuple(raw_predicates)
    if len(set(predicates)) != len(predicates):
        raise ValueError(f"duplicate predicate_id in clue {clue_id!r}")
    targetable = record["targetable"]
    if not isinstance(targetable, bool):
        raise ValueError("targetable must be a boolean")
    return BaselineClue(
        clue_id=clue_id,
        rank=rank,
        description=_text(record["description"], field="description"),
        rationale=_text(record["rationale"], field="rationale"),
        provenance=_text(record["provenance"], field="provenance"),
        predicate_ids=predicates,
        targetable=targetable,
    )


def _parse_rule(value: object) -> BaselineRuleClues:
    record = _object(value, field="rule")
    _exact_fields(record, _RULE_FIELDS, field="rule")
    rule_id = _identifier(record["rule_id"], field="rule_id")
    target_cve = _text(record["target_cve"], field="target_cve")
    if not _CVE_RE.fullmatch(target_cve):
        raise ValueError(f"malformed target_cve: {target_cve!r}")
    raw_clues = record["clues"]
    if not isinstance(raw_clues, list):
        raise ValueError("clues must be an array")
    clues = tuple(_parse_clue(clue) for clue in raw_clues)
    seen: set[str] = set()
    for clue in clues:
        if clue.clue_id in seen:
            raise ValueError(f"duplicate clue_id: {clue.clue_id}")
        seen.add(clue.clue_id)
    return BaselineRuleClues(rule_id=rule_id, target_cve=target_cve, clues=clues)


def load_baseline_clue_registry(path: Path) -> BaselineClueRegistry:
    """Load a strict versioned registry; incomplete rules remain valid drafts."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError(f"{path} is not valid JSON: {error}") from error
    record = _object(data, field="clue registry")
    _exact_fields(record, _TOP_LEVEL_FIELDS, field="clue registry")
    version = record["version"]
    if isinstance(version, bool) or version != _SUPPORTED_VERSION:
        raise ValueError(f"unsupported clue registry version: {version!r}")
    raw_rules = record["rules"]
    if not isinstance(raw_rules, list):
        raise ValueError("rules must be an array")
    rules = tuple(_parse_rule(rule) for rule in raw_rules)
    rule_ids: set[str] = set()
    clue_ids: set[str] = set()
    for rule in rules:
        if rule.rule_id in rule_ids:
            raise ValueError(f"duplicate rule_id: {rule.rule_id}")
        rule_ids.add(rule.rule_id)
        for clue in rule.clues:
            if clue.clue_id in clue_ids:
                raise ValueError(f"duplicate clue_id: {clue.clue_id}")
            clue_ids.add(clue.clue_id)
    return BaselineClueRegistry(version=version, rules=rules)


def validate_completed_rule(rule: BaselineRuleClues) -> None:
    """Apply the stricter invariant used once a rule's review is complete."""
    ranks = [clue.rank for clue in rule.clues if clue.rank is not None]
    if sorted(ranks) != [1, 2, 3]:
        raise ValueError(
            "completed rule must contain exactly one clue at each major rank 1, 2, and 3"
        )


def registry_sha256(registry: BaselineClueRegistry) -> str:
    """Hash canonical registry content, independent of JSON whitespace."""
    canonical = json.dumps(
        asdict(registry),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()
