"""Canonical predicate IDs and source evidence shared across game subsystems."""

from __future__ import annotations

from collections import Counter
import re
from typing import Iterable, Mapping

from hardening_game.suricata.rule_model import (
    RULE_HEADER_PATTERN,
    ParsedRule,
    RuleOption,
    Span,
)


_STATIC_ALIASES = {
    "header-source-address": ("header-src-address",),
    "header-source-port": ("header-src-port",),
    "header-destination-address": ("header-dst-address",),
    "header-destination-port": ("header-dst-port",),
}
_NESTED_OPTION_ALIAS = re.compile(
    r"^(?P<owner_type>content|buffer)-(?P<owner_index>\d+)-"
    r"(?P<kind>pcre|byte_test|bsize)-(?P<index>\d+)$"
)
_CONTENT_MODIFIER_ALIAS = re.compile(
    r"^content-(?P<owner_index>\d+)-(?P<modifier>[a-z][a-z0-9_]*)(?:-(?P<index>\d+))?$"
)
_FLOWBITS_NAMED_ACTIONS = frozenset({"set", "unset", "toggle", "isset", "isnotset"})


def _span_record(
    parsed: ParsedRule,
    *,
    kind: str,
    value: object,
    span: Span,
    option_index: int | None,
    **extra: object,
) -> dict[str, object]:
    source = parsed.source[span.start : span.end]
    return {
        "kind": kind,
        "normalized_option": normalize_evidence_text(source),
        "option_index": option_index,
        "source_span": {"start": span.start, "end": span.end},
        "value": value,
        **extra,
    }


def normalize_evidence_text(text: str) -> str:
    """Remove only whitespace outside quotes and one harmless trailing semicolon."""
    output: list[str] = []
    quoted = escaped = False
    for character in text.strip():
        if quoted and escaped:
            output.append(character)
            escaped = False
        elif quoted and character == "\\":
            output.append(character)
            escaped = True
        elif character == '"':
            output.append(character)
            quoted = not quoted
        elif not quoted and character.isspace():
            continue
        else:
            output.append(character)
    normalized = "".join(output)
    return normalized[:-1] if normalized.endswith(";") else normalized


def _flow_flag_spans(parsed: ParsedRule, option: RuleOption) -> tuple[tuple[str, Span], ...]:
    source = parsed.source
    colon = source.find(":", option.span.start, option.span.end)
    if colon < 0:
        raise ValueError(f"invalid flow option at option_index {option.option_index}")
    end = option.span.end
    while end > colon and source[end - 1] in " \t\r\n;":
        end -= 1
    flags: list[tuple[str, Span]] = []
    start = colon + 1
    for boundary in (*(
        index for index in range(start, end) if source[index] == ","
    ), end):
        flag_start = start
        flag_end = boundary
        while flag_start < flag_end and source[flag_start].isspace():
            flag_start += 1
        while flag_end > flag_start and source[flag_end - 1].isspace():
            flag_end -= 1
        if flag_start == flag_end:
            raise ValueError(f"invalid flow option at option_index {option.option_index}")
        flags.append((source[flag_start:flag_end].casefold(), Span(flag_start, flag_end)))
        start = boundary + 1
    if not flags:
        raise ValueError(f"invalid flow option at option_index {option.option_index}")
    return tuple(flags)


def _flowbits_fields(option: RuleOption) -> dict[str, object]:
    if option.value is None:
        raise ValueError(f"invalid flowbits option at option_index {option.option_index}")
    parts = [part.strip() for part in option.value.split(",")]
    action = parts[0].casefold() if parts else ""
    if action == "noalert" and len(parts) == 1:
        name: str | None = None
    elif action in _FLOWBITS_NAMED_ACTIONS and len(parts) == 2 and parts[1]:
        name = parts[1]
    else:
        raise ValueError(f"invalid flowbits option at option_index {option.option_index}")
    return {"flowbits_action": action, "flowbits_name": name}


def canonical_rule_predicates(parsed: ParsedRule) -> dict[str, dict[str, object]]:
    """Extract one canonical record per physical predicate, plus flow subpredicates."""
    predicates: dict[str, dict[str, object]] = {}
    assigned_options: set[int] = set()
    option_owners: dict[int, dict[str, str]] = {}
    header = RULE_HEADER_PATTERN.match(parsed.source)
    if header is None:
        raise ValueError("unsupported Suricata rule header")
    header_fields = (
        ("header-action", "action"),
        ("header-protocol", "protocol"),
        ("header-src-address", "src_address"),
        ("header-src-port", "src_port"),
        ("header-direction", "direction"),
        ("header-dst-address", "dst_address"),
        ("header-dst-port", "dst_port"),
    )
    for predicate_id, group_name in header_fields:
        span = Span(header.start(group_name), header.end(group_name))
        predicates[predicate_id] = _span_record(
            parsed,
            kind="header",
            value=header.group(group_name),
            span=span,
            option_index=None,
        )

    modifier_counts: Counter[tuple[str, str]] = Counter()
    for group_index, group in enumerate(parsed.sticky_groups):
        buffer_id = f"buffer-{group_index}"
        for scoped_option in group.scoped_options:
            option_owners.setdefault(scoped_option.option_index, {})[
                "owner_buffer_id"
            ] = buffer_id
        if group.declaration is not None:
            declaration = group.declaration
            assigned_options.add(declaration.option_index)
            predicates[buffer_id] = _span_record(
                parsed,
                kind="sticky_buffer",
                value=group.buffer,
                span=declaration.span,
                option_index=declaration.option_index,
            )
        for content in group.predicates:
            assigned_options.add(content.option_index)
            predicates[content.predicate_id] = _span_record(
                parsed,
                kind="content",
                value=content.value.hex() if content.value is not None else None,
                span=content.span,
                option_index=content.option_index,
                buffer=content.buffer,
                negated=content.negated,
                representation=content.representation,
                value_hex=content.value.hex() if content.value is not None else None,
            )
            for modifier in content.modifiers:
                option = next(
                    (item for item in parsed.options if item.span == modifier.span),
                    None,
                )
                if option is None:
                    raise ValueError(
                        f"modifier span has no parser option: {modifier.span}"
                    )
                assigned_options.add(option.option_index)
                key = (content.predicate_id, modifier.name)
                occurrence = modifier_counts[key]
                modifier_counts[key] += 1
                predicate_id = f"{content.predicate_id}-{modifier.name}"
                if occurrence:
                    predicate_id += f"-{occurrence}"
                predicates[predicate_id] = _span_record(
                    parsed,
                    kind="content_modifier",
                    value=modifier.value,
                    span=modifier.span,
                    option_index=option.option_index,
                    modifier_name=modifier.name,
                    modifier_occurrence=occurrence,
                    owner_content_id=content.predicate_id,
                )
            for consumer in content.relative_consumers:
                ownership = option_owners.setdefault(consumer.option_index, {})
                ownership["owner_buffer_id"] = buffer_id
                ownership["owner_content_id"] = content.predicate_id
        for constraint in group.buffer_constraints:
            option_owners.setdefault(constraint.option_index, {})[
                "owner_buffer_id"
            ] = buffer_id

    option_counts: Counter[str] = Counter()
    for option in parsed.options:
        if option.option_index in assigned_options:
            continue
        if option.name == "flow":
            assigned_options.add(option.option_index)
            for value, value_span in _flow_flag_spans(parsed, option):
                predicate_id = f"flow-{value}"
                if predicate_id in predicates:
                    raise ValueError(f"duplicate canonical predicate: {predicate_id}")
                predicates[predicate_id] = _span_record(
                    parsed,
                    kind="flow",
                    value=value,
                    span=value_span,
                    option_index=option.option_index,
                    option_span={
                        "start": option.span.start,
                        "end": option.span.end,
                    },
                )
            continue
        predicate_id = f"{option.name}-{option_counts[option.name]}"
        option_counts[option.name] += 1
        extra: dict[str, object] = dict(option_owners.get(option.option_index, {}))
        if option.name == "flowbits":
            extra.update(_flowbits_fields(option))
        predicates[predicate_id] = _span_record(
            parsed,
            kind=option.name,
            value=option.value,
            span=option.span,
            option_index=option.option_index,
            **extra,
        )

    predicates["rule-baseline"] = {
        "kind": "virtual",
        "normalized_option": None,
        "option_index": None,
        "source_span": None,
        "value": None,
    }
    return dict(sorted(predicates.items()))


def _resolve_one(
    predicate_id: str,
    *,
    known_predicate_ids: set[str],
    predicate_records: Mapping[str, Mapping[str, object]] | None,
) -> tuple[str, ...]:
    modifier = _CONTENT_MODIFIER_ALIAS.fullmatch(predicate_id)
    if modifier is not None:
        owner_id = f"content-{modifier.group('owner_index')}"
        occurrence = int(modifier.group("index") or 0)
        if predicate_id in known_predicate_ids:
            if predicate_records is not None:
                record = predicate_records[predicate_id]
                if (
                    record.get("kind") != "content_modifier"
                    or record.get("owner_content_id") != owner_id
                ):
                    raise ValueError(
                        f"nested alias owner {owner_id!r} does not own {predicate_id!r}"
                    )
            return (predicate_id,)
        candidates = (
            [
                candidate_id
                for candidate_id, record in predicate_records.items()
                if record.get("kind") == "content_modifier"
                and record.get("modifier_name") == modifier.group("modifier")
                and record.get("modifier_occurrence") == occurrence
            ]
            if predicate_records is not None
            else []
        )
        if candidates:
            raise ValueError(
                f"nested alias owner {owner_id!r} does not own modifier "
                f"{modifier.group('modifier')!r}"
            )
    if predicate_id in known_predicate_ids:
        return (predicate_id,)
    resolved = _STATIC_ALIASES.get(predicate_id)
    if resolved is None:
        nested = _NESTED_OPTION_ALIAS.fullmatch(predicate_id)
        if nested is not None:
            target_id = f"{nested.group('kind')}-{nested.group('index')}"
            if target_id not in known_predicate_ids:
                raise ValueError(
                    f"nested alias {predicate_id!r} references unknown physical "
                    f"predicate {target_id!r}"
                )
            if predicate_records is None:
                raise ValueError(
                    f"nested alias {predicate_id!r} requires ownership metadata"
                )
            owner_id = f"{nested.group('owner_type')}-{nested.group('owner_index')}"
            owner_field = f"owner_{nested.group('owner_type')}_id"
            if predicate_records[target_id].get(owner_field) != owner_id:
                raise ValueError(
                    f"nested alias owner {owner_id!r} does not own {target_id!r}"
                )
            resolved = (target_id,)
        elif predicate_id == "flow":
            resolved = tuple(
                sorted(item for item in known_predicate_ids if item.startswith("flow-"))
            )
        else:
            raise ValueError(f"unknown predicate alias: {predicate_id}")
    if not resolved or any(item not in known_predicate_ids for item in resolved):
        raise ValueError(
            f"predicate alias {predicate_id!r} does not resolve to a known predicate"
        )
    return resolved


def resolve_predicate_ids(
    predicate_ids: Iterable[str], *, known_predicate_ids: Iterable[str]
) -> tuple[str, ...]:
    """Resolve canonical and explicitly supported legacy IDs, failing closed."""
    known = set(known_predicate_ids)
    records = (
        known_predicate_ids
        if isinstance(known_predicate_ids, Mapping)
        and all(
            isinstance(key, str) and isinstance(value, Mapping)
            for key, value in known_predicate_ids.items()
        )
        else None
    )
    resolved: set[str] = set()
    for predicate_id in predicate_ids:
        if not isinstance(predicate_id, str) or not predicate_id:
            raise ValueError("invalid predicate alias")
        resolved.update(
            _resolve_one(
                predicate_id,
                known_predicate_ids=known,
                predicate_records=records,
            )
        )
    return tuple(sorted(resolved))


def canonical_touched_predicate_ids(
    metadata: Mapping[str, object], *, known_predicate_ids: Iterable[str]
) -> tuple[str, ...]:
    """Read mutation touched metadata and resolve it through the shared vocabulary."""
    singular = metadata.get("predicate_id")
    plural = metadata.get("predicate_ids")
    if singular is not None and plural is not None:
        raise ValueError("mutation metadata cannot contain both predicate_id forms")
    if singular is not None:
        raw: list[object] = [singular]
    elif plural is not None:
        if not isinstance(plural, (list, tuple)):
            raise ValueError("mutation predicate_ids must be an array")
        raw = list(plural)
    else:
        raw = []
    compensation = metadata.get("compensation")
    if compensation is not None:
        # One edit compensates a single partner constraint; a clue-targeted
        # release may free several at once, so both shapes are accepted.
        records = (
            [compensation]
            if isinstance(compensation, Mapping)
            else compensation
            if isinstance(compensation, (list, tuple))
            else None
        )
        if records is None or any(
            not isinstance(record, Mapping) for record in records
        ):
            raise ValueError(
                "mutation compensation must be an object or an array of objects"
            )
        for record in records:
            compensation_predicate = record.get("predicate_id")
            if compensation_predicate is not None:
                raw.append(compensation_predicate)
    if not raw:
        return ()
    if any(not isinstance(item, str) for item in raw):
        raise ValueError("mutation touched predicate IDs must be strings")
    return resolve_predicate_ids(
        (item for item in raw if isinstance(item, str)),
        known_predicate_ids=known_predicate_ids,
    )


def predicate_ids_for_option(
    parsed: ParsedRule, option_index: int
) -> tuple[str, ...]:
    """Return canonical IDs represented by one parser option index."""
    predicates = canonical_rule_predicates(parsed)
    matched = tuple(
        predicate_id
        for predicate_id, record in predicates.items()
        if record.get("option_index") == option_index
    )
    if not matched:
        raise ValueError(f"option index {option_index} has no canonical predicate")
    return matched


def predicate_spans(
    predicates: Mapping[str, Mapping[str, object]],
) -> tuple[tuple[str, int, int], ...]:
    """Return validated mappable predicate spans from a serialized packet."""
    spans: list[tuple[str, int, int]] = []
    for predicate_id, record in predicates.items():
        raw_span = record.get("source_span")
        if raw_span is None:
            continue
        if (
            not isinstance(raw_span, dict)
            or not isinstance(raw_span.get("start"), int)
            or not isinstance(raw_span.get("end"), int)
            or raw_span["start"] >= raw_span["end"]
        ):
            raise ValueError(f"invalid source span for predicate {predicate_id}")
        spans.append((predicate_id, raw_span["start"], raw_span["end"]))
    return tuple(spans)


def predicate_coverage_spans(
    predicates: Mapping[str, Mapping[str, object]],
) -> tuple[tuple[int, int], ...]:
    """Return source areas whose syntax may surround exact predicate values."""
    spans = {(start, end) for _predicate_id, start, end in predicate_spans(predicates)}
    for predicate_id, record in predicates.items():
        raw_span = record.get("option_span")
        if raw_span is None:
            continue
        if (
            not isinstance(raw_span, dict)
            or not isinstance(raw_span.get("start"), int)
            or not isinstance(raw_span.get("end"), int)
            or raw_span["start"] >= raw_span["end"]
        ):
            raise ValueError(f"invalid option span for predicate {predicate_id}")
        spans.add((raw_span["start"], raw_span["end"]))
    return tuple(sorted(spans))
