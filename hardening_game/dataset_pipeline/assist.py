"""Guided completion for rules the automatic synthesizer refuses.

A rule whose real match condition is a `pcre` or a `byte_test` needs a human to
decide what bytes satisfy it - that is a judgement about the regex or the
encoding, not something to guess. But everything *else* about the traffic is
still mechanically derivable, so the user should not have to hand-build a whole
PCAP for it.

`explain_rule` prints exactly what is already determined and what is missing.
`complete_manual_pcap` takes the one piece the user supplies, splices it into
the derived skeleton, and immediately replays the result through real Suricata
so a wrong guess comes back as a specific failure rather than silence.
"""

from __future__ import annotations

from pathlib import Path

from hardening_game.dataset_pipeline.auto_suite import (
    AutoSuiteResult,
    UnsupportedRule,
    blocking_options,
    build_cases,
    plan_traffic,
    validate_cases,
)
from hardening_game.dataset_pipeline.manifest import DatasetRecord, dataset_root
from hardening_game.suricata.rule_model import ParsedRule, parse_suricata_rule


_BYTE_TEST_OPERATORS = {
    "<": "less than",
    ">": "greater than",
    "=": "equal to",
    "<=": "at most",
    ">=": "at least",
    "!=": "not equal to",
    "&": "bitwise-AND non-zero against",
    "^": "bitwise-XOR non-zero against",
}


def _preview(value: bytes) -> str:
    printable = "".join(
        chr(byte) if 32 <= byte < 127 else "." for byte in value
    )
    return f"{printable!r} ({value.hex(' ')})"


def describe_byte_test(value: str) -> str:
    """Translate `4,>,16,9,relative,little` into a sentence, when it parses."""
    parts = [part.strip() for part in value.split(",")]
    if len(parts) < 4:
        return f"byte_test:{value}"
    count, operator, compare, offset = parts[0], parts[1], parts[2], parts[3]
    flags = {part for part in parts[4:]}
    endian = "little-endian" if "little" in flags else "big-endian"
    anchor = (
        "after the end of the previous match"
        if "relative" in flags
        else "from the start of the buffer"
    )
    readable = _BYTE_TEST_OPERATORS.get(operator, operator)
    return (
        f"the {count} bytes at offset {offset} {anchor} must decode as a "
        f"{endian} integer {readable} {compare}"
    )


def describe_pcre(value: str) -> str:
    relative = "/R" in value.rsplit("/", 1)[-1] if value.count("/") >= 2 else False
    where = (
        "starting where the previous content match ended"
        if relative
        else "anywhere in the buffer"
    )
    return f"the buffer must match the regex {value} {where}"


def blocking_predicate_anchor(parsed: ParsedRule) -> tuple[str, str] | None:
    """Return (buffer, predicate_id) the unsatisfiable option is anchored to."""
    for group in parsed.sticky_groups:
        for predicate in group.predicates:
            for consumer in predicate.relative_consumers:
                if consumer.name in {"pcre", "byte_test", "byte_jump", "isdataat"}:
                    return group.buffer, predicate.predicate_id
    return None


def explain_rule(record: DatasetRecord, *, dataset_id: str = "<dataset-id>") -> str:
    """A plain-language account of what is derived and what the user must supply."""
    parsed = parse_suricata_rule(record.rule)
    lines = [
        f"{record.name} - {record.cve}",
        f"  rule: {record.rule}",
        "",
        "Already determined automatically:",
        f"  protocol {parsed.header.protocol}, destination port "
        f"{parsed.header.destination_port}, flow {parsed.flow or 'unspecified'}",
    ]

    for group in parsed.sticky_groups:
        lines.append(f"  buffer {group.buffer}:")
        for predicate in group.predicates:
            modifiers = ", ".join(
                modifier.name + (f":{modifier.value}" if modifier.value else "")
                for modifier in predicate.modifiers
            )
            literal = (
                _preview(predicate.value)
                if predicate.value is not None
                else "<undecodable>"
            )
            suffix = f"  [{modifiers}]" if modifiers else ""
            lines.append(f"    {predicate.predicate_id}: {literal}{suffix}")

    blockers = blocking_options(parsed)
    if not blockers:
        lines.extend(
            ["", "Nothing is blocking automatic synthesis for this rule."]
        )
        return "\n".join(lines)

    lines.extend(["", "You need to supply bytes that satisfy:"])
    for option in parsed.other_options:
        if option.name == "pcre" and option.value:
            lines.append(f"  pcre: {describe_pcre(option.value)}")
        elif option.name == "byte_test" and option.value:
            lines.append(f"  byte_test: {describe_byte_test(option.value)}")
        elif option.name in blockers:
            lines.append(f"  {option.name}: {option.value or ''}".rstrip())

    anchor = blocking_predicate_anchor(parsed)
    if anchor is not None:
        buffer, predicate_id = anchor
        lines.extend(
            [
                "",
                f"Those bytes are appended after {predicate_id} in buffer {buffer}.",
            ]
        )
    lines.extend(
        [
            "",
            "Supply them with:",
            f"  hardening-experiment complete-pcap {dataset_id} {record.name} \\",
            '      --fill-text "<the bytes that satisfy the above>"',
            "  (use --fill-hex for non-printable bytes, and --insert-after "
            "<predicate-id> to place them elsewhere)",
        ]
    )
    return "\n".join(lines)


def complete_manual_pcap(
    record: DatasetRecord,
    *,
    dataset_id: str,
    fill: bytes,
    project_root: Path,
    insert_after: str | None = None,
) -> AutoSuiteResult:
    """Splice user-supplied bytes into the derived skeleton and verify it."""
    parsed = parse_suricata_rule(record.rule)
    anchor = insert_after
    if anchor is None:
        found = blocking_predicate_anchor(parsed)
        if found is None:
            all_predicates = [
                predicate.predicate_id
                for group in parsed.sticky_groups
                for predicate in group.predicates
            ]
            if not all_predicates:
                return AutoSuiteResult(
                    "needs_manual_pcap",
                    (),
                    "the rule has no content match to anchor supplied bytes to",
                )
            anchor = all_predicates[-1]
        else:
            anchor = found[1]

    try:
        plan = plan_traffic(
            parsed, inject_after=anchor, injection=fill, allow_blocking=True
        )
    except UnsupportedRule as error:
        return AutoSuiteResult("needs_manual_pcap", (), error.reason, error.blocking)

    output_dir = dataset_root(dataset_id, project_root=project_root) / "pcap" / record.name
    cases = build_cases(plan, output_dir=output_dir, prefix="manual")
    failure = validate_cases(record.rule, cases, sid=record.sid)
    if failure is not None:
        for case in cases:
            case.pcap_path.unlink(missing_ok=True)
        return AutoSuiteResult(
            "needs_manual_pcap",
            (),
            f"the supplied bytes did not satisfy the rule under real Suricata "
            f"({failure}). Check the requirements with `explain` and try again - "
            f"they were inserted after {anchor}.",
        )
    return AutoSuiteResult(
        status="generated",
        cases=cases,
        reason=f"Supplied bytes satisfied the rule; {len(cases)} cases written.",
        kind=plan.kind,
    )
