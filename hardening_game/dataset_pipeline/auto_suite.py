"""Synthesize a validation suite directly from a rule's own content matches.

The premise the whole project rests on is that an IDS rule's content matches
*are* the exploit signature. That makes the positive case mechanically
derivable: place every required literal in the buffer it belongs to, at the
offset its modifiers demand, and the rule fires. This module does that for the
shapes it can do honestly - HTTP request buffers and raw TCP payloads matched
by plain `content` - and refuses, by name, for anything whose match condition
it cannot construct (pcre, byte_test, and friends).

Nothing is ever accepted on reasoning alone: every generated case is replayed
through real Suricata, and a suite whose positive does not fire (or whose
negative does) is reported as needing a hand-supplied PCAP rather than written
out as if it worked. `assist.py` reuses the same planner to fill in the one
piece a human has to decide for those rules.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Literal

from hardening_game.fixture import ValidationCase
from hardening_game.pcap.suite_builders import build_established_tcp_stream, write_case_pcap
from hardening_game.suricata.rule_model import ParsedRule, StickyBufferGroup, parse_suricata_rule
from hardening_game.suricata.validate import replay_suite


SuiteKind = Literal["auto_http", "auto_raw_tcp"]

# Buffers this module knows how to place bytes into unambiguously. Everything
# else is refused by name rather than guessed at.
_HTTP_METHOD = "http.method"
_HTTP_URI = ("http.uri", "http.uri.raw")
_HTTP_BODY = ("http.request_body", "http.client_body")
_HTTP_HEADER_BUFFERS = {
    "http.host": b"Host",
    "http.user_agent": b"User-Agent",
    "http.cookie": b"Cookie",
    "http.content_type": b"Content-Type",
}
RAW_BUFFER = "payload"

# Options whose match condition cannot be satisfied by placing literal bytes.
BLOCKING_OPTIONS = frozenset(
    {
        "pcre",
        "byte_test",
        "byte_jump",
        "byte_extract",
        "isdataat",
        "threshold",
        "dsize",
        "base64_decode",
        "luajit",
        "lua",
    }
)

_DEFAULT_HOST = b"target.local"
_FILLER_BYTE = b"A"
_NUMERIC = re.compile(r"^\d+$")


class UnsupportedRule(Exception):
    """This rule's traffic cannot be derived from its literals alone."""

    def __init__(self, reason: str, blocking: tuple[str, ...] = ()) -> None:
        super().__init__(reason)
        self.reason = reason
        self.blocking = blocking


@dataclass(frozen=True)
class AutoSuiteResult:
    status: Literal["generated", "needs_manual_pcap"]
    cases: tuple[ValidationCase, ...]
    reason: str
    blocking_predicates: tuple[str, ...] = ()
    kind: SuiteKind | None = None


@dataclass(frozen=True)
class TrafficPlan:
    """Everything needed to build one conversation, derived from the rule."""

    kind: SuiteKind
    port: int
    direction: str
    groups: dict[str, bytes]
    ordered_buffers: tuple[str, ...]


def blocking_options(parsed: ParsedRule) -> tuple[str, ...]:
    """Name every option that stops traffic from being derived mechanically."""
    blockers: list[str] = []
    for option in parsed.other_options:
        if option.name in BLOCKING_OPTIONS:
            blockers.append(option.name)
        elif option.name == "flowbits":
            # `set` only writes state, it never gates whether the rule fires.
            # `isset`/`isnotset` need a prior flow to have run, and `noalert`
            # means the rule can never alert at all - neither is satisfiable
            # with a single synthesized conversation.
            value = (option.value or "").strip()
            if not value.startswith("set"):
                blockers.append(f"flowbits:{value.split(',')[0]}")
    for group in parsed.sticky_groups:
        for predicate in group.predicates:
            for consumer in predicate.relative_consumers:
                if consumer.name in BLOCKING_OPTIONS:
                    blockers.append(consumer.name)
    seen: set[str] = set()
    ordered: list[str] = []
    for name in blockers:
        if name not in seen:
            seen.add(name)
            ordered.append(name)
    return tuple(ordered)


def _modifier_values(predicate) -> dict[str, str | None]:
    return {modifier.name: modifier.value for modifier in predicate.modifiers}


def buffer_bytes(
    group: StickyBufferGroup,
    *,
    inject_after: str | None = None,
    injection: bytes = b"",
) -> bytes:
    """Lay this buffer's literals out so every positional modifier holds.

    Contents are packed as tightly as `offset`/`distance` allow, which is the
    one placement that satisfies a minimum-offset constraint while leaving the
    most room under any `depth`/`within` upper bound. `inject_after` splices
    extra bytes in immediately after one predicate's literal, which is how a
    hand-supplied pcre/byte_test payload gets placed.
    """
    out = bytearray()
    for predicate in group.predicates:
        if predicate.value is None:
            raise UnsupportedRule(
                f"{predicate.predicate_id} has no decodable literal",
                (predicate.predicate_id,),
            )
        modifiers = _modifier_values(predicate)
        offset = modifiers.get("offset")
        distance = modifiers.get("distance")
        pad = 0
        if offset is not None and _NUMERIC.fullmatch((offset or "").strip()):
            pad = max(0, int(offset) - len(out))
        elif distance is not None and _NUMERIC.fullmatch((distance or "").strip()):
            pad = int(distance)
        out.extend(_FILLER_BYTE * pad)
        out.extend(predicate.value)
        if inject_after is not None and predicate.predicate_id == inject_after:
            out.extend(injection)
    return bytes(out)


def mutate_last_literal(value: bytes) -> bytes:
    """Break a literal while preserving its length, so `bsize` still holds."""
    if not value:
        return b"X"
    tail = value[-1:]
    return value[:-1] + (b"Z" if tail != b"Z" else b"Q")


def _resolve_port(parsed: ParsedRule, *, default: int) -> int:
    raw = parsed.header.destination_port.strip()
    if raw.startswith("!"):
        raise UnsupportedRule(
            f"destination port {raw!r} is negated, so no single port is implied"
        )
    if _NUMERIC.fullmatch(raw):
        return int(raw)
    numbers = re.findall(r"\d+", raw)
    if numbers:
        return int(numbers[0])
    if not default:
        raise UnsupportedRule(
            f"destination port {raw!r} does not resolve to a single port"
        )
    return default


def _direction(parsed: ParsedRule) -> str:
    return "to_client" if "to_client" in (parsed.flow or "").lower() else "to_server"


def plan_traffic(
    parsed: ParsedRule,
    *,
    inject_after: str | None = None,
    injection: bytes = b"",
    allow_blocking: bool = False,
) -> TrafficPlan:
    """Derive the conversation this rule requires, or explain why we can't.

    `allow_blocking` is for the assisted path: the caller has supplied the
    bytes that satisfy the pcre/byte_test the automatic path refuses to guess,
    so the block is lifted and real Suricata still gets the final say.
    """
    protocol = parsed.header.protocol.lower()
    if protocol not in {"http", "tcp"}:
        raise UnsupportedRule(
            f"protocol {protocol!r} is not supported for automatic traffic "
            "synthesis (only http and tcp are)"
        )

    if not allow_blocking:
        blockers = blocking_options(parsed)
        if blockers:
            raise UnsupportedRule(
                "the rule's match condition depends on "
                + ", ".join(blockers)
                + ", which cannot be satisfied by placing literal bytes",
                blockers,
            )

    negated = tuple(
        predicate.predicate_id
        for group in parsed.sticky_groups
        for predicate in group.predicates
        if predicate.negated
    )
    if negated:
        raise UnsupportedRule(
            "negated content ("
            + ", ".join(negated)
            + ") requires traffic that provably lacks a pattern, which is not "
            "derived automatically",
            negated,
        )

    if not parsed.sticky_groups:
        raise UnsupportedRule("the rule has no content matches to build traffic from")

    groups: dict[str, bytes] = {}
    for group in parsed.sticky_groups:
        groups[group.buffer] = buffer_bytes(
            group, inject_after=inject_after, injection=injection
        )

    http_buffers = {
        name
        for name in groups
        if name == _HTTP_METHOD
        or name in _HTTP_URI
        or name in _HTTP_BODY
        or name in _HTTP_HEADER_BUFFERS
    }
    unsupported = set(groups) - http_buffers - {RAW_BUFFER}
    if unsupported:
        raise UnsupportedRule(
            "buffer(s) "
            + ", ".join(sorted(unsupported))
            + " are not supported for automatic traffic synthesis",
            tuple(sorted(unsupported)),
        )
    if http_buffers and RAW_BUFFER in groups:
        raise UnsupportedRule(
            "the rule mixes HTTP buffers with a raw payload match, which is not "
            "supported for automatic traffic synthesis"
        )

    kind: SuiteKind = "auto_http" if http_buffers else "auto_raw_tcp"
    return TrafficPlan(
        kind=kind,
        port=_resolve_port(parsed, default=80 if kind == "auto_http" else 0),
        direction=_direction(parsed),
        groups=groups,
        ordered_buffers=tuple(groups),
    )


def assemble_payload(plan: TrafficPlan, groups: dict[str, bytes] | None = None) -> bytes:
    """Render one buffer map as the bytes that cross the wire."""
    source = plan.groups if groups is None else groups
    if plan.kind == "auto_raw_tcp":
        return source[RAW_BUFFER]

    body = next((source[name] for name in _HTTP_BODY if name in source), b"")
    method = source.get(_HTTP_METHOD) or (b"POST" if body else b"GET")
    target = next((source[name] for name in _HTTP_URI if name in source), b"/")
    if not target.startswith(b"/"):
        target = b"/" + target

    headers: list[tuple[bytes, bytes]] = [
        (b"Host", source.get("http.host", _DEFAULT_HOST))
    ]
    for buffer, header_name in _HTTP_HEADER_BUFFERS.items():
        if buffer != "http.host" and buffer in source:
            headers.append((header_name, source[buffer]))
    if body:
        headers.append((b"Content-Length", str(len(body)).encode("ascii")))

    head = method + b" " + target + b" HTTP/1.1\r\n"
    for name, value in headers:
        head += name + b": " + value + b"\r\n"
    return head + b"\r\n" + body


def write_case(
    payload: bytes,
    *,
    name: str,
    expected_alert: bool,
    reason: str,
    plan: TrafficPlan,
    output_dir: Path,
) -> ValidationCase:
    packets = build_established_tcp_stream(
        payload,
        port=plan.port,
        direction=plan.direction,
        segment_sizes=None,
        retransmit_segment=None,
    )
    return ValidationCase(
        name=name,
        pcap_path=write_case_pcap(packets, output_dir / f"{name}.pcap"),
        expected_alert=expected_alert,
        reason=reason,
        predicate_id=None,
    )


def validate_cases(
    rule: str, cases: tuple[ValidationCase, ...], *, sid: int
) -> str | None:
    """Return None when real Suricata agrees with every expectation."""
    replay = replay_suite(rule, cases, expected_sid=sid)
    if replay.fired:
        return None
    failures = [case.name for case in replay.cases if not case.passed]
    return replay.error or ", ".join(failures) or "unknown"


def build_cases(
    plan: TrafficPlan, *, output_dir: Path, prefix: str = "auto"
) -> tuple[ValidationCase, ...]:
    """One positive plus one same-length negative that breaks the last literal."""
    last_buffer = plan.ordered_buffers[-1]
    negative_groups = dict(plan.groups)
    negative_groups[last_buffer] = mutate_last_literal(plan.groups[last_buffer])
    output_dir.mkdir(parents=True, exist_ok=True)
    return (
        write_case(
            assemble_payload(plan),
            name=f"P0-{prefix}-canonical",
            expected_alert=True,
            reason="Traffic carrying every literal the rule matches on.",
            plan=plan,
            output_dir=output_dir,
        ),
        write_case(
            assemble_payload(plan, negative_groups),
            name=f"N0-{prefix}-last-literal-changed",
            expected_alert=False,
            reason=(
                f"Same traffic with the final literal of {last_buffer} altered, "
                "so the rule's last match no longer holds."
            ),
            plan=plan,
            output_dir=output_dir,
        ),
    )


def generate_auto_suite(
    rule: str,
    *,
    rule_name: str,
    sid: int,
    output_dir: Path,
    project_root: Path,
) -> AutoSuiteResult:
    """Derive, write, and real-Suricata-validate a suite for one rule."""
    try:
        parsed = parse_suricata_rule(rule)
    except ValueError as error:
        return AutoSuiteResult(
            "needs_manual_pcap", (), f"rule could not be parsed: {error}"
        )
    try:
        plan = plan_traffic(parsed)
    except UnsupportedRule as error:
        return AutoSuiteResult("needs_manual_pcap", (), error.reason, error.blocking)

    cases = build_cases(plan, output_dir=output_dir)
    failure = validate_cases(rule, cases, sid=sid)
    if failure is not None:
        for case in cases:
            case.pcap_path.unlink(missing_ok=True)
        return AutoSuiteResult(
            "needs_manual_pcap",
            (),
            "synthesized traffic did not behave as required under real "
            f"Suricata ({failure}); the rule needs a hand-supplied PCAP",
        )
    return AutoSuiteResult(
        status="generated",
        cases=cases,
        reason=f"Derived {len(cases)} cases from the rule's own content matches.",
        kind=plan.kind,
    )
