"""Source-span model for the supported Suricata rule-option subset."""

from __future__ import annotations

from dataclasses import dataclass, replace
import re
from typing import Literal


RULE_HEADER_PATTERN = re.compile(
    r"^\s*(?P<action>\S+)\s+(?P<protocol>\S+)\s+(?P<src_address>\S+)\s+"
    r"(?P<src_port>\S+)\s+(?P<direction>->|<-|<>)\s+"
    r"(?P<dst_address>\S+)\s+(?P<dst_port>\S+)\s*\("
)

# Public rule-option vocabulary.  Every module that reasons about Suricata
# options must import these rather than restate them, so option classification
# has exactly one definition.
CONTENT_OPTION = re.compile(
    r'^\s*content\s*:\s*(?P<negated>!)?\s*"(?P<value>(?:\\.|[^"\\])*)"\s*;\s*$',
    re.IGNORECASE,
)
STICKY_BUFFER_NAMES = frozenset(
    {"pkt_data", "file_data", "base64_data", "js_data", "vba_data"}
)
CONTENT_MODIFIERS = frozenset(
    {
        "nocase", "fast_pattern", "startswith", "endswith", "offset", "depth",
        "distance", "within", "rawbytes",
    }
)
RELATIVE_CONSUMER_NAMES = frozenset({"byte_test", "byte_jump", "isdataat", "pcre"})
BUFFER_SCOPED_OPTIONS = RELATIVE_CONSUMER_NAMES | {"bsize"}


@dataclass(frozen=True)
class Span:
    start: int
    end: int


@dataclass(frozen=True)
class RuleHeader:
    protocol: str
    source_address: str
    source_port: str
    direction: str
    destination_address: str
    destination_port: str
    destination_port_span: Span


@dataclass(frozen=True)
class RuleOption:
    name: str
    value: str | None
    span: Span
    option_index: int


@dataclass(frozen=True)
class Modifier:
    name: str
    value: str | None
    span: Span


@dataclass(frozen=True)
class ContentPredicate:
    predicate_id: str
    buffer: str
    content_index: int
    option_index: int
    span: Span
    value: bytes | None
    negated: bool
    representation: Literal["literal", "hex", "mixed"]
    modifiers: tuple[Modifier, ...]
    relative_consumers: tuple[RuleOption, ...]


@dataclass(frozen=True)
class StickyBufferGroup:
    buffer: str
    declaration: RuleOption | None
    predicates: tuple[ContentPredicate, ...]
    buffer_constraints: tuple[RuleOption, ...]
    scoped_options: tuple[RuleOption, ...]


@dataclass(frozen=True)
class ParsedRule:
    source: str
    header: RuleHeader
    options: tuple[RuleOption, ...]
    sticky_groups: tuple[StickyBufferGroup, ...]
    other_options: tuple[RuleOption, ...]
    flow: str | None


def _option_parts(source: str, span: Span, index: int) -> RuleOption:
    body = source[span.start : span.end].strip().rstrip(";").strip()
    name, separator, value = body.partition(":")
    return RuleOption(
        name=name.strip().casefold(),
        value=value.strip() if separator else None,
        span=span,
        option_index=index,
    )


def _option_spans(rule: str, opening: int, closing: int) -> list[Span]:
    spans: list[Span] = []
    start = opening + 1
    quoted = escaped = False
    for index in range(start, closing):
        character = rule[index]
        if quoted and escaped:
            escaped = False
        elif quoted and character == "\\":
            escaped = True
        elif character == '"':
            quoted = not quoted
        elif character == ";" and not quoted:
            spans.append(Span(start, index + 1))
            start = index + 1
    return spans


def is_sticky_declaration(option: RuleOption) -> bool:
    """Return whether an option declares a sticky buffer rather than a match."""
    return option.value is None and (
        "." in option.name or option.name in STICKY_BUFFER_NAMES
    )


def pcre_is_relative(value: str) -> bool:
    """Return whether a `pcre` option value carries the relative `R` flag.

    This is the only implementation of the `/R` test.  Surrounding quotes and
    trailing whitespace are ignored so callers never need to pre-normalize.
    """
    trailing = value.rstrip().rstrip('"').rstrip("'")
    _, separator, flags = trailing.rpartition("/")
    return bool(separator) and "R" in flags


def is_relative_consumer(option: RuleOption) -> bool:
    """Return whether an option anchors itself to the preceding content match."""
    if option.name not in RELATIVE_CONSUMER_NAMES or option.value is None:
        return False
    if option.name == "pcre":
        return pcre_is_relative(option.value)
    return "relative" in [part.strip().casefold() for part in option.value.split(",")]


def decode_content(value: str) -> tuple[bytes | None, Literal["literal", "hex", "mixed"]]:
    # Rendering a decoded escape sequence would lose its original escaping.
    # Keep it parsed as mixed/unsupported until a dedicated escape-safe renderer
    # is introduced.
    if "\\" in value:
        return None, "mixed"
    parts = re.split(r"(\|[^|]*\|)", value)
    saw_hex = False
    output = bytearray()
    try:
        for part in parts:
            if not part:
                continue
            if part.startswith("|") and part.endswith("|"):
                hex_bytes = part[1:-1].split()
                if not hex_bytes or any(not re.fullmatch(r"[0-9A-Fa-f]{2}", byte) for byte in hex_bytes):
                    return None, "mixed"
                output.extend(bytes.fromhex(" ".join(hex_bytes)))
                saw_hex = True
            else:
                output.extend(part.encode("ascii"))
    except UnicodeEncodeError:
        return None, "mixed"
    if saw_hex and len(parts) == 3 and not parts[0] and not parts[-1]:
        return bytes(output), "hex"
    return bytes(output), "mixed" if saw_hex else "literal"


def parse_suricata_rule(rule: str) -> ParsedRule:
    """Parse options without normalizing source text or reordering it."""
    header_match = RULE_HEADER_PATTERN.match(rule)
    opening = rule.find("(")
    closing = rule.rfind(")")
    if header_match is None or opening < 0 or closing <= opening:
        raise ValueError("unsupported Suricata rule header or option block")
    header = RuleHeader(
        protocol=header_match.group("protocol"),
        source_address=header_match.group("src_address"),
        source_port=header_match.group("src_port"),
        direction=header_match.group("direction"),
        destination_address=header_match.group("dst_address"),
        destination_port=header_match.group("dst_port"),
        destination_port_span=Span(
            header_match.start("dst_port"), header_match.end("dst_port")
        ),
    )
    options = tuple(
        _option_parts(rule, span, index)
        for index, span in enumerate(_option_spans(rule, opening, closing))
    )
    groups: list[dict[str, object]] = []
    current: dict[str, object] | None = None
    other: list[RuleOption] = []
    flow: str | None = None
    content_index = 0
    for option in options:
        if option.name == "flow":
            flow = option.value
            continue
        if is_sticky_declaration(option):
            current = {
                "buffer": option.name,
                "declaration": option,
                "predicates": [],
                "constraints": [],
                "scoped_options": [],
            }
            groups.append(current)
            continue
        if option.name == "content":
            if current is None:
                current = {
                    "buffer": "payload",
                    "declaration": None,
                    "predicates": [],
                    "constraints": [],
                    "scoped_options": [],
                }
                groups.append(current)
            match = CONTENT_OPTION.fullmatch(rule[option.span.start : option.span.end])
            if match is None:
                value, representation, negated = None, "mixed", False
            else:
                value, representation = decode_content(match.group("value"))
                negated = match.group("negated") == "!"
            current["predicates"].append(
                ContentPredicate(
                    predicate_id=f"content-{content_index}",
                    buffer=str(current["buffer"]),
                    content_index=content_index,
                    option_index=option.option_index,
                    span=option.span,
                    value=value,
                    negated=negated,
                    representation=representation,
                    modifiers=(),
                    relative_consumers=(),
                )
            )
            content_index += 1
            continue
        if option.name in CONTENT_MODIFIERS and current is not None and current["predicates"]:
            predicates = current["predicates"]
            predicate = predicates[-1]
            predicates[-1] = replace(
                predicate,
                modifiers=predicate.modifiers + (
                    Modifier(option.name, option.value, option.span),
                ),
            )
            continue
        if option.name == "bsize" and current is not None:
            current["constraints"].append(option)
            current["scoped_options"].append(option)
            other.append(option)
            continue
        if (
            current is not None
            and current["predicates"]
            and is_relative_consumer(option)
        ):
            predicates = current["predicates"]
            predicates[-1] = replace(
                predicates[-1],
                relative_consumers=predicates[-1].relative_consumers + (option,),
            )
            other.append(option)
            continue
        if option.name in BUFFER_SCOPED_OPTIONS and current is not None:
            current["scoped_options"].append(option)
            other.append(option)
            continue
        other.append(option)
    return ParsedRule(
        source=rule,
        header=header,
        options=options,
        sticky_groups=tuple(
            StickyBufferGroup(
                buffer=str(group["buffer"]),
                declaration=group["declaration"],
                predicates=tuple(group["predicates"]),
                buffer_constraints=tuple(group["constraints"]),
                scoped_options=tuple(group["scoped_options"]),
            )
            for group in groups
        ),
        other_options=tuple(other),
        flow=flow,
    )
