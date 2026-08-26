"""Conservative semantic checks for hardened Suricata rules.

This intentionally recognizes only the rule fragments needed to identify
unambiguous regressions.  Syntax and full rule semantics remain Suricata's
responsibility.
"""

from __future__ import annotations

from collections.abc import Sequence
from collections import defaultdict
from dataclasses import dataclass
import hashlib
import json
import re


_HEADER = re.compile(
    r"^\s*(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(->|<>|<-)\s+(\S+)\s+(\S+)\s*\(",
    re.IGNORECASE,
)
_OPTION = re.compile(r"^\s*([a-zA-Z_][\w.-]*)\s*:\s*(.*?)\s*$", re.DOTALL)
_BARE_OPTION = re.compile(r"^\s*([a-zA-Z_][\w.-]*)\s*$")
_INTEGER_VALUE = re.compile(r"[+-]?\d+")
_CONTENT_STRUCTURE_OPTIONS = frozenset(
    {"content", "distance", "within", "offset", "depth"}
)
# Keep this deliberately narrow.  The game already uses these content-bound
# options as hardening moves; identity and administrative options (gid, msg,
# metadata, reference, classtype, and unknown options) are never transformations.
_ALLOWED_HARDENING_OPTIONS = frozenset({"fast_pattern"})
# Options with rule-wide or administrative meaning remain global.  Every other
# parsed option after a content match is conservatively tied to that fragment,
# which also covers future payload/cursor options without a modifier allowlist.
_RULE_GLOBAL_OPTIONS = frozenset(
    {
        "ack",
        "app-layer-event",
        "classtype",
        "detection_filter",
        "dsize",
        "flags",
        "flow",
        "flowbits",
        "fragbits",
        "fragoffset",
        "gid",
        "id",
        "ip_proto",
        "ipopts",
        "metadata",
        "msg",
        "pcre",
        "priority",
        "reference",
        "rev",
        "rpc",
        "sameip",
        "seq",
        "sid",
        "tag",
        "target",
        "tcp.mss",
        "threshold",
        "tos",
        "ttl",
        "window",
    }
)
_STICKY_BUFFERS = frozenset(
    {
        "file.data",
        "http.content_type",
        "http.cookie",
        "http.header",
        "http.host",
        "http.method",
        "http.protocol",
        "http.raw_header",
        "http.raw_host",
        "http.raw_uri",
        "http.request_body",
        "http.request_header",
        "http.request_line",
        "http.response_body",
        "http.response_header",
        "http.response_line",
        "http.stat_code",
        "http.stat_msg",
        "http.uri",
        "http.user_agent",
    }
)


@dataclass(frozen=True)
class _Content:
    value: bytes
    distance: int | None
    within: int | None
    offset: int | None
    depth: int | None
    buffer: str | None
    modifiers: tuple[tuple[str, str], ...] = ()
    negated: bool = False


def canonical_rule_fingerprint_input(rule: str) -> bytes:
    """Return a stable, revision-independent representation of a rule."""
    header = _HEADER.match(rule)
    if header is None:
        canonical_header: tuple[str, ...] | str = _normalize_whitespace(rule)
    else:
        canonical_header = _normalized_header(header)

    canonical_options: list[tuple[str, str]] = []
    for name, value in _options(rule):
        if name == "rev":
            continue
        canonical_options.append((name, _canonical_option_value(name, value)))
    return json.dumps(
        [canonical_header, canonical_options],
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_rule_fingerprint(rule: str) -> str:
    """Hash the canonical meaningful rule representation."""
    return hashlib.sha256(canonical_rule_fingerprint_input(rule)).hexdigest()


def exactly_one_transformation_problem(
    oracle_rule: str, current_rule: str, candidate_rule: str
) -> str | None:
    """Require one structural change relative to immutable oracle groups."""
    oracle_content = _content_options(_options(oracle_rule))
    current_groups = _map_content_to_oracle_groups(
        oracle_content, _content_options(_options(current_rule))
    )
    candidate_groups = _map_content_to_oracle_groups(
        oracle_content, _content_options(_options(candidate_rule))
    )
    if current_groups is None or candidate_groups is None:
        return (
            "hardened_rule content fragments must map exactly to immutable "
            "oracle content match groups"
        )

    changed_groups = sum(
        _content_group_shape(current_group) != _content_group_shape(candidate_group)
        for current_group, candidate_group in zip(current_groups, candidate_groups)
    )
    if changed_groups > 1:
        return "hardened_rule changes multiple oracle content match groups"

    disallowed_changes = (
        _changed_associated_disallowed_options(current_groups, candidate_groups)
        | set(_changed_disallowed_options(current_rule, candidate_rule))
    )
    if _pcre_scopes(_options(current_rule)) != _pcre_scopes(
        _options(candidate_rule)
    ):
        disallowed_changes.add("pcre")
    if disallowed_changes:
        return (
            "hardened_rule changes an option that is not an allowed hardening "
            f"option: {', '.join(sorted(disallowed_changes))}"
        )

    option_changes = _associated_option_change_count(
        current_groups, candidate_groups
    )
    total_changes = changed_groups + option_changes
    if total_changes == 0:
        return "hardened_rule makes zero meaningful transformations"
    if total_changes > 1:
        return (
            "hardened_rule must change exactly one oracle content match group "
            "or one allowed non-content option"
        )
    return None


def semantic_rule_problem(original_rule: str, hardened_rule: str) -> str | None:
    """Return a reason only for an unambiguous semantic regression.

    The function deliberately ignores unrecognized syntax and options.  It
    preserves immutable headers and flows, literal content material/order,
    PCRE text, and relative distance/within constraints on original literal
    boundaries.
    """
    original_header = _HEADER.match(original_rule)
    hardened_header = _HEADER.match(hardened_rule)
    if original_header is not None and hardened_header is not None:
        if _normalized_header(original_header) != _normalized_header(hardened_header):
            return "hardened_rule must preserve action, protocol, addresses, ports, and direction"

    original_options = _options(original_rule)
    hardened_options = _options(hardened_rule)
    if _flow_options(original_options) != _flow_options(hardened_options):
        return "hardened_rule must preserve flow constraints"

    original_pcre = _option_values(original_options, "pcre")
    hardened_pcre = _option_values(hardened_options, "pcre")
    if original_pcre != hardened_pcre:
        return "hardened_rule must preserve pcre constraints"
    if _pcre_scopes(original_options) != _pcre_scopes(hardened_options):
        return "hardened_rule must preserve pcre sticky-buffer context"

    original_content = _content_options(original_options)
    hardened_content = _content_options(hardened_options)
    problem = _case_sensitivity_problem(original_content, hardened_content)
    if problem is not None:
        return problem
    problem = _literal_material_problem(original_content, hardened_content)
    if problem is not None:
        return problem
    problem = _negated_content_problem(original_content, hardened_content)
    if problem is not None:
        return problem
    problem = _relative_boundary_problem(original_content, hardened_content)
    if problem is not None:
        return problem
    problem = _absolute_boundary_problem(original_content, hardened_content)
    if problem is not None:
        return problem
    problem = _split_adjacency_problem(original_content, hardened_content)
    if problem is not None:
        return problem
    return _sticky_buffer_problem(original_content, hardened_content)


def _normalized_header(match: re.Match[str]) -> tuple[str, ...]:
    action, protocol, source_address, source_port, direction, destination_address, destination_port = (
        match.groups()
    )
    return (
        action.lower(),
        protocol.lower(),
        source_address,
        source_port,
        direction.lower(),
        destination_address,
        destination_port,
    )


def _canonical_option_value(name: str, value: str) -> str:
    if name == "content":
        parsed = _parsed_content_literal(value)
        if parsed is not None:
            literal, negated = parsed
            return ("!" if negated else "") + literal.hex()
    if name == "flow":
        return ",".join(sorted(_flow_flags(value)))
    stripped = value.strip()
    if _INTEGER_VALUE.fullmatch(stripped):
        return str(int(stripped))
    return _normalize_whitespace(stripped)


def _normalize_whitespace(value: str) -> str:
    normalized: list[str] = []
    quoted = False
    escaped = False
    pending_space = False
    for character in value.strip():
        if escaped:
            if pending_space and normalized and not quoted:
                normalized.append(" ")
            pending_space = False
            normalized.append(character)
            escaped = False
        elif character == "\\":
            if pending_space and normalized and not quoted:
                normalized.append(" ")
            pending_space = False
            normalized.append(character)
            escaped = True
        elif character == '"':
            if pending_space and normalized and not quoted:
                normalized.append(" ")
            pending_space = False
            normalized.append(character)
            quoted = not quoted
        elif character.isspace() and not quoted:
            pending_space = True
        else:
            if pending_space and normalized:
                normalized.append(" ")
            pending_space = False
            normalized.append(character)
    return "".join(normalized)


def _options(rule: str) -> list[tuple[str, str]]:
    opening = rule.find("(")
    closing = rule.rfind(")")
    if opening < 0 or closing <= opening:
        return []
    options: list[tuple[str, str]] = []
    for chunk in _split_options(rule[opening + 1 : closing]):
        if match := _OPTION.match(chunk):
            options.append((match.group(1).lower(), match.group(2)))
        elif match := _BARE_OPTION.match(chunk):
            options.append((match.group(1).lower(), ""))
    return options


def _split_options(text: str) -> list[str]:
    chunks: list[str] = []
    start = 0
    quoted = False
    escaped = False
    for index, character in enumerate(text):
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == '"':
            quoted = not quoted
        elif character == ";" and not quoted:
            chunks.append(text[start:index])
            start = index + 1
    chunks.append(text[start:])
    return chunks


def _option_values(options: list[tuple[str, str]], name: str) -> list[str]:
    return [value.strip() for option, value in options if option == name]


def _flow_options(options: list[tuple[str, str]]) -> frozenset[str]:
    return frozenset(
        flag
        for value in _option_values(options, "flow")
        for flag in _flow_flags(value)
    )


def _flow_flags(value: str) -> frozenset[str]:
    return frozenset(
        flag.lower()
        for flag in re.sub(r"\s+", "", value).split(",")
        if flag
    )


def _is_sticky_buffer_option(name: str, value: str) -> bool:
    return value == "" and (name in _STICKY_BUFFERS or name.startswith("http."))


def _pcre_scopes(options: list[tuple[str, str]]) -> list[tuple[str, str | None]]:
    active_buffer: str | None = None
    scopes: list[tuple[str, str | None]] = []
    for name, value in options:
        if _is_sticky_buffer_option(name, value):
            active_buffer = name
        elif name == "pcre":
            scopes.append((value.strip(), active_buffer))
    return scopes


def _content_options(options: list[tuple[str, str]]) -> list[_Content]:
    contents: list[_Content] = []
    active_buffer: str | None = None
    for name, value in options:
        if _is_sticky_buffer_option(name, value):
            active_buffer = name
        elif name == "distance":
            if contents:
                contents[-1] = _Content(
                    contents[-1].value,
                    _integer(value),
                    contents[-1].within,
                    contents[-1].offset,
                    contents[-1].depth,
                    contents[-1].buffer,
                    contents[-1].modifiers,
                    contents[-1].negated,
                )
        elif name == "within":
            if contents:
                contents[-1] = _Content(
                    contents[-1].value,
                    contents[-1].distance,
                    _integer(value),
                    contents[-1].offset,
                    contents[-1].depth,
                    contents[-1].buffer,
                    contents[-1].modifiers,
                    contents[-1].negated,
                )
        elif name == "offset":
            if contents:
                contents[-1] = _Content(
                    contents[-1].value,
                    contents[-1].distance,
                    contents[-1].within,
                    _integer(value),
                    contents[-1].depth,
                    contents[-1].buffer,
                    contents[-1].modifiers,
                    contents[-1].negated,
                )
        elif name == "depth":
            if contents:
                contents[-1] = _Content(
                    contents[-1].value,
                    contents[-1].distance,
                    contents[-1].within,
                    contents[-1].offset,
                    _integer(value),
                    contents[-1].buffer,
                    contents[-1].modifiers,
                    contents[-1].negated,
                )
        elif name == "pcre" and contents and _is_relative_pcre(value):
            contents[-1] = _Content(
                contents[-1].value,
                contents[-1].distance,
                contents[-1].within,
                contents[-1].offset,
                contents[-1].depth,
                contents[-1].buffer,
                contents[-1].modifiers
                + ((name, _canonical_option_value(name, value)),),
                contents[-1].negated,
            )
        elif name == "content":
            parsed = _parsed_content_literal(value)
            if parsed is not None:
                literal, negated = parsed
                contents.append(
                    _Content(
                        literal,
                        None,
                        None,
                        None,
                        None,
                        active_buffer,
                        negated=negated,
                    )
                )
        elif contents and name not in _RULE_GLOBAL_OPTIONS:
            contents[-1] = _Content(
                contents[-1].value,
                contents[-1].distance,
                contents[-1].within,
                contents[-1].offset,
                contents[-1].depth,
                contents[-1].buffer,
                contents[-1].modifiers
                + ((name, _canonical_option_value(name, value)),),
                contents[-1].negated,
            )
    return contents


def _is_relative_pcre(value: str) -> bool:
    stripped = value.strip()
    if len(stripped) < 2 or stripped[0] != '"' or stripped[-1] != '"':
        return False
    source = stripped[1:-1]
    opening = source.find("/")
    if opening < 0:
        return False
    escaped = False
    for index in range(opening + 1, len(source)):
        character = source[index]
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == "/":
            return "R" in source[index + 1 :]
    return False


def _map_content_to_oracle_groups(
    oracle: list[_Content], fragments: list[_Content]
) -> tuple[tuple[_Content, ...], ...] | None:
    groups: list[tuple[_Content, ...]] = []
    fragment_index = 0
    for oracle_content in oracle:
        if oracle_content.negated:
            if fragment_index >= len(fragments):
                return None
            fragment = fragments[fragment_index]
            if not fragment.negated or fragment.value != oracle_content.value:
                return None
            groups.append((fragment,))
            fragment_index += 1
            continue
        group: list[_Content] = []
        material = b""
        while fragment_index < len(fragments) and len(material) < len(
            oracle_content.value
        ):
            fragment = fragments[fragment_index]
            if fragment.negated != oracle_content.negated:
                return None
            material += fragment.value
            if not oracle_content.value.startswith(material):
                return None
            group.append(fragment)
            fragment_index += 1
        if material != oracle_content.value:
            return None
        groups.append(tuple(group))
    if fragment_index != len(fragments):
        return None
    return tuple(groups)


def _case_sensitivity_problem(
    original: list[_Content], hardened: list[_Content]
) -> str | None:
    hardened_groups = _map_content_to_oracle_groups(original, hardened)
    if hardened_groups is None:
        return None
    for expected, group in zip(original, hardened_groups):
        expected_nocase = any(name == "nocase" for name, _ in expected.modifiers)
        if any(
            any(name == "nocase" for name, _ in fragment.modifiers)
            != expected_nocase
            for fragment in group
        ):
            return (
                "hardened_rule must preserve content case sensitivity; "
                "adding nocase broadens matching"
            )
    return None


def _content_group_shape(
    group: tuple[_Content, ...],
) -> tuple[
    tuple[bytes, int | None, int | None, int | None, int | None, str | None, bool],
    ...,
]:
    return tuple(
        (
            content.value,
            content.distance,
            content.within,
            content.offset,
            content.depth,
            content.buffer,
            content.negated,
        )
        for content in group
    )


def _associated_option_change_count(
    current_groups: tuple[tuple[_Content, ...], ...],
    candidate_groups: tuple[tuple[_Content, ...], ...],
) -> int:
    current = _associated_options_by_position(
        current_groups, allowed=True
    )
    candidate = _associated_options_by_position(
        candidate_groups, allowed=True
    )
    return _option_change_count(current, candidate)


def _changed_associated_disallowed_options(
    current_groups: tuple[tuple[_Content, ...], ...],
    candidate_groups: tuple[tuple[_Content, ...], ...],
) -> set[str]:
    current = _associated_options_by_position(current_groups, allowed=False)
    candidate = _associated_options_by_position(candidate_groups, allowed=False)
    return {
        key[2]
        for key in current.keys() | candidate.keys()
        if current.get(key, ()) != candidate.get(key, ())
    }


def _associated_options_by_position(
    groups: tuple[tuple[_Content, ...], ...],
    *,
    allowed: bool,
) -> dict[tuple[int, int, str], tuple[str, ...]]:
    grouped: defaultdict[tuple[int, int, str], list[str]] = defaultdict(list)
    for group_index, group in enumerate(groups):
        for fragment_index, content in enumerate(group):
            for name, value in content.modifiers:
                if (name in _ALLOWED_HARDENING_OPTIONS) == allowed:
                    grouped[(group_index, fragment_index, name)].append(value)
    return {key: tuple(values) for key, values in grouped.items()}


def _option_change_count(
    current: dict[object, tuple[str, ...]],
    candidate: dict[object, tuple[str, ...]],
) -> int:
    changes = 0
    for key in current.keys() | candidate.keys():
        current_values = current.get(key, ())
        candidate_values = candidate.get(key, ())
        shared = min(len(current_values), len(candidate_values))
        changes += sum(
            current_values[index] != candidate_values[index]
            for index in range(shared)
        )
        changes += abs(len(current_values) - len(candidate_values))
    return changes


def _changed_disallowed_options(
    current_rule: str, candidate_rule: str
) -> list[str]:
    current = _disallowed_options_by_name(current_rule)
    candidate = _disallowed_options_by_name(candidate_rule)
    return sorted(
        name
        for name in current.keys() | candidate.keys()
        if current.get(name, ()) != candidate.get(name, ())
    )


def _disallowed_options_by_name(rule: str) -> dict[str, tuple[str, ...]]:
    grouped: defaultdict[str, list[str]] = defaultdict(list)
    for name, value in _options(rule):
        if (
            name == "rev"
            or name in _CONTENT_STRUCTURE_OPTIONS
            or name in _ALLOWED_HARDENING_OPTIONS
            or name in _STICKY_BUFFERS
            or (value == "" and name.startswith("http."))
        ):
            continue
        grouped[name].append(_canonical_option_value(name, value))
    return {name: tuple(values) for name, values in grouped.items()}


def _integer(value: str) -> int | None:
    try:
        return int(value.strip())
    except ValueError:
        return None


def _parsed_content_literal(value: str) -> tuple[bytes, bool] | None:
    stripped = value.strip()
    negated = stripped.startswith("!")
    if negated:
        stripped = stripped[1:].lstrip()
    if len(stripped) < 2 or stripped[0] != '"' or stripped[-1] != '"':
        return None
    source = stripped[1:-1]
    try:
        result = bytearray()
        index = 0
        while index < len(source):
            character = source[index]
            if character == "|":
                closing = source.find("|", index + 1)
                if closing >= 0:
                    compact = "".join(source[index + 1 : closing].split())
                    if (
                        len(compact) % 2 == 0
                        and re.fullmatch(r"[0-9A-Fa-f]*", compact)
                    ):
                        result.extend(bytes.fromhex(compact))
                        index = closing + 1
                        continue
            if (
                character == "\\"
                and index + 3 < len(source)
                and source[index + 1] == "x"
                and re.fullmatch(r"[0-9A-Fa-f]{2}", source[index + 2 : index + 4])
            ):
                result.append(int(source[index + 2 : index + 4], 16))
                index += 4
                continue
            if character == "\\" and index + 1 < len(source):
                result.extend(source[index + 1].encode("latin-1"))
                index += 2
                continue
            result.extend(character.encode("latin-1"))
            index += 1
        return bytes(result), negated
    except UnicodeEncodeError:
        return None


def _literal_material_problem(
    original: list[_Content], hardened: list[_Content]
) -> str | None:
    original_material = b"".join(content.value for content in original)
    hardened_material = b"".join(content.value for content in hardened)
    if original_material and not _is_subsequence(original_material, hardened_material):
        return "hardened_rule removes or reorders literal content material"
    original_signed_material = [
        (byte, content.negated)
        for content in original
        for byte in content.value
    ]
    hardened_signed_material = [
        (byte, content.negated)
        for content in hardened
        for byte in content.value
    ]
    if original_signed_material and not _is_subsequence(
        original_signed_material, hardened_signed_material
    ):
        return "hardened_rule changes literal content negation"
    return None


def _negated_content_problem(
    original: list[_Content], hardened: list[_Content]
) -> str | None:
    hardened_index = 0
    for expected in original:
        if not expected.negated:
            continue
        while hardened_index < len(hardened):
            candidate = hardened[hardened_index]
            hardened_index += 1
            if candidate.negated and candidate.value == expected.value:
                break
        else:
            return (
                "hardened_rule must preserve each negated content as one "
                "match with identical bytes"
            )
        expected_constraints = (
            expected.distance,
            expected.within,
            expected.offset,
            expected.depth,
            expected.buffer,
        )
        candidate_constraints = (
            candidate.distance,
            candidate.within,
            candidate.offset,
            candidate.depth,
            candidate.buffer,
        )
        if candidate_constraints != expected_constraints:
            return (
                "hardened_rule must preserve negated content positional "
                "constraints and sticky buffer"
            )
    return None


def _is_subsequence(expected: Sequence[object], actual: Sequence[object]) -> bool:
    position = 0
    for item in actual:
        if position < len(expected) and item == expected[position]:
            position += 1
    return position == len(expected)


def _relative_boundary_problem(
    original: list[_Content], hardened: list[_Content]
) -> str | None:
    for content in original:
        if content.distance is None and content.within is None:
            continue
        match = _matching_content_span(content.value, hardened)
        if match is None:
            if _is_merged_content_boundary(content.value, hardened):
                return "hardened_rule changes distance or within at an original literal boundary"
            continue
        start, end = match
        split = hardened[start:end]
        first = split[0]
        suffix_length = sum(len(candidate.value) for candidate in split[1:])
        expected_within = (
            None if content.within is None else content.within - suffix_length
        )
        if first.distance != content.distance:
            return (
                "hardened_rule changes distance at an original literal boundary: "
                f"expected first fragment distance {_modifier(content.distance)}, "
                f"got {_modifier(first.distance)}"
            )
        if first.within != expected_within:
            return (
                "hardened_rule changes within at an original literal boundary: "
                f"expected first fragment within {_modifier(expected_within)} "
                f"after subtracting suffix length {suffix_length}, "
                f"got {_modifier(first.within)}"
            )
    return None


def _absolute_boundary_problem(
    original: list[_Content], hardened: list[_Content]
) -> str | None:
    for content in original:
        if content.offset is None and content.depth is None:
            continue
        match = _matching_content_span(content.value, hardened)
        if match is None:
            return "hardened_rule removes offset or depth on original content"
        start, end = match
        split = hardened[start:end]
        first = split[0]
        suffix_length = sum(len(candidate.value) for candidate in split[1:])
        expected_depth = (
            None if content.depth is None else content.depth - suffix_length
        )
        if first.offset != content.offset:
            return (
                "hardened_rule changes offset on original content: "
                f"expected first fragment offset {_modifier(content.offset)}, "
                f"got {_modifier(first.offset)}"
            )
        if first.depth != expected_depth:
            return (
                "hardened_rule changes depth on original content: "
                f"expected first fragment depth {_modifier(expected_depth)} "
                f"after subtracting suffix length {suffix_length}, "
                f"got {_modifier(first.depth)}"
            )
    return None


def _split_adjacency_problem(
    original: list[_Content], hardened: list[_Content]
) -> str | None:
    for content in original:
        match = _matching_content_span(content.value, hardened)
        if match is None:
            continue
        start, end = match
        for candidate in hardened[start + 1 : end]:
            if (
                candidate.distance != 0
                or candidate.within != len(candidate.value)
            ):
                return (
                    "hardened_rule changes literal contiguity: every following "
                    "split fragment must use distance:0 and within equal to its "
                    "fragment length"
                )
    return None


def _modifier(value: int | None) -> str:
    return "unset" if value is None else str(value)


def _sticky_buffer_problem(
    original: list[_Content], hardened: list[_Content]
) -> str | None:
    expected = [
        (byte, content.buffer)
        for content in original
        for byte in content.value
    ]
    position = 0
    for content in hardened:
        for byte in content.value:
            if position >= len(expected):
                break
            expected_byte, expected_buffer = expected[position]
            if byte == expected_byte and content.buffer == expected_buffer:
                position += 1
    if position != len(expected):
        return "hardened_rule moves content between sticky buffers"
    return None


def _matching_content_start(value: bytes, candidates: list[_Content]) -> int | None:
    match = _matching_content_span(value, candidates)
    return None if match is None else match[0]


def _matching_content_span(
    value: bytes, candidates: list[_Content]
) -> tuple[int, int] | None:
    for index in range(len(candidates)):
        material = b""
        for end, candidate in enumerate(candidates[index:], start=index + 1):
            material += candidate.value
            if material == value:
                return index, end
            if not value.startswith(material):
                break
    return None


def _is_merged_content_boundary(value: bytes, candidates: list[_Content]) -> bool:
    return any(value in candidate.value and candidate.value != value for candidate in candidates)
