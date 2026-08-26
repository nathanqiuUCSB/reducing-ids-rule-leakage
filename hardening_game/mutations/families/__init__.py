"""Single-semantic-component Suricata mutation families.

Every family exposes ``generate(rule, *, fixture_name)`` and returns accepted
``MutationSpec`` edits alongside deterministic ``RejectedSpec`` entries for
variants whose semantics or grammar cannot be established from the source text.
``fixture_name`` is required because rejection identities are fixture scoped.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
import re

from hardening_game.predicates import canonical_rule_predicates
from hardening_game.suricata.rule_model import (
    CONTENT_OPTION,
    RELATIVE_CONSUMER_NAMES,
    STICKY_BUFFER_NAMES,
    ContentPredicate,
    Modifier,
    ParsedRule,
    RuleOption,
    Span,
    decode_content,
    is_relative_consumer,
    is_sticky_declaration,
)


__all__ = [
    "Edit",
    "RELATIVE_CONSUMER_NAMES",
    "RELEASABLE_MODIFIERS",
    "STICKY_BUFFER_NAMES",
    "apply_edits",
    "canonical_content_predicate",
    "canonical_modifier",
    "canonical_option",
    "content_hex_mask",
    "decode_content_token",
    "depends_on_previous_match",
    "is_printable_literal",
    "is_sticky_declaration",
    "leading_whitespace",
    "option_index_of",
    "predicate_tags",
    "predicate_tail",
    "released_modifier_record",
    "remove_spans",
    "render_byte_mask",
    "render_content_value",
    "require_source_spelling",
    "render_content",
    "replace_span",
]

# Modifiers that tie a content to the previous match endpoint and can therefore
# be dropped to free that content when its anchor is edited away.
RELEASABLE_MODIFIERS = ("distance", "within")

Edit = tuple[int, int, str]


def apply_edits(source: str, edits: Sequence[Edit]) -> str:
    """Apply (start, end, replacement) edits right to left over source text."""
    rendered = source
    for start, end, replacement in sorted(edits, key=lambda edit: edit[0], reverse=True):
        rendered = rendered[:start] + replacement + rendered[end:]
    return rendered


def replace_span(source: str, span: Span, replacement: str) -> str:
    return apply_edits(source, ((span.start, span.end, replacement),))


def remove_spans(source: str, spans: Iterable[Span]) -> str:
    return apply_edits(source, tuple((span.start, span.end, "") for span in spans))


def leading_whitespace(source: str, span: Span) -> str:
    """Return the separator whitespace an option span inherited from its source."""
    text = source[span.start : span.end]
    return text[: len(text) - len(text.lstrip())]


def render_content(value: bytes, *, hex_value: bool, negated: bool = False) -> str:
    negation = "!" if negated else ""
    if hex_value:
        return f'content:{negation}"|{" ".join(f"{byte:02x}" for byte in value)}|";'
    return f'content:{negation}"{value.decode("ascii")}";'


def is_printable_literal(value: bytes) -> bool:
    """Return whether bytes render as a literal without escaping or ambiguity."""
    return bool(value) and all(
        0x20 <= byte <= 0x7E and byte not in b'"\\|;' for byte in value
    )


def predicate_tail(predicate: ContentPredicate) -> int:
    """Return the offset just past a content option and its attached modifiers."""
    return max(
        (modifier.span.end for modifier in predicate.modifiers),
        default=predicate.span.end,
    )


def option_index_of(rule: ParsedRule, span: Span) -> int:
    option = next((option for option in rule.options if option.span == span), None)
    if option is None:
        raise ValueError(f"span has no parser option: {span}")
    return option.option_index


def predicate_tags(predicate: ContentPredicate) -> dict[str, object]:
    return {
        "buffer": predicate.buffer,
        "content_index": predicate.content_index,
        "option_index": predicate.option_index,
        "predicate_id": predicate.predicate_id,
    }


def decode_content_token(token: str, *, field: str) -> bytes:
    """Decode one recipe-supplied Suricata content literal into exact bytes."""
    if not isinstance(token, str) or not token:
        raise ValueError(f"{field} must be a non-empty content literal")
    value, _representation = decode_content(token)
    if value is None:
        raise ValueError(f"{field} is not a decodable content literal: {token!r}")
    return value


def content_hex_mask(rule: ParsedRule, predicate: ContentPredicate) -> list[bool]:
    """Return, per matched byte, whether the source wrote it as hex."""
    match = CONTENT_OPTION.fullmatch(rule.source[predicate.span.start : predicate.span.end])
    if match is None or predicate.value is None:
        raise ValueError(f"content {predicate.predicate_id} has no decodable value")
    mask: list[bool] = []
    for part in re.split(r"(\|[^|]*\|)", match.group("value")):
        if not part:
            continue
        if part.startswith("|") and part.endswith("|"):
            mask.extend([True] * len(part[1:-1].split()))
        else:
            mask.extend([False] * len(part))
    if len(mask) != len(predicate.value):
        raise ValueError(
            f"content {predicate.predicate_id} representation does not align with "
            "its decoded bytes"
        )
    return mask


def render_content_value(value: bytes, hex_mask: Sequence[bool]) -> str:
    """Render exact bytes as the inner text of a mixed literal/hex content."""
    if len(value) != len(hex_mask):
        raise ValueError("byte mask length does not match the content length")
    parts: list[str] = []
    index = 0
    while index < len(value):
        end = index
        while end < len(value) and hex_mask[end] == hex_mask[index]:
            end += 1
        run = value[index:end]
        if hex_mask[index]:
            parts.append("|" + " ".join(f"{byte:02x}" for byte in run) + "|")
        else:
            if not is_printable_literal(run):
                raise ValueError("literal run contains bytes that need hex encoding")
            parts.append(run.decode("ascii"))
        index = end
    return "".join(parts)


def render_byte_mask(
    value: bytes, hex_mask: Sequence[bool], *, negated: bool = False
) -> str:
    """Render exact bytes as a mixed literal/hex content option."""
    negation = "!" if negated else ""
    return f'content:{negation}"{render_content_value(value, hex_mask)}";'


def require_source_spelling(
    token: str,
    *,
    rule: ParsedRule,
    predicate: ContentPredicate,
    offset: int,
    length: int,
    field: str,
) -> None:
    """Reject a recipe token the source does not spell that way.

    A recipe names a token by writing it the way the rule writes it.  Decoding
    alone is not enough: `/api/` and `|2f|api/` decode to the same bytes, so a
    recipe could name a boundary the reviewer never saw in the rule text and the
    emitted content would silently change representation.  Re-deriving the
    spelling from the source's own byte mask makes the recipe reference exact.
    """
    mask = content_hex_mask(rule, predicate)
    assert predicate.value is not None
    expected = render_content_value(
        predicate.value[offset : offset + length], mask[offset : offset + length]
    )
    if token != expected:
        raise ValueError(
            f"{field} is written {token!r} but the source spells those bytes "
            f"{expected!r}; name the token exactly as the rule writes it"
        )


def canonical_option(rule: ParsedRule, predicate_id: str) -> RuleOption:
    """Return the single physical option a canonical predicate ID names."""
    record = canonical_rule_predicates(rule).get(predicate_id)
    if record is None:
        raise ValueError(f"unknown canonical predicate: {predicate_id}")
    option_index = record.get("option_index")
    if not isinstance(option_index, int):
        raise ValueError(f"canonical predicate {predicate_id} has no physical option")
    return next(
        option for option in rule.options if option.option_index == option_index
    )


def canonical_content_predicate(
    rule: ParsedRule, predicate_id: str
) -> ContentPredicate:
    """Return the parsed content predicate a canonical content ID names."""
    for group in rule.sticky_groups:
        for predicate in group.predicates:
            if predicate.predicate_id == predicate_id:
                return predicate
    raise ValueError(f"unknown canonical content predicate: {predicate_id}")


def canonical_modifier(
    rule: ParsedRule, predicate_id: str
) -> tuple[ContentPredicate, Modifier]:
    """Return the content and modifier a canonical `content-N-name` ID names."""
    record = canonical_rule_predicates(rule).get(predicate_id)
    if record is None or record.get("kind") != "content_modifier":
        raise ValueError(f"unknown canonical content modifier: {predicate_id}")
    owner = canonical_content_predicate(rule, str(record["owner_content_id"]))
    span = record["source_span"]
    modifier = next(
        (
            item
            for item in owner.modifiers
            if item.span.start == span["start"] and item.span.end == span["end"]
        ),
        None,
    )
    if modifier is None:
        raise ValueError(f"canonical modifier {predicate_id} has no parsed modifier")
    return owner, modifier


def released_modifier_record(
    rule: ParsedRule, modifier: Modifier
) -> dict[str, object]:
    """Describe one relative modifier dropped to compensate an edited anchor."""
    from hardening_game.predicates import predicate_ids_for_option

    option_index = option_index_of(rule, modifier.span)
    return {
        "operation": "release",
        "constraint": modifier.name,
        "option_index": option_index,
        "predicate_id": predicate_ids_for_option(rule, option_index)[0],
        "from": modifier.value,
        "to": None,
    }


def depends_on_previous_match(option: RuleOption) -> bool:
    """Return whether an option anchors itself to the preceding match endpoint.

    Positional modifiers anchor implicitly; every other relative test is
    delegated to the parser so `relative` and PCRE `/R` have one definition.
    """
    if option.name in {"distance", "within"}:
        return True
    return is_relative_consumer(option)
