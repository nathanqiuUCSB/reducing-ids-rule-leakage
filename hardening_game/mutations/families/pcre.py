"""Conservative PCRE removal, anchor relaxation, and targeted pattern widening."""

from __future__ import annotations

import re
from typing import Mapping

from hardening_game.mutations.families import (
    RELEASABLE_MODIFIERS,
    canonical_option,
    depends_on_previous_match,
    is_sticky_declaration,
    leading_whitespace,
    released_modifier_record,
    remove_spans,
    replace_span,
)
from hardening_game.mutations.specifications import (
    MutationSpec,
    RejectedSpec,
    rejected_spec,
)
from hardening_game.predicates import predicate_ids_for_option
from hardening_game.suricata.rule_model import Modifier, ParsedRule, RuleOption


def _pcre_parts(value: str | None) -> tuple[str, str] | None:
    """Return (body, flags) only for the plain quoted /pattern/flags grammar."""
    if value is None:
        return None
    text = value.strip()
    if len(text) < 2 or not text.startswith('"') or not text.endswith('"'):
        return None
    inner = text[1:-1]
    closing = inner.rfind("/")
    if not inner.startswith("/") or closing <= 0:
        return None
    body, flags = inner[1:closing], inner[closing + 1 :]
    if not body or (flags and not flags.isalpha()):
        return None
    return body, flags


def _has_end_anchor(body: str) -> bool:
    if not body.endswith("$") or len(body) < 2:
        return False
    escapes = len(body) - 1 - len(body[:-1].rstrip("\\"))
    return escapes % 2 == 0


def _following_dependents(rule: ParsedRule, option: RuleOption) -> tuple[RuleOption, ...]:
    """Return later options in the same buffer anchored to the preceding match."""
    dependents: list[RuleOption] = []
    for other in rule.options:
        if other.option_index <= option.option_index:
            continue
        if is_sticky_declaration(other):
            break
        if depends_on_previous_match(other):
            dependents.append(other)
    return tuple(dependents)


def _relaxation_specifications(
    rule: ParsedRule, option: RuleOption, *, fixture_name: str
) -> list[MutationSpec | RejectedSpec]:
    predicate_id = predicate_ids_for_option(rule, option.option_index)[0]
    parts = _pcre_parts(option.value)
    if parts is None:
        return [
            rejected_spec(
                fixture_name=fixture_name,
                component="pcre",
                operator="relax_anchor",
                params={
                    "option_index": option.option_index,
                    "operation": "relax_anchor",
                    "predicate_id": predicate_id,
                },
                reason="unsupported",
                diagnostic=(
                    f"pcre value {option.value!r} does not use the recognized "
                    "quoted /pattern/flags grammar"
                ),
            )
        ]
    body, flags = parts
    relaxations: list[tuple[str, str, str]] = []
    if body.startswith("^") and len(body) > 1:
        relaxations.append(
            ("relax_start_anchor", body[1:], "Relax the PCRE start anchor.")
        )
    if _has_end_anchor(body):
        relaxations.append(
            ("relax_end_anchor", body[:-1], "Relax the PCRE end anchor.")
        )
    return [
        MutationSpec(
            component="pcre",
            operator=operator,
            params={
                "option_index": option.option_index,
                "operation": operator,
                "predicate_id": predicate_id,
            },
            description=description,
            rule=replace_span(
                rule.source,
                option.span,
                leading_whitespace(rule.source, option.span)
                + f'pcre:"/{relaxed}/{flags}";',
            ),
        )
        for operator, relaxed, description in relaxations
    ]


def generate(
    rule: ParsedRule, *, fixture_name: str
) -> tuple[MutationSpec | RejectedSpec, ...]:
    """Remove or anchor-relax one PCRE when nothing downstream depends on it."""
    specifications: list[MutationSpec | RejectedSpec] = []
    for option in rule.options:
        if option.name != "pcre":
            continue
        dependents = _following_dependents(rule, option)
        params = {
            "option_index": option.option_index,
            "operation": "remove",
            "predicate_id": predicate_ids_for_option(rule, option.option_index)[0],
        }
        if dependents:
            specifications.append(
                rejected_spec(
                    fixture_name=fixture_name,
                    component="pcre",
                    operator="remove",
                    params=params,
                    reason="structural",
                    diagnostic=(
                        "later options anchor themselves to this PCRE match: "
                        + ", ".join(dependent.name for dependent in dependents)
                    ),
                )
            )
        else:
            specifications.append(
                MutationSpec(
                    component="pcre",
                    operator="remove",
                    params=params,
                    description="Remove one PCRE with no relative dependency.",
                    rule=remove_spans(rule.source, (option.span,)),
                )
            )
        specifications.extend(
            _relaxation_specifications(rule, option, fixture_name=fixture_name)
        )
    return tuple(specifications)


# ---------------------------------------------------------------------------
# Clue-targeted operators
#
# The generic matrix only removes a PCRE outright or drops its `^`/`$` anchors.
# Several ranked clues are carried by material inside the pattern — a product
# path such as `MICROS`, an affected-version class such as `[1-6]`, or a
# proximity window such as `.{0,10}` — and those need edits that keep the
# pattern executable and still matching the baseline traffic.
# ---------------------------------------------------------------------------

_ONE_BYTE_LITERAL = re.compile(r"^[A-Za-z0-9_\-]+$")
_HEX = frozenset("0123456789abcdefABCDEF")
_BOUNDED_QUANTIFIER = re.compile(r"^\{(?P<low>\d+),(?P<high>\d+)\}$")
_SIMPLE_CLASS = re.compile(r"^\[(?P<members>[A-Za-z0-9-]+)\]$")


def _targeted_option(
    rule: ParsedRule, params: Mapping[str, object]
) -> tuple[RuleOption, str, str]:
    predicate_id = params.get("predicate_id")
    if not isinstance(predicate_id, str):
        raise ValueError("targeted pcre operators require a predicate_id")
    option = canonical_option(rule, predicate_id)
    if option.name != "pcre":
        raise ValueError(f"{predicate_id} is not a pcre option")
    parts = _pcre_parts(option.value)
    if parts is None:
        raise ValueError(
            f"pcre value {option.value!r} does not use the recognized quoted "
            "/pattern/flags grammar"
        )
    return option, parts[0], parts[1]


def _replaced(
    rule: ParsedRule,
    option: RuleOption,
    body: str,
    flags: str,
    *,
    operator: str,
    params: dict[str, object],
    description: str,
) -> MutationSpec:
    return MutationSpec(
        component="pcre",
        operator=operator,
        params=params,
        description=description,
        rule=replace_span(
            rule.source,
            option.span,
            leading_whitespace(rule.source, option.span) + f'pcre:"/{body}/{flags}";',
        ),
    )


def _class_members(expression: str) -> frozenset[str] | None:
    """Expand a simple positive character class into the characters it accepts."""
    match = _SIMPLE_CLASS.fullmatch(expression)
    if match is None:
        return None
    members = match.group("members")
    accepted: set[str] = set()
    index = 0
    while index < len(members):
        if index + 2 < len(members) and members[index + 1] == "-":
            start, end = members[index], members[index + 2]
            if ord(start) > ord(end):
                return None
            accepted.update(chr(point) for point in range(ord(start), ord(end) + 1))
            index += 3
            continue
        if members[index] == "-":
            return None
        accepted.add(members[index])
        index += 1
    return frozenset(accepted)


def plain_literal_spans(body: str) -> tuple[tuple[int, int], ...]:
    """Return the runs of pattern text that are neither escapes nor classes.

    A `.{n}` wildcard may only replace characters that stand for themselves.
    Text inside `[...]` is a class member list and text introduced by a
    backslash is part of an escape sequence, so substituting either one rewrites
    the pattern's structure instead of hiding a name: `[abc]` would become
    `[.{3}]`, and the `x2f` of `\\x2fabc` would become `\\.{3}abc`.

    A `\\Q...\\E` region is the third case.  Its characters are literal *because
    of the quoting*, so dropping a `.{n}` inside one would not be a wildcard at
    all: it would match the six characters `.`, `{`, `n`, `}` and the braces.
    """
    spans: list[tuple[int, int]] = []
    start: int | None = None
    index = 0
    in_class = False
    quoted = False
    while index < len(body):
        character = body[index]
        if character == "\\":
            if start is not None:
                spans.append((start, index))
                start = None
            introducer = body[index + 1] if index + 1 < len(body) else ""
            index += 2
            if introducer == "Q":
                quoted = True
                continue
            if introducer == "E":
                quoted = False
                continue
            if introducer == "x" and not quoted:
                # `\xhh` consumes up to two hex digits, so `\x2fabc` is one
                # escape followed by the plain run `abc`, never `fabc`.
                digits = 0
                while index < len(body) and digits < 2 and body[index] in _HEX:
                    index += 1
                    digits += 1
            continue
        if quoted:
            index += 1
            continue
        if in_class:
            if character == "]":
                in_class = False
            index += 1
            continue
        if character == "[":
            if start is not None:
                spans.append((start, index))
                start = None
            in_class = True
            index += 1
            continue
        if start is None:
            start = index
        index += 1
    if start is not None:
        spans.append((start, len(body)))
    return tuple(spans)


def generalize_literal_run(
    rule: ParsedRule, params: Mapping[str, object], *, fixture_name: str
) -> MutationSpec | RejectedSpec:
    """Replace a naming literal inside a pattern with an equal-length wildcard."""
    option, body, flags = _targeted_option(rule, params)
    literal = params.get("literal")
    if not isinstance(literal, str) or not _ONE_BYTE_LITERAL.fullmatch(literal):
        raise ValueError(
            "pcre/generalize_literal_run requires a literal run of characters that "
            "each match exactly one byte"
        )
    identity: dict[str, object] = {
        "option_index": option.option_index,
        "operation": "generalize_literal_run",
        "from": literal,
        "to": f".{{{len(literal)}}}",
        "predicate_id": params.get("predicate_id"),
    }
    if body.count(literal) != 1:
        return rejected_spec(
            fixture_name=fixture_name,
            component="pcre",
            operator="generalize_literal_run",
            params=identity,
            reason="unsupported",
            diagnostic=(
                f"literal run {literal!r} occurs {body.count(literal)} times in the "
                "pattern, so its replacement is not uniquely determined"
            ),
        )
    start = body.index(literal)
    end = start + len(literal)
    plain = plain_literal_spans(body)
    if not any(low <= start and end <= high for low, high in plain):
        return rejected_spec(
            fixture_name=fixture_name,
            component="pcre",
            operator="generalize_literal_run",
            params=identity,
            reason="structural",
            diagnostic=_containment_diagnostic(body, start, end, literal),
        )
    return _replaced(
        rule,
        option,
        body[:start] + f".{{{len(literal)}}}" + body[end:],
        flags,
        operator="generalize_literal_run",
        params=identity,
        description=(
            f"Replace the {literal!r} run in the pattern with a wildcard of the "
            "same length."
        ),
    )


def _containment_diagnostic(body: str, start: int, end: int, literal: str) -> str:
    """Say which of the three structures the run landed in."""
    if _within_quoted_literal(body, start, end):
        return (
            f"literal run {literal!r} lies inside a \\Q...\\E quoted literal "
            "region, where a wildcard would be matched as literal text"
        )
    if _within_character_class(body, start, end):
        return (
            f"literal run {literal!r} lies inside a character class, so "
            "replacing it would rewrite the class rather than hide a name"
        )
    return (
        f"literal run {literal!r} overlaps an escape sequence, so replacing it "
        "would corrupt the escape rather than hide a name"
    )


def _within_quoted_literal(body: str, start: int, end: int) -> bool:
    r"""Return whether any of `body[start:end]` sits between `\Q` and `\E`."""
    quoted = False
    index = 0
    while index < len(body):
        if body[index] == "\\" and index + 1 < len(body):
            introducer = body[index + 1]
            if introducer == "Q":
                quoted = True
                index += 2
                continue
            if introducer == "E":
                quoted = False
                index += 2
                continue
            index += 2
            continue
        if quoted and start <= index < end:
            return True
        index += 1
    return False


def _within_character_class(body: str, start: int, end: int) -> bool:
    """Return whether any of `body[start:end]` sits between `[` and `]`."""
    in_class = False
    index = 0
    while index < len(body):
        if body[index] == "\\":
            index += 2
            continue
        if in_class:
            if body[index] == "]":
                in_class = False
            elif start <= index < end:
                return True
            index += 1
            continue
        if body[index] == "[":
            in_class = True
        index += 1
    return False


def widen_quantifier(
    rule: ParsedRule, params: Mapping[str, object], *, fixture_name: str
) -> MutationSpec | RejectedSpec:
    """Raise the upper bound of one bounded proximity window inside a pattern."""
    option, body, flags = _targeted_option(rule, params)
    quantifier = params.get("quantifier")
    upper = params.get("upper")
    match = (
        _BOUNDED_QUANTIFIER.fullmatch(quantifier)
        if isinstance(quantifier, str)
        else None
    )
    if match is None or not isinstance(upper, int) or isinstance(upper, bool):
        raise ValueError(
            "pcre/widen_quantifier requires a {low,high} quantifier and an integer "
            "upper bound"
        )
    low, high = int(match.group("low")), int(match.group("high"))
    replacement = f"{{{low},{upper}}}"
    identity: dict[str, object] = {
        "option_index": option.option_index,
        "operation": "widen_quantifier",
        "from": quantifier,
        "to": replacement,
        "direction": "broadening",
        "predicate_id": params.get("predicate_id"),
    }
    if upper <= high:
        return rejected_spec(
            fixture_name=fixture_name,
            component="pcre",
            operator="widen_quantifier",
            params=identity,
            reason="unsupported",
            diagnostic=(
                f"upper bound {upper} does not widen the existing window {quantifier}"
            ),
        )
    if body.count(quantifier) != 1:
        return rejected_spec(
            fixture_name=fixture_name,
            component="pcre",
            operator="widen_quantifier",
            params=identity,
            reason="unsupported",
            diagnostic=(
                f"quantifier {quantifier} occurs {body.count(quantifier)} times in "
                "the pattern, so its replacement is not uniquely determined"
            ),
        )
    return _replaced(
        rule,
        option,
        body.replace(quantifier, replacement),
        flags,
        operator="widen_quantifier",
        params=identity,
        description=f"Widen the {quantifier} proximity window to {replacement}.",
    )


def broaden_character_class(
    rule: ParsedRule, params: Mapping[str, object], *, fixture_name: str
) -> MutationSpec | RejectedSpec:
    """Replace a specific character class with a proven superset of it."""
    option, body, flags = _targeted_option(rule, params)
    original = params.get("character_class")
    replacement = params.get("replacement")
    if not isinstance(original, str) or not isinstance(replacement, str):
        raise ValueError(
            "pcre/broaden_character_class requires character_class and replacement"
        )
    identity: dict[str, object] = {
        "option_index": option.option_index,
        "operation": "broaden_character_class",
        "from": original,
        "to": replacement,
        "direction": "broadening",
        "predicate_id": params.get("predicate_id"),
    }
    accepted = _class_members(original)
    widened = _class_members(replacement)
    if accepted is None or widened is None:
        return rejected_spec(
            fixture_name=fixture_name,
            component="pcre",
            operator="broaden_character_class",
            params=identity,
            reason="unsupported",
            diagnostic=(
                "only simple positive character classes of literal characters and "
                "ranges can be compared for containment"
            ),
        )
    if not accepted < widened:
        return rejected_spec(
            fixture_name=fixture_name,
            component="pcre",
            operator="broaden_character_class",
            params=identity,
            reason="unsupported",
            diagnostic=(
                f"{replacement} is not a strict superset of {original}, so the "
                "baseline traffic is not guaranteed to keep matching"
            ),
        )
    if body.count(original) != 1:
        return rejected_spec(
            fixture_name=fixture_name,
            component="pcre",
            operator="broaden_character_class",
            params=identity,
            reason="unsupported",
            diagnostic=(
                f"character class {original} occurs {body.count(original)} times in "
                "the pattern, so its replacement is not uniquely determined"
            ),
        )
    return _replaced(
        rule,
        option,
        body.replace(original, replacement),
        flags,
        operator="broaden_character_class",
        params=identity,
        description=f"Broaden the {original} character class to {replacement}.",
    )


def _following_released_modifiers(
    rule: ParsedRule, option: RuleOption
) -> tuple[Modifier, ...]:
    """Return the next content's relative modifiers inside the same buffer."""
    for group in rule.sticky_groups:
        for predicate in group.predicates:
            if predicate.option_index <= option.option_index:
                continue
            if (
                group.declaration is not None
                and group.declaration.option_index > option.option_index
            ):
                continue
            return tuple(
                modifier
                for modifier in predicate.modifiers
                if modifier.name in RELEASABLE_MODIFIERS
            )
    return ()


def remove_with_relative_release(
    rule: ParsedRule, params: Mapping[str, object], *, fixture_name: str
) -> MutationSpec | RejectedSpec:
    """Remove a PCRE and free the following content that anchored to its match."""
    option, _body, _flags = _targeted_option(rule, params)
    identity: dict[str, object] = {
        "option_index": option.option_index,
        "operation": "remove_with_relative_release",
        "predicate_id": params.get("predicate_id"),
    }
    dependents = _following_dependents(rule, option)
    released = _following_released_modifiers(rule, option)
    unreleasable = tuple(
        dependent.name
        for dependent in dependents
        if dependent.name not in RELEASABLE_MODIFIERS
    )
    if unreleasable:
        return rejected_spec(
            fixture_name=fixture_name,
            component="pcre",
            operator="remove_with_relative_release",
            params=identity,
            reason="structural",
            diagnostic=(
                "later options anchor to this PCRE through constraints that cannot "
                "be released positionally: " + ", ".join(unreleasable)
            ),
        )
    if not released:
        return rejected_spec(
            fixture_name=fixture_name,
            component="pcre",
            operator="remove_with_relative_release",
            params=identity,
            reason="unsupported",
            diagnostic=(
                "no relative dependent follows this PCRE, so the generic "
                "pcre/remove operator already covers it"
            ),
        )
    compensation = [released_modifier_record(rule, modifier) for modifier in released]
    return MutationSpec(
        component="pcre",
        operator="remove_with_relative_release",
        params={**identity, "compensation": compensation},
        description=(
            "Remove this PCRE and release the "
            + ", ".join(modifier.name for modifier in released)
            + " constraint that anchored to its match."
        ),
        rule=remove_spans(
            rule.source,
            (option.span, *(modifier.span for modifier in released)),
        ),
    )


TARGETED_OPERATORS = {
    "pcre/generalize_literal_run": generalize_literal_run,
    "pcre/widen_quantifier": widen_quantifier,
    "pcre/broaden_character_class": broaden_character_class,
    "pcre/remove_with_relative_release": remove_with_relative_release,
}
