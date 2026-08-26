"""Content representation, adjacent split, retention, and removal variants."""

from __future__ import annotations

from hardening_game.mutations.dependencies import (
    content_dependency_group,
    downstream_endpoint_consumers,
)
from hardening_game.mutations.families import (
    require_source_spelling,
    apply_edits,
    canonical_content_predicate,
    content_hex_mask,
    decode_content_token,
    is_printable_literal,
    leading_whitespace,
    predicate_tags,
    predicate_tail,
    released_modifier_record,
    remove_spans,
    render_byte_mask,
    render_content,
    replace_span,
)
from hardening_game.mutations.specifications import (
    MutationSpec,
    RejectedSpec,
    rejected_spec,
)
from hardening_game.suricata.rule_model import (
    ContentPredicate,
    Modifier,
    ParsedRule,
    RuleOption,
)
from typing import Mapping


EndpointConsumers = tuple[RuleOption | Modifier, ...]


RETENTION_FRACTIONS = (0.75, 0.5, 0.25)
ALTERNATING_BLOCK = 4
_MULTI_FRAGMENT_MODIFIERS = {
    "nocase",
    "fast_pattern",
    "distance",
    "within",
    "offset",
    "depth",
    "startswith",
}
_SLICE_OPERATORS = ("shorten_prefix", "shorten_suffix", "retain_middle")
_FRAGMENT_OPERATORS = ("retain_alternating", "split_adjacent")


def generate(
    rule: ParsedRule, *, fixture_name: str
) -> tuple[MutationSpec | RejectedSpec, ...]:
    """Emit one-component content edits for every parsed content predicate."""
    specifications: list[MutationSpec | RejectedSpec] = []
    for group in rule.sticky_groups:
        for predicate in group.predicates:
            specifications.extend(
                _predicate_specifications(rule, predicate, fixture_name=fixture_name)
            )
    return tuple(specifications)


def _reject(
    predicate: ContentPredicate,
    *,
    fixture_name: str,
    operator: str,
    reason: str,
    diagnostic: str,
) -> RejectedSpec:
    return rejected_spec(
        fixture_name=fixture_name,
        component="content",
        operator=operator,
        params={**predicate_tags(predicate), "operation": operator},
        reason=reason,
        diagnostic=diagnostic,
    )


def _predicate_specifications(
    rule: ParsedRule, predicate: ContentPredicate, *, fixture_name: str
) -> list[MutationSpec | RejectedSpec]:
    specifications: list[MutationSpec | RejectedSpec] = []
    endpoint_consumers = predicate.relative_consumers + downstream_endpoint_consumers(
        rule, predicate.predicate_id
    )
    if predicate.value is None:
        specifications.append(
            _reject(
                predicate,
                fixture_name=fixture_name,
                operator="shorten_prefix",
                reason="unsupported",
                diagnostic="content contains escapes or unsupported byte syntax",
            )
        )
    else:
        specifications.extend(
            _representation_specifications(rule, predicate)
        )
        if predicate.negated:
            specifications.extend(
                _reject(
                    predicate,
                    fixture_name=fixture_name,
                    operator=operator,
                    reason="unsupported",
                    diagnostic=(
                        "negated content cannot be shortened or split because a "
                        "partial negative match is not implied by the original"
                    ),
                )
                for operator in (*_SLICE_OPERATORS, *_FRAGMENT_OPERATORS)
            )
        else:
            specifications.extend(
                _slice_specifications(
                    rule,
                    predicate,
                    fixture_name=fixture_name,
                    endpoint_consumers=endpoint_consumers,
                )
            )
            specifications.extend(
                _fragment_specifications(
                    rule,
                    predicate,
                    fixture_name=fixture_name,
                    endpoint_consumers=endpoint_consumers,
                )
            )
    if not predicate.negated:
        specifications.append(
            _removal_specification(
                rule,
                predicate,
                fixture_name=fixture_name,
                endpoint_consumers=endpoint_consumers,
            )
        )
    return specifications


def _representation_specifications(
    rule: ParsedRule, predicate: ContentPredicate
) -> list[MutationSpec]:
    assert predicate.value is not None
    leading = leading_whitespace(rule.source, predicate.span)
    specifications: list[MutationSpec] = []
    if predicate.representation in {"literal", "mixed"}:
        specifications.append(
            MutationSpec(
                component="content",
                operator="literal_as_hex",
                params={
                    **predicate_tags(predicate),
                    "operation": "literal_as_hex",
                    "representation": "hex",
                },
                description="Encode one content as equivalent hex bytes.",
                rule=replace_span(
                    rule.source,
                    predicate.span,
                    leading
                    + render_content(
                        predicate.value, hex_value=True, negated=predicate.negated
                    ),
                ),
            )
        )
    if predicate.representation == "hex" and is_printable_literal(predicate.value):
        specifications.append(
            MutationSpec(
                component="content",
                operator="hex_as_literal",
                params={
                    **predicate_tags(predicate),
                    "operation": "hex_as_literal",
                    "representation": "literal",
                },
                description="Decode one printable hex content to its literal form.",
                rule=replace_span(
                    rule.source,
                    predicate.span,
                    leading
                    + render_content(
                        predicate.value, hex_value=False, negated=predicate.negated
                    ),
                ),
            )
        )
    return specifications


def _slice_blocker(
    operator: str,
    modifier_names: set[str],
    endpoint_consumers: EndpointConsumers,
) -> str | None:
    if operator in {"shorten_prefix", "retain_middle"}:
        if "endswith" in modifier_names:
            return "endswith anchors this content to the buffer end"
        if endpoint_consumers:
            return "downstream consumers depend on this content endpoint: " + ", ".join(
                consumer.name for consumer in endpoint_consumers
            )
    if operator in {"shorten_suffix", "retain_middle"} and "startswith" in modifier_names:
        return "startswith anchors this content to the buffer start"
    return None


def _slice_bytes(operator: str, value: bytes, retained: int) -> bytes:
    if operator == "shorten_prefix":
        return value[:retained]
    if operator == "shorten_suffix":
        return value[len(value) - retained :]
    start = (len(value) - retained) // 2
    return value[start : start + retained]


def _slice_specifications(
    rule: ParsedRule,
    predicate: ContentPredicate,
    *,
    fixture_name: str,
    endpoint_consumers: EndpointConsumers,
) -> list[MutationSpec | RejectedSpec]:
    assert predicate.value is not None
    value = predicate.value
    modifier_names = {modifier.name for modifier in predicate.modifiers}
    leading = leading_whitespace(rule.source, predicate.span)
    is_hex = predicate.representation != "literal"
    specifications: list[MutationSpec | RejectedSpec] = []
    for operator in _SLICE_OPERATORS:
        blocker = _slice_blocker(operator, modifier_names, endpoint_consumers)
        if blocker is not None:
            specifications.append(
                _reject(
                    predicate,
                    fixture_name=fixture_name,
                    operator=operator,
                    reason="structural",
                    diagnostic=blocker,
                )
            )
            continue
        for fraction in RETENTION_FRACTIONS:
            retained = max(1, int(len(value) * fraction))
            if retained >= len(value):
                continue
            specifications.append(
                MutationSpec(
                    component="content",
                    operator=operator,
                    params={
                        **predicate_tags(predicate),
                        "operation": operator,
                        "retained_fraction": fraction,
                        "retained_length": retained,
                    },
                    description=f"Retain {retained} content bytes ({operator}).",
                    rule=replace_span(
                        rule.source,
                        predicate.span,
                        leading
                        + render_content(
                            _slice_bytes(operator, value, retained), hex_value=is_hex
                        ),
                    ),
                )
            )
    return specifications


def _fragment_blocker(
    modifier_names: set[str],
    *,
    endpoint_sensitive: bool,
    endpoint_consumers: EndpointConsumers,
) -> tuple[str, str] | None:
    if "endswith" in modifier_names:
        return "structural", "endswith anchors this content to the buffer end"
    unsupported = modifier_names - _MULTI_FRAGMENT_MODIFIERS
    if unsupported:
        return (
            "unsupported",
            "cannot re-attach modifiers to split fragments: "
            + ", ".join(sorted(unsupported)),
        )
    if endpoint_sensitive and endpoint_consumers:
        return (
            "structural",
            "downstream consumers depend on this content endpoint: "
            + ", ".join(consumer.name for consumer in endpoint_consumers),
        )
    return None


def _render_fragments(
    rule: ParsedRule,
    predicate: ContentPredicate,
    fragments: tuple[tuple[int, bytes], ...],
) -> str:
    """Render the leading fragment in place and anchor the rest by exact distance."""
    assert predicate.value is not None
    is_hex = predicate.representation != "literal"
    has_nocase = any(modifier.name == "nocase" for modifier in predicate.modifiers)
    nocase = " nocase;" if has_nocase else ""
    leading = leading_whitespace(rule.source, predicate.span)
    first_offset, first_value = fragments[0]
    trailing = ""
    previous_end = first_offset + len(first_value)
    for offset, value in fragments[1:]:
        trailing += (
            f" {render_content(value, hex_value=is_hex)}"
            f" distance:{offset - previous_end}; within:{len(value)};{nocase}"
        )
        previous_end = offset + len(value)
    tail = predicate_tail(predicate)
    return apply_edits(
        rule.source,
        (
            (
                predicate.span.start,
                predicate.span.end,
                leading + render_content(first_value, hex_value=is_hex),
            ),
            (tail, tail, trailing),
        ),
    )


def _fragment_specifications(
    rule: ParsedRule,
    predicate: ContentPredicate,
    *,
    fixture_name: str,
    endpoint_consumers: EndpointConsumers,
) -> list[MutationSpec | RejectedSpec]:
    assert predicate.value is not None
    value = predicate.value
    modifier_names = {modifier.name for modifier in predicate.modifiers}
    specifications: list[MutationSpec | RejectedSpec] = []

    if len(value) >= 2:
        blocker = _fragment_blocker(
            modifier_names,
            endpoint_sensitive=False,
            endpoint_consumers=endpoint_consumers,
        )
        if blocker is None:
            middle = len(value) // 2
            specifications.append(
                MutationSpec(
                    component="content",
                    operator="split_adjacent",
                    params={
                        **predicate_tags(predicate),
                        "operation": "split_adjacent",
                        "lengths": [middle, len(value) - middle],
                    },
                    description="Split one content into two adjacent checks.",
                    rule=_render_fragments(
                        rule,
                        predicate,
                        ((0, value[:middle]), (middle, value[middle:])),
                    ),
                )
            )
        else:
            reason, diagnostic = blocker
            specifications.append(
                _reject(
                    predicate,
                    fixture_name=fixture_name,
                    operator="split_adjacent",
                    reason=reason,
                    diagnostic=diagnostic,
                )
            )

    if len(value) < 2 * ALTERNATING_BLOCK:
        return specifications
    blocker = _fragment_blocker(
        modifier_names,
        endpoint_sensitive=True,
        endpoint_consumers=endpoint_consumers,
    )
    if blocker is not None:
        reason, diagnostic = blocker
        specifications.append(
            _reject(
                predicate,
                fixture_name=fixture_name,
                operator="retain_alternating",
                reason=reason,
                diagnostic=diagnostic,
            )
        )
        return specifications
    for fraction in RETENTION_FRACTIONS:
        retained_per_block = round(ALTERNATING_BLOCK * fraction)
        if not 1 <= retained_per_block < ALTERNATING_BLOCK:
            continue
        fragments = tuple(
            (offset, value[offset : offset + retained_per_block])
            for offset in range(0, len(value), ALTERNATING_BLOCK)
        )
        fragments = tuple(fragment for fragment in fragments if fragment[1])
        if len(fragments) < 2:
            continue
        specifications.append(
            MutationSpec(
                component="content",
                operator="retain_alternating",
                params={
                    **predicate_tags(predicate),
                    "operation": "retain_alternating",
                    "retained_fraction": fraction,
                    "retained_length": sum(len(part) for _offset, part in fragments),
                },
                description=(
                    f"Retain {retained_per_block} of every {ALTERNATING_BLOCK} "
                    "content bytes at their original positions."
                ),
                rule=_render_fragments(rule, predicate, fragments),
            )
        )
    return specifications


def _removal_specification(
    rule: ParsedRule,
    predicate: ContentPredicate,
    *,
    fixture_name: str,
    endpoint_consumers: EndpointConsumers,
) -> MutationSpec | RejectedSpec:
    if endpoint_consumers:
        return _reject(
            predicate,
            fixture_name=fixture_name,
            operator="remove",
            reason="structural",
            diagnostic=(
                "downstream consumers prevent content removal: "
                + ", ".join(consumer.name for consumer in endpoint_consumers)
            ),
        )
    dependency = content_dependency_group(rule, predicate.predicate_id)
    return MutationSpec(
        component="content",
        operator="remove",
        params={**predicate_tags(predicate), "operation": "remove"},
        description="Remove this content dependency group.",
        rule=remove_spans(rule.source, dependency.spans),
    )


# ---------------------------------------------------------------------------
# Clue-targeted operators
#
# The generic matrix cuts content at fixed fractions of its length and splits
# it at its midpoint, which lands inside vendor and endpoint tokens.  The
# operators below are driven by a reviewed recipe that names the exact token
# boundary, so a reduction can be read as "the endpoint survives but the
# product name does not" rather than "seven bytes survive".
# ---------------------------------------------------------------------------


def _targeted_reject(
    *,
    fixture_name: str,
    operator: str,
    params: dict[str, object],
    reason: str,
    diagnostic: str,
) -> RejectedSpec:
    return rejected_spec(
        fixture_name=fixture_name,
        component="content",
        operator=operator,
        params=params,
        reason=reason,
        diagnostic=diagnostic,
    )


def _target(
    rule: ParsedRule, params: Mapping[str, object]
) -> ContentPredicate:
    predicate_id = params.get("predicate_id")
    if not isinstance(predicate_id, str):
        raise ValueError("targeted content operators require a predicate_id")
    predicate = canonical_content_predicate(rule, predicate_id)
    if predicate.value is None:
        raise ValueError(
            f"content {predicate_id} has no decodable value to edit"
        )
    return predicate


def _boundary_reduction(
    rule: ParsedRule,
    params: Mapping[str, object],
    *,
    fixture_name: str,
    operator: str,
) -> MutationSpec | RejectedSpec:
    predicate = _target(rule, params)
    assert predicate.value is not None
    token = params.get("boundary")
    if not isinstance(token, str):
        raise ValueError(f"content/{operator} requires a boundary content literal")
    retained = decode_content_token(token, field=f"content/{operator} boundary")
    keeps_prefix = operator == "retain_boundary_prefix"
    fits = (
        predicate.value.startswith(retained)
        if keeps_prefix
        else predicate.value.endswith(retained)
    )
    if fits and retained != predicate.value:
        require_source_spelling(
            token,
            rule=rule,
            predicate=predicate,
            offset=0 if keeps_prefix else len(predicate.value) - len(retained),
            length=len(retained),
            field=f"content/{operator} boundary",
        )
    identity: dict[str, object] = {
        **predicate_tags(predicate),
        "operation": operator,
        "boundary": token,
        "retained_length": len(retained),
    }
    if not fits or retained == predicate.value:
        raise ValueError(
            f"content/{operator} boundary {token!r} is not a proper "
            f"{'prefix' if keeps_prefix else 'suffix'} of "
            f"{predicate.predicate_id} in {fixture_name}"
        )
    modifier_names = {modifier.name for modifier in predicate.modifiers}
    endpoint_consumers = predicate.relative_consumers + downstream_endpoint_consumers(
        rule, predicate.predicate_id
    )
    blocker = _slice_blocker(
        "shorten_prefix" if keeps_prefix else "shorten_suffix",
        modifier_names,
        endpoint_consumers,
    )
    if blocker is not None:
        return _targeted_reject(
            fixture_name=fixture_name,
            operator=operator,
            params=identity,
            reason="structural",
            diagnostic=blocker,
        )
    return MutationSpec(
        component="content",
        operator=operator,
        params=identity,
        description=(
            f"Reduce {predicate.predicate_id} to the reviewed token boundary "
            f"{token!r}."
        ),
        rule=replace_span(
            rule.source,
            predicate.span,
            leading_whitespace(rule.source, predicate.span)
            + f'content:{"!" if predicate.negated else ""}"{token}";',
        ),
    )


def retain_boundary_prefix(
    rule: ParsedRule, params: Mapping[str, object], *, fixture_name: str
) -> MutationSpec | RejectedSpec:
    """Keep only the leading tokens of a content up to a reviewed boundary."""
    return _boundary_reduction(
        rule, params, fixture_name=fixture_name, operator="retain_boundary_prefix"
    )


def retain_boundary_suffix(
    rule: ParsedRule, params: Mapping[str, object], *, fixture_name: str
) -> MutationSpec | RejectedSpec:
    """Keep only the trailing tokens of a content from a reviewed boundary."""
    return _boundary_reduction(
        rule, params, fixture_name=fixture_name, operator="retain_boundary_suffix"
    )


def partial_hex(
    rule: ParsedRule, params: Mapping[str, object], *, fixture_name: str
) -> MutationSpec | RejectedSpec:
    """Hex-encode one reviewed token in place, preserving every matched byte."""
    predicate = _target(rule, params)
    assert predicate.value is not None
    token = params.get("hex_token")
    if not isinstance(token, str):
        raise ValueError("content/partial_hex requires a hex_token content literal")
    run = decode_content_token(token, field="content/partial_hex hex_token")
    occurrences = [
        offset
        for offset in range(len(predicate.value) - len(run) + 1)
        if predicate.value[offset : offset + len(run)] == run
    ]
    if len(occurrences) != 1:
        raise ValueError(
            f"content/partial_hex token {token!r} occurs {len(occurrences)} times "
            f"in {predicate.predicate_id}; it must occur exactly once"
        )
    start = occurrences[0]
    require_source_spelling(
        token,
        rule=rule,
        predicate=predicate,
        offset=start,
        length=len(run),
        field="content/partial_hex hex_token",
    )
    mask = content_hex_mask(rule, predicate)
    if all(mask[start : start + len(run)]):
        raise ValueError(
            f"content/partial_hex token {token!r} is already written as hex in "
            f"{predicate.predicate_id}"
        )
    for offset in range(start, start + len(run)):
        mask[offset] = True
    return MutationSpec(
        component="content",
        operator="partial_hex",
        params={
            **predicate_tags(predicate),
            "operation": "partial_hex",
            "hex_token": token,
            "hex_offset": start,
            "representation": "mixed",
        },
        description=(
            f"Rewrite {token!r} inside {predicate.predicate_id} as hex bytes "
            "without changing what the rule matches."
        ),
        rule=replace_span(
            rule.source,
            predicate.span,
            leading_whitespace(rule.source, predicate.span)
            + render_byte_mask(predicate.value, mask, negated=predicate.negated),
        ),
    )


def split_at_token(
    rule: ParsedRule, params: Mapping[str, object], *, fixture_name: str
) -> MutationSpec | RejectedSpec:
    """Split a content into two adjacent checks at a reviewed token boundary."""
    predicate = _target(rule, params)
    assert predicate.value is not None
    token = params.get("boundary")
    if not isinstance(token, str):
        raise ValueError("content/split_at_token requires a boundary content literal")
    head = decode_content_token(token, field="content/split_at_token boundary")
    if not predicate.value.startswith(head) or head == predicate.value:
        raise ValueError(
            f"content/split_at_token boundary {token!r} is not a proper prefix of "
            f"{predicate.predicate_id} in {fixture_name}"
        )
    require_source_spelling(
        token,
        rule=rule,
        predicate=predicate,
        offset=0,
        length=len(head),
        field="content/split_at_token boundary",
    )
    identity: dict[str, object] = {
        **predicate_tags(predicate),
        "operation": "split_at_token",
        "boundary": token,
        "lengths": [len(head), len(predicate.value) - len(head)],
    }
    blocker = _fragment_blocker(
        {modifier.name for modifier in predicate.modifiers},
        endpoint_sensitive=False,
        endpoint_consumers=(),
    )
    if blocker is not None:
        reason, diagnostic = blocker
        return _targeted_reject(
            fixture_name=fixture_name,
            operator="split_at_token",
            params=identity,
            reason=reason,
            diagnostic=diagnostic,
        )
    return MutationSpec(
        component="content",
        operator="split_at_token",
        params=identity,
        description=(
            f"Split {predicate.predicate_id} into adjacent checks at {token!r}."
        ),
        rule=_render_fragments(
            rule,
            predicate,
            ((0, head), (len(head), predicate.value[len(head) :])),
        ),
    )


def remove_with_relative_release(
    rule: ParsedRule, params: Mapping[str, object], *, fixture_name: str
) -> MutationSpec | RejectedSpec:
    """Remove an anchor content and free the constraints that depended on it."""
    predicate = _target(rule, params)
    identity: dict[str, object] = {
        **predicate_tags(predicate),
        "operation": "remove_with_relative_release",
    }
    blockers = tuple(
        consumer.name
        for consumer in predicate.relative_consumers
    )
    if blockers:
        return _targeted_reject(
            fixture_name=fixture_name,
            operator="remove_with_relative_release",
            params=identity,
            reason="structural",
            diagnostic=(
                "this content owns relative consumers that cannot be released by "
                "dropping a positional modifier: " + ", ".join(blockers)
            ),
        )
    successor = downstream_endpoint_consumers(rule, predicate.predicate_id)
    if not successor:
        return _targeted_reject(
            fixture_name=fixture_name,
            operator="remove_with_relative_release",
            params=identity,
            reason="unsupported",
            diagnostic=(
                "no relative dependent follows this content, so the generic "
                "content/remove operator already covers it"
            ),
        )
    dependency = content_dependency_group(rule, predicate.predicate_id)
    compensation = [released_modifier_record(rule, modifier) for modifier in successor]
    return MutationSpec(
        component="content",
        operator="remove_with_relative_release",
        params={**identity, "compensation": compensation},
        description=(
            f"Remove {predicate.predicate_id} and release the "
            + ", ".join(modifier.name for modifier in successor)
            + " constraint that anchored to it."
        ),
        rule=remove_spans(
            rule.source,
            dependency.spans + tuple(modifier.span for modifier in successor),
        ),
    )


TARGETED_OPERATORS = {
    "content/retain_boundary_prefix": retain_boundary_prefix,
    "content/retain_boundary_suffix": retain_boundary_suffix,
    "content/partial_hex": partial_hex,
    "content/split_at_token": split_at_token,
    "content/remove_with_relative_release": remove_with_relative_release,
}
