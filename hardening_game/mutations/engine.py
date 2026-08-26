"""Deterministic Smart Install-only Suricata mutation renderer.

This module intentionally renders a known fixture shape.  It is not a general
Suricata rewriter and does not use the conservative game semantic parser.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any

from hardening_game.mutations.families import remove_spans
from hardening_game.mutations.families import (
    byte_predicates,
    content as content_family,
    modifiers as modifier_family,
    pcre as pcre_family,
    ports as port_family,
    position as position_family,
)
from hardening_game.mutations.specifications import (
    CandidateSet,
    MutationSpec,
    RejectedSpec,
    identity_params,
    rejected_spec,
)
from hardening_game.suricata.rule_model import ParsedRule, parse_suricata_rule


HEADER_HEX = "00 00 00 01 00 00 00 01 00 00 00 07"
A_BYTES = "A" * 36
B_BYTES = "B" * 44
_REV = re.compile(r"\brev\s*:\s*\d+\s*;", re.IGNORECASE)
_FLOW_OPTION = re.compile(r"^\s*flow\s*:\s*(?P<value>[^;]+)\s*;$", re.IGNORECASE)
_BUFFER_BOUND_POSITIONAL_MODIFIERS = {"startswith", "endswith", "offset", "depth"}
_FAMILIES = (
    port_family,
    content_family,
    modifier_family,
    position_family,
    pcre_family,
    byte_predicates,
)


@dataclass(frozen=True)
class MutationCandidate:
    id: str
    component: str
    operator: str
    params: dict[str, Any]
    description: str
    rule: str
    revision: int
    fingerprint: str
    buffer: str | None = None
    option_index: int | None = None
    # Set only for candidates composed from a locked combination manifest.
    experiment_manifest_hash: str | None = None
    source_candidate_ids: tuple[str, ...] | None = None
    block_count: int | None = None


def canonical_fingerprint(rule: str) -> str:
    """Fingerprint source text without revision or inconsequential whitespace."""
    without_revision = _REV.sub("", rule)
    return " ".join(without_revision.split()).casefold()


def _content(value: str, *, hex_value: bool = False, modifiers: str = "") -> str:
    literal = f'"|{value}|"' if hex_value else f'"{value}"'
    return f"content:{literal}; {modifiers}".strip()


def _render(
    *,
    revision: int,
    port: str = "4786",
    flow: str = "established,to_server",
    header: tuple[tuple[str, bool, str], ...] | None = None,
    a_length: int | None = 36,
    b_length: int | None = 44,
    a_fragments: tuple[int, ...] | None = None,
    b_fragments: tuple[int, ...] | None = None,
    a_distance: int = 12,
    b_distance: int | None = None,
) -> str:
    """Render one limited, syntactically valid Smart Install rule."""
    header = header or ((HEADER_HEX, True, "depth:12;"),)
    options = [f"flow:{flow};"]
    options.extend(
        _content(value, hex_value=hex_value, modifiers=modifiers)
        for value, hex_value, modifiers in header
    )
    if a_fragments is None and a_length is not None:
        a_fragments = (a_length,)
    if b_fragments is None and b_length is not None:
        b_fragments = (b_length,)
    if a_fragments is not None:
        start = 0
        for index, length in enumerate(a_fragments):
            distance = a_distance if index == 0 else 0
            options.append(
                _content(
                    A_BYTES[start : start + length],
                    modifiers=f"distance:{distance}; within:{length};",
                )
            )
            start += length
    if b_fragments is not None:
        if b_distance is None:
            b_distance = 4 if a_fragments is not None else 52
        start = 0
        for index, length in enumerate(b_fragments):
            distance = b_distance if index == 0 else 0
            options.append(
                _content(
                    B_BYTES[start : start + length],
                    modifiers=f"distance:{distance}; within:{length};",
                )
            )
            start += length
    options.extend([f"sid:2025472;", f"rev:{revision};"])
    return f"alert tcp any any -> $HOME_NET {port} ({' '.join(options)})"


def _candidate(
    *,
    component: str,
    operator: str,
    params: dict[str, Any],
    description: str,
    rule: str,
    revision: int,
    id_prefix: str = "smart-install",
) -> MutationCandidate:
    identity = json.dumps(
        {
            "component": component,
            "operator": operator,
            "params": identity_params(params),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(identity.encode()).hexdigest()[:12]
    return MutationCandidate(
        id=f"{id_prefix}-{component}-{operator}-{digest}",
        component=component,
        operator=operator,
        params=params,
        description=description,
        rule=rule,
        revision=revision,
        fingerprint=canonical_fingerprint(rule),
        buffer=params.get("buffer") if isinstance(params.get("buffer"), str) else None,
        option_index=(
            params.get("option_index")
            if isinstance(params.get("option_index"), int)
            else None
        ),
    )


def generate_smart_install_candidates(
    baseline_rule: str, *, revision: int
) -> list[MutationCandidate]:
    """Return stable, deduplicated one-component candidates for Smart Install.

    ``baseline_rule`` is accepted to make the baseline explicit and to guard
    against accidentally evaluating another fixture.  The renderer deliberately
    does not parse or rewrite it.
    """
    if "sid:2025472" not in baseline_rule.replace(" ", ""):
        raise ValueError("Smart Install mutation engine requires SID 2025472")

    specifications: list[tuple[str, str, dict[str, Any], str, dict[str, Any]]] = [
        ("baseline", "original", {}, "Original Smart Install detection layout.", {}),
        (
            "header",
            "split_4_4_4",
            {},
            "Split the Smart Install header into three adjacent hex fragments.",
            {
                "header": (
                    ("00 00 00 01", True, "depth:4;"),
                    ("00 00 00 01", True, "distance:0; within:4;"),
                    ("00 00 00 07", True, "distance:0; within:4;"),
                )
            },
        ),
        (
            "header",
            "retain_first_8",
            {},
            "Retain only the first eight header bytes and compensate A distance.",
            {
                "header": (("00 00 00 01 00 00 00 01", True, "depth:8;"),),
                "a_distance": 16,
            },
        ),
        (
            "header",
            "retain_last_4",
            {},
            "Retain only the final header marker at its fixed offset.",
            {"header": (("00 00 00 07", True, "offset:8; depth:12;"),)},
        ),
        ("port", "any", {"port": "any"}, "Broaden the destination port.", {"port": "any"}),
        ("port", "range", {"port": "4786:4790"}, "Use a Smart Install port range.", {"port": "4786:4790"}),
        ("flow", "to_server", {}, "Drop the established flow requirement.", {"flow": "to_server"}),
        ("flow", "established", {}, "Drop the to-server flow requirement.", {"flow": "established"}),
        (
            "a_anchor",
            "split_a",
            {"length": 36},
            "Split the A anchor into adjacent fragments.",
            {
                "a_length": None,
                "a_fragments": (18, 18),
            },
        ),
        (
            "b_anchor",
            "split_b",
            {"length": 44},
            "Split the B anchor into adjacent fragments.",
            {"b_length": None, "b_fragments": (22, 22)},
        ),
    ]
    for length in (27, 18, 9):
        specifications.append(
            (
                "a_anchor",
                "truncate",
                {"length": length},
                f"Retain {length} A bytes and preserve B's absolute position.",
                {"a_length": length, "b_distance": 40 - length},
            )
        )
    specifications.append(
        (
            "a_anchor",
            "remove",
            {},
            "Remove A and compensate B relative to the header.",
            {"a_length": None, "b_distance": 52},
        )
    )
    for length in (33, 22, 11):
        specifications.append(
            (
                "b_anchor",
                "truncate",
                {"length": length},
                f"Retain the first {length} B bytes.",
                {"b_length": length},
            )
        )
    specifications.append(("b_anchor", "remove", {}, "Remove B.", {"b_length": None}))
    for distance in (0, 6, 18):
        specifications.append(
            (
                "position_window",
                "a_distance",
                {"distance": distance},
                "Move the A position window without changing its anchor.",
                {"a_distance": distance},
            )
        )

    candidates: list[MutationCandidate] = []
    fingerprints: set[str] = set()
    for index, (component, operator, params, description, render_kwargs) in enumerate(
        specifications
    ):
        candidate_revision = revision + index
        rule = _render(revision=candidate_revision, **render_kwargs)
        candidate = _candidate(
            component=component,
            operator=operator,
            params=params,
            description=description,
            rule=rule,
            revision=candidate_revision,
        )
        if candidate.fingerprint not in fingerprints:
            fingerprints.add(candidate.fingerprint)
            candidates.append(candidate)

    baseline = candidates[0]
    candidates[0] = MutationCandidate(
        id="smart-install-baseline",
        component=baseline.component,
        operator=baseline.operator,
        params=baseline.params,
        description=baseline.description,
        rule=baseline.rule,
        revision=baseline.revision,
        fingerprint=baseline.fingerprint,
        buffer=baseline.buffer,
        option_index=baseline.option_index,
    )
    return candidates


def _option_spans(rule: str) -> list[tuple[int, int]]:
    """Return semicolon-terminated option spans outside quoted content."""
    opening = rule.find("(")
    closing = rule.rfind(")")
    if opening < 0 or closing <= opening:
        return []

    spans: list[tuple[int, int]] = []
    start = opening + 1
    quoted = False
    escaped = False
    for index in range(start, closing):
        character = rule[index]
        if quoted and escaped:
            escaped = False
            continue
        if quoted and character == "\\":
            escaped = True
            continue
        if character == '"':
            quoted = not quoted
        elif character == ";" and not quoted:
            spans.append((start, index + 1))
            start = index + 1
    return spans


def _replace_option(rule: str, span: tuple[int, int], replacement: str) -> str:
    return rule[: span[0]] + replacement + rule[span[1] :]


def _with_revision(rule: str, revision: int) -> str:
    """Set the one existing revision field required by fixture metadata."""
    if not _REV.search(rule):
        raise ValueError("generic mutation engine requires a rule revision")
    return _REV.sub(f"rev:{revision};", rule, count=1)


def build_fixture_candidate(
    *,
    fixture_name: str,
    component: str,
    operator: str,
    params: dict[str, Any],
    description: str,
    rule: str,
    revision: int,
) -> MutationCandidate:
    candidate = _candidate(
        component=component,
        operator=operator,
        params=params,
        description=description,
        rule=_with_revision(rule, revision),
        revision=revision,
        id_prefix=fixture_name,
    )
    if component == "baseline":
        return MutationCandidate(
            id=f"{fixture_name}-baseline",
            component=candidate.component,
            operator=candidate.operator,
            params=candidate.params,
            description=candidate.description,
            rule=candidate.rule,
            revision=candidate.revision,
            fingerprint=candidate.fingerprint,
            buffer=candidate.buffer,
            option_index=candidate.option_index,
        )
    return candidate


def generate_baseline_candidate(
    baseline_rule: str, *, revision: int, fixture_name: str
) -> MutationCandidate:
    """Build only the original baseline without enumerating mutation families."""
    candidate_name = "smart-install" if fixture_name == "smart_install" else fixture_name
    return build_fixture_candidate(
        fixture_name=candidate_name,
        component="baseline",
        operator="original",
        params={},
        description="Original validated fixture rule.",
        rule=baseline_rule,
        revision=revision,
    )


def _sticky_buffer_specifications(
    parsed: ParsedRule, fixture_name: str
) -> list[MutationSpec | RejectedSpec]:
    """Enumerate sticky-buffer removals and their unsafe-reassignment rejections."""
    specifications: list[MutationSpec | RejectedSpec] = []
    for group_index, group in enumerate(parsed.sticky_groups):
        if group.declaration is not None:
            params = {
                "buffer": group.buffer,
                "option_index": group.declaration.option_index,
                "operation": "remove",
                "predicate_id": f"buffer-{group_index}",
            }
            relative_consumers = tuple(
                consumer
                for predicate in group.predicates
                for consumer in predicate.relative_consumers
            )
            buffer_bound_positionals = tuple(
                modifier
                for predicate in group.predicates
                for modifier in predicate.modifiers
                if modifier.name in _BUFFER_BOUND_POSITIONAL_MODIFIERS
            )
            predecessor = (
                parsed.sticky_groups[group_index - 1] if group_index else None
            )
            predecessor_has_buffer_constraint = (
                predecessor is not None and bool(predecessor.scoped_options)
            )
            predecessor_has_buffer_bound_positionals = (
                predecessor is not None
                and any(
                    modifier.name in _BUFFER_BOUND_POSITIONAL_MODIFIERS
                    for predicate in predecessor.predicates
                    for modifier in predicate.modifiers
                )
            )
            if (
                not group.buffer_constraints
                and not group.scoped_options
                and not relative_consumers
                and not buffer_bound_positionals
                and not predecessor_has_buffer_constraint
                and not predecessor_has_buffer_bound_positionals
            ):
                specifications.append(
                    MutationSpec(
                        component="sticky_buffer",
                        operator="remove",
                        params=params,
                        description=(
                            f"Remove sticky buffer {group.buffer} and reassign its contents."
                        ),
                        rule=remove_spans(parsed.source, (group.declaration.span,)),
                    )
                )
            else:
                diagnostic = (
                    f"sticky buffer {group.buffer} owns bsize and cannot be removed safely"
                    if group.buffer_constraints
                    else (
                        f"sticky buffer {group.buffer} has relative consumers"
                        if relative_consumers
                        else (
                            f"sticky buffer {group.buffer} relocates contents with "
                            "buffer-bound positional modifiers"
                            if buffer_bound_positionals
                            else (
                                f"sticky buffer {group.buffer} reassigns content to a constrained "
                                "preceding buffer"
                                if predecessor_has_buffer_constraint
                            else (
                                f"sticky buffer {group.buffer} relocates contents into a "
                                "preceding buffer with buffer-bound positional modifiers"
                                if predecessor_has_buffer_bound_positionals
                                else f"sticky buffer {group.buffer} has surviving buffer-scoped options"
                            )
                            )
                        )
                    )
                )
                specifications.append(
                    rejected_spec(
                        fixture_name=fixture_name,
                        component="sticky_buffer",
                        operator="remove",
                        params=params,
                        reason="structural",
                        diagnostic=diagnostic,
                    )
                )
    return specifications


def _flow_specifications(baseline_rule: str) -> list[MutationSpec]:
    """Relax one flow option without inferring protocol semantics."""
    for span in _option_spans(baseline_rule):
        option = baseline_rule[span[0] : span[1]]
        flow = _FLOW_OPTION.fullmatch(option)
        if flow is None:
            continue
        values = [value.strip() for value in flow.group("value").split(",") if value.strip()]
        lowered = [value.casefold() for value in values]
        specifications: list[MutationSpec] = []
        if "established" in lowered and len(values) > 1:
            retained = [value for value in values if value.casefold() != "established"]
            specifications.append(
                MutationSpec(
                    component="flow",
                    operator="remove_established",
                    params={
                        "removed": "established",
                        "predicate_id": "flow-established",
                    },
                    description="Remove only the established flow requirement.",
                    rule=_replace_option(
                        baseline_rule, span, f" flow:{','.join(retained)};"
                    ),
                )
            )
        directions = {"to_server", "to_client"}
        if any(value in directions for value in lowered) and len(values) > 1:
            retained = [value for value in values if value.casefold() not in directions]
            removed_direction = next(
                (value for value in lowered if value in directions), None
            )
            if removed_direction is None:
                raise ValueError("flow direction mutation lacks a direction predicate")
            specifications.append(
                MutationSpec(
                    component="flow",
                    operator="remove_direction",
                    params={
                        "removed": "direction",
                        "predicate_id": f"flow-{removed_direction}",
                    },
                    description="Remove only the flow direction requirement.",
                    rule=_replace_option(
                        baseline_rule, span, f" flow:{','.join(retained)};"
                    ),
                )
            )
        specifications.append(
            MutationSpec(
                component="flow",
                operator="remove",
                params={
                    "predicate_ids": [f"flow-{value}" for value in lowered if value]
                },
                description=(
                    "Remove the complete flow option without inferring protocol semantics."
                ),
                rule=_replace_option(baseline_rule, span, ""),
            )
        )
        return specifications
    return []


def generate_generic_candidates(
    baseline_rule: str, *, revision: int, fixture_name: str
) -> CandidateSet:
    """Generate deterministic accepted candidates and rejected unsafe specs."""
    parsed = parse_suricata_rule(baseline_rule)
    specifications: list[MutationSpec | RejectedSpec] = [
        MutationSpec(
            component="baseline",
            operator="original",
            params={},
            description="Original validated fixture rule.",
            rule=baseline_rule,
        )
    ]
    specifications.extend(_flow_specifications(baseline_rule))
    specifications.extend(_sticky_buffer_specifications(parsed, fixture_name))
    for family in _FAMILIES:
        specifications.extend(family.generate(parsed, fixture_name=fixture_name))

    candidates: list[MutationCandidate] = []
    rejections: list[RejectedSpec] = []
    fingerprints: set[str] = set()
    for specification in specifications:
        if isinstance(specification, RejectedSpec):
            rejections.append(specification)
            continue
        candidate = build_fixture_candidate(
            fixture_name=fixture_name,
            component=specification.component,
            operator=specification.operator,
            params=specification.params,
            description=specification.description,
            rule=specification.rule,
            revision=revision + len(candidates),
        )
        if candidate.fingerprint not in fingerprints:
            fingerprints.add(candidate.fingerprint)
            candidates.append(candidate)
    return CandidateSet(accepted=tuple(candidates), rejected=tuple(rejections))
