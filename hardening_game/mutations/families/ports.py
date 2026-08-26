"""Controlled destination-port broadening for literal, list, and variable headers.

`generate` covers the single bare numeric port and is the locked generic matrix.
The targeted operators additionally reach group headers such as
`[$HTTP_PORTS,5432]`, where the exact service port is itself the inference clue
but the surrounding variable cannot be widened arithmetically.
"""

from __future__ import annotations

import re
from typing import Mapping

from hardening_game.mutations.families import replace_span
from hardening_game.mutations.specifications import (
    MutationSpec,
    RejectedSpec,
    rejected_spec,
)
from hardening_game.suricata.rule_model import ParsedRule


# Suricata accepts port 0, so broadened ranges clamp to 0 rather than to 1.
MINIMUM_PORT = 0
MAXIMUM_PORT = 65535
_PORT_LIST = re.compile(r"^\[(?P<members>[^\[\]]+)\]$")


def _clamp(port: int) -> int:
    return max(MINIMUM_PORT, min(MAXIMUM_PORT, port))


def _reject(
    *, fixture_name: str, operator: str, params: dict[str, object], diagnostic: str
) -> RejectedSpec:
    return rejected_spec(
        fixture_name=fixture_name,
        component="destination_port",
        operator=operator,
        params=params,
        reason="unsupported",
        diagnostic=diagnostic,
    )


def broaden_group_members(
    rule: ParsedRule, params: Mapping[str, object], *, fixture_name: str
) -> MutationSpec | RejectedSpec:
    """Widen every bare numeric member of a destination-port group by a margin."""
    port = rule.header.destination_port
    margin = params.get("margin")
    if not isinstance(margin, int) or isinstance(margin, bool) or margin < 1:
        raise ValueError("destination_port/broaden_group_members requires margin >= 1")
    identity: dict[str, object] = {
        "operation": "broaden_group_members",
        "from": port,
        "margin": margin,
        "predicate_id": "header-dst-port",
    }
    group = _PORT_LIST.fullmatch(port)
    if group is None:
        return _reject(
            fixture_name=fixture_name,
            operator="broaden_group_members",
            params=identity,
            diagnostic=(
                f"destination port {port} is not a bracketed group, so a member "
                "cannot be widened in place"
            ),
        )
    members = [member.strip() for member in group.group("members").split(",")]
    if not any(member.isdigit() for member in members):
        return _reject(
            fixture_name=fixture_name,
            operator="broaden_group_members",
            params=identity,
            diagnostic=(
                f"destination port group {port} has no bare numeric member whose "
                "broadening can be derived from the rule text"
            ),
        )
    widened = [
        f"{_clamp(int(member) - margin)}:{_clamp(int(member) + margin)}"
        if member.isdigit()
        else member
        for member in members
    ]
    replacement = f"[{','.join(widened)}]"
    return MutationSpec(
        component="destination_port",
        operator="broaden_group_members",
        params={**identity, "to": replacement},
        description=(
            f"Broaden each numeric destination-port group member by {margin}."
        ),
        rule=replace_span(
            rule.source, rule.header.destination_port_span, replacement
        ),
    )


def broaden_to_any(
    rule: ParsedRule, params: Mapping[str, object], *, fixture_name: str
) -> MutationSpec | RejectedSpec:
    """Replace a whole destination-port expression, however written, with `any`."""
    port = rule.header.destination_port
    identity: dict[str, object] = {
        "operation": "broaden_to_any",
        "from": port,
        "to": "any",
        "predicate_id": "header-dst-port",
    }
    if port.casefold() == "any":
        return _reject(
            fixture_name=fixture_name,
            operator="broaden_to_any",
            params=identity,
            diagnostic="destination port is already any",
        )
    return MutationSpec(
        component="destination_port",
        operator="broaden_to_any",
        params=identity,
        description="Broaden the whole destination-port expression to any.",
        rule=replace_span(rule.source, rule.header.destination_port_span, "any"),
    )


TARGETED_OPERATORS = {
    "destination_port/broaden_group_members": broaden_group_members,
    "destination_port/broaden_to_any": broaden_to_any,
}


def generate(
    rule: ParsedRule, *, fixture_name: str
) -> tuple[MutationSpec | RejectedSpec, ...]:
    """Broaden one numeric destination port through four controlled levels."""
    port = rule.header.destination_port
    if port.casefold() == "any":
        return ()
    if not port.isdigit():
        return (
            rejected_spec(
                fixture_name=fixture_name,
                component="destination_port",
                operator="broaden",
                params={
                    "port": port,
                    "operation": "broaden",
                    "predicate_id": "header-dst-port",
                },
                reason="unsupported",
                diagnostic=(
                    f"destination port {port} is a group, variable, negation, or "
                    "range whose broadening cannot be derived from the rule text"
                ),
            ),
        )

    number = int(port)
    levels: list[tuple[str, str, str]] = []
    if number < MAXIMUM_PORT:
        levels.append(
            (
                "small_list",
                f"[{number},{number + 1}]",
                "Extend the destination port to the adjacent port.",
            )
        )
    levels.extend(
        (
            (
                "narrow_range",
                f"{_clamp(number - 2)}:{_clamp(number + 2)}",
                "Broaden the destination port to a narrow numeric range.",
            ),
            (
                "broad_range",
                f"{_clamp(number - 8)}:{_clamp(number + 8)}",
                "Broaden the destination port to a wider numeric range.",
            ),
            ("any", "any", "Broaden the destination port to any."),
        )
    )
    return tuple(
        MutationSpec(
            component="destination_port",
            operator=operator,
            params={
                "operation": "broaden",
                "from": port,
                "to": replacement,
                "predicate_id": "header-dst-port",
            },
            description=description,
            rule=replace_span(
                rule.source, rule.header.destination_port_span, replacement
            ),
        )
        for operator, replacement, description in levels
        if replacement != port
    )
