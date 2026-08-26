"""Legacy response contracts and prompts retained for artifact compatibility."""

from __future__ import annotations

from dataclasses import dataclass
import json
import logging
import re
from typing import Callable, Protocol

import httpx
from openai import OpenAI


log = logging.getLogger(__name__)

ATTACKER_PROMPT_VERSION = "ranked-clues-sanitized-rule-v2"
ATTACKER_RESPONSE_SCHEMA_VERSION = 3
ATTACKER_RULE_SANITIZER_VERSION = "suricata-metadata-options-v2"
_ATTACKER_HIDDEN_RULE_OPTIONS = frozenset(
    {"sid", "rev", "gid", "reference", "metadata", "msg", "classtype"}
)


@dataclass(frozen=True)
class RankedAttackerClue:
    description: str
    rule_evidence: list[str]


@dataclass(frozen=True)
class PreparedAttackerInput:
    visible_rule: str
    prompt: str


class _RankedClueDescriptions(list[str]):
    """Legacy string clues carrying structured evidence outside dataclass fields."""

    def __init__(
        self,
        descriptions: object = (),
        *,
        ranked_clues: list[RankedAttackerClue] | None = None,
    ) -> None:
        super().__init__(descriptions)  # type: ignore[arg-type]
        self.ranked_clues = ranked_clues


@dataclass(frozen=True)
class AttackerResponse:
    predicted_cve: str
    reasoning: str
    clues: list[str]

    @property
    def ranked_clues(self) -> list[RankedAttackerClue] | None:
        return getattr(self.clues, "ranked_clues", None)


def attacker_response_payload(response: AttackerResponse) -> dict[str, object]:
    """Serialize ranked evidence when present, retaining legacy string clues."""
    ranked_clues = response.ranked_clues
    clues: list[object]
    if ranked_clues is None:
        clues = list(response.clues)
    else:
        clues = [
            {
                "description": clue.description,
                "rule_evidence": list(clue.rule_evidence),
            }
            for clue in ranked_clues
        ]
    return {
        "predicted_cve": response.predicted_cve,
        "reasoning": response.reasoning,
        "clues": clues,
    }


@dataclass(frozen=True)
class DefenderResponse:
    hardened_rule: str
    rationale: str
    changes: list[str]


@dataclass(frozen=True)
class ProviderAttempt:
    model: str
    prompt: str
    raw_response: str | None
    error: str | None


class AgentClient(Protocol):
    def complete(self, *, model: str, prompt: str) -> str:
        """Return an agent's JSON response."""


class LiteLLMClient:
    """OpenAI-compatible client for the configured LiteLLM endpoint."""

    def __init__(
        self, *, api_key: str, base_url: str, timeout_seconds: float = 120
    ) -> None:
        self._client = OpenAI(
            api_key=api_key,
            base_url=base_url,
            http_client=httpx.Client(verify=False, timeout=timeout_seconds),
        )

    def complete(self, *, model: str, prompt: str) -> str:
        for token_budget in _token_budgets_for_model(model):
            response = self._client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                max_completion_tokens=token_budget,
            )
            content = response.choices[0].message.content
            if isinstance(content, str) and content.strip():
                return content
            message = response.choices[0].message
            finish_reason = getattr(response.choices[0], "finish_reason", None)
            log.warning(
                "LiteLLM model %s returned empty visible content at token budget %s "
                "(finish reason: %s, reasoning content present: %s); retrying once",
                model,
                token_budget,
                finish_reason or "unknown",
                bool(getattr(message, "reasoning_content", None)),
            )
        raise ValueError("model returned empty content after retry")


def _token_budgets_for_model(model: str) -> tuple[int, int]:
    lowered = model.lower()
    if "gpt-5.5" in lowered or "gpt-5.6" in lowered or "opus" in lowered:
        return 8000, 16000
    return 2000, 4000


def _attacker_option_spans(rule: str) -> tuple[int, int, list[tuple[int, int]]]:
    quoted = escaped = False
    bracket_depth = 0
    opening = -1
    for index, character in enumerate(rule):
        if quoted and escaped:
            escaped = False
        elif quoted and character == "\\":
            escaped = True
        elif character == '"':
            quoted = not quoted
        elif not quoted and character == "[":
            bracket_depth += 1
        elif not quoted and character == "]":
            bracket_depth -= 1
            if bracket_depth < 0:
                raise ValueError("malformed attacker rule: unmatched closing bracket")
        elif not quoted and character == "(" and bracket_depth == 0:
            opening = index
            break
    if opening <= 0 or quoted or bracket_depth:
        raise ValueError("malformed attacker rule: missing top-level option block")

    spans: list[tuple[int, int]] = []
    start = opening + 1
    quoted = escaped = False
    closing = -1
    for index in range(start, len(rule)):
        character = rule[index]
        if quoted and escaped:
            escaped = False
        elif quoted and character == "\\":
            escaped = True
        elif character == '"':
            quoted = not quoted
        elif not quoted and character == ";":
            spans.append((start, index + 1))
            start = index + 1
        elif not quoted and character == ")":
            closing = index
            break
    if quoted or closing < 0:
        raise ValueError("malformed attacker rule: unterminated option block or quote")
    if rule[start:closing].strip():
        raise ValueError("malformed attacker rule: option must end with a semicolon")
    if rule[closing + 1 :].strip():
        raise ValueError("malformed attacker rule: trailing text after option block")
    return opening, closing, spans


def sanitize_attacker_rule(rule: str) -> str:
    """Remove public identity options without parsing or normalizing the header."""
    _, _, option_spans = _attacker_option_spans(rule)
    hidden_spans = [
        (start, end)
        for start, end in option_spans
        if rule[start:end].strip().partition(":")[0].strip().casefold()
        in _ATTACKER_HIDDEN_RULE_OPTIONS
    ]
    if not hidden_spans:
        return rule
    fragments: list[str] = []
    cursor = 0
    for start, end in hidden_spans:
        fragments.append(rule[cursor:start])
        cursor = end
    fragments.append(rule[cursor:])
    return "".join(fragments)


def _render_attacker_prompt(visible_rule: str) -> str:
    return f"""You are the attacker in an IDS-rule hardening game.
Infer the single most likely CVE from only the Suricata rule below. Do not use
outside metadata and do not invent identifiers.

Return only JSON with exactly these keys:
predicted_cve (CVE-YYYY-NNNN), reasoning (string), clues (ordered array of
objects). Each clue object must contain exactly description (string) and
rule_evidence (non-empty ordered array of exact snippets/options from the rule).

Rule:
{visible_rule}
"""


def prepare_attacker_input(rule: str) -> PreparedAttackerInput:
    visible_rule = sanitize_attacker_rule(rule)
    return PreparedAttackerInput(
        visible_rule=visible_rule,
        prompt=_render_attacker_prompt(visible_rule),
    )


def build_attacker_prompt(rule: str) -> str:
    """Build a sanitized prompt for legacy callers."""
    return prepare_attacker_input(rule).prompt


_CVE_IDENTIFIER = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def _redact_cve_identifiers(text: str) -> str:
    return _CVE_IDENTIFIER.sub("[CVE redacted]", text)


def build_defender_prompt(
    *,
    rule: str,
    original_rule: str,
    suite_contract: str,
    reasoning: str,
    clues: list[str],
) -> str:
    sanitized_reasoning = _redact_cve_identifiers(reasoning)
    clue_json = json.dumps([_redact_cve_identifiers(clue) for clue in clues])
    return f"""You are the defender in an IDS-rule hardening game.
Harden the Suricata rule by obscuring one or more clues listed below while
preserving its detection behavior. Offset and depth constrain matches relative to
their buffer; distance and within preserve relationships to the preceding content
match. Preserve sticky buffer context and immutable detection scope (action, protocol,
addresses, ports, direction, and flow).

Make exactly one hardening transformation per response; incrementing rev does not
count as a transformation. Modify at most one original content match. Splitting one
original content match is allowed, but preserve its bytes, order, buffer, and exact
match window:
- first fragment distance = original distance
- first fragment within = original within - total suffix length
- first fragment offset = original offset
- first fragment depth = original depth - total suffix length
- following fragments must use distance:0 and within equal to that fragment's length
Omit a first-fragment modifier when the original did not have that modifier. Do not
delete literal bytes or add unrelated content requirements. Do not replace content
matches with pcre. Do not change sid. Increment rev. Return a complete, valid rule, not a
patch. Avoid cosmetic-only changes.

Return only JSON with exactly these keys:
hardened_rule (string), rationale (string), changes (array of strings).

Original sanitized oracle rule:
This is the known-good detection reference. Its identity metadata has already
been removed.
{original_rule}

Validation contract:
{suite_contract}

Current rule:
{rule}

Attacker reasoning:
{sanitized_reasoning}

Attacker clues:
{clue_json}
"""


def _parse_object(raw_response: str) -> dict[str, object]:
    text = raw_response.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.IGNORECASE)
    start, end = text.find("{"), text.rfind("}")
    if start >= 0 and end > start:
        text = text[start : end + 1]
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"agent response was not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError("agent response must be a JSON object")
    return parsed


def _string_list(data: dict[str, object], key: str) -> list[str]:
    value = data.get(key)
    if not isinstance(value, list) or not value or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise ValueError(f"{key} must be a non-empty array of strings")
    return [item.strip() for item in value]


def _attacker_clues(
    data: dict[str, object],
    *,
    rule: str | None = None,
) -> list[str]:
    value = data.get("clues")
    if not isinstance(value, list) or not value:
        raise ValueError("clues must be a non-empty array")
    if all(isinstance(item, str) and item.strip() for item in value):
        return [item.strip() for item in value if isinstance(item, str)]
    ranked_clues: list[RankedAttackerClue] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(
                "clues must contain either legacy strings or ranked clue objects"
            )
        _require_exact_keys(item, {"description", "rule_evidence"})
        description = item.get("description")
        if not isinstance(description, str) or not description.strip():
            raise ValueError(f"clues[{index}].description must be a non-empty string")
        evidence = _string_list(item, "rule_evidence")
        if rule is not None:
            normalized_rule = " ".join(rule.split())
            for snippet in evidence:
                # Evidence matching ignores only whitespace-run differences;
                # punctuation, option names, and literal bytes remain exact.
                if " ".join(snippet.split()) not in normalized_rule:
                    raise ValueError(
                        f"clues[{index}].rule_evidence is not present in the supplied rule"
                    )
        ranked_clues.append(
            RankedAttackerClue(
                description=description.strip(),
                rule_evidence=evidence,
            )
        )
    return _RankedClueDescriptions(
        [clue.description for clue in ranked_clues],
        ranked_clues=ranked_clues,
    )


def _require_exact_keys(data: dict[str, object], keys: set[str]) -> None:
    if set(data) != keys:
        raise ValueError(f"agent response must contain exactly: {', '.join(sorted(keys))}")


def parse_attacker_response(
    raw_response: str,
    *,
    rule: str | None = None,
    visible_rule: str | None = None,
) -> AttackerResponse:
    """Parse an attacker response and optionally verify structured rule evidence."""
    if rule is not None and visible_rule is not None:
        raise ValueError("provide either rule or visible_rule, not both")
    data = _parse_object(raw_response)
    _require_exact_keys(data, {"predicted_cve", "reasoning", "clues"})
    predicted_cve = data.get("predicted_cve")
    reasoning = data.get("reasoning")
    if not isinstance(predicted_cve, str) or not re.fullmatch(
        r"CVE-\d{4}-\d{4,}", predicted_cve.strip(), re.IGNORECASE
    ):
        raise ValueError("predicted_cve must be a CVE identifier")
    if not isinstance(reasoning, str) or not reasoning.strip():
        raise ValueError("reasoning must be a non-empty string")
    return AttackerResponse(
        predicted_cve=predicted_cve.strip().upper(),
        reasoning=reasoning.strip(),
        clues=_attacker_clues(
            data,
            rule=(
                visible_rule
                if visible_rule is not None
                else sanitize_attacker_rule(rule) if rule is not None else None
            ),
        ),
    )


def parse_defender_response(raw_response: str) -> DefenderResponse:
    data = _parse_object(raw_response)
    _require_exact_keys(data, {"hardened_rule", "rationale", "changes"})
    hardened_rule = data.get("hardened_rule")
    rationale = data.get("rationale")
    if not isinstance(hardened_rule, str) or not hardened_rule.strip():
        raise ValueError("hardened_rule must be a non-empty string")
    if not isinstance(rationale, str) or not rationale.strip():
        raise ValueError("rationale must be a non-empty string")
    return DefenderResponse(
        hardened_rule=hardened_rule.strip(),
        rationale=rationale.strip(),
        changes=_string_list(data, "changes"),
    )
