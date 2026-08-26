import json

import pytest

import hardening_game.agents as agents
from hardening_game.agents import (
    ATTACKER_PROMPT_VERSION,
    ATTACKER_RULE_SANITIZER_VERSION,
    ATTACKER_RESPONSE_SCHEMA_VERSION,
    AttackerResponse,
    DefenderResponse,
    LiteLLMClient,
    RankedAttackerClue,
    build_attacker_prompt,
    build_defender_prompt,
    parse_attacker_response,
    parse_defender_response,
    sanitize_attacker_rule,
)


def test_litellm_client_sends_prompt_to_openai_compatible_completion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    class FakeCompletions:
        def create(self, **kwargs: object) -> object:
            observed.update(kwargs)
            return type(
                "Response",
                (),
                {
                    "choices": [
                        type(
                            "Choice",
                            (),
                            {
                                "message": type("Message", (), {"content": '{"ok": true}'})(),
                                "finish_reason": "stop",
                            },
                        )()
                    ]
                },
            )()

    class FakeOpenAI:
        def __init__(self, **kwargs: object) -> None:
            observed["client"] = kwargs
            self.chat = type("Chat", (), {"completions": FakeCompletions()})()

    monkeypatch.setattr("hardening_game.agents.OpenAI", FakeOpenAI)

    response = LiteLLMClient(api_key="secret", base_url="https://example.test/v1").complete(
        model="defender-model", prompt="return JSON"
    )

    assert response == '{"ok": true}'
    assert observed["client"]["base_url"] == "https://example.test/v1"
    assert observed["model"] == "defender-model"
    assert observed["messages"] == [{"role": "user", "content": "return JSON"}]


def test_parse_attacker_response_requires_cve_reasoning_and_clues() -> None:
    response = parse_attacker_response(
        '{"predicted_cve":"cve-2025-9961","reasoning":"The URI is distinctive.",'
        '"clues":["/api/devices/", "setParameterValues"]}'
    )

    assert response == AttackerResponse(
        predicted_cve="CVE-2025-9961",
        reasoning="The URI is distinctive.",
        clues=["/api/devices/", "setParameterValues"],
    )


def test_parse_attacker_response_accepts_ranked_clues_with_rule_evidence() -> None:
    response = parse_attacker_response(
        '{"predicted_cve":"CVE-2025-9961","reasoning":"The rule is distinctive.",'
        '"clues":[{"description":"Product endpoint","rule_evidence":["/api/devices/"]},'
        '{"description":"Operation name","rule_evidence":["setParameterValues"]}]}'
    )

    assert response == AttackerResponse(
        predicted_cve="CVE-2025-9961",
        reasoning="The rule is distinctive.",
        clues=["Product endpoint", "Operation name"],
    )
    assert response.ranked_clues == [
        RankedAttackerClue("Product endpoint", ["/api/devices/"]),
        RankedAttackerClue("Operation name", ["setParameterValues"]),
    ]


def test_attacker_prompt_requests_ranked_clue_objects_with_exact_evidence() -> None:
    prompt = build_attacker_prompt('alert http any any -> any any (sid:2065809; rev:1;)')

    assert "description" in prompt
    assert "rule_evidence" in prompt
    assert "exact snippets/options from the rule" in prompt


def test_attacker_rule_sanitizer_removes_only_public_lookup_metadata() -> None:
    rule = (
        "alert http any any -> $HOME_NET 443 ( "
        'msg:"Public rule name"; flow:established,to_server; http.uri; '
        'content:"/admin"; nocase; pcre:"/sid:[0-9]+;/R"; '
        "byte_test:1,=,1,0,relative; detection_filter:track by_src,count 5,seconds 60; "
        "threshold:type limit,track by_src,count 1,seconds 10; "
        "reference:cve,2025-1234; classtype:web-application-attack; "
        "metadata:affected_product Example, deployment Perimeter; "
        "gid:1; sid:2065809; rev:7;)"
    )

    sanitized = sanitize_attacker_rule(rule)

    for stripped in (
        'msg:"Public rule name";',
        "reference:cve,2025-1234;",
        "classtype:web-application-attack;",
        "metadata:affected_product Example, deployment Perimeter;",
        "gid:1;",
        "sid:2065809;",
        "rev:7;",
    ):
        assert stripped not in sanitized
    for detection_option in (
        "alert http any any -> $HOME_NET 443",
        "flow:established,to_server;",
        "http.uri;",
        'content:"/admin";',
        "nocase;",
        'pcre:"/sid:[0-9]+;/R";',
        "byte_test:1,=,1,0,relative;",
        "detection_filter:track by_src,count 5,seconds 60;",
        "threshold:type limit,track by_src,count 1,seconds 10;",
    ):
        assert detection_option in sanitized


def test_attacker_rule_sanitizer_preserves_quoted_metadata_words() -> None:
    rule = (
        'alert tcp any any -> any any (content:"sid:7; rev:9; '
        'msg:\\"not metadata\\""; sid:7; rev:9;)'
    )

    sanitized = sanitize_attacker_rule(rule)

    assert 'content:"sid:7; rev:9; msg:\\"not metadata\\"";' in sanitized
    assert sanitized.count("sid:7;") == 1
    assert sanitized.count("rev:9;") == 1


def test_attacker_rule_sanitizer_preserves_spaced_bracket_header_byte_for_byte() -> None:
    header = (
        "alert tcp [10.0.0.1, 10.0.0.2] [80, 443] -> "
        "[$HOME_NET, !10.0.0.0/8] [8080, 8443] "
    )
    rule = (
        header
        + '(flow:established,to_server; content:"marker"; sid:2065809; rev:1;)'
    )

    sanitized = sanitize_attacker_rule(rule)

    assert sanitized.startswith(header + "(")
    assert "flow:established,to_server;" in sanitized
    assert 'content:"marker";' in sanitized
    assert "sid:2065809;" not in sanitized
    assert "rev:1;" not in sanitized


def test_attacker_rule_sanitizer_preserves_escaped_quotes_and_quoted_identifiers() -> None:
    rule = (
        'alert tcp any any -> any any (content:"prefix \\"sid:7; rev:9;\\" suffix"; '
        'pcre:"/msg:\\"sid:123;\\"/R"; msg:"remove me"; sid:7; rev:9;)'
    )

    sanitized = sanitize_attacker_rule(rule)

    assert 'content:"prefix \\"sid:7; rev:9;\\" suffix";' in sanitized
    assert 'pcre:"/msg:\\"sid:123;\\"/R";' in sanitized
    assert 'msg:"remove me";' not in sanitized
    assert sanitized.endswith(")")


@pytest.mark.parametrize(
    "rule",
    [
        'alert tcp any any -> any any (content:"unterminated; sid:7; rev:1;)',
        'alert tcp any any -> any any (content:"marker"; sid:7; rev:1;',
        'alert tcp any any -> any any content:"marker"; sid:7; rev:1;)',
        'alert tcp any any -> any any (content:"marker"; sid:7; rev:1)',
    ],
)
def test_attacker_rule_sanitizer_rejects_malformed_rules(rule: str) -> None:
    with pytest.raises(ValueError, match="attacker rule"):
        sanitize_attacker_rule(rule)


def test_attacker_prompt_versions_identify_sanitized_rule_contract() -> None:
    assert ATTACKER_PROMPT_VERSION == "ranked-clues-sanitized-rule-v2"
    assert ATTACKER_RESPONSE_SCHEMA_VERSION == 3
    assert ATTACKER_RULE_SANITIZER_VERSION == "suricata-metadata-options-v2"


def test_prepare_attacker_input_sanitizes_once_and_binds_prompt_to_visible_rule(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rule = 'alert tcp any any -> any any (content:"marker"; sid:7; rev:1;)'
    calls: list[str] = []
    real_sanitizer = agents.sanitize_attacker_rule

    def counting_sanitizer(candidate: str) -> str:
        calls.append(candidate)
        return real_sanitizer(candidate)

    monkeypatch.setattr(agents, "sanitize_attacker_rule", counting_sanitizer)

    prepared = agents.prepare_attacker_input(rule)

    assert calls == [rule]
    assert prepared.visible_rule == (
        'alert tcp any any -> any any (content:"marker";)'
    )
    assert prepared.visible_rule in prepared.prompt
    assert "sid:7;" not in prepared.prompt
    assert "rev:1;" not in prepared.prompt


def test_structured_rule_evidence_accepts_exact_snippet_after_whitespace_normalization() -> None:
    response = parse_attacker_response(
        '{"predicted_cve":"CVE-2025-9961","reasoning":"Distinctive marker.",'
        '"clues":[{"description":"Marker","rule_evidence":'
        '["content:\\"marker\\";   fast_pattern;"]}]}',
        rule=(
            "alert http any any -> any any (\n"
            '  content:"marker"; fast_pattern;\n'
            "  sid:2065809; rev:1;)"
        ),
    )

    assert response.ranked_clues == [
        RankedAttackerClue("Marker", ['content:"marker";   fast_pattern;'])
    ]


def test_structured_rule_evidence_rejects_text_not_present_in_rule() -> None:
    with pytest.raises(ValueError, match="rule_evidence.*not present"):
        parse_attacker_response(
            '{"predicted_cve":"CVE-2025-9961","reasoning":"Distinctive marker.",'
            '"clues":[{"description":"Invented","rule_evidence":'
            '["content:\\"hallucinated\\";"]}]}',
            rule='alert http any any -> any any (content:"marker"; sid:2065809; rev:1;)',
        )


@pytest.mark.parametrize(
    "stripped_evidence",
    ["sid:2065809;", "rev:1;", 'msg:"Public rule name";', "reference:cve,2025-1234;"],
)
def test_structured_rule_evidence_cannot_cite_attacker_hidden_metadata(
    stripped_evidence: str,
) -> None:
    rule = (
        'alert http any any -> any any (msg:"Public rule name"; content:"marker"; '
        "reference:cve,2025-1234; sid:2065809; rev:1;)"
    )
    response = json.dumps(
        {
            "predicted_cve": "CVE-2025-9961",
            "reasoning": "Metadata claim.",
            "clues": [
                {
                    "description": "Hidden metadata",
                    "rule_evidence": [stripped_evidence],
                }
            ],
        }
    )

    with pytest.raises(ValueError, match="rule_evidence.*not present"):
        parse_attacker_response(response, rule=rule)


def test_parse_defender_response_requires_rule_rationale_and_changes() -> None:
    response = parse_defender_response(
        '{"hardened_rule":"alert http any any -> any any (sid:2065809; rev:2;)",'
        '"rationale":"Hide one clue.", "changes":["removed URI literal"]}'
    )

    assert response == DefenderResponse(
        hardened_rule="alert http any any -> any any (sid:2065809; rev:2;)",
        rationale="Hide one clue.",
        changes=["removed URI literal"],
    )


def test_defender_prompt_preserves_suricata_semantics() -> None:
    prompt = build_defender_prompt(
        rule='alert http any any -> any any (sid:2065809; rev:1;)',
        original_rule='alert http any any -> any any (content:"oracle"; sid:2065809; rev:1;)',
        suite_contract="Required signature-positives — must alert:\n- P0: canonical payload",
        reasoning="The request body identifies the product.",
        clues=["setParameterValues"],
    )

    lowered = " ".join(prompt.lower().split())
    assert "offset and depth constrain matches relative to their buffer" in lowered
    assert (
        "distance and within preserve relationships to the preceding content match"
        in lowered
    )
    assert "sticky buffer" in lowered
    assert "action, protocol, addresses, ports, direction, and flow" in lowered
    assert "make exactly one hardening transformation" in lowered
    assert "splitting one original content match is allowed" in lowered
    assert "first fragment depth = original depth - total suffix length" in lowered
    assert "first fragment within = original within - total suffix length" in lowered
    assert "following fragments must use distance:0" in lowered
    assert "do not replace content matches with pcre" in lowered
    assert "CVE-2025-9961" not in prompt
    assert "setParameterValues" in prompt
    assert "Original sanitized oracle rule:" in prompt
    assert 'content:"oracle"' in prompt
    assert "Current rule:" in prompt
    assert "Required signature-positives — must alert:" in prompt
    assert "P0: canonical payload" in prompt


def test_defender_prompt_redacts_cves_from_attacker_reasoning_and_clues() -> None:
    prompt = build_defender_prompt(
        rule='alert http any any -> any any (sid:2065809; rev:1;)',
        original_rule='alert http any any -> any any (sid:2065809; rev:1;)',
        suite_contract="Legacy single-PCAP contract",
        reasoning=(
            "CVE-2025-9961 is suggested by the request body and endpoint behavior."
        ),
        clues=[
            "setParameterValues for CVE-2024-12345",
            "The URI remains a useful marker.",
        ],
    )

    assert "CVE-2025-9961" not in prompt
    assert "CVE-2024-12345" not in prompt
    assert "request body and endpoint behavior" in prompt
    assert "setParameterValues" in prompt
    assert "URI remains a useful marker" in prompt


def test_parse_attacker_response_rejects_missing_clues() -> None:
    with pytest.raises(ValueError, match="clues"):
        parse_attacker_response(
            '{"predicted_cve":"CVE-2025-9961","reasoning":"The URI is distinctive."}'
        )


def test_parse_attacker_response_rejects_extra_fields() -> None:
    with pytest.raises(ValueError, match="exactly"):
        parse_attacker_response(
            '{"predicted_cve":"CVE-2025-9961","reasoning":"x","clues":["marker"],'
            '"ground_truth":"CVE-2025-9961"}'
        )


def test_attacker_prompt_contains_only_rule_and_output_contract() -> None:
    prompt = build_attacker_prompt(
        'alert http any any -> any any (content:"sid: literal"; sid:2065809; rev:1;)'
    )

    assert "predicted_cve" in prompt
    assert 'content:"sid: literal"' in prompt
    assert "sid:2065809" not in prompt
    assert "rev:1" not in prompt
