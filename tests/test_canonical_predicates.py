import json
from dataclasses import replace
from pathlib import Path

import pytest

from hardening_game.attribution.clue_scoring import map_attacker_evidence
from hardening_game.mutations.clue_review import (
    _rule_predicates,
    audit_review_packet_mapping,
    build_review_packet,
)
from hardening_game.predicates import (
    canonical_rule_predicates,
    canonical_touched_predicate_ids,
    resolve_predicate_ids,
)
from hardening_game.mutations.families import option_index_of
from hardening_game.suricata.rule_model import (
    RULE_HEADER_PATTERN,
    Span,
    parse_suricata_rule,
)


ROOT = Path(__file__).parents[1]


def _fixture_rule(name: str) -> str:
    payload = json.loads(
        (ROOT / "fixtures" / "dataset" / f"{name}.json").read_text()
    )
    return payload["rule"]


def test_canonical_header_spans_reuse_authoritative_parser_pattern() -> None:
    rule = "alert http any any -> $HOME_NET 8080 (flow:established,to_server;)"
    match = RULE_HEADER_PATTERN.match(rule)
    assert match is not None
    predicates = _rule_predicates(parse_suricata_rule(rule))

    expected = {
        "header-action": "action",
        "header-protocol": "protocol",
        "header-src-address": "src_address",
        "header-src-port": "src_port",
        "header-direction": "direction",
        "header-dst-address": "dst_address",
        "header-dst-port": "dst_port",
    }
    for predicate_id, group_name in expected.items():
        assert predicates[predicate_id]["source_span"] == {
            "start": match.start(group_name),
            "end": match.end(group_name),
        }


@pytest.mark.parametrize(
    ("alias", "expected"),
    [
        ("header-destination-port", ("header-dst-port",)),
        ("header-destination-address", ("header-dst-address",)),
        ("header-source-address", ("header-src-address",)),
        ("flow", ("flow-established", "flow-to_server")),
    ],
)
def test_alias_resolver_is_explicit_and_context_checked(
    alias: str, expected: tuple[str, ...]
) -> None:
    known = {
        "header-dst-port",
        "header-dst-address",
        "header-src-address",
        "pcre-0",
        "byte_test-2",
        "bsize-0",
        "flow-established",
        "flow-to_server",
    }
    assert resolve_predicate_ids((alias,), known_predicate_ids=known) == expected


def test_alias_resolver_rejects_unknown_or_inapplicable_aliases() -> None:
    with pytest.raises(ValueError, match="unknown predicate alias"):
        resolve_predicate_ids(("header-target-port",), known_predicate_ids={"content-0"})
    with pytest.raises(ValueError, match="does not resolve to a known predicate"):
        resolve_predicate_ids(
            ("header-destination-port",), known_predicate_ids={"content-0"}
        )


def test_nested_aliases_validate_physical_ownership_with_multiple_owners() -> None:
    rule = (
        'alert tcp any any -> any any (content:"a"; pcre:"/one/R"; '
        'http.uri; bsize:3; content:"b"; pcre:"/two/R"; '
        "byte_test:1,=,1,0,relative; fast_pattern;)"
    )
    predicates = _rule_predicates(parse_suricata_rule(rule))

    assert resolve_predicate_ids(
        (
            "content-0-pcre-0",
            "buffer-0-pcre-0",
            "content-1-pcre-1",
            "buffer-1-pcre-1",
            "content-1-byte_test-0",
            "buffer-1-byte_test-0",
            "buffer-1-bsize-0",
            "content-1-fast_pattern",
        ),
        known_predicate_ids=predicates,
    ) == (
        "bsize-0",
        "byte_test-0",
        "content-1-fast_pattern",
        "pcre-0",
        "pcre-1",
    )

    for alias in (
        "content-1-pcre-0",
        "content-0-pcre-1",
        "content-0-byte_test-0",
        "buffer-1-pcre-0",
        "buffer-0-byte_test-0",
        "buffer-0-bsize-0",
        "content-0-fast_pattern",
    ):
        with pytest.raises(ValueError, match="does not own"):
            resolve_predicate_ids((alias,), known_predicate_ids=predicates)
    with pytest.raises(ValueError, match="unknown physical predicate"):
        resolve_predicate_ids(
            ("content-0-pcre-9",), known_predicate_ids=predicates
        )


def test_mutation_touched_metadata_uses_the_canonical_alias_resolver() -> None:
    known = {"header-dst-port", "flow-established", "flow-to_server"}
    assert canonical_touched_predicate_ids(
        {"predicate_id": "header-destination-port"}, known_predicate_ids=known
    ) == ("header-dst-port",)
    assert canonical_touched_predicate_ids(
        {"predicate_ids": ["flow"]}, known_predicate_ids=known
    ) == ("flow-established", "flow-to_server")
    with pytest.raises(ValueError, match="unknown predicate alias"):
        canonical_touched_predicate_ids(
            {"predicate_id": "unknown-touch"}, known_predicate_ids=known
        )


@pytest.mark.parametrize(
    ("flow_value", "single_evidence", "single_expected"),
    [
        ("established,to_server", "established", ("flow-established",)),
        ("established,to_server", "to_server", ("flow-to_server",)),
        ("established,to_client", "to_client", ("flow-to_client",)),
    ],
)
def test_flow_flags_have_exact_value_spans_and_map_independently(
    flow_value: str,
    single_evidence: str,
    single_expected: tuple[str, ...],
) -> None:
    rule = f"alert tcp any any -> any any (flow:{flow_value};)"
    predicates = _rule_predicates(parse_suricata_rule(rule))

    for predicate_id in (f"flow-{value}" for value in flow_value.split(",")):
        span = predicates[predicate_id]["source_span"]
        assert rule[span["start"] : span["end"]] == predicate_id.removeprefix("flow-")

    assert map_attacker_evidence(
        [single_evidence],
        visible_rule=rule,
        rule_predicates=predicates,
    ).predicate_ids == single_expected
    assert map_attacker_evidence(
        [f"flow:{flow_value};"],
        visible_rule=rule,
        rule_predicates=predicates,
    ).predicate_ids == tuple(
        sorted(f"flow-{value}" for value in flow_value.split(","))
    )
    assert map_attacker_evidence(
        [flow_value],
        visible_rule=rule,
        rule_predicates=predicates,
    ).predicate_ids == tuple(
        sorted(f"flow-{value}" for value in flow_value.split(","))
    )


def test_flowbits_records_are_consistent_and_invalid_shapes_fail_closed() -> None:
    valid = _rule_predicates(
        parse_suricata_rule(
            "alert tcp any any -> any any "
            "(flowbits:set,example.name; flowbits:noalert;)"
        )
    )
    assert valid["flowbits-0"]["flowbits_action"] == "set"
    assert valid["flowbits-0"]["flowbits_name"] == "example.name"
    assert valid["flowbits-1"]["flowbits_action"] == "noalert"
    assert valid["flowbits-1"]["flowbits_name"] is None

    for option in (
        "flowbits;",
        "flowbits:set;",
        "flowbits:set,name,extra;",
        "flowbits:noalert,name;",
        "flowbits:unknown,name;",
    ):
        with pytest.raises(ValueError, match="invalid flowbits option"):
            canonical_rule_predicates(
                parse_suricata_rule(f"alert tcp any any -> any any ({option})")
            )


def test_repeated_constraints_map_to_distinct_occurrence_predicates() -> None:
    rule = (
        'alert tcp any any -> any any (content:"a"; content:"b"; '
        "distance:1; within:10; distance:2; within:20;)"
    )
    predicates = _rule_predicates(parse_suricata_rule(rule))

    assert {
        predicate_id
        for predicate_id in predicates
        if predicate_id.startswith("content-1-distance")
        or predicate_id.startswith("content-1-within")
    } == {
        "content-1-distance",
        "content-1-distance-1",
        "content-1-within",
        "content-1-within-1",
    }
    assert map_attacker_evidence(
        ["distance:1;", "within:10;", "distance:2;", "within:20;"],
        visible_rule=rule,
        rule_predicates=predicates,
    ).predicate_ids == (
        "content-1-distance",
        "content-1-distance-1",
        "content-1-within",
        "content-1-within-1",
    )
    assert canonical_touched_predicate_ids(
        {
            "predicate_id": "content-1-distance-1",
            "compensation": {"predicate_id": "content-1-within-1"},
        },
        known_predicate_ids=predicates,
    ) == ("content-1-distance-1", "content-1-within-1")
    assert resolve_predicate_ids(
        (
            "content-1-distance",
            "content-1-distance-1",
            "content-1-within",
            "content-1-within-1",
        ),
        known_predicate_ids=predicates,
    ) == (
        "content-1-distance",
        "content-1-distance-1",
        "content-1-within",
        "content-1-within-1",
    )


def test_malformed_touched_span_paths_raise_diagnostic_value_errors() -> None:
    parsed = parse_suricata_rule(
        'alert tcp any any -> any any (content:"x"; fast_pattern;)'
    )
    malformed = replace(
        parsed,
        options=tuple(option for option in parsed.options if option.name != "fast_pattern"),
    )
    with pytest.raises(ValueError, match="modifier span has no parser option"):
        canonical_rule_predicates(malformed)
    with pytest.raises(ValueError, match="span has no parser option"):
        option_index_of(parsed, Span(999, 1000))


def test_evidence_mapping_unions_adjacent_rsync_options_and_trailing_variants() -> None:
    rule = _fixture_rule("et-2067354")
    visible = rule.replace(" sid:2067354;", "").replace(" rev:1;", "")
    predicates = _rule_predicates(parse_suricata_rule(visible))

    mapping = map_attacker_evidence(
        [
            'content:"|0e|"; distance:0',
            "byte_test:1,&,0x80,0,relative;",
            "byte_test:4,>,16,9,relative,little; "
            "byte_test:4,<,65,9,relative,little",
        ],
        visible_rule=visible,
        rule_predicates=predicates,
    )

    assert mapping.measured is True
    assert mapping.predicate_ids == (
        "byte_test-0",
        "byte_test-1",
        "byte_test-2",
        "content-4",
        "content-4-distance",
    )


def test_evidence_mapping_covers_bsize_flow_header_and_flowbits() -> None:
    bsize_rule = _fixture_rule("et-2059741")
    bsize_visible = bsize_rule.replace(" sid:2059741;", "").replace(" rev:1;", "")
    bsize_predicates = _rule_predicates(parse_suricata_rule(bsize_visible))
    assert map_attacker_evidence(
        ['http.uri; bsize:12; content:"/options.php";'],
        visible_rule=bsize_visible,
        rule_predicates=bsize_predicates,
    ).predicate_ids == ("bsize-0", "buffer-1", "content-1")

    flowbits_rule = _fixture_rule("et-2050988")
    flowbits_visible = flowbits_rule.replace(" sid:2050988;", "").replace(" rev:1;", "")
    flowbits_predicates = _rule_predicates(parse_suricata_rule(flowbits_visible))
    mapping = map_attacker_evidence(
        [
            "-> [$HOME_NET,$HTTP_SERVERS] any",
            "flow:established,to_server;",
            "flowbits:set,ET.ScreenConnectAuthBypass.Attempt",
        ],
        visible_rule=flowbits_visible,
        rule_predicates=flowbits_predicates,
    )
    assert mapping.measured is True
    assert mapping.predicate_ids == (
        "flow-established",
        "flow-to_server",
        "flowbits-0",
        "header-direction",
        "header-dst-address",
        "header-dst-port",
    )


def test_repeated_identical_evidence_is_explicitly_ambiguous() -> None:
    rule = 'alert tcp any any -> any any (content:"same"; content:"same";)'
    predicates = _rule_predicates(parse_suricata_rule(rule))

    mapping = map_attacker_evidence(
        ['content:"same";'],
        visible_rule=rule,
        rule_predicates=predicates,
    )

    assert mapping.measured is False
    assert mapping.reason == "ambiguous_evidence"


def test_semantic_text_and_partly_unmapped_material_are_not_fuzzy_matched() -> None:
    rule = 'alert tcp any any -> any 873 (content:"RSYNCD";)'
    predicates = _rule_predicates(parse_suricata_rule(rule))

    semantic = map_attacker_evidence(
        ["standard rsync port"],
        visible_rule=rule,
        rule_predicates=predicates,
    )
    mixed = map_attacker_evidence(
        ['content:"RSYNCD"; exploit marker'],
        visible_rule=rule,
        rule_predicates=predicates,
    )

    assert semantic.reason == "unmapped_evidence"
    assert mixed.reason == "unmapped_evidence"


def test_all_57_v2_trials_are_included_in_deterministic_mapping_audit() -> None:
    run_root = ROOT / "runs" / "mutations" / "dataset-clue-baseline-v2"
    packet = build_review_packet(
        project_root=ROOT,
        manifest_path=ROOT / "fixtures" / "dataset_manifest.json",
        run_root=run_root,
    )

    audit = audit_review_packet_mapping(packet)

    assert audit == audit_review_packet_mapping(packet)
    assert audit["trial_count"] == 57
    assert audit["measurable_count"] == 55
    assert audit["unmeasured_count"] == 2
    assert {
        (item["fixture"], item["trial_index"]) for item in audit["ambiguities"]
    } == {("et-2045307", 0), ("et-2045307", 1)}
    assert all(
        item["reason"] in {"ambiguous_evidence", "unmapped_evidence"}
        for item in audit["ambiguities"]
    )
