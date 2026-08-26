from hardening_game.pcap.generate import _payload_for_rule, parse_content_pattern


def test_parse_content_pattern_decodes_suricata_hex_escapes() -> None:
    assert parse_content_pattern("|2f|api|2f|") == b"/api/"


def test_payload_respects_distance_between_content_patterns() -> None:
    rule = (
        'alert tcp any any -> any 4786 '
        '(content:"X"; content:"A"; distance:2; content:"B"; distance:1;)'
    )

    assert _payload_for_rule(rule) == b"X\0\0A\0B"
