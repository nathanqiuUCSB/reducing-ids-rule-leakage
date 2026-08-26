from pathlib import Path

from scapy.all import TCP, Raw, rdpcap

from hardening_game.pcap.smart_install_suite import (
    A_RUN,
    B_RUN,
    HEADER,
    SMART_INSTALL_CASES,
    build_smart_install_payload,
    build_smart_install_tcp_packets,
    write_smart_install_suite,
)


def test_baseline_payload_matches_canonical_layout() -> None:
    payload = build_smart_install_payload(
        prefix=b"",
        gap_before_a=12,
        a_bytes=b"A" * 36,
        gap_before_b=4,
        b_bytes=b"B" * 44,
        trailing=b"",
    )

    assert payload == HEADER + (b"\0" * 12) + (b"A" * 36) + (b"\0" * 4) + (b"B" * 44)
    assert len(payload) == 108


def test_uninspected_gap_payload_preserves_exact_distances() -> None:
    payload = HEADER + (b"\xab" * 12) + (b"A" * 36) + (b"\xcd" * 4) + (b"B" * 44)

    assert payload[:12] == HEADER
    assert payload[12:24] == b"\xab" * 12
    assert payload[24:60] == b"A" * 36
    assert payload[60:64] == b"\xcd" * 4
    assert payload[64:108] == b"B" * 44


def test_tcp_segmentation_splits_payload_across_data_segments() -> None:
    packets = build_smart_install_tcp_packets(
        payload=HEADER + (b"\0" * 12) + (b"A" * 36) + (b"\0" * 4) + (b"B" * 44),
        segment_sizes=(20, 40, 48),
        established=True,
    )
    data_packets = [packet for packet in packets if Raw in packet and packet[TCP].flags.P]

    assert [len(bytes(packet[Raw])) for packet in data_packets] == [20, 40, 48]


def test_manifest_covers_required_positive_and_negative_cases() -> None:
    names = {case.name for case in SMART_INSTALL_CASES}
    assert {
        "P0-baseline",
        "P1-uninspected-gaps",
        "P2-tcp-segmented-alt",
        "P3-trailing-bytes",
        "P4-tcp-segmented",
        "N1-depth-prefix",
        "N3-A-too-early",
        "N4-A-too-late",
        "N6-B-too-early",
        "N7-B-too-late",
        "N9-wrong-header-byte",
        "N10-flow-not-established",
        "N11-benign-4786",
    }.issubset(names)


def test_late_negative_cases_are_adjacent_to_exact_allowed_boundaries() -> None:
    cases = {case.name: case for case in SMART_INSTALL_CASES}

    assert cases["N4-A-too-late"].gap_before_a == 13
    assert cases["N7-B-too-late"].gap_before_b == 5


def test_write_suite_is_deterministic(tmp_path: Path) -> None:
    first = write_smart_install_suite(tmp_path / "a")
    second = write_smart_install_suite(tmp_path / "b")
    for case in SMART_INSTALL_CASES:
        left = (tmp_path / "a" / f"{case.name}.pcap").read_bytes()
        right = (tmp_path / "b" / f"{case.name}.pcap").read_bytes()
        assert left == right
        assert rdpcap(str(tmp_path / "a" / f"{case.name}.pcap"))
    assert first == second


def test_smoke_suite_has_requested_segmentation_and_challenge_coverage() -> None:
    names = {case.name for case in SMART_INSTALL_CASES}

    assert {
        "P0-baseline",
        "P5-header-split",
        "P6-a-anchor-split",
        "P7-b-anchor-split",
        "P8-many-small-segments",
        "P9-retransmission",
        "N12-wrong-port",
        "N13-wrong-direction",
        "N14-wrong-a-bytes",
        "N15-wrong-b-bytes",
        "N16-a-too-short",
        "N17-b-too-short",
        "N18-a-b-reversed",
        "N19-header-without-anchors",
        "N20-anchors-without-header",
        "N21-random-4786",
    }.issubset(names)


def test_retransmission_case_replays_one_duplicate_data_segment() -> None:
    case = next(case for case in SMART_INSTALL_CASES if case.name == "P9-retransmission")

    packets = build_smart_install_tcp_packets(
        payload=HEADER + (b"\0" * 12) + A_RUN + (b"\0" * 4) + B_RUN,
        segment_sizes=case.segment_sizes,
        retransmit_segment=case.retransmit_segment,
    )
    data_packets = [packet for packet in packets if Raw in packet and packet[TCP].flags.P]

    assert len(data_packets) == len(case.segment_sizes or ()) + 1
    assert bytes(data_packets[1][Raw]) == bytes(data_packets[2][Raw])
    assert data_packets[1][TCP].seq == data_packets[2][TCP].seq
