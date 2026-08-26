from pathlib import Path

import pytest
from scapy.all import IP, TCP, Raw, rdpcap

from hardening_game.pcap.suite_builders import (
    build_established_tcp_stream,
    http_request,
    http_response,
    render_payload,
    segment_sizes_for,
    write_case_pcap,
)


def test_segmented_stream_reassembles_to_canonical_payload() -> None:
    payload = b"abcdefghijklmnopqrstuvwxyz"

    packets = build_established_tcp_stream(
        payload,
        port=80,
        direction="to_server",
        segment_sizes=(5, 7, 14),
        retransmit_segment=None,
    )

    data = [bytes(packet[Raw]) for packet in packets if Raw in packet]
    assert b"".join(data) == payload


def test_retransmission_duplicates_sequence_and_bytes() -> None:
    packets = build_established_tcp_stream(
        b"abcdefghijkl",
        port=80,
        direction="to_server",
        segment_sizes=(4, 4, 4),
        retransmit_segment=1,
    )

    data = [packet for packet in packets if Raw in packet]
    assert data[1][TCP].seq == data[2][TCP].seq
    assert bytes(data[1][Raw]) == bytes(data[2][Raw])


def test_unestablished_stream_carries_payload_without_a_completed_handshake() -> None:
    packets = build_established_tcp_stream(
        b"payload",
        port=80,
        direction="to_server",
        segment_sizes=None,
        retransmit_segment=None,
        established=False,
    )

    flags = [str(packet[TCP].flags) for packet in packets]
    assert "SA" not in flags
    assert b"".join(bytes(packet[Raw]) for packet in packets if Raw in packet) == b"payload"


def test_to_client_stream_sends_payload_from_the_server_port() -> None:
    packets = build_established_tcp_stream(
        b"body",
        port=8080,
        direction="to_client",
        segment_sizes=None,
        retransmit_segment=None,
    )

    data = [packet for packet in packets if Raw in packet]
    assert len(data) == 1
    assert data[0][TCP].sport == 8080
    assert data[0][IP].src == "10.0.0.2"


def test_preamble_is_sent_in_the_opposite_direction_before_the_payload() -> None:
    packets = build_established_tcp_stream(
        b"response",
        port=80,
        direction="to_client",
        segment_sizes=None,
        retransmit_segment=None,
        preamble=b"request",
    )

    data = [packet for packet in packets if Raw in packet]
    assert [bytes(packet[Raw]) for packet in data] == [b"request", b"response"]
    assert data[0][TCP].dport == 80
    assert data[1][TCP].sport == 80
    assert data[1][TCP].ack == data[0][TCP].seq + len(b"request")


def test_endpoint_overrides_place_traffic_on_explicit_addresses() -> None:
    packets = build_established_tcp_stream(
        b"payload",
        port=80,
        direction="to_server",
        segment_sizes=None,
        retransmit_segment=None,
        client_ip="10.0.0.9",
        server_ip="203.0.113.5",
    )

    data = [packet for packet in packets if Raw in packet]
    assert data[0][IP].src == "10.0.0.9"
    assert data[0][IP].dst == "203.0.113.5"


def test_segment_sizes_must_sum_to_the_payload_length() -> None:
    with pytest.raises(ValueError):
        build_established_tcp_stream(
            b"abc",
            port=80,
            direction="to_server",
            segment_sizes=(2,),
            retransmit_segment=None,
        )


def test_identical_specifications_produce_byte_identical_pcaps(tmp_path: Path) -> None:
    def write(name: str) -> bytes:
        path = write_case_pcap(
            build_established_tcp_stream(
                b"deterministic payload",
                port=80,
                direction="to_server",
                segment_sizes=(4, 17),
                retransmit_segment=0,
            ),
            tmp_path / name,
        )
        return path.read_bytes()

    assert write("first.pcap") == write("second.pcap")


def test_written_pcap_round_trips_the_reassembled_payload(tmp_path: Path) -> None:
    path = write_case_pcap(
        build_established_tcp_stream(
            b"round trip",
            port=80,
            direction="to_server",
            segment_sizes=None,
            retransmit_segment=None,
        ),
        tmp_path / "case.pcap",
    )

    packets = rdpcap(str(path))
    assert b"".join(bytes(packet[Raw]) for packet in packets if Raw in packet) == b"round trip"


def test_http_request_declares_content_length_for_a_body() -> None:
    request = http_request("POST", "/x", headers={"Cookie": "Auth=1"}, body="a=b")

    assert request.startswith(b"POST /x HTTP/1.1\r\n")
    assert b"Host: target.local\r\n" in request
    assert b"Cookie: Auth=1\r\n" in request
    assert b"Content-Length: 3\r\n" in request
    assert request.endswith(b"\r\n\r\na=b")


def test_http_response_declares_content_length_for_its_body() -> None:
    response = http_response("hello", status="200 OK")

    assert response.startswith(b"HTTP/1.1 200 OK\r\n")
    assert b"Content-Length: 5\r\n" in response
    assert response.endswith(b"\r\n\r\nhello")


def test_render_payload_merges_only_the_mutated_request_fields() -> None:
    canonical = {"method": "POST", "target": "/x", "headers": {"Cookie": "Auth=1"}, "body": "a=b"}

    rendered = render_payload("http", "to_server", canonical, {"method": "GET"})

    assert rendered.startswith(b"GET /x HTTP/1.1\r\n")
    assert b"Cookie: Auth=1\r\n" in rendered
    assert b"a=b" in rendered


def test_render_payload_header_mutation_can_add_and_remove_headers() -> None:
    canonical = {"method": "GET", "target": "/", "headers": {"X-Keep": "1", "X-Drop": "2"}}

    rendered = render_payload(
        "http", "to_server", canonical, {"headers": {"X-Drop": None, "X-Add": "3"}}
    )

    assert b"X-Keep: 1\r\n" in rendered
    assert b"X-Drop" not in rendered
    assert b"X-Add: 3\r\n" in rendered


def test_render_payload_supports_raw_tcp_and_full_payload_override() -> None:
    assert render_payload("raw_tcp", "to_server", {"payload": b"\x01\x02"}, {}) == b"\x01\x02"
    assert (
        render_payload("raw_tcp", "to_server", {"payload": b"\x01"}, {"payload": b"\x02"})
        == b"\x02"
    )
    assert (
        render_payload("http", "to_server", {"method": "GET", "target": "/"}, {"raw_payload": b"junk"})
        == b"junk"
    )


def test_segment_sizes_split_immediately_after_each_marker() -> None:
    payload = b"GET /x HTTP/1.1\r\nHost: a\r\n\r\n"

    sizes = segment_sizes_for(payload, split_after=(b"GET ", b"\r\n\r\n"))

    assert sum(sizes) == len(payload)
    assert sizes[0] == 4
    assert sizes[0] + sizes[1] == len(payload)


def test_uniform_segment_sizes_chunk_the_payload_evenly() -> None:
    sizes = segment_sizes_for(b"a" * 10, uniform_segment_size=4)

    assert sizes == (4, 4, 2)


def test_segment_sizes_reject_a_marker_that_is_absent() -> None:
    with pytest.raises(ValueError):
        segment_sizes_for(b"abc", split_after=(b"zzz",))
