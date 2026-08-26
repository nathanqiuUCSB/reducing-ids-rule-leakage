"""Deterministic synthetic traffic for the SID 2025472 Smart Install signature."""

from __future__ import annotations

from pathlib import Path
from collections.abc import Sequence

from scapy.all import IP, TCP, Raw, wrpcap


SMART_INSTALL_HEADER = bytes.fromhex("00 00 00 01 00 00 00 01 00 00 00 07")


def smart_install_payload(
    *,
    header: bytes = SMART_INSTALL_HEADER,
    prefix: bytes = b"",
    a_gap: int = 12,
    a_bytes: int = 36,
    b_gap: int = 4,
    b_bytes: int = 44,
    trailing: bytes = b"",
) -> bytes:
    """Build the synthetic PoC-shaped byte layout used by SID 2025472."""
    return (
        prefix
        + header
        + b"\0" * a_gap
        + b"A" * a_bytes
        + b"\0" * b_gap
        + b"B" * b_bytes
        + trailing
    )


def build_smart_install_pcap(
    output_path: Path,
    *,
    payload: bytes | None = None,
    segment_sizes: Sequence[int] | None = None,
    established: bool = True,
) -> Path:
    """Write one deterministic TCP stream carrying a Smart Install test payload."""
    payload = payload if payload is not None else smart_install_payload()
    client, server = "10.0.0.1", "10.0.0.2"
    sport, dport = 49152, 4786
    client_isn, server_isn = 1000, 5000
    packets = []

    if established:
        packets.extend(
            [
                IP(src=client, dst=server) / TCP(sport=sport, dport=dport, flags="S", seq=client_isn),
                IP(src=server, dst=client)
                / TCP(sport=dport, dport=sport, flags="SA", seq=server_isn, ack=client_isn + 1),
                IP(src=client, dst=server)
                / TCP(sport=sport, dport=dport, flags="A", seq=client_isn + 1, ack=server_isn + 1),
            ]
        )
    sequence = client_isn + 1
    ack = server_isn + 1
    for chunk in _segments(payload, segment_sizes):
        packets.append(
            IP(src=client, dst=server)
            / TCP(sport=sport, dport=dport, flags="PA", seq=sequence, ack=ack)
            / Raw(chunk)
        )
        sequence += len(chunk)
    if established:
        packets.extend(
            [
                IP(src=server, dst=client)
                / TCP(sport=dport, dport=sport, flags="A", seq=ack, ack=sequence),
                IP(src=client, dst=server)
                / TCP(sport=sport, dport=dport, flags="FA", seq=sequence, ack=ack),
                IP(src=server, dst=client)
                / TCP(sport=dport, dport=sport, flags="FA", seq=ack, ack=sequence + 1),
                IP(src=client, dst=server)
                / TCP(sport=sport, dport=dport, flags="A", seq=sequence + 1, ack=ack + 1),
            ]
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output_path), packets)
    return output_path


def _segments(payload: bytes, sizes: Sequence[int] | None) -> list[bytes]:
    if not sizes:
        return [payload]
    chunks: list[bytes] = []
    position = 0
    for size in sizes:
        if size <= 0:
            raise ValueError("segment sizes must be positive")
        if position >= len(payload):
            break
        chunks.append(payload[position : position + size])
        position += size
    if position < len(payload):
        chunks.append(payload[position:])
    return chunks
