"""Deterministic Smart Install (SID 2025472) PCAP suite builders.

These fixtures exercise the PoC-shaped Suricata signature, not every possible
CVE-2018-0171 encoding. Positive cases must alert under the original rule;
negative cases must remain silent.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from scapy.all import IP, TCP, Raw, wrpcap


HEADER = bytes.fromhex("000000010000000100000007")
A_RUN = b"A" * 36
B_RUN = b"B" * 44
SPORT = 49152
DPORT = 4786
CLIENT = "10.0.0.1"
SERVER = "10.0.0.2"


@dataclass(frozen=True)
class SmartInstallCase:
    name: str
    expected_alert: bool
    reason: str
    prefix: bytes = b""
    gap_before_a: int = 12
    a_bytes: bytes = A_RUN
    gap_before_b: int = 4
    b_bytes: bytes = B_RUN
    trailing: bytes = b""
    segment_sizes: tuple[int, ...] | None = None
    established: bool = True
    custom_payload: bytes | None = None
    dport: int = DPORT
    reverse_direction: bool = False
    retransmit_segment: int | None = None


def build_smart_install_payload(
    *,
    prefix: bytes = b"",
    gap_before_a: int = 12,
    a_bytes: bytes = A_RUN,
    gap_before_b: int = 4,
    b_bytes: bytes = B_RUN,
    trailing: bytes = b"",
) -> bytes:
    """Assemble one Smart Install-shaped TCP payload from explicit regions."""
    return (
        prefix
        + HEADER
        + (b"\0" * gap_before_a)
        + a_bytes
        + (b"\0" * gap_before_b)
        + b_bytes
        + trailing
    )


def build_smart_install_tcp_packets(
    *,
    payload: bytes,
    segment_sizes: tuple[int, ...] | None = None,
    established: bool = True,
    dport: int = DPORT,
    reverse_direction: bool = False,
    retransmit_segment: int | None = None,
) -> list:
    """Build a deterministic TCP conversation carrying the payload."""
    if not established:
        packets = [
            IP(src=CLIENT, dst=SERVER) / TCP(sport=SPORT, dport=dport, flags="S", seq=100),
            IP(src=CLIENT, dst=SERVER)
            / TCP(sport=SPORT, dport=dport, flags="PA", seq=101, ack=0)
            / Raw(payload),
        ]
        return _with_fixed_timestamps(packets)

    packets = [
        IP(src=CLIENT, dst=SERVER) / TCP(sport=SPORT, dport=dport, flags="S", seq=100),
        IP(src=SERVER, dst=CLIENT)
        / TCP(sport=dport, dport=SPORT, flags="SA", seq=200, ack=101),
        IP(src=CLIENT, dst=SERVER) / TCP(sport=SPORT, dport=dport, flags="A", seq=101, ack=201),
    ]
    seq = 201 if reverse_direction else 101
    chunks = _segment_payload(payload, segment_sizes)
    for index, chunk in enumerate(chunks):
        data_packet = (
            IP(src=SERVER, dst=CLIENT)
            / TCP(sport=dport, dport=SPORT, flags="PA", seq=seq, ack=101)
            / Raw(chunk)
            if reverse_direction
            else IP(src=CLIENT, dst=SERVER)
            / TCP(sport=SPORT, dport=dport, flags="PA", seq=seq, ack=201)
            / Raw(chunk)
        )
        packets.append(data_packet)
        if retransmit_segment == index:
            packets.append(data_packet.copy())
        seq += len(chunk)
    packets.extend(
        [
            IP(src=SERVER, dst=CLIENT)
            / TCP(sport=DPORT, dport=SPORT, flags="A", seq=201, ack=seq),
            IP(src=CLIENT, dst=SERVER)
            / TCP(sport=SPORT, dport=DPORT, flags="FA", seq=seq, ack=201),
            IP(src=SERVER, dst=CLIENT)
            / TCP(sport=DPORT, dport=SPORT, flags="FA", seq=201, ack=seq + 1),
            IP(src=CLIENT, dst=SERVER)
            / TCP(sport=SPORT, dport=DPORT, flags="A", seq=seq + 1, ack=202),
        ]
    )
    return _with_fixed_timestamps(packets)


def _with_fixed_timestamps(packets: list) -> list:
    for index, packet in enumerate(packets):
        packet.time = 1_700_000_000 + index * 0.001
    return packets


def _segment_payload(
    payload: bytes, segment_sizes: tuple[int, ...] | None
) -> list[bytes]:
    if not payload:
        return [b""]
    if segment_sizes is None:
        return [payload]
    if sum(segment_sizes) != len(payload):
        raise ValueError("segment_sizes must sum to the payload length")
    chunks: list[bytes] = []
    offset = 0
    for size in segment_sizes:
        chunks.append(payload[offset : offset + size])
        offset += size
    return chunks


SMART_INSTALL_CASES: tuple[SmartInstallCase, ...] = (
    SmartInstallCase(
        name="P0-baseline",
        expected_alert=True,
        reason="Canonical layout: header + distance:12 A-run + distance:4 B-run",
    ),
    SmartInstallCase(
        name="P1-uninspected-gaps",
        expected_alert=True,
        reason="Exact distance gaps filled with non-zero uninspected bytes",
        # within equals content length, so only exact distance:12 / distance:4 fire.
        custom_payload=HEADER + (b"\xab" * 12) + A_RUN + (b"\xcd" * 4) + B_RUN,
    ),
    SmartInstallCase(
        name="P2-tcp-segmented-alt",
        expected_alert=True,
        reason="Canonical payload with alternate TCP segment boundaries",
        segment_sizes=(12, 48, 48),
    ),
    SmartInstallCase(
        name="P3-trailing-bytes",
        expected_alert=True,
        reason="Trailing bytes after the required literals remain uninspected",
        gap_before_a=12,
        gap_before_b=4,
        trailing=b"\xde\xad\xbe\xef",
    ),
    SmartInstallCase(
        name="P4-tcp-segmented",
        expected_alert=True,
        reason="Same logical payload split across TCP segments for reassembly",
        segment_sizes=(20, 40, 48),
    ),
    SmartInstallCase(
        name="P5-header-split",
        expected_alert=True,
        reason="Header split across TCP segments",
        segment_sizes=(6, 102),
    ),
    SmartInstallCase(
        name="P6-a-anchor-split",
        expected_alert=True,
        reason="A anchor split across TCP segments",
        segment_sizes=(42, 66),
    ),
    SmartInstallCase(
        name="P7-b-anchor-split",
        expected_alert=True,
        reason="B anchor split across TCP segments",
        segment_sizes=(86, 22),
    ),
    SmartInstallCase(
        name="P8-many-small-segments",
        expected_alert=True,
        reason="Canonical payload split into many small TCP segments",
        segment_sizes=(9,) * 12,
    ),
    SmartInstallCase(
        name="P9-retransmission",
        expected_alert=True,
        reason="Canonical payload with one retransmitted TCP data segment",
        segment_sizes=(24, 12, 72),
        retransmit_segment=1,
    ),
    SmartInstallCase(
        name="N1-depth-prefix",
        expected_alert=False,
        reason="One-byte prefix pushes the header outside depth:12",
        prefix=b"\xff",
    ),
    SmartInstallCase(
        name="N2-depth-late-header",
        expected_alert=False,
        reason="Junk fills the first 12 bytes so the real header is too late",
        custom_payload=(b"\x11" * 12) + HEADER + (b"\0" * 12) + A_RUN + (b"\0" * 4) + B_RUN,
    ),
    SmartInstallCase(
        name="N3-A-too-early",
        expected_alert=False,
        reason="A starts before distance:12 minimum",
        gap_before_a=6,
    ),
    SmartInstallCase(
        name="N4-A-too-late",
        expected_alert=False,
        reason="A starts one byte after the exact distance:12/within:36 boundary",
        gap_before_a=13,
    ),
    SmartInstallCase(
        name="N5-A-short",
        expected_alert=False,
        reason="A literal is one byte short of the required 36-byte run",
        a_bytes=b"A" * 35,
    ),
    SmartInstallCase(
        name="N6-B-too-early",
        expected_alert=False,
        reason="B starts before distance:4 minimum",
        gap_before_b=2,
    ),
    SmartInstallCase(
        name="N7-B-too-late",
        expected_alert=False,
        reason="B starts one byte after the exact distance:4/within:44 boundary",
        gap_before_b=5,
    ),
    SmartInstallCase(
        name="N8-B-short",
        expected_alert=False,
        reason="B literal is one byte short of the required 44-byte run",
        b_bytes=b"B" * 43,
    ),
    SmartInstallCase(
        name="N9-wrong-header-byte",
        expected_alert=False,
        reason="Header last byte differs from the required Smart Install marker",
        custom_payload=bytes.fromhex("000000010000000100000008")
        + (b"\0" * 12)
        + A_RUN
        + (b"\0" * 4)
        + B_RUN,
    ),
    SmartInstallCase(
        name="N10-flow-not-established",
        expected_alert=False,
        reason="Payload is sent without an established TCP handshake",
        established=False,
    ),
    SmartInstallCase(
        name="N11-benign-4786",
        expected_alert=False,
        reason="Established TCP/4786 with benign payload and no signature markers",
        custom_payload=b"HELLO_SMART_INSTALL_PROBE",
    ),
    SmartInstallCase(
        name="N12-wrong-port",
        expected_alert=False,
        reason="Canonical payload sent to a non-Smart-Install destination port",
        dport=4787,
    ),
    SmartInstallCase(
        name="N13-wrong-direction",
        expected_alert=False,
        reason="Canonical payload sent from server to client",
        reverse_direction=True,
    ),
    SmartInstallCase(
        name="N14-wrong-a-bytes",
        expected_alert=False,
        reason="A anchor bytes differ from the required literal",
        a_bytes=b"C" * 36,
    ),
    SmartInstallCase(
        name="N15-wrong-b-bytes",
        expected_alert=False,
        reason="B anchor bytes differ from the required literal",
        b_bytes=b"C" * 44,
    ),
    SmartInstallCase(
        name="N16-a-too-short",
        expected_alert=False,
        reason="A anchor is one byte shorter than the required literal",
        a_bytes=b"A" * 35,
    ),
    SmartInstallCase(
        name="N17-b-too-short",
        expected_alert=False,
        reason="B anchor is one byte shorter than the required literal",
        b_bytes=b"B" * 43,
    ),
    SmartInstallCase(
        name="N18-a-b-reversed",
        expected_alert=False,
        reason="A and B anchors appear in the opposite order",
        custom_payload=HEADER + (b"\0" * 12) + B_RUN + (b"\0" * 4) + A_RUN,
    ),
    SmartInstallCase(
        name="N19-header-without-anchors",
        expected_alert=False,
        reason="Correct header has no A or B anchors",
        custom_payload=HEADER + (b"\0" * 96),
    ),
    SmartInstallCase(
        name="N20-anchors-without-header",
        expected_alert=False,
        reason="A and B anchors lack the required header",
        custom_payload=(b"\xff" * 12) + (b"\0" * 12) + A_RUN + (b"\0" * 4) + B_RUN,
    ),
    SmartInstallCase(
        name="N21-random-4786",
        expected_alert=False,
        reason="Random established payload on TCP/4786",
        custom_payload=bytes(range(108)),
    ),
)


def payload_for_case(case: SmartInstallCase) -> bytes:
    if case.custom_payload is not None:
        return case.custom_payload
    return build_smart_install_payload(
        prefix=case.prefix,
        gap_before_a=case.gap_before_a,
        a_bytes=case.a_bytes,
        gap_before_b=case.gap_before_b,
        b_bytes=case.b_bytes,
        trailing=case.trailing,
    )


def write_smart_install_case(case: SmartInstallCase, output_path: Path) -> Path:
    payload = payload_for_case(case)
    packets = build_smart_install_tcp_packets(
        payload=payload,
        segment_sizes=case.segment_sizes,
        established=case.established,
        dport=case.dport,
        reverse_direction=case.reverse_direction,
        retransmit_segment=case.retransmit_segment,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output_path), packets)
    return output_path


def write_smart_install_suite(output_dir: Path) -> list[dict[str, object]]:
    """Write all suite PCAPs and return a serializable manifest."""
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest: list[dict[str, object]] = []
    for case in SMART_INSTALL_CASES:
        path = output_dir / f"{case.name}.pcap"
        write_smart_install_case(case, path)
        manifest.append(
            {
                "name": case.name,
                "pcap": f"pcap/smart_install/{case.name}.pcap",
                "expected_alert": case.expected_alert,
                "reason": case.reason,
            }
        )
    return manifest
