"""Small deterministic PCAP generator adapted from cve_signature_obfuscation.

It supports content-bearing HTTP/TCP/UDP rules for creating future game fixtures.
The v1 game replays a prevalidated committed PCAP instead of generating one live.
"""

from __future__ import annotations

from pathlib import Path
import re

from scapy.all import IP, TCP, UDP, Raw, wrpcap


_HEX_ESCAPE = re.compile(r"\|([0-9a-fA-F ]+)\|")
_HEADER = re.compile(
    r"^(?:alert|drop|pass)\s+(?P<protocol>\S+)\s+\S+\s+\S+\s+"
    r"(?:->|<>)\s+\S+\s+(?P<port>\S+)\s+\((?P<options>.*)\)\s*$",
    re.DOTALL,
)
_CONTENT = re.compile(r'content\s*:\s*"(?P<content>(?:[^"\\]|\\.)*)"\s*;', re.IGNORECASE)
_DISTANCE = re.compile(r"distance\s*:\s*(?P<distance>\d+)\s*;", re.IGNORECASE)


def parse_content_pattern(value: str) -> bytes:
    """Decode a Suricata content value with `|hex|` escape groups."""
    value = value.strip().strip('"')

    def decode_hex(match: re.Match[str]) -> str:
        return bytes.fromhex(match.group(1).replace(" ", "")).decode("latin-1")

    return _HEX_ESCAPE.sub(decode_hex, value).encode("latin-1", errors="replace")


def _payload_for_rule(rule_text: str) -> bytes | None:
    """Build a payload respecting literal `content` and `distance` options."""
    payload = bytearray()
    contents = list(_CONTENT.finditer(rule_text))
    for index, match in enumerate(contents):
        if index:
            next_start = contents[index + 1].start() if index + 1 < len(contents) else len(rule_text)
            modifiers = rule_text[match.end() : next_start]
            distance = _DISTANCE.search(modifiers)
            padding = int(distance.group("distance")) if distance else 1
            payload.extend(b"\0" * padding)
        payload.extend(parse_content_pattern(match.group("content")))
    return bytes(payload) if contents else None


def rule_to_pcap(rule_text: str, output_path: Path) -> Path | None:
    """Create one minimal packet satisfying literal content patterns, if supported."""
    header = _HEADER.match(rule_text.strip())
    if header is None:
        return None

    protocol = header.group("protocol").lower()
    if protocol not in {"http", "tcp", "udp"}:
        return None
    port_text = header.group("port")
    port = int(port_text) if port_text.isdigit() else (80 if protocol == "http" else 0)
    if port == 0:
        return None

    payload = _payload_for_rule(rule_text)
    if payload is None:
        return None

    if protocol == "http":
        payload = b"POST / HTTP/1.1\r\nHost: target.example\r\nContent-Length: " + str(
            len(payload)
        ).encode() + b"\r\n\r\n" + payload
    if protocol == "udp":
        packets = [
            IP(src="10.0.0.1", dst="10.0.0.2")
            / UDP(sport=49152, dport=port)
            / Raw(payload)
        ]
    else:
        client, server = "10.0.0.1", "10.0.0.2"
        packets = [
            IP(src=client, dst=server) / TCP(sport=49152, dport=port, flags="S", seq=100),
            IP(src=server, dst=client)
            / TCP(sport=port, dport=49152, flags="SA", seq=200, ack=101),
            IP(src=client, dst=server) / TCP(sport=49152, dport=port, flags="A", seq=101, ack=201),
            IP(src=client, dst=server)
            / TCP(sport=49152, dport=port, flags="PA", seq=101, ack=201)
            / Raw(payload),
            IP(src=server, dst=client)
            / TCP(sport=port, dport=49152, flags="A", seq=201, ack=101 + len(payload)),
            IP(src=client, dst=server)
            / TCP(sport=49152, dport=port, flags="FA", seq=101 + len(payload), ack=201),
            IP(src=server, dst=client)
            / TCP(sport=port, dport=49152, flags="FA", seq=201, ack=102 + len(payload)),
            IP(src=client, dst=server)
            / TCP(sport=49152, dport=port, flags="A", seq=102 + len(payload), ack=202),
        ]

    output_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output_path), packets)
    return output_path
