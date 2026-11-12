"""Ethernet and ARP wire-format packet parsing helpers."""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from datetime import UTC, datetime

DLT_EN10MB = 1
ETH_HDR_LEN = 14
ETHERTYPE_VLAN_8021Q = 0x8100
ETHERTYPE_VLAN_8021AD = 0x88A8
ETHERTYPE_ARP = 0x0806
MAX_VLAN_TAGS = 2

ARP_HDR_LEN = 28
ARP_HTYPE_ETHERNET = 1
ARP_PTYPE_IPV4 = 0x0800
ARP_OP_REQUEST = 1
ARP_OP_REPLY = 2

ZERO_MAC = "00:00:00:00:00:00"
BCAST_MAC = "ff:ff:ff:ff:ff:ff"


@dataclass(frozen=True)
class ArpPacket:
    op: int
    eth_src: str
    eth_dst: str
    sha: str
    spa: str
    tha: str
    tpa: str
    sha_multicast: bool
    vlan_ids: tuple[int, ...]


def format_mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def format_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def make_event(
    ts: float,
    event: str,
    severity: str,
    src_ip: str | None,
    src_mac: str | None,
    detail: dict[str, object],
) -> dict[str, object]:
    return {
        "ts": format_ts(ts),
        "tool": "neighwatch",
        "event": event,
        "severity": severity,
        "src_ip": src_ip,
        "src_mac": src_mac,
        "detail": detail,
    }


def parse_ethernet_arp(frame: bytes) -> tuple[ArpPacket | None, str | None]:
    """Decode Ethernet (+ optional 802.1Q tags) and IPv4-over-Ethernet ARP payload."""
    if len(frame) < ETH_HDR_LEN:
        return None, "short_ethernet_frame"

    eth_dst_raw, eth_src_raw, ethertype = struct.unpack_from("!6s6sH", frame, 0)
    offset = ETH_HDR_LEN
    vlan_ids: list[int] = []

    while ethertype in (ETHERTYPE_VLAN_8021Q, ETHERTYPE_VLAN_8021AD):
        if len(vlan_ids) >= MAX_VLAN_TAGS or offset + 4 > len(frame):
            return None, "malformed_vlan_header"
        tci, ethertype = struct.unpack_from("!HH", frame, offset)
        vlan_ids.append(tci & 0x0FFF)
        offset += 4

    if ethertype != ETHERTYPE_ARP:
        return None, None

    # Standard minimum 60-byte Ethernet frames pad 28-byte ARP payloads with trailing zeros;
    # unpack_from at offset reads the fixed 28-byte ARP body without failing on padding.
    if len(frame) - offset < ARP_HDR_LEN:
        return None, "short_arp_payload"

    htype, ptype, hlen, plen, op, sha_raw, spa_raw, tha_raw, tpa_raw = struct.unpack_from(
        "!HHBBH6s4s6s4s",
        frame,
        offset,
    )
    if htype != ARP_HTYPE_ETHERNET or ptype != ARP_PTYPE_IPV4 or hlen != 6 or plen != 4:
        return None, None

    return (
        ArpPacket(
            op=op,
            eth_src=format_mac(eth_src_raw),
            eth_dst=format_mac(eth_dst_raw),
            sha=format_mac(sha_raw),
            spa=socket.inet_ntoa(spa_raw),
            tha=format_mac(tha_raw),
            tpa=socket.inet_ntoa(tpa_raw),
            sha_multicast=bool(sha_raw[0] & 0x01),
            vlan_ids=tuple(vlan_ids),
        ),
        None,
    )
