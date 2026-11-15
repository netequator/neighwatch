"""Ethernet, ARP, and IPv6 NDP wire-format packet parsing helpers."""

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
ETHERTYPE_IPV6 = 0x86DD
MAX_VLAN_TAGS = 2

IPV6_HDR_LEN = 40
IPPROTO_ICMPV6 = 58
ICMPV6_TYPE_NS = 135
ICMPV6_TYPE_NA = 136
NDP_OPT_SLLA = 1
NDP_OPT_TLLA = 2

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


@dataclass(frozen=True)
class NdpPacket:
    icmp_type: int
    code: int
    hop_limit: int
    eth_src: str
    eth_dst: str
    src_ip: str
    dst_ip: str
    target_ip: str
    link_layer_addr: str | None
    is_dad: bool
    router_flag: bool
    solicited_flag: bool
    override_flag: bool
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


def parse_ethernet_ndp(frame: bytes) -> tuple[NdpPacket | None, str | None]:
    """Decode Ethernet (+ optional 802.1Q tags) and ICMPv6 Neighbor Discovery payload."""
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

    if ethertype != ETHERTYPE_IPV6:
        return None, None

    if len(frame) - offset < IPV6_HDR_LEN:
        return None, "short_ipv6_header"

    vtc_flow, payload_len, next_header, hop_limit, src_ip_raw, dst_ip_raw = struct.unpack_from(
        "!IHBB16s16s",
        frame,
        offset,
    )
    if (vtc_flow >> 28) != 6:
        return None, "invalid_ipv6_version"

    if next_header != IPPROTO_ICMPV6:
        return None, None

    icmp_offset = offset + IPV6_HDR_LEN
    if len(frame) - icmp_offset < 24:
        return None, "short_ndp_payload"

    icmp_type, icmp_code, _csum, flags_raw, target_raw = struct.unpack_from(
        "!BBHI16s",
        frame,
        icmp_offset,
    )
    if icmp_type not in (ICMPV6_TYPE_NS, ICMPV6_TYPE_NA):
        return None, None

    if icmp_code != 0:
        return None, "invalid_ndp_code"

    if target_raw[0] == 0xFF:
        return None, "ndp_multicast_target"

    src_ip = socket.inet_ntop(socket.AF_INET6, src_ip_raw)
    dst_ip = socket.inet_ntop(socket.AF_INET6, dst_ip_raw)
    target_ip = socket.inet_ntop(socket.AF_INET6, target_raw)

    is_dad = (icmp_type == ICMPV6_TYPE_NS) and (src_ip == "::")
    router_flag = bool(flags_raw & 0x80000000) if icmp_type == ICMPV6_TYPE_NA else False
    solicited_flag = bool(flags_raw & 0x40000000) if icmp_type == ICMPV6_TYPE_NA else False
    override_flag = bool(flags_raw & 0x20000000) if icmp_type == ICMPV6_TYPE_NA else False

    opt_offset = icmp_offset + 24
    pkt_end = min(len(frame), icmp_offset + payload_len) if payload_len > 0 else len(frame)
    link_layer_addr: str | None = None

    while opt_offset + 2 <= pkt_end:
        opt_type, opt_len_units = struct.unpack_from("!BB", frame, opt_offset)
        if opt_len_units == 0:
            return None, "malformed_ndp_option_zero_len"
        opt_bytes = opt_len_units * 8
        if opt_offset + opt_bytes > pkt_end:
            return None, "truncated_ndp_option"
        if opt_len_units == 1 and (
            (opt_type == NDP_OPT_SLLA and icmp_type == ICMPV6_TYPE_NS)
            or (opt_type == NDP_OPT_TLLA and icmp_type == ICMPV6_TYPE_NA)
        ):
            link_layer_addr = format_mac(frame[opt_offset + 2 : opt_offset + 8])
        opt_offset += opt_bytes

    return (
        NdpPacket(
            icmp_type=icmp_type,
            code=icmp_code,
            hop_limit=hop_limit,
            eth_src=format_mac(eth_src_raw),
            eth_dst=format_mac(eth_dst_raw),
            src_ip=src_ip,
            dst_ip=dst_ip,
            target_ip=target_ip,
            link_layer_addr=link_layer_addr,
            is_dad=is_dad,
            router_flag=router_flag,
            solicited_flag=solicited_flag,
            override_flag=override_flag,
            vlan_ids=tuple(vlan_ids),
        ),
        None,
    )
