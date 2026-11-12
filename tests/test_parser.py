"""Unit tests for Ethernet and ARP wire parsing."""

from __future__ import annotations

import socket
import struct

from neighwatch.parser import (
    ARP_HTYPE_ETHERNET,
    ARP_OP_REPLY,
    ARP_OP_REQUEST,
    ARP_PTYPE_IPV4,
    ETHERTYPE_ARP,
    ETHERTYPE_VLAN_8021Q,
    format_mac,
    format_ts,
    make_event,
    parse_ethernet_arp,
)


def _mac_bytes(mac_str: str) -> bytes:
    return bytes.fromhex(mac_str.replace(":", ""))


def _build_arp_frame(
    eth_dst: str = "ff:ff:ff:ff:ff:ff",
    eth_src: str = "00:11:22:33:44:55",
    op: int = ARP_OP_REQUEST,
    sha: str = "00:11:22:33:44:55",
    spa: str = "192.168.1.10",
    tha: str = "00:00:00:00:00:00",
    tpa: str = "192.168.1.1",
    vlan_id: int | None = None,
    pad_to: int | None = None,
) -> bytes:
    if vlan_id is not None:
        eth_hdr = struct.pack(
            "!6s6sHH",
            _mac_bytes(eth_dst),
            _mac_bytes(eth_src),
            ETHERTYPE_VLAN_8021Q,
            vlan_id & 0x0FFF,
        ) + struct.pack("!H", ETHERTYPE_ARP)
    else:
        eth_hdr = struct.pack(
            "!6s6sH",
            _mac_bytes(eth_dst),
            _mac_bytes(eth_src),
            ETHERTYPE_ARP,
        )

    arp_body = struct.pack(
        "!HHBBH6s4s6s4s",
        ARP_HTYPE_ETHERNET,
        ARP_PTYPE_IPV4,
        6,
        4,
        op,
        _mac_bytes(sha),
        socket.inet_aton(spa),
        _mac_bytes(tha),
        socket.inet_aton(tpa),
    )

    frame = eth_hdr + arp_body
    if pad_to is not None and len(frame) < pad_to:
        frame += b"\x00" * (pad_to - len(frame))
    return frame


def test_parse_valid_arp_request() -> None:
    frame = _build_arp_frame(op=ARP_OP_REQUEST, sha="00:11:22:33:44:55", spa="192.168.1.50")
    pkt, err = parse_ethernet_arp(frame)
    assert err is None
    assert pkt is not None
    assert pkt.op == ARP_OP_REQUEST
    assert pkt.sha == "00:11:22:33:44:55"
    assert pkt.spa == "192.168.1.50"
    assert pkt.tpa == "192.168.1.1"
    assert not pkt.sha_multicast
    assert pkt.vlan_ids == ()


def test_parse_valid_arp_reply() -> None:
    frame = _build_arp_frame(
        eth_dst="00:11:22:33:44:55",
        eth_src="00:aa:bb:cc:dd:ee",
        op=ARP_OP_REPLY,
        sha="00:aa:bb:cc:dd:ee",
        spa="192.168.1.1",
        tha="00:11:22:33:44:55",
        tpa="192.168.1.50",
    )
    pkt, err = parse_ethernet_arp(frame)
    assert err is None
    assert pkt is not None
    assert pkt.op == ARP_OP_REPLY
    assert pkt.sha == "00:aa:bb:cc:dd:ee"
    assert pkt.spa == "192.168.1.1"
    assert pkt.tha == "00:11:22:33:44:55"
    assert pkt.tpa == "192.168.1.50"


def test_parse_with_8021q_vlan() -> None:
    frame = _build_arp_frame(vlan_id=100)
    pkt, err = parse_ethernet_arp(frame)
    assert err is None
    assert pkt is not None
    assert pkt.vlan_ids == (100,)


def test_parse_with_60_byte_padding() -> None:
    frame = _build_arp_frame(pad_to=60)
    assert len(frame) == 60
    pkt, err = parse_ethernet_arp(frame)
    assert err is None
    assert pkt is not None
    assert pkt.spa == "192.168.1.10"


def test_parse_short_ethernet_frame() -> None:
    frame = b"\x00" * 10
    pkt, err = parse_ethernet_arp(frame)
    assert pkt is None
    assert err == "short_ethernet_frame"


def test_parse_non_arp_ethertype() -> None:
    frame = struct.pack("!6s6sH", b"\xff" * 6, b"\x00" * 6, 0x0800) + b"\x00" * 30
    pkt, err = parse_ethernet_arp(frame)
    assert pkt is None
    assert err is None


def test_parse_short_arp_payload() -> None:
    frame = struct.pack("!6s6sH", b"\xff" * 6, b"\x00" * 6, ETHERTYPE_ARP) + b"\x00" * 10
    pkt, err = parse_ethernet_arp(frame)
    assert pkt is None
    assert err == "short_arp_payload"


def test_format_mac_and_ts() -> None:
    raw = bytes([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E])
    assert format_mac(raw) == "00:1a:2b:3c:4d:5e"

    ts_str = format_ts(1700000000.0)
    assert ts_str.startswith("2023-")
    assert ts_str.endswith("Z")

    event = make_event(1700000000.0, "test", "info", "1.1.1.1", "aa:bb:cc:dd:ee:ff", {"key": "val"})
    assert event["event"] == "test"
    assert event["tool"] == "neighwatch"
