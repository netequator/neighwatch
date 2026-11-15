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
    ETHERTYPE_IPV6,
    ETHERTYPE_VLAN_8021Q,
    ICMPV6_TYPE_NA,
    ICMPV6_TYPE_NS,
    NDP_OPT_SLLA,
    NDP_OPT_TLLA,
    format_mac,
    format_ts,
    make_event,
    parse_ethernet_arp,
    parse_ethernet_ndp,
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


def _build_ndp_frame(
    eth_dst: str = "33:33:00:00:00:01",
    eth_src: str = "00:11:22:33:44:55",
    icmp_type: int = ICMPV6_TYPE_NS,
    code: int = 0,
    hop_limit: int = 255,
    src_ip: str = "2001:db8::1",
    dst_ip: str = "ff02::1",
    target_ip: str = "2001:db8::2",
    opt_type: int | None = NDP_OPT_SLLA,
    opt_mac: str | None = "00:11:22:33:44:55",
    router: bool = False,
    solicited: bool = False,
    override: bool = False,
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
        ) + struct.pack("!H", ETHERTYPE_IPV6)
    else:
        eth_hdr = struct.pack(
            "!6s6sH",
            _mac_bytes(eth_dst),
            _mac_bytes(eth_src),
            ETHERTYPE_IPV6,
        )

    flags = 0
    if router:
        flags |= 0x80000000
    if solicited:
        flags |= 0x40000000
    if override:
        flags |= 0x20000000

    icmp_body = struct.pack(
        "!BBHI16s",
        icmp_type,
        code,
        0,
        flags,
        socket.inet_pton(socket.AF_INET6, target_ip),
    )

    if opt_type is not None and opt_mac is not None:
        icmp_body += struct.pack("!BB6s", opt_type, 1, _mac_bytes(opt_mac))

    ipv6_hdr = struct.pack(
        "!IHBB16s16s",
        0x60000000,
        len(icmp_body),
        58,
        hop_limit,
        socket.inet_pton(socket.AF_INET6, src_ip),
        socket.inet_pton(socket.AF_INET6, dst_ip),
    )

    frame = eth_hdr + ipv6_hdr + icmp_body
    if pad_to is not None and len(frame) < pad_to:
        frame += b"\x00" * (pad_to - len(frame))
    return frame


def test_parse_valid_ndp_solicitation() -> None:
    frame = _build_ndp_frame(
        icmp_type=ICMPV6_TYPE_NS,
        src_ip="2001:db8::10",
        target_ip="2001:db8::1",
        opt_type=NDP_OPT_SLLA,
        opt_mac="00:11:22:33:44:55",
    )
    pkt, err = parse_ethernet_ndp(frame)
    assert err is None
    assert pkt is not None
    assert pkt.icmp_type == ICMPV6_TYPE_NS
    assert pkt.code == 0
    assert pkt.hop_limit == 255
    assert pkt.src_ip == "2001:db8::10"
    assert pkt.target_ip == "2001:db8::1"
    assert pkt.link_layer_addr == "00:11:22:33:44:55"
    assert not pkt.is_dad
    assert pkt.vlan_ids == ()


def test_parse_valid_ndp_advertisement() -> None:
    frame = _build_ndp_frame(
        icmp_type=ICMPV6_TYPE_NA,
        src_ip="2001:db8::1",
        dst_ip="2001:db8::10",
        target_ip="2001:db8::1",
        opt_type=NDP_OPT_TLLA,
        opt_mac="00:aa:bb:cc:dd:ee",
        router=True,
        solicited=True,
        override=True,
    )
    pkt, err = parse_ethernet_ndp(frame)
    assert err is None
    assert pkt is not None
    assert pkt.icmp_type == ICMPV6_TYPE_NA
    assert pkt.router_flag
    assert pkt.solicited_flag
    assert pkt.override_flag
    assert pkt.link_layer_addr == "00:aa:bb:cc:dd:ee"
    assert pkt.target_ip == "2001:db8::1"


def test_parse_ndp_dad_probe() -> None:
    frame = _build_ndp_frame(
        icmp_type=ICMPV6_TYPE_NS,
        src_ip="::",
        target_ip="fe80::1",
        opt_type=None,
        opt_mac=None,
    )
    pkt, err = parse_ethernet_ndp(frame)
    assert err is None
    assert pkt is not None
    assert pkt.is_dad
    assert pkt.src_ip == "::"
    assert pkt.target_ip == "fe80::1"
    assert pkt.link_layer_addr is None


def test_parse_ndp_with_vlan() -> None:
    frame = _build_ndp_frame(vlan_id=200)
    pkt, err = parse_ethernet_ndp(frame)
    assert err is None
    assert pkt is not None
    assert pkt.vlan_ids == (200,)


def test_parse_ndp_short_ipv6_header() -> None:
    frame = struct.pack("!6s6sH", b"\xff" * 6, b"\x00" * 6, ETHERTYPE_IPV6) + b"\x00" * 20
    pkt, err = parse_ethernet_ndp(frame)
    assert pkt is None
    assert err == "short_ipv6_header"


def test_parse_ndp_short_icmp_payload() -> None:
    eth_hdr = struct.pack("!6s6sH", b"\xff" * 6, b"\x00" * 6, ETHERTYPE_IPV6)
    ipv6_hdr = struct.pack(
        "!IHBB16s16s",
        0x60000000,
        10,
        58,
        255,
        b"\x00" * 16,
        b"\x00" * 16,
    )
    frame = eth_hdr + ipv6_hdr + b"\x00" * 10
    pkt, err = parse_ethernet_ndp(frame)
    assert pkt is None
    assert err == "short_ndp_payload"


def test_parse_ndp_invalid_code() -> None:
    frame = _build_ndp_frame(code=1)
    pkt, err = parse_ethernet_ndp(frame)
    assert pkt is None
    assert err == "invalid_ndp_code"


def test_parse_ndp_multicast_target() -> None:
    frame = _build_ndp_frame(target_ip="ff02::1")
    pkt, err = parse_ethernet_ndp(frame)
    assert pkt is None
    assert err == "ndp_multicast_target"


def test_parse_ndp_non_icmpv6() -> None:
    eth_hdr = struct.pack("!6s6sH", b"\xff" * 6, b"\x00" * 6, ETHERTYPE_IPV6)
    ipv6_hdr = struct.pack(
        "!IHBB16s16s",
        0x60000000,
        20,
        6,  # TCP
        255,
        b"\x00" * 16,
        b"\x00" * 16,
    )
    frame = eth_hdr + ipv6_hdr + b"\x00" * 20
    pkt, err = parse_ethernet_ndp(frame)
    assert pkt is None
    assert err is None


def test_parse_ndp_option_zero_len() -> None:
    eth_hdr = struct.pack("!6s6sH", b"\xff" * 6, b"\x00" * 6, ETHERTYPE_IPV6)
    icmp_body = struct.pack(
        "!BBHI16s",
        ICMPV6_TYPE_NS,
        0,
        0,
        0,
        socket.inet_pton(socket.AF_INET6, "2001:db8::1"),
    ) + struct.pack("!BB", 1, 0)  # len=0 invalid
    ipv6_hdr = struct.pack(
        "!IHBB16s16s",
        0x60000000,
        len(icmp_body),
        58,
        255,
        socket.inet_pton(socket.AF_INET6, "2001:db8::2"),
        socket.inet_pton(socket.AF_INET6, "ff02::1"),
    )
    frame = eth_hdr + ipv6_hdr + icmp_body
    pkt, err = parse_ethernet_ndp(frame)
    assert pkt is None
    assert err == "malformed_ndp_option_zero_len"
