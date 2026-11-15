"""Unit tests for NeighborTable state tracking and alert generation."""

from __future__ import annotations

from pathlib import Path

import pytest

from neighwatch.parser import (
    ARP_OP_REQUEST,
    DLT_EN10MB,
    ICMPV6_TYPE_NA,
    ICMPV6_TYPE_NS,
    NDP_OPT_SLLA,
    NDP_OPT_TLLA,
)
from neighwatch.table import NeighborTable
from tests.test_parser import _build_arp_frame, _build_ndp_frame


def test_table_learn_and_seen() -> None:
    table = NeighborTable(emit_unchanged=True)
    frame = _build_arp_frame(
        eth_src="00:11:22:33:44:55",
        sha="00:11:22:33:44:55",
        spa="192.168.1.50",
    )

    # First packet: learned
    events = table.process_frame(frame, 100.0, DLT_EN10MB)
    assert len(events) == 1
    assert events[0]["event"] == "arp_learned"
    assert table.bindings == {"192.168.1.50": "00:11:22:33:44:55"}

    # Repeated packet with emit_unchanged=True: seen
    events2 = table.process_frame(frame, 105.0, DLT_EN10MB)
    assert len(events2) == 1
    assert events2[0]["event"] == "arp_seen"


def test_table_mac_change_alert() -> None:
    table = NeighborTable()
    frame1 = _build_arp_frame(
        eth_src="00:11:22:33:44:55",
        sha="00:11:22:33:44:55",
        spa="192.168.1.1",
    )
    table.process_frame(frame1, 100.0, DLT_EN10MB)

    # Different MAC claims the same IP: mac change alert
    frame2 = _build_arp_frame(
        eth_src="aa:bb:cc:dd:ee:ff",
        sha="aa:bb:cc:dd:ee:ff",
        spa="192.168.1.1",
    )
    events = table.process_frame(frame2, 102.0, DLT_EN10MB)
    assert len(events) == 1
    ev = events[0]
    assert ev["event"] == "arp_mac_change"
    assert ev["severity"] == "alert"
    assert ev["detail"]["prev_mac"] == "00:11:22:33:44:55"
    assert table.bindings["192.168.1.1"] == "aa:bb:cc:dd:ee:ff"


def test_table_rfc5227_probe_exclusion() -> None:
    table = NeighborTable()
    probe_frame = _build_arp_frame(
        op=ARP_OP_REQUEST,
        eth_src="00:11:22:33:44:55",
        sha="00:11:22:33:44:55",
        spa="0.0.0.0",
        tpa="192.168.1.100",
    )
    events = table.process_frame(probe_frame, 100.0, DLT_EN10MB)
    assert len(events) == 1
    assert events[0]["event"] == "arp_probe"
    # Ensure 0.0.0.0 was not entered into bindings
    assert "0.0.0.0" not in table.bindings


def test_table_hardware_mismatch() -> None:
    table = NeighborTable()
    # Spoofed frame where Ethernet source does not match ARP SHA
    mismatch_frame = _build_arp_frame(
        eth_src="00:11:22:33:44:55",
        sha="00:aa:bb:cc:dd:ee",
        spa="192.168.1.50",
    )
    events = table.process_frame(mismatch_frame, 100.0, DLT_EN10MB)
    assert len(events) == 1
    assert events[0]["event"] == "arp_hw_mismatch"
    assert events[0]["severity"] == "alert"
    assert "192.168.1.50" not in table.bindings


def test_table_ttl_eviction() -> None:
    table = NeighborTable(ttl=30.0)
    frame = _build_arp_frame(
        eth_src="00:11:22:33:44:55",
        sha="00:11:22:33:44:55",
        spa="192.168.1.50",
    )
    table.process_frame(frame, 100.0, DLT_EN10MB)
    assert "192.168.1.50" in table.bindings

    # Process frame at t=120 (elapsed 20s <= 30s) -> no eviction
    ev_120 = table.prune_stale(120.0)
    assert len(ev_120) == 0

    # At t=131 (elapsed 31s > 30s) -> evicted
    ev_131 = table.prune_stale(131.0)
    assert len(ev_131) == 1
    assert ev_131[0]["event"] == "arp_expired"
    assert "192.168.1.50" not in table.bindings


def test_table_state_save_and_load(tmp_path: Path) -> None:
    table = NeighborTable()
    frame = _build_arp_frame(
        eth_src="00:11:22:33:44:55",
        sha="00:11:22:33:44:55",
        spa="192.168.1.50",
    )
    table.process_frame(frame, 100.0, DLT_EN10MB)

    state_file = tmp_path / "neighbors.json"
    table.save_state(state_file, current_ts=100.0)
    assert state_file.is_file()

    # Load into a new table
    new_table = NeighborTable()
    count = new_table.load_state(state_file)
    assert count == 1
    assert new_table.bindings == {"192.168.1.50": "00:11:22:33:44:55"}


def test_table_unsupported_linktype() -> None:
    table = NeighborTable()
    frame = b"\x00" * 30
    with pytest.raises(ValueError, match="unsupported linktype 0"):
        table.process_frame(frame, 100.0, linktype=0)


def test_table_ndp_learn_and_seen() -> None:
    table = NeighborTable(emit_unchanged=True)
    frame = _build_ndp_frame(
        icmp_type=ICMPV6_TYPE_NS,
        eth_src="00:11:22:33:44:55",
        src_ip="2001:db8::10",
        target_ip="2001:db8::1",
        opt_type=NDP_OPT_SLLA,
        opt_mac="00:11:22:33:44:55",
    )
    events = table.process_frame(frame, 100.0, DLT_EN10MB)
    assert len(events) == 1
    assert events[0]["event"] == "ndp_learned"
    assert events[0]["src_ip"] == "2001:db8::10"
    assert events[0]["src_mac"] == "00:11:22:33:44:55"
    assert table.bindings["2001:db8::10"] == "00:11:22:33:44:55"

    events2 = table.process_frame(frame, 105.0, DLT_EN10MB)
    assert len(events2) == 1
    assert events2[0]["event"] == "ndp_seen"


def test_table_ndp_advertisement_learn_and_change() -> None:
    table = NeighborTable()
    frame_adv = _build_ndp_frame(
        icmp_type=ICMPV6_TYPE_NA,
        eth_src="00:11:22:33:44:55",
        target_ip="2001:db8::1",
        opt_type=NDP_OPT_TLLA,
        opt_mac="00:11:22:33:44:55",
        solicited=True,
        override=True,
    )
    events = table.process_frame(frame_adv, 100.0, DLT_EN10MB)
    assert len(events) == 1
    assert events[0]["event"] == "ndp_learned"
    assert table.bindings["2001:db8::1"] == "00:11:22:33:44:55"

    # Conflicting advertisement with different MAC
    frame_spoof = _build_ndp_frame(
        icmp_type=ICMPV6_TYPE_NA,
        eth_src="aa:bb:cc:dd:ee:ff",
        target_ip="2001:db8::1",
        opt_type=NDP_OPT_TLLA,
        opt_mac="aa:bb:cc:dd:ee:ff",
        solicited=False,
        override=True,
    )
    events2 = table.process_frame(frame_spoof, 105.0, DLT_EN10MB)
    assert len(events2) == 1
    assert events2[0]["event"] == "ndp_mac_change"
    assert events2[0]["severity"] == "alert"
    assert events2[0]["detail"]["prev_mac"] == "00:11:22:33:44:55"
    assert table.bindings["2001:db8::1"] == "aa:bb:cc:dd:ee:ff"


def test_table_ndp_dad_probe_quarantine() -> None:
    table = NeighborTable()
    dad_frame = _build_ndp_frame(
        icmp_type=ICMPV6_TYPE_NS,
        eth_src="00:11:22:33:44:55",
        src_ip="::",
        target_ip="fe80::1",
        opt_type=None,
        opt_mac=None,
    )
    events = table.process_frame(dad_frame, 100.0, DLT_EN10MB)
    assert len(events) == 1
    assert events[0]["event"] == "ndp_dad_probe"
    assert events[0]["severity"] == "info"
    assert events[0]["src_ip"] == "::"
    # Ensure :: is never added to neighbor table
    assert "::" not in table.bindings
    assert len(table.bindings) == 0


def test_table_ndp_dad_probe_invalid_slla() -> None:
    table = NeighborTable()
    # RFC 4861 prohibits SLLA in DAD probes from ::
    bad_dad = _build_ndp_frame(
        icmp_type=ICMPV6_TYPE_NS,
        eth_src="00:11:22:33:44:55",
        src_ip="::",
        target_ip="fe80::1",
        opt_type=NDP_OPT_SLLA,
        opt_mac="00:11:22:33:44:55",
    )
    events = table.process_frame(bad_dad, 100.0, DLT_EN10MB)
    assert len(events) == 1
    assert events[0]["event"] == "ndp_invalid_slla"
    assert events[0]["severity"] == "warn"


def test_table_ndp_hardware_mismatch() -> None:
    table = NeighborTable()
    # Spoofed frame where Ethernet source MAC does not match SLLA
    mismatch_frame = _build_ndp_frame(
        icmp_type=ICMPV6_TYPE_NS,
        eth_src="00:11:22:33:44:55",
        src_ip="2001:db8::10",
        target_ip="2001:db8::1",
        opt_type=NDP_OPT_SLLA,
        opt_mac="00:aa:bb:cc:dd:ee",
    )
    events = table.process_frame(mismatch_frame, 100.0, DLT_EN10MB)
    assert len(events) == 1
    assert events[0]["event"] == "ndp_hw_mismatch"
    assert events[0]["severity"] == "alert"
    assert "2001:db8::10" not in table.bindings


def test_table_ndp_hop_limit_check() -> None:
    table = NeighborTable()
    # RFC 4861 requires hop_limit == 255 to prevent off-link spoofing
    routed_frame = _build_ndp_frame(hop_limit=64)
    events = table.process_frame(routed_frame, 100.0, DLT_EN10MB)
    assert len(events) == 1
    assert events[0]["event"] == "ndp_invalid_hop_limit"
    assert events[0]["severity"] == "warn"


def test_table_ndp_ttl_eviction() -> None:
    table = NeighborTable(ttl=30.0)
    frame = _build_ndp_frame(
        icmp_type=ICMPV6_TYPE_NS,
        eth_src="00:11:22:33:44:55",
        src_ip="2001:db8::50",
        target_ip="2001:db8::1",
        opt_type=NDP_OPT_SLLA,
        opt_mac="00:11:22:33:44:55",
    )
    table.process_frame(frame, 100.0, DLT_EN10MB)
    assert "2001:db8::50" in table.bindings

    ev_135 = table.prune_stale(135.0)
    assert len(ev_135) == 1
    assert ev_135[0]["event"] == "ndp_expired"
    assert ev_135[0]["src_ip"] == "2001:db8::50"
    assert "2001:db8::50" not in table.bindings
