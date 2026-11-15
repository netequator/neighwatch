"""Backward-compatible shim delegating to the modular neighwatch package."""

from __future__ import annotations

import sys

from neighwatch import (
    DLT_EN10MB,
    ETHERTYPE_ARP,
    ETHERTYPE_IPV6,
    ICMPV6_TYPE_NA,
    ICMPV6_TYPE_NS,
    ArpPacket,
    NdpPacket,
    NeighborEntry,
    NeighborTable,
    SlidingWindowCounter,
    format_mac,
    format_ts,
    make_event,
    parse_ethernet_arp,
    parse_ethernet_ndp,
)
from neighwatch.capture import (
    PCAP_MAGICS,
    iter_capture,
    iter_classic_pcap,
    iter_pcapng,
    resolve_scapy_datalink,
    run_live,
    run_live_native_linux,
    run_live_scapy,
    run_pcap,
)
from neighwatch.cli import main, parse_args

__all__ = [
    "DLT_EN10MB",
    "ETHERTYPE_ARP",
    "ETHERTYPE_IPV6",
    "ICMPV6_TYPE_NA",
    "ICMPV6_TYPE_NS",
    "PCAP_MAGICS",
    "ArpPacket",
    "NdpPacket",
    "NeighborEntry",
    "NeighborTable",
    "SlidingWindowCounter",
    "format_mac",
    "format_ts",
    "iter_capture",
    "iter_classic_pcap",
    "iter_pcapng",
    "main",
    "make_event",
    "parse_args",
    "parse_ethernet_arp",
    "parse_ethernet_ndp",
    "resolve_scapy_datalink",
    "run_live",
    "run_live_native_linux",
    "run_live_scapy",
    "run_pcap",
]

if __name__ == "__main__":
    sys.exit(main())
