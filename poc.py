"""Backward-compatible shim delegating to the modular neighwatch package."""

from __future__ import annotations

import sys

from neighwatch import (
    DLT_EN10MB,
    ETHERTYPE_ARP,
    ArpPacket,
    NeighborEntry,
    NeighborTable,
    SlidingWindowCounter,
    format_mac,
    format_ts,
    make_event,
    parse_ethernet_arp,
)
from neighwatch.capture import (
    PCAP_MAGICS,
    iter_classic_pcap,
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
    "PCAP_MAGICS",
    "ArpPacket",
    "NeighborEntry",
    "NeighborTable",
    "SlidingWindowCounter",
    "format_mac",
    "format_ts",
    "iter_classic_pcap",
    "main",
    "make_event",
    "parse_args",
    "parse_ethernet_arp",
    "resolve_scapy_datalink",
    "run_live",
    "run_live_native_linux",
    "run_live_scapy",
    "run_pcap",
]

if __name__ == "__main__":
    sys.exit(main())
