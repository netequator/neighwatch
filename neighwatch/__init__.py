"""neighwatch — Passive L2 ARP and IPv6 NDP neighbor monitor and spoof detector."""

from __future__ import annotations

from neighwatch.capture import (
    iter_capture,
    iter_classic_pcap,
    iter_pcapng,
    run_live,
    run_pcap,
)
from neighwatch.parser import (
    DLT_EN10MB,
    ETHERTYPE_ARP,
    ETHERTYPE_IPV6,
    ICMPV6_TYPE_NA,
    ICMPV6_TYPE_NS,
    ArpPacket,
    NdpPacket,
    format_mac,
    format_ts,
    make_event,
    parse_ethernet_arp,
    parse_ethernet_ndp,
)
from neighwatch.table import NeighborEntry, NeighborTable
from neighwatch.window import SlidingWindowCounter

__version__ = "0.1.0"

__all__ = [
    "DLT_EN10MB",
    "ETHERTYPE_ARP",
    "ETHERTYPE_IPV6",
    "ICMPV6_TYPE_NA",
    "ICMPV6_TYPE_NS",
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
    "make_event",
    "parse_ethernet_arp",
    "parse_ethernet_ndp",
    "run_live",
    "run_pcap",
]
