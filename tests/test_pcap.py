"""Unit tests for classic PCAP and PCAPNG readers."""

from __future__ import annotations

import io
import struct
from pathlib import Path

import pytest

from neighwatch.capture import (
    iter_capture,
    iter_classic_pcap,
    iter_pcapng,
    run_pcap,
)
from neighwatch.parser import DLT_EN10MB
from neighwatch.table import NeighborTable
from tests.test_parser import _build_arp_frame


def _create_pcap_bytes(
    frames: list[tuple[float, bytes]],
    endian: str = "<",
    nanosecond: bool = False,
    linktype: int = DLT_EN10MB,
) -> bytes:
    if nanosecond:
        magic = b"\x4d\x3c\xb2\xa1" if endian == "<" else b"\xa1\xb2\x3c\x4d"
        ts_scale = 1e9
    else:
        magic = b"\xd4\xc3\xb2\xa1" if endian == "<" else b"\xa1\xb2\xc3\xd4"
        ts_scale = 1e6

    ghdr = magic + struct.pack(f"{endian}HHIIII", 2, 4, 0, 0, 65535, linktype)
    body = bytearray()
    for ts, pkt in frames:
        sec = int(ts)
        frac = round((ts - sec) * ts_scale)
        rhdr = struct.pack(f"{endian}IIII", sec, frac, len(pkt), len(pkt))
        body.extend(rhdr)
        body.extend(pkt)
    return ghdr + bytes(body)


def _create_pcapng_bytes(
    sections: list[dict[str, object]],
    endian: str = "<",
) -> bytes:
    """Serialize synthetic PCAPNG stream containing SHB, IDB, and packet blocks."""
    out = bytearray()
    bom = b"\x4d\x3c\x2b\x1a" if endian == "<" else b"\x1a\x2b\x3c\x4d"

    for sec in sections:
        # 1. Section Header Block (SHB)
        shb_body = bom + struct.pack(f"{endian}HHq", 1, 0, -1)
        shb_len = 8 + len(shb_body) + 4
        out.extend(b"\x0a\x0d\x0d\x0a")
        out.extend(struct.pack(f"{endian}I", shb_len))
        out.extend(shb_body)
        out.extend(struct.pack(f"{endian}I", shb_len))

        # 2. Interface Description Blocks (IDBs)
        interfaces = sec.get("interfaces", [{"linktype": DLT_EN10MB, "snaplen": 65535, "tsresol": 6}])
        ts_scales: list[float] = []

        for iface in interfaces:
            linktype = int(iface.get("linktype", DLT_EN10MB))
            snaplen = int(iface.get("snaplen", 65535))
            tsresol = int(iface.get("tsresol", 6))
            ts_scales.append(10.0 ** (-tsresol))

            # Options: code 9 (if_tsresol), len 1, 1 byte value + 3 bytes padding
            opt_data = struct.pack(f"{endian}HH", 9, 1) + bytes([tsresol]) + b"\x00\x00\x00"
            idb_body = struct.pack(f"{endian}HHI", linktype, 0, snaplen) + opt_data
            idb_len = 8 + len(idb_body) + 4
            out.extend(struct.pack(f"{endian}II", 1, idb_len))
            out.extend(idb_body)
            out.extend(struct.pack(f"{endian}I", idb_len))

        # Optional custom / unhandled block injection for test verification
        if sec.get("inject_unhandled"):
            isb_body = struct.pack(f"{endian}II", 0, 0)  # Dummy Interface Statistics Block
            isb_len = 8 + len(isb_body) + 4
            out.extend(struct.pack(f"{endian}II", 5, isb_len))
            out.extend(isb_body)
            out.extend(struct.pack(f"{endian}I", isb_len))

        # 3. Packet Blocks (EPBs or SPBs)
        packets = sec.get("packets", [])
        for pkt_info in packets:
            if pkt_info.get("type") == "spb":
                pkt = pkt_info["data"]
                pad_len = (4 - (len(pkt) % 4)) % 4
                spb_body = struct.pack(f"{endian}I", len(pkt)) + pkt + (b"\x00" * pad_len)
                spb_len = 8 + len(spb_body) + 4
                out.extend(struct.pack(f"{endian}II", 3, spb_len))
                out.extend(spb_body)
                out.extend(struct.pack(f"{endian}I", spb_len))
            else:
                iface_id = int(pkt_info.get("iface", 0))
                ts = float(pkt_info.get("ts", 0.0))
                pkt = pkt_info["data"]
                scale = ts_scales[iface_id] if iface_id < len(ts_scales) else 1e-6
                raw_units = round(ts / scale)
                ts_high = (raw_units >> 32) & 0xFFFFFFFF
                ts_low = raw_units & 0xFFFFFFFF

                pad_len = (4 - (len(pkt) % 4)) % 4
                epb_body = (
                    struct.pack(f"{endian}IIIII", iface_id, ts_high, ts_low, len(pkt), len(pkt))
                    + pkt
                    + (b"\x00" * pad_len)
                )
                epb_len = 8 + len(epb_body) + 4
                out.extend(struct.pack(f"{endian}II", 6, epb_len))
                out.extend(epb_body)
                out.extend(struct.pack(f"{endian}I", epb_len))

    return bytes(out)


def test_iter_classic_pcap_little_endian_microsecond() -> None:
    frame1 = _build_arp_frame(spa="192.168.1.10")
    frame2 = _build_arp_frame(spa="192.168.1.20")
    raw = _create_pcap_bytes([(100.5, frame1), (101.25, frame2)], endian="<", nanosecond=False)

    stream = io.BytesIO(raw)
    records = list(iter_classic_pcap(stream))
    assert len(records) == 2
    assert records[0][0] == DLT_EN10MB
    assert pytest.approx(records[0][1], rel=1e-5) == 100.5
    assert records[0][2] == frame1
    assert pytest.approx(records[1][1], rel=1e-5) == 101.25
    assert records[1][2] == frame2


def test_iter_classic_pcap_big_endian_nanosecond() -> None:
    frame = _build_arp_frame(spa="10.0.0.1")
    raw = _create_pcap_bytes([(500.123456789, frame)], endian=">", nanosecond=True)

    stream = io.BytesIO(raw)
    records = list(iter_classic_pcap(stream))
    assert len(records) == 1
    assert pytest.approx(records[0][1], rel=1e-7) == 500.123456789


def test_iter_classic_pcap_invalid_magic() -> None:
    stream = io.BytesIO(b"\x00\x00\x00\x00" + b"\x00" * 20)
    with pytest.raises(ValueError, match="unsupported capture magic"):
        list(iter_classic_pcap(stream))


def test_iter_pcapng_little_endian_microsecond() -> None:
    frame = _build_arp_frame(spa="192.168.1.10")
    raw = _create_pcapng_bytes(
        [
            {
                "interfaces": [{"linktype": DLT_EN10MB, "tsresol": 6}],
                "packets": [{"iface": 0, "ts": 123456.789012, "data": frame}],
            }
        ],
        endian="<",
    )
    stream = io.BytesIO(raw)
    records = list(iter_pcapng(stream))
    assert len(records) == 1
    assert records[0][0] == DLT_EN10MB
    assert pytest.approx(records[0][1], rel=1e-6) == 123456.789012
    assert records[0][2] == frame


def test_iter_pcapng_big_endian_nanosecond() -> None:
    frame = _build_arp_frame(spa="172.16.0.5")
    raw = _create_pcapng_bytes(
        [
            {
                "interfaces": [{"linktype": DLT_EN10MB, "tsresol": 9}],
                "packets": [{"iface": 0, "ts": 987654.123456789, "data": frame}],
            }
        ],
        endian=">",
    )
    stream = io.BytesIO(raw)
    records = list(iter_pcapng(stream))
    assert len(records) == 1
    assert records[0][0] == DLT_EN10MB
    assert pytest.approx(records[0][1], rel=1e-8) == 987654.123456789
    assert records[0][2] == frame


def test_iter_pcapng_multiple_interfaces() -> None:
    frame1 = _build_arp_frame(spa="10.0.0.1")
    frame2 = _build_arp_frame(spa="10.0.0.2")
    raw = _create_pcapng_bytes(
        [
            {
                "interfaces": [
                    {"linktype": DLT_EN10MB, "tsresol": 6},
                    {"linktype": DLT_EN10MB, "tsresol": 9},
                ],
                "packets": [
                    {"iface": 0, "ts": 100.1, "data": frame1},
                    {"iface": 1, "ts": 100.2, "data": frame2},
                ],
            }
        ],
        endian="<",
    )
    records = list(iter_pcapng(io.BytesIO(raw)))
    assert len(records) == 2
    assert records[0][2] == frame1
    assert records[1][2] == frame2


def test_iter_pcapng_skips_unhandled_blocks() -> None:
    frame = _build_arp_frame(spa="192.168.1.1")
    raw = _create_pcapng_bytes(
        [
            {
                "interfaces": [{"linktype": DLT_EN10MB, "tsresol": 6}],
                "inject_unhandled": True,
                "packets": [{"iface": 0, "ts": 50.0, "data": frame}],
            }
        ],
        endian="<",
    )
    records = list(iter_pcapng(io.BytesIO(raw)))
    assert len(records) == 1
    assert records[0][2] == frame


def test_iter_pcapng_simple_packet_block() -> None:
    frame = _build_arp_frame(spa="192.168.1.254")
    raw = _create_pcapng_bytes(
        [
            {
                "interfaces": [{"linktype": DLT_EN10MB, "tsresol": 6}],
                "packets": [{"type": "spb", "data": frame}],
            }
        ],
        endian="<",
    )
    records = list(iter_pcapng(io.BytesIO(raw)))
    assert len(records) == 1
    assert records[0][0] == DLT_EN10MB
    assert records[0][1] == 0.0
    assert records[0][2] == frame


def test_iter_pcapng_undefined_interface_error() -> None:
    frame = _build_arp_frame()
    raw = _create_pcapng_bytes(
        [
            {
                "interfaces": [{"linktype": DLT_EN10MB}],
                "packets": [{"iface": 5, "ts": 1.0, "data": frame}],
            }
        ]
    )
    with pytest.raises(ValueError, match="undefined interface 5"):
        list(iter_pcapng(io.BytesIO(raw)))


def test_iter_capture_unified_dispatch() -> None:
    frame = _build_arp_frame(spa="192.168.1.50")

    # Classic PCAP stream
    classic_raw = _create_pcap_bytes([(10.0, frame)])
    records_classic = list(iter_capture(io.BytesIO(classic_raw)))
    assert len(records_classic) == 1
    assert records_classic[0][2] == frame

    # PCAPNG stream
    pcapng_raw = _create_pcapng_bytes(
        [{"interfaces": [{"linktype": DLT_EN10MB}], "packets": [{"iface": 0, "ts": 20.0, "data": frame}]}]
    )
    records_pcapng = list(iter_capture(io.BytesIO(pcapng_raw)))
    assert len(records_pcapng) == 1
    assert records_pcapng[0][2] == frame


def test_run_pcap_with_pcapng(tmp_path: Path) -> None:
    pcapng_file = tmp_path / "dumpcap_capture.pcapng"
    frame = _build_arp_frame(spa="10.10.10.1", sha="00:aa:bb:cc:dd:ee", eth_src="00:aa:bb:cc:dd:ee")
    raw = _create_pcapng_bytes(
        [
            {
                "interfaces": [{"linktype": DLT_EN10MB, "tsresol": 6}],
                "packets": [{"iface": 0, "ts": 100.0, "data": frame}],
            }
        ]
    )
    pcapng_file.write_bytes(raw)

    tracker = NeighborTable()
    count = run_pcap(pcapng_file, tracker)
    assert count == 1
    assert tracker.bindings == {"10.10.10.1": "00:aa:bb:cc:dd:ee"}
