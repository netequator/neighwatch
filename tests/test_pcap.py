"""Unit tests for classic PCAP reader."""

from __future__ import annotations

import io
import struct
from pathlib import Path

import pytest

from neighwatch.capture import iter_classic_pcap, run_pcap
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


def test_run_pcap(tmp_path: Path) -> None:
    pcap_file = tmp_path / "test.pcap"
    frame = _build_arp_frame(spa="192.168.1.100", sha="00:11:22:33:44:55")
    pcap_file.write_bytes(_create_pcap_bytes([(100.0, frame)]))

    tracker = NeighborTable()
    count = run_pcap(pcap_file, tracker)
    assert count == 1
    assert tracker.bindings == {"192.168.1.100": "00:11:22:33:44:55"}
