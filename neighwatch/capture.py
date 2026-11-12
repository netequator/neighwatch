"""Classic PCAP stream reader and live packet capture backends."""

from __future__ import annotations

import json
import socket
import struct
import sys
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO

from neighwatch.parser import DLT_EN10MB
from neighwatch.table import NeighborTable

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6),
    b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9),
    b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}


def iter_classic_pcap(fh: BinaryIO) -> Iterator[tuple[int, float, bytes]]:
    """Yield (linktype, timestamp, raw_frame) tuples from a classic .pcap stream."""
    ghdr = fh.read(24)
    if len(ghdr) < 24:
        raise ValueError("truncated pcap global header")

    magic = ghdr[:4]
    if magic not in PCAP_MAGICS:
        raise ValueError(f"unsupported capture magic {magic.hex()}; classic .pcap required")

    endian, ts_scale = PCAP_MAGICS[magic]
    _ver_maj, _ver_min, _tz, _sigfigs, _snaplen, raw_linktype = struct.unpack(f"{endian}HHIIII", ghdr[4:])
    # Classic PCAP reserves upper bits for FCS length flags; lower 28 bits hold DLT_*.
    linktype = raw_linktype & 0x0FFFFFFF

    while True:
        rhdr = fh.read(16)
        if not rhdr:
            break
        if len(rhdr) < 16:
            raise ValueError("truncated pcap packet record header")
        ts_sec, ts_frac, incl_len, _orig_len = struct.unpack(f"{endian}IIII", rhdr)
        frame = fh.read(incl_len)
        if len(frame) < incl_len:
            raise ValueError("truncated pcap packet payload")
        yield linktype, ts_sec + ts_frac * ts_scale, frame


def run_pcap(path: Path, tracker: NeighborTable) -> int:
    frames = 0
    with path.open("rb") as fh:
        for linktype, ts, frame in iter_classic_pcap(fh):
            frames += 1
            for ev in tracker.process_frame(frame, ts, linktype):
                print(json.dumps(ev), flush=True)
    return frames


def resolve_scapy_datalink(sock: object) -> int | None:
    pcap_fd = getattr(sock, "pcap_fd", None)
    if pcap_fd is not None and hasattr(pcap_fd, "datalink"):
        return int(pcap_fd.datalink())
    # Linux AF_PACKET sockets expose .ins.getsockopt / datalink via LL fallback.
    ll_cls = getattr(sock, "LL", None)
    if ll_cls is not None and getattr(ll_cls, "__name__", "") == "Ether":
        return DLT_EN10MB
    return None


def run_live_native_linux(
    iface: str,
    tracker: NeighborTable,
    count: int = 0,
    timeout: float | None = None,
) -> int:
    """Zero-dependency live ARP capture on Linux using native AF_PACKET raw socket."""
    if not hasattr(socket, "AF_PACKET"):
        raise RuntimeError("native AF_PACKET backend is only supported on Linux")

    eth_p_arp = 0x0806
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(eth_p_arp))
    except PermissionError as exc:
        raise PermissionError(
            f"raw capture on interface {iface!r} requires CAP_NET_RAW capability or root privileges"
        ) from exc
    except OSError as exc:
        raise OSError(f"failed to open AF_PACKET socket: {exc}") from exc

    try:
        sock.bind((iface, socket.htons(eth_p_arp)))
    except OSError as exc:
        sock.close()
        raise OSError(f"failed to bind to interface {iface!r}: {exc}") from exc

    frames = 0
    start_time = datetime.now(UTC).timestamp()

    try:
        while True:
            if count > 0 and frames >= count:
                break
            if timeout is not None and timeout > 0:
                elapsed = datetime.now(UTC).timestamp() - start_time
                if elapsed >= timeout:
                    break
                sock.settimeout(max(0.01, timeout - elapsed))

            try:
                raw_frame = sock.recv(2048)
            except TimeoutError:
                break

            if not raw_frame:
                break

            frames += 1
            now = datetime.now(UTC).timestamp()
            for ev in tracker.process_frame(raw_frame, now, DLT_EN10MB):
                print(json.dumps(ev), flush=True)
    finally:
        sock.close()

    return frames


def run_live_scapy(iface: str, tracker: NeighborTable, count: int, timeout: float | None) -> int:
    # scapy.config reports use_pcap=False on Windows until scapy.all initializes Npcap.
    from scapy.all import conf, sniff  # type: ignore[import-untyped]
    from scapy.error import Scapy_Exception  # type: ignore[import-untyped]

    if sys.platform == "win32" and not conf.use_pcap:
        raise RuntimeError("Npcap backend inactive (conf.use_pcap is False)")

    bpf = "arp or (vlan and arp)"
    try:
        # Open without BPF first; compiling "arp" on DLT_NULL loopback raises Scapy_Exception
        # ("expression rejects all packets") before we can report the datalink mismatch.
        sock = conf.L2listen(iface=iface)
    except Scapy_Exception as exc:
        raise RuntimeError(str(exc)) from exc

    frames = 0

    def _on_packet(pkt: object) -> None:
        nonlocal frames
        frames += 1
        raw = bytes(pkt)  # type: ignore[arg-type]
        pkt_ts = float(getattr(pkt, "time", 0.0))
        for ev in tracker.process_frame(raw, pkt_ts, DLT_EN10MB):
            print(json.dumps(ev), flush=True)

    try:
        datalink = resolve_scapy_datalink(sock)
        if datalink != DLT_EN10MB:
            raise ValueError(
                f"interface {iface!r} uses datalink {datalink}; expected DLT_EN10MB ({DLT_EN10MB})"
            )

        pcap_fd = getattr(sock, "pcap_fd", None)
        if pcap_fd is not None:
            pcap_fd.setfilter(bpf)
            sniff(
                opened_socket=sock,
                store=False,
                prn=_on_packet,
                count=count,
                timeout=timeout,
            )
        else:
            sock.close()
            sniff(
                iface=iface,
                filter=bpf,
                store=False,
                prn=_on_packet,
                count=count,
                timeout=timeout,
            )
    except Scapy_Exception as exc:
        raise RuntimeError(str(exc)) from exc
    finally:
        sock.close()

    return frames


def run_live(
    iface: str,
    tracker: NeighborTable,
    count: int = 0,
    timeout: float | None = None,
    backend: str = "auto",
) -> int:
    if backend == "auto":
        backend = "native" if hasattr(socket, "AF_PACKET") else "scapy"

    if backend == "native":
        if not hasattr(socket, "AF_PACKET"):
            raise RuntimeError("native AF_PACKET backend is only supported on Linux")
        return run_live_native_linux(iface, tracker, count=count, timeout=timeout)
    if backend == "scapy":
        return run_live_scapy(iface, tracker, count=count, timeout=timeout)
    raise ValueError(f"unknown backend {backend!r}; choose 'auto', 'native', or 'scapy'")
