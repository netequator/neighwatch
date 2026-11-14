"""Classic PCAP and PCAPNG stream readers and live capture backends."""

from __future__ import annotations

import json
import socket
import struct
import sys
from collections.abc import Iterator
from dataclasses import dataclass
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

PCAPNG_SHB_TYPE = 0x0A0D0D0A
PCAPNG_IDB_TYPE = 0x00000001
PCAPNG_SPB_TYPE = 0x00000003
PCAPNG_EPB_TYPE = 0x00000006
PCAPNG_BOM_LE = b"\x4d\x3c\x2b\x1a"
PCAPNG_BOM_BE = b"\x1a\x2b\x3c\x4d"


@dataclass(frozen=True)
class _PcapngInterface:
    linktype: int
    snaplen: int
    ts_scale: float


def iter_classic_pcap(fh: BinaryIO, pre_magic: bytes | None = None) -> Iterator[tuple[int, float, bytes]]:
    """Yield (linktype, timestamp, raw_frame) tuples from a classic .pcap stream."""
    if pre_magic is not None:
        magic = pre_magic
        rest_ghdr = fh.read(20)
        if len(rest_ghdr) < 20:
            raise ValueError("truncated pcap global header")
        ghdr = magic + rest_ghdr
    else:
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


def iter_pcapng(fh: BinaryIO, pre_magic: bytes | None = None) -> Iterator[tuple[int, float, bytes]]:
    """Yield (linktype, timestamp, raw_frame) tuples from a .pcapng stream."""
    interfaces: list[_PcapngInterface] = []
    endian = "<"
    first_block = True

    while True:
        if first_block and pre_magic is not None:
            first_block = False
            len_and_bom = fh.read(8)
            if len(len_and_bom) < 8:
                raise ValueError("truncated pcapng section header block")
            bom = len_and_bom[4:8]
            if bom == PCAPNG_BOM_LE:
                endian = "<"
            elif bom == PCAPNG_BOM_BE:
                endian = ">"
            else:
                raise ValueError(f"unsupported pcapng byte order magic: {bom.hex()}")

            total_len = struct.unpack(f"{endian}I", len_and_bom[:4])[0]
            if total_len < 28 or (total_len % 4) != 0:
                raise ValueError(f"malformed pcapng section header block length: {total_len}")

            remaining = fh.read(total_len - 12)
            if len(remaining) < total_len - 12:
                raise ValueError("truncated pcapng section header block body")
            trailing_len = struct.unpack(f"{endian}I", remaining[-4:])[0]
            if trailing_len != total_len:
                raise ValueError(f"pcapng block length mismatch: {total_len} != {trailing_len}")
            interfaces.clear()
            continue

        first_block = False
        hdr = fh.read(8)
        if not hdr:
            break
        if len(hdr) < 8:
            raise ValueError("truncated pcapng block header")

        # Check for Section Header Block (SHB can appear mid-stream with new endianness)
        if hdr[:4] in (b"\x0a\x0d\x0d\x0a", b"\x0a\x0d\x0d\x0a"[::-1]):
            bom = fh.read(4)
            if len(bom) < 4:
                raise ValueError("truncated pcapng section header block")
            if bom == PCAPNG_BOM_LE:
                endian = "<"
            elif bom == PCAPNG_BOM_BE:
                endian = ">"
            else:
                raise ValueError(f"unsupported pcapng byte order magic: {bom.hex()}")

            total_len = struct.unpack(f"{endian}I", hdr[4:8])[0]
            if total_len < 28 or (total_len % 4) != 0:
                raise ValueError(f"malformed pcapng section header block length: {total_len}")

            remaining = fh.read(total_len - 12)
            if len(remaining) < total_len - 12:
                raise ValueError("truncated pcapng section header block body")
            trailing_len = struct.unpack(f"{endian}I", remaining[-4:])[0]
            if trailing_len != total_len:
                raise ValueError(f"pcapng block length mismatch: {total_len} != {trailing_len}")
            interfaces.clear()
            continue

        block_type, total_len = struct.unpack(f"{endian}II", hdr)
        if total_len < 12 or (total_len % 4) != 0:
            raise ValueError(f"malformed pcapng block length: {total_len}")

        body = fh.read(total_len - 8)
        if len(body) < total_len - 8:
            raise ValueError(f"truncated pcapng block body for type 0x{block_type:08x}")

        trailing_len = struct.unpack_from(f"{endian}I", body, len(body) - 4)[0]
        if trailing_len != total_len:
            raise ValueError(f"pcapng block length mismatch: {total_len} != {trailing_len}")

        if block_type == PCAPNG_IDB_TYPE:
            if total_len < 20:
                raise ValueError(f"malformed pcapng interface description block length: {total_len}")
            linktype, _reserved, snaplen = struct.unpack_from(f"{endian}HHI", body, 0)
            ts_scale = 1e-6  # Default microsecond resolution per PCAPNG spec §4.2

            # Parse optional options
            opt_offset = 8
            opt_limit = len(body) - 4
            while opt_offset + 4 <= opt_limit:
                opt_code, opt_len = struct.unpack_from(f"{endian}HH", body, opt_offset)
                opt_offset += 4
                if opt_code == 0:
                    break
                if opt_offset + opt_len > opt_limit:
                    break
                if opt_code == 9 and opt_len >= 1:
                    raw_res = body[opt_offset]
                    if raw_res & 0x80:
                        ts_scale = 2.0 ** (-(raw_res & 0x7F))
                    else:
                        ts_scale = 10.0 ** (-raw_res)
                opt_offset += (opt_len + 3) & ~3

            interfaces.append(_PcapngInterface(linktype=linktype, snaplen=snaplen, ts_scale=ts_scale))

        elif block_type == PCAPNG_EPB_TYPE:
            if total_len < 32:
                raise ValueError(f"malformed pcapng enhanced packet block length: {total_len}")
            iface_id, ts_high, ts_low, cap_len, _orig_len = struct.unpack_from(f"{endian}IIIII", body, 0)
            if iface_id >= len(interfaces):
                raise ValueError(
                    f"pcapng enhanced packet references undefined interface {iface_id} ({len(interfaces)} known)"
                )
            iface = interfaces[iface_id]
            ts = ((ts_high << 32) | ts_low) * iface.ts_scale
            pkt_offset = 20
            pkt_end = pkt_offset + cap_len
            if pkt_end > len(body) - 4:
                raise ValueError("pcapng packet payload exceeds block length")
            frame = body[pkt_offset:pkt_end]
            yield iface.linktype, ts, frame

        elif block_type == PCAPNG_SPB_TYPE:
            if total_len < 16:
                raise ValueError(f"malformed pcapng simple packet block length: {total_len}")
            orig_len = struct.unpack_from(f"{endian}I", body, 0)[0]
            iface = interfaces[0] if interfaces else _PcapngInterface(DLT_EN10MB, 65535, 1e-6)
            cap_len = min(orig_len, total_len - 16)
            frame = body[4 : 4 + cap_len]
            yield iface.linktype, 0.0, frame


def iter_capture(fh: BinaryIO) -> Iterator[tuple[int, float, bytes]]:
    """Yield (linktype, timestamp, raw_frame) from classic .pcap or modern .pcapng streams."""
    magic = fh.read(4)
    if not magic:
        return
    if magic in PCAP_MAGICS:
        yield from iter_classic_pcap(fh, pre_magic=magic)
    elif magic in (b"\x0a\x0d\x0d\x0a", b"\x0a\x0d\x0d\x0a"[::-1]):
        yield from iter_pcapng(fh, pre_magic=magic)
    else:
        raise ValueError(
            f"unsupported capture magic 0x{magic.hex()}; classic .pcap or .pcapng required"
        )


def run_pcap(path: Path, tracker: NeighborTable) -> int:
    frames = 0
    with path.open("rb") as fh:
        for linktype, ts, frame in iter_capture(fh):
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
