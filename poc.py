"""Minimal passive L2 ARP watcher PoC for offline PCAPs and Npcap/libpcap interfaces."""

from __future__ import annotations

import argparse
import json
import os
import socket
import struct
import sys
from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO

DLT_EN10MB = 1
ETH_HDR_LEN = 14
ETHERTYPE_VLAN_8021Q = 0x8100
ETHERTYPE_VLAN_8021AD = 0x88A8
ETHERTYPE_ARP = 0x0806
MAX_VLAN_TAGS = 2

ARP_HDR_LEN = 28
ARP_HTYPE_ETHERNET = 1
ARP_PTYPE_IPV4 = 0x0800
ARP_OP_REQUEST = 1
ARP_OP_REPLY = 2

ZERO_MAC = "00:00:00:00:00:00"
BCAST_MAC = "ff:ff:ff:ff:ff:ff"

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6),
    b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9),
    b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}


@dataclass(frozen=True)
class ArpPacket:
    op: int
    eth_src: str
    eth_dst: str
    sha: str
    spa: str
    tha: str
    tpa: str
    sha_multicast: bool
    vlan_ids: tuple[int, ...]


@dataclass
class NeighborEntry:
    mac: str
    first_seen: float
    last_seen: float


def format_mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def format_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def make_event(
    ts: float,
    event: str,
    severity: str,
    src_ip: str | None,
    src_mac: str | None,
    detail: dict[str, object],
) -> dict[str, object]:
    return {
        "ts": format_ts(ts),
        "tool": "neighwatch",
        "event": event,
        "severity": severity,
        "src_ip": src_ip,
        "src_mac": src_mac,
        "detail": detail,
    }


def parse_ethernet_arp(frame: bytes) -> tuple[ArpPacket | None, str | None]:
    """Decode Ethernet (+ optional 802.1Q tags) and IPv4-over-Ethernet ARP payload."""
    if len(frame) < ETH_HDR_LEN:
        return None, "short_ethernet_frame"

    eth_dst_raw, eth_src_raw, ethertype = struct.unpack_from("!6s6sH", frame, 0)
    offset = ETH_HDR_LEN
    vlan_ids: list[int] = []

    while ethertype in (ETHERTYPE_VLAN_8021Q, ETHERTYPE_VLAN_8021AD):
        if len(vlan_ids) >= MAX_VLAN_TAGS or offset + 4 > len(frame):
            return None, "malformed_vlan_header"
        tci, ethertype = struct.unpack_from("!HH", frame, offset)
        vlan_ids.append(tci & 0x0FFF)
        offset += 4

    if ethertype != ETHERTYPE_ARP:
        return None, None

    # Standard minimum 60-byte Ethernet frames pad 28-byte ARP payloads with trailing zeros;
    # unpack_from at offset reads the fixed 28-byte ARP body without failing on padding.
    if len(frame) - offset < ARP_HDR_LEN:
        return None, "short_arp_payload"

    htype, ptype, hlen, plen, op, sha_raw, spa_raw, tha_raw, tpa_raw = struct.unpack_from(
        "!HHBBH6s4s6s4s",
        frame,
        offset,
    )
    if htype != ARP_HTYPE_ETHERNET or ptype != ARP_PTYPE_IPV4 or hlen != 6 or plen != 4:
        return None, None

    return (
        ArpPacket(
            op=op,
            eth_src=format_mac(eth_src_raw),
            eth_dst=format_mac(eth_dst_raw),
            sha=format_mac(sha_raw),
            spa=socket.inet_ntoa(spa_raw),
            tha=format_mac(tha_raw),
            tpa=socket.inet_ntoa(tpa_raw),
            sha_multicast=bool(sha_raw[0] & 0x01),
            vlan_ids=tuple(vlan_ids),
        ),
        None,
    )


class SlidingWindowCounter:
    """Bounded packet-timestamp sliding window counter with per-key alert cooldown."""

    def __init__(self, window_sec: float, max_keys: int = 4096) -> None:
        self.window_sec = window_sec
        self.max_keys = max_keys
        self._events: dict[str, deque[float]] = {}
        self._last_alert: dict[str, float] = {}

    def record(self, key: str, ts: float, threshold: int) -> tuple[int, bool, bool]:
        """Record packet timestamp for key; return (count_in_window, triggered, in_cooldown)."""
        if self.window_sec <= 0 or threshold <= 0:
            return 0, False, False

        cutoff = ts - self.window_sec
        dq = self._events.get(key)
        if dq is None:
            if len(self._events) >= self.max_keys:
                self._evict_stale(cutoff)
            if len(self._events) >= self.max_keys:
                oldest_key = next(iter(self._events))
                del self._events[oldest_key]
                self._last_alert.pop(oldest_key, None)
            dq = deque()
            self._events[key] = dq

        dq.append(ts)
        while dq and dq[0] < cutoff:
            dq.popleft()

        count = len(dq)
        if count < threshold:
            return count, False, False

        last = self._last_alert.get(key)
        if last is not None and (ts - last) < self.window_sec:
            return count, False, True

        self._last_alert[key] = ts
        return count, True, False

    def _evict_stale(self, cutoff: float) -> None:
        stale = [k for k, dq in self._events.items() if not dq or dq[-1] < cutoff]
        for k in stale:
            del self._events[k]
            self._last_alert.pop(k, None)


class NeighborTable:
    """In-memory IP-to-MAC tracker emitting normalized JSONL neighbor events."""

    def __init__(
        self,
        emit_unchanged: bool = False,
        garp_window: float = 10.0,
        garp_threshold: int = 5,
        ttl: float = 0.0,
    ) -> None:
        if garp_threshold < 0:
            raise ValueError("garp_threshold must be >= 0")
        if garp_threshold > 0 and garp_window <= 0:
            raise ValueError("garp_window must be > 0 when garp_threshold > 0")
        if ttl < 0:
            raise ValueError("ttl must be >= 0")

        self.entries: dict[str, NeighborEntry] = {}
        self.emit_unchanged = emit_unchanged
        self.garp_window = garp_window
        self.garp_threshold = garp_threshold
        self.ttl = ttl
        self._garp_counter = SlidingWindowCounter(window_sec=garp_window)

    @property
    def bindings(self) -> dict[str, str]:
        return {ip: entry.mac for ip, entry in self.entries.items()}

    def prune_stale(self, ts: float) -> list[dict[str, object]]:
        if self.ttl <= 0:
            return []
        events: list[dict[str, object]] = []
        stale_ips = [ip for ip, entry in self.entries.items() if (ts - entry.last_seen) > self.ttl]
        for ip in stale_ips:
            entry = self.entries.pop(ip)
            events.append(
                make_event(
                    ts,
                    "arp_expired",
                    "info",
                    ip,
                    entry.mac,
                    {
                        "inactive_sec": round(ts - entry.last_seen, 6),
                        "ttl": self.ttl,
                        "first_seen": format_ts(entry.first_seen),
                        "last_seen": format_ts(entry.last_seen),
                    },
                )
            )
        return events

    def load_state(self, path: Path) -> int:
        path = Path(path)
        if not path.is_file():
            return 0
        with path.open("r", encoding="utf-8") as fh:
            try:
                data = json.load(fh)
            except json.JSONDecodeError as exc:
                raise ValueError(f"malformed json in state file {path}: {exc}") from exc

        if not isinstance(data, dict):
            raise TypeError(f"invalid state file format in {path}: expected top-level json object")

        raw_entries = data.get("entries") if "entries" in data else data
        if not isinstance(raw_entries, dict):
            raise TypeError(f"invalid entries in state file {path}: expected dict")

        count = 0
        now = datetime.now(UTC).timestamp()
        for ip, val in raw_entries.items():
            if not isinstance(ip, str):
                continue
            if isinstance(val, str):
                self.entries[ip] = NeighborEntry(mac=val.lower(), first_seen=now, last_seen=now)
                count += 1
            elif isinstance(val, dict) and isinstance(val.get("mac"), str):
                first = float(val.get("first_seen", now))
                last = float(val.get("last_seen", now))
                self.entries[ip] = NeighborEntry(mac=val["mac"].lower(), first_seen=first, last_seen=last)
                count += 1
        return count

    def save_state(self, path: Path, current_ts: float | None = None) -> None:
        path = Path(path)
        ts = current_ts if current_ts is not None else datetime.now(UTC).timestamp()
        data = {
            "version": 1,
            "updated_at": format_ts(ts),
            "entries": {
                ip: {
                    "mac": entry.mac,
                    "first_seen": entry.first_seen,
                    "last_seen": entry.last_seen,
                }
                for ip, entry in sorted(self.entries.items())
            },
        }
        tmp_path = path.with_name(f".{path.name}.tmp.{os.getpid()}")
        if not path.parent.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
        with tmp_path.open("w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
            fh.write("\n")
        tmp_path.replace(path)

    def _record_gratuitous(self, spa: str, sha: str, ts: float) -> tuple[bool, bool, dict[str, object]]:
        ip_count, ip_trig, ip_cool = self._garp_counter.record(f"ip:{spa}", ts, self.garp_threshold)
        mac_count, mac_trig, mac_cool = self._garp_counter.record(f"mac:{sha}", ts, self.garp_threshold)

        scopes: list[str] = []
        if ip_trig:
            scopes.append("ip")
        if mac_trig:
            scopes.append("mac")

        triggered = bool(scopes)
        in_cooldown = (not triggered) and (ip_cool or mac_cool)
        meta: dict[str, object] = {}
        if triggered or in_cooldown:
            meta = {
                "window_sec": self.garp_window,
                "threshold": self.garp_threshold,
                "ip_count": ip_count,
                "mac_count": mac_count,
            }
            if scopes:
                meta["flood_scope"] = "+".join(scopes)
        return triggered, in_cooldown, meta

    def process_frame(self, frame: bytes, ts: float, linktype: int) -> list[dict[str, object]]:
        if linktype != DLT_EN10MB:
            raise ValueError(f"unsupported linktype {linktype}; expected DLT_EN10MB ({DLT_EN10MB})")

        events = self.prune_stale(ts)

        pkt, err = parse_ethernet_arp(frame)
        if err is not None:
            events.append(make_event(ts, "arp_malformed", "warn", None, None, {"reason": err, "len": len(frame)}))
            return events
        if pkt is None:
            return events

        op_name = {ARP_OP_REQUEST: "who-has", ARP_OP_REPLY: "is-at"}.get(pkt.op, f"op-{pkt.op}")
        base_detail: dict[str, object] = {
            "op": op_name,
            "dst_ip": pkt.tpa,
            "dst_mac": pkt.tha,
            "eth_src": pkt.eth_src,
            "eth_dst": pkt.eth_dst,
        }
        if pkt.vlan_ids:
            base_detail["vlan_ids"] = list(pkt.vlan_ids)

        if pkt.op not in (ARP_OP_REQUEST, ARP_OP_REPLY):
            events.append(make_event(ts, "arp_unexpected_op", "warn", pkt.spa, pkt.sha, base_detail))
            return events

        if pkt.sha in (ZERO_MAC, BCAST_MAC) or pkt.sha_multicast:
            events.append(make_event(ts, "arp_invalid_sha", "warn", pkt.spa, pkt.sha, base_detail))
            return events

        # Do not let L2/ARP hardware address mismatches update the trusted table.
        if pkt.eth_src != pkt.sha:
            events.append(make_event(ts, "arp_hw_mismatch", "alert", pkt.spa, pkt.sha, base_detail))
            return events

        # RFC 5227 ARP probes use op=who-has with sender protocol address 0.0.0.0;
        # record the probe without polluting 0.0.0.0 into IP->MAC bindings.
        if pkt.spa == "0.0.0.0":
            if pkt.op == ARP_OP_REQUEST:
                events.append(make_event(ts, "arp_probe", "info", pkt.spa, pkt.sha, base_detail))
            else:
                events.append(make_event(ts, "arp_invalid_spa", "warn", pkt.spa, pkt.sha, base_detail))
            return events

        entry = self.entries.get(pkt.spa)
        prev_mac = entry.mac if entry is not None else None
        gratuitous = pkt.spa == pkt.tpa
        flood_triggered = False
        flood_cooldown = False
        flood_meta: dict[str, object] = {}
        if gratuitous:
            flood_triggered, flood_cooldown, flood_meta = self._record_gratuitous(pkt.spa, pkt.sha, ts)

        if prev_mac is not None and prev_mac != pkt.sha:
            if entry is not None:
                entry.mac = pkt.sha
                entry.last_seen = max(entry.last_seen, ts)
            else:
                self.entries[pkt.spa] = NeighborEntry(mac=pkt.sha, first_seen=ts, last_seen=ts)
            detail = {**base_detail, "prev_mac": prev_mac, "gratuitous": gratuitous}
            if flood_triggered:
                detail["flood"] = True
                detail.update(flood_meta)
            events.append(make_event(ts, "arp_mac_change", "alert", pkt.spa, pkt.sha, detail))
            return events

        if gratuitous:
            already_known = prev_mac is not None
            if entry is not None:
                entry.last_seen = max(entry.last_seen, ts)
            else:
                self.entries[pkt.spa] = NeighborEntry(mac=pkt.sha, first_seen=ts, last_seen=ts)
            if flood_triggered:
                detail = {**base_detail, "already_known": already_known, **flood_meta}
                events.append(make_event(ts, "arp_gratuitous_flood", "alert", pkt.spa, pkt.sha, detail))
                return events
            if flood_cooldown and not self.emit_unchanged:
                return events
            detail = {**base_detail, "already_known": already_known}
            events.append(make_event(ts, "arp_gratuitous", "info", pkt.spa, pkt.sha, detail))
            return events

        if prev_mac is None:
            self.entries[pkt.spa] = NeighborEntry(mac=pkt.sha, first_seen=ts, last_seen=ts)
            events.append(make_event(ts, "arp_learned", "info", pkt.spa, pkt.sha, base_detail))
            return events

        assert entry is not None
        entry.last_seen = max(entry.last_seen, ts)
        if self.emit_unchanged:
            events.append(make_event(ts, "arp_seen", "info", pkt.spa, pkt.sha, base_detail))
        return events


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


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="neighwatch",
        description="Passive L2 ARP neighbor monitor emitting JSONL events.",
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("-r", "--pcap", type=Path, help="Read offline classic .pcap file.")
    source.add_argument("-i", "--iface", help="Capture live ARP frames on interface.")
    parser.add_argument(
        "--all",
        action="store_true",
        dest="emit_unchanged",
        help="Emit arp_seen events for unchanged known bindings.",
    )
    parser.add_argument("-c", "--count", type=int, default=0, help="Live capture frame limit (0 = unlimited).")
    parser.add_argument("-t", "--timeout", type=float, default=None, help="Live capture timeout in seconds.")
    parser.add_argument(
        "--garp-window",
        type=float,
        default=10.0,
        help="Sliding window in seconds for gratuitous ARP flood detection (default: 10.0).",
    )
    parser.add_argument(
        "--garp-threshold",
        type=int,
        default=5,
        help="Gratuitous ARP count in window before alerting; 0 disables (default: 5).",
    )
    parser.add_argument(
        "-s",
        "--state-file",
        type=Path,
        help="Path to load and persist IP-to-MAC neighbor state JSON file.",
    )
    parser.add_argument(
        "--ttl",
        type=float,
        default=0.0,
        help="Entry time-to-live in seconds; evicts stale bindings (default: 0.0, disabled).",
    )
    parser.add_argument(
        "--backend",
        choices=["auto", "native", "scapy"],
        default="auto",
        help="Live capture backend: 'auto' (native on Linux, scapy on Windows), 'native' (AF_PACKET), or 'scapy' (default: auto).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        tracker = NeighborTable(
            emit_unchanged=args.emit_unchanged,
            garp_window=args.garp_window,
            garp_threshold=args.garp_threshold,
            ttl=args.ttl,
        )
        if args.state_file is not None and args.state_file.is_file():
            loaded = tracker.load_state(args.state_file)
            print(f"loaded {loaded} bindings from {args.state_file}", file=sys.stderr)

        if args.pcap is not None:
            frames = run_pcap(args.pcap, tracker)
        else:
            frames = run_live(
                args.iface,
                tracker,
                count=args.count,
                timeout=args.timeout,
                backend=args.backend,
            )
    except KeyboardInterrupt:
        if args.state_file is not None:
            try:
                tracker.save_state(args.state_file)
                print(f"saved {len(tracker.bindings)} bindings to {args.state_file}", file=sys.stderr)
            except OSError as exc:
                print(f"warning: failed to save state on interrupt: {exc}", file=sys.stderr)
        print(f"interrupted; tracked={len(tracker.bindings)}", file=sys.stderr)
        return 0
    except (OSError, ValueError, TypeError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.state_file is not None:
        try:
            tracker.save_state(args.state_file)
            print(f"saved {len(tracker.bindings)} bindings to {args.state_file}", file=sys.stderr)
        except OSError as exc:
            print(f"error: failed to save state: {exc}", file=sys.stderr)
            return 2

    print(f"done; frames={frames} tracked={len(tracker.bindings)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
