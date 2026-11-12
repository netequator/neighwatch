"""Neighbor table state management, persistence, and event generation."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from neighwatch.parser import (
    ARP_OP_REPLY,
    ARP_OP_REQUEST,
    BCAST_MAC,
    DLT_EN10MB,
    ZERO_MAC,
    format_ts,
    make_event,
    parse_ethernet_arp,
)
from neighwatch.window import SlidingWindowCounter


@dataclass
class NeighborEntry:
    mac: str
    first_seen: float
    last_seen: float


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
