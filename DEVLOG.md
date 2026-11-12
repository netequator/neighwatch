# DEVLOG

## 2026-11-12 — Stage 1 PoC

### Context
- Initialized `neighwatch` as the first Month 1 micro-tool (`d:\agent 009\neighwatch`).
- Goals for Iteration 1:
  - Keep offline `.pcap` parsing pure Python stdlib so replay tests have zero heavy runtime dependencies.
  - Share a single wire-format decoder (`parse_ethernet_arp`) between offline `.pcap` replay and live Npcap capture.
  - Validate RFC 5227 (`0.0.0.0` probe) and Ethernet-vs-ARP `sha` spoofing edge cases early.

### Bug Discovery and Quirks Observed
- **Scapy BPF compilation vs datalink check order (Windows Npcap):**
  - Calling `conf.L2listen(iface="Loopback Pseudo-Interface 1", filter="arp")` raises `scapy.error.Scapy_Exception: Cannot set filter: expression rejects all packets` inside `pcap_compile()` before user code can inspect the datalink type.
  - Fix: open `conf.L2listen(iface=iface)` without a BPF filter first, check `sock.pcap_fd.datalink() == 1` (`DLT_EN10MB`), then apply `sock.pcap_fd.setfilter("arp or (vlan and arp)")` and hand `opened_socket=sock` directly to `sniff()`. This also avoids opening/closing duplicate Npcap handles.
- **Scapy `L2pcapListenSocket` attributes on Windows:**
  - `L2pcapListenSocket` exposes `pcap_fd.datalink()`, not `.ins` (`AttributeError`). On this Windows 10 host, `Loopback Pseudo-Interface 1` returns `0` (`DLT_NULL`) and Hyper-V/Ethernet interfaces return `1` (`DLT_EN10MB`).
- **Minimum 60-byte Ethernet padding:**
  - Wire ARP frames are 42 bytes (14 Ethernet + 28 ARP) padded with 18 zero bytes to 60 bytes; `struct.unpack_from` at the post-VLAN offset ignores trailing zero padding cleanly.
- **RFC 5227 zero-IP probe vs reply:**
  - Only `who-has` (`op=1`) with `spa=0.0.0.0` is a valid RFC 5227 DAD probe (`arp_probe`). An `is-at` (`op=2`) claiming `spa=0.0.0.0` is now flagged as `arp_invalid_spa` (`warn`).

### Verification
- `ruff check poc.py` passed (`0` errors).
- Synthetic classic `.pcap` (big-endian nanosecond magic `0xa1b23c4d`, RFC 5737/7042 addresses): verified `arp_learned`, VLAN `802.1Q` unwrapping, RFC 5227 `arp_probe` without polluting `0.0.0.0`, `arp_invalid_spa`, `arp_hw_mismatch` (preserving trusted binding), gratuitous `arp_mac_change`, multicast `arp_invalid_sha`, short ARP `arp_malformed`, and `DLT_NULL` exit code `2`.
- Live Npcap checks on Windows 10: verified clean datalink rejection on `Loopback Pseudo-Interface 1` (`exit 2`), clean error on invalid interface name (`exit 2`), and live capture of an ARP request across `vEthernet (WSL)`.

### Next Steps / Planned Issues
- Tracked on GitHub (`netequator/neighwatch`): `#1`..`#5`.

## 2026-11-12 — Issue #1: Gratuitous ARP Flood Sliding Window

### Design Notes
- Added `SlidingWindowCounter` driven by packet timestamps (`pkt.time` / PCAP header timestamps) rather than wall clock so offline replay stays deterministic.
- Keyed gratuitous (`spa == tpa`, `spa != 0.0.0.0`) counts by both `ip:<spa>` and `mac:<sha>` (with `max_keys=4096` stale/FIFO eviction) to catch single-target floods, rotating-MAC spoofs against one IP, and single-NIC multi-IP cache spray.
- Default `--garp-window 10.0` and `--garp-threshold 5` sit above normal RFC 5227 §2.3 announcement bursts (`ANNOUNCE_NUM = 2`, `ANNOUNCE_INTERVAL = 2s`); per-key cooldown (`window_sec`) suppresses duplicate flood alerts during sustained bursts while preserving `arp_mac_change` priority if a MAC flip occurs concurrently.

### Verification
- `ruff check poc.py`: passed (`0` errors).
- Synthetic `.pcap` verification: verified normal 3-frame RFC 5227 burst emits zero flood alerts, single-IP/MAC burst (`8` frames) alerts once per window and re-alerts post-window, single-MAC multi-IP spray triggers `flood_scope="mac"`, rotating-MAC flood attaches `flood=True` to `arp_mac_change`, `--garp-threshold 0` disables flood detection, and negative threshold fails with exit code `2`.

## 2026-11-12 — Issue #2: Neighbor State Persistence & TTL Eviction

### Design Notes
- Replaced flat `IP -> MAC` string dictionary with `NeighborEntry(mac, first_seen, last_seen)` while preserving `bindings` property compatibility.
- Added `--state-file` (`load_state` / atomic `save_state` via temp file + `Path.replace` on normal exit and `KeyboardInterrupt`). Malformed JSON or invalid top-level type fails fast with exit code `2` instead of overwriting existing baseline files.
- Added `--ttl` (seconds, default `0.0` disabled). `prune_stale(ts)` evaluates `ts - entry.last_seen > ttl` against packet timestamps (`pkt.time` / PCAP header timestamps) before frame decoding so offline `.pcap` replay stays deterministic; evicted entries emit `arp_expired` (`info`) and re-learn cleanly if seen again.
- Updated `process_frame` to return `list[dict[str, object]]` so zero, one, or multiple events (expired entries followed by frame event) stream cleanly in JSONL order.
- Preserved security invariant: `arp_hw_mismatch` (`eth_src != sha`) and `0.0.0.0` probes do not refresh `last_seen`.

### Verification
- `ruff check poc.py`: passed (`0` errors).
- Synthetic `.pcap` verification: verified TTL eviction (`arp_expired` with `inactive_sec`, subsequent re-learning without false `arp_mac_change`), negative TTL exit `2`, state dump/reload cycle detecting `arp_mac_change` against persisted baseline, and malformed/wrong-type state file exit `2`.

## 2026-11-12 — Issue #6: Native Linux AF_PACKET & Systemd Daemon

### Design Notes
- Added zero-dependency Linux live capture via `socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))` bound to the target interface.
- Added `--backend {auto,native,scapy}`. In `auto` mode, Linux hosts automatically use stdlib `AF_PACKET` without requiring Scapy installed; Windows hosts route to Scapy/Npcap.
- Captured `PermissionError` when binding raw sockets on Linux, printing an actionable message explaining `CAP_NET_RAW` capability or root requirements.
- Added hardened `systemd/neighwatch.service` unit with `DynamicUser=yes`, `AmbientCapabilities=CAP_NET_RAW`, `StateDirectory=neighwatch`, and strict filesystem sandboxing.

### Verification
- `ruff check poc.py`: passed (`0` errors).
- Windows test: `poc.py -i <iface> --backend native` exits `2` with `error: native AF_PACKET backend is only supported on Linux`.
- Linux (WSL2 Ubuntu) test: `python3 poc.py -i lo` exits `2` with `error: raw capture on interface 'lo' requires CAP_NET_RAW capability or root privileges`. Offline PCAP replay runs identically with zero external dependencies.
- Synthetic PCAP test suite (`verify_neighwatch.py`): passed across all cases.
