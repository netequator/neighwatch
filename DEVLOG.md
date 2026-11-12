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
