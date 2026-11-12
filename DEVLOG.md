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
- File initial GitHub issues once remote repo creation is confirmed by Director:
  1. `gratuitous arp flood rate-window alert`
  2. `persist ip-mac neighbor table state with entry ttl`
  3. `add ipv6 ndp (ns/na) and dad tracking`
  4. `support pcapng interface description blocks`
  5. `extract neighbor table module and add pytest suite`
