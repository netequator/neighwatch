# DEVLOG

## 2026-11-12 — Stage 1 PoC

### Context
- Initialized `neighwatch` as the first Month 1 micro-tool (`d:\agent 009\neighwatch`).
- Goals for Iteration 1:
  - Keep offline `.pcap` parsing pure Python stdlib so replay tests have zero heavy runtime dependencies.
  - Share a single wire-format decoder (`parse_ethernet_arp`) between offline `.pcap` replay and live Npcap capture.
  - Validate RFC 5227 (`0.0.0.0` probe) and Ethernet-vs-ARP `sha` spoofing edge cases early.

### Host / OS Quirks Observed
- Windows 10 (`Npcap`) + Scapy 2.8.0:
  - Importing `scapy.config` before `scapy.all` reports `conf.use_pcap == False`; `poc.py` lazy-imports `scapy.all` only in live capture mode (`--iface`).
  - `conf.L2listen(iface=...)` returns `L2pcapListenSocket`, which lacks `.ins` (`AttributeError`). Datalink ID is available via `sock.pcap_fd.datalink()`, returning `0` (`DLT_NULL`) on `Loopback Pseudo-Interface 1` and `1` (`DLT_EN10MB`) on Ethernet/WSL virtual interfaces.
- Minimum 60-byte Ethernet frames pad 28-byte ARP payloads with 18 trailing zero bytes; `struct.unpack_from` at the post-VLAN offset avoids false truncation/length errors.

### Next Steps
- Verify `poc.py` against a synthetic multi-scenario `.pcap` (RFC 5227 probe, VLAN tag, MAC flap, `eth_src != sha` mismatch, and `DLT_NULL` rejection) and passive live capture on `vEthernet (WSL)`.
- Record discovered edge cases as follow-up issues (`DEVLOG.md` / `gh issue create`).
