# neighwatch

## OVERVIEW

Passive Layer 2 ARP neighbor monitor maintaining an in-memory `IP -> MAC` binding table. Emits normalized JSONL events for learned neighbors, MAC flaps, Ethernet/ARP hardware mismatches, RFC 5227 probes (`0.0.0.0`), and gratuitous ARP frames.

Current stage: `PoC` (`poc.py`).

## USAGE

Read an offline classic `.pcap` file (pure Python stdlib, no runtime dependencies):

```powershell
python poc.py --pcap capture.pcap
```

Capture live ARP traffic via Scapy and Npcap (`Windows`) or `AF_PACKET` (`Linux/WSL2`):

```powershell
python poc.py --iface "vEthernet (WSL)" --timeout 10
```

Include unchanged repeat observations with `--all`.

## LIMITATIONS

- Supports classic `.pcap` (microsecond and nanosecond magics); `.pcapng` is not yet parsed directly.
- Requires `DLT_EN10MB` (Ethernet) link type; loopback (`DLT_NULL`) and cooked captures (`LINUX_SLL`) are rejected.
- No state persistence across restarts yet; bindings live in memory for the current run.
- No IPv6 Neighbor Discovery (`ICMPv6` 135/136) or gratuitous flood rate-windowing yet.

## TODO

- Track gratuitous ARP flood rate per sliding window.
- Persist `IP -> MAC` state snapshots across restarts with stale-entry TTLs.
- Add IPv6 NDP (`NS`/`NA`) and `DAD` (`::`) handling.
- Add `.pcapng` interface block parsing or clean fallback.
- Add deterministic `pytest` fixture suite and package layout once PoC stabilizes.
