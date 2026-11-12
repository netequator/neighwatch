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

Include unchanged repeat observations with `--all`, tune gratuitous ARP flood detection (`--garp-window 10 --garp-threshold 5`, `0` disables), or persist baseline state with stale-entry eviction (`--state-file`, `--ttl` in seconds):

```powershell
python poc.py --pcap capture.pcap --garp-window 5 --garp-threshold 4
python poc.py --iface "vEthernet (WSL)" --state-file state.json --ttl 3600
```

## LIMITATIONS

- Supports classic `.pcap` (microsecond and nanosecond magics); `.pcapng` is not yet parsed directly.
- Requires `DLT_EN10MB` (Ethernet) link type; loopback (`DLT_NULL`) and cooked captures (`LINUX_SLL`) are rejected.
- No IPv6 Neighbor Discovery (`ICMPv6` 135/136) yet.

## TODO

- Add IPv6 NDP (`NS`/`NA`) and `DAD` (`::`) handling (`#3`).
- Add `.pcapng` interface block parsing or clean fallback (`#4`).
- Add deterministic `pytest` fixture suite and package layout once PoC stabilizes (`#5`).
