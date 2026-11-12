# neighwatch

## OVERVIEW

Passive Layer 2 ARP neighbor monitor maintaining an in-memory `IP -> MAC` binding table. Emits normalized JSONL events for learned neighbors, MAC flaps, Ethernet/ARP hardware mismatches, RFC 5227 probes (`0.0.0.0`), and gratuitous ARP frames.

Current stage: `PoC` (`poc.py`).

## USAGE

Read an offline classic `.pcap` file (pure Python stdlib, zero third-party dependencies):

```sh
python3 poc.py --pcap capture.pcap
```

Capture live ARP traffic on Linux via zero-dependency native `AF_PACKET` raw sockets (requires `CAP_NET_RAW` or root):

```sh
# Grant cap_net_raw to python binary for unprivileged capture:
sudo setcap cap_net_raw=eip $(which python3)
python3 poc.py --iface eth0 --state-file /var/lib/neighwatch/state.json --ttl 86400
```

Capture live ARP traffic on Windows via Scapy and Npcap:

```powershell
python poc.py --iface "vEthernet (WSL)" --state-file state.json --ttl 3600
```

Tune gratuitous ARP flood detection (`--garp-window 10 --garp-threshold 5`, `0` disables) or backend selection (`--backend auto|native|scapy`):

```sh
python3 poc.py --iface eth0 --garp-window 5 --garp-threshold 4 --backend native
```

## SYSTEMD DAEMON (LINUX)

A hardened systemd unit file is provided at `systemd/neighwatch.service`. It runs under `DynamicUser=yes` with ambient `CAP_NET_RAW` capabilities, sandbox isolation (`ProtectSystem=strict`, `ProtectHome=yes`, `NoNewPrivileges=yes`), and streams structured JSONL events directly into `journald`:

```sh
sudo cp systemd/neighwatch.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now neighwatch
journalctl -u neighwatch -f -o cat
```

## LIMITATIONS

- Supports classic `.pcap` (microsecond and nanosecond magics); `.pcapng` is not yet parsed directly.
- Requires `DLT_EN10MB` (Ethernet) link type; loopback (`DLT_NULL`) and cooked captures (`LINUX_SLL`) are rejected.
- No IPv6 Neighbor Discovery (`ICMPv6` 135/136) yet.

## TODO

- Add IPv6 NDP (`NS`/`NA`) and `DAD` (`::`) handling (`#3`).
- Add `.pcapng` interface block parsing or clean fallback (`#4`).
- Add deterministic `pytest` fixture suite and package layout once PoC stabilizes (`#5`).
