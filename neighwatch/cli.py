"""Command-line interface and daemon runtime entrypoint."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from neighwatch.capture import run_live, run_pcap
from neighwatch.table import NeighborTable


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
