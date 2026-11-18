# Security Policy

## Supported Versions

Only the latest minor release receives active security patches and vulnerability triage.

| Version | Supported          |
| :------ | :----------------- |
| 0.1.x   | Yes                |
| < 0.1.0 | No                 |

---

## Threat Model & Scope

`neighwatch` is designed as a passive network sniffer and ARP/NDP anomaly detector operating on untrusted Layer 2 network frames.

### In Scope
- Denial of service or crashes triggered by malformed wire packets (e.g., malformed ARP headers, truncated IPv6 NDP options, invalid hop limit frames).
- Memory exhaustion, infinite loops, or algorithmic complexity attacks in frame decoding.
- Flaws in state table persistence or JSONL telemetry output serialization.
- Subnet isolation bypass or unauthorized state manipulation.

### Out of Scope
- Attacks requiring existing local root or administrator privileges on the capture host.
- Hardware physical layer disruptions or physical NIC tampering.
- Upstream kernel driver flaws (e.g., Npcap driver crashes on Windows or kernel AF_PACKET panics).

---

## Reporting a Vulnerability

Please do not report security vulnerabilities through public GitHub issues.

To report a vulnerability:
1. Open a confidential draft security advisory via GitHub Security Advisories on `netequator/neighwatch`.
2. Alternatively, email security disclosures to `netequator@users.noreply.github.com` with:
   - Affected version and component.
   - Proof of concept (`.pcap` or `.pcapng` capture file demonstrating the issue).
   - Expected behavior versus observed behavior.
3. You will receive an initial response acknowledging receipt within 48 hours.
4. Security advisories will be credited upon coordinated disclosure and patch release.
