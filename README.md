# Temporal Network Enumerator

A small utility for passive and minimal active network enumeration that captures ARP/TCP/UDP/ICMP observations over a short time window and exports a session summary.

## Included

- `core/scanner.py` — main scanner script (sniffs packets, performs optional ARP sweep, saves `session.json`, and draws a graph).

## Requirements

- Python 3.8+
- scapy
- networkx
- matplotlib
- rich

Install requirements (recommended in a virtualenv):

```bash
pip install scapy networkx matplotlib rich
```

## Usage

Run the scanner (may require elevated privileges for packet capture):

```bash
python core/scanner.py
```

The script writes `session.json` to the working directory and displays a small network graph.

## Notes

- Adjust configuration at the top of `core/scanner.py` (`OBSERVATION_TIME`, `ARP_RANGE`, `PCAP_FILTER`).
- Active ARP sweep uses `scapy.srp` and requires appropriate network permissions.
