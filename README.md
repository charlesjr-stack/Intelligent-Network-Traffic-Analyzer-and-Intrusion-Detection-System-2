# Intelligent Network Traffic Analyzer and IDS

A Python tool that reads (or captures) network packets, summarises traffic, raises rule-based alerts and exports reports.

## Features
- PCAP import (own parser using `struct`) and optional live capture (Scapy)
- Extracts timestamp, source/destination IP, protocol, length, ports
- Classifies TCP, UDP, ICMP, DNS; HTTP/HTTPS by port (metadata only, never decrypted)
- Top talkers, packets/bytes per protocol
- 3 alert rules (thresholds in `src/config.json`): high packet rate, possible port scan, unexpected protocol
- Outputs: SQLite DB, dashboard PNG, `summary.json`, `alerts.csv`

## Install and run
    pip install -r requirements.txt
    python src/utils/make_sample_pcap.py          # creates simulated lab data
    python src/main.py --pcap data/sample_data/lab_traffic.pcap
    python tests/test_ids.py                      # run tests
    # Live capture (authorised lab only, needs root + scapy):
    sudo python src/main.py --live --iface eth0 --count 200

## Limitations
- Fixed thresholds cause false positives (busy normal hosts) and false negatives (slow attackers).
- HTTP/HTTPS are guessed from port numbers, which is not proof.
- IPv4 + Ethernet classic PCAP only (no pcapng, no IPv6).
- Sample data is simulated; test only on networks you are authorised to monitor.
