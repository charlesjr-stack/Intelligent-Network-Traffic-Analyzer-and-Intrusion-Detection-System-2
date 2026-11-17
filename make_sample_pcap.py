"""Create a lab PCAP with KNOWN patterns (simulated data) to test the IDS.
Known events: (1) 10.0.0.5 floods 400 packets in 2s  (expect HIGH_PACKET_RATE)
              (2) 10.0.0.9 probes 30 ports           (expect POSSIBLE_PORT_SCAN)
              (3) 10.0.0.7 sends GRE (proto 47)      (expect UNEXPECTED_PROTOCOL)
              plus normal TCP/UDP/DNS/ICMP/HTTPS traffic."""
import struct, random, sys

def ip(s): return bytes(map(int, s.split(".")))

def frame(src, dst, proto, sport=0, dport=0, size=60):
    if proto == 6:   l4 = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 0x50, 2, 8192, 0, 0)
    elif proto == 17: l4 = struct.pack("!HHHH", sport, dport, 8, 0)
    elif proto == 1: l4 = struct.pack("!BBHI", 8, 0, 0, 0)
    else: l4 = b"\0" * 8
    total = 20 + len(l4)
    iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, proto, 0, ip(src), ip(dst))
    eth = b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x00"
    return (eth + iph + l4).ljust(size, b"\0")

def write(path):
    random.seed(1)
    pk = []  # (time, frame)
    t0 = 1_700_000_000.0
    hosts = ["10.0.0.2", "10.0.0.3", "10.0.0.4"]
    for i in range(120):                       # normal traffic over 60 s
        t = t0 + i * 0.5; s = random.choice(hosts)
        k = random.choice(["tcp80", "https", "dns", "udp", "icmp"])
        if k == "tcp80": f = frame(s, "10.0.0.100", 6, 40000+i, 80, 120)
        elif k == "https": f = frame(s, "10.0.0.100", 6, 41000+i, 443, 200)
        elif k == "dns": f = frame(s, "10.0.0.1", 17, 50000+i, 53, 80)
        elif k == "udp": f = frame(s, "10.0.0.100", 17, 51000+i, 5000, 100)
        else: f = frame(s, "10.0.0.1", 1, size=64)
        pk.append((t, f))
    for i in range(400):                       # flood from 10.0.0.5
        pk.append((t0 + 20 + i * 0.005, frame("10.0.0.5", "10.0.0.100", 17, 6000, 9999, 100)))
    for i in range(30):                        # port scan from 10.0.0.9
        pk.append((t0 + 40 + i * 0.05, frame("10.0.0.9", "10.0.0.100", 6, 33333, 1000+i, 60)))
    for i in range(3):                         # policy violation (GRE)
        pk.append((t0 + 50 + i, frame("10.0.0.7", "10.0.0.100", 47)))
    pk.sort(key=lambda x: x[0])
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for t, fr in pk:
            s = int(t); us = int((t - s) * 1e6)
            f.write(struct.pack("<IIII", s, us, len(fr), len(fr)) + fr)
    print(f"Wrote {len(pk)} packets to {path}")

if __name__ == "__main__":
    write(sys.argv[1] if len(sys.argv) > 1 else "data/sample_data/lab_traffic.pcap")
