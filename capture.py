"""Live capture (needs Scapy + admin/root rights, authorised lab only)."""
import time
from .pcap_reader import _classify

def live_capture(interface=None, count=200, timeout=30):
    try:
        from scapy.all import sniff, IP, TCP, UDP
    except ImportError:
        raise SystemExit("Live capture needs Scapy: pip install scapy "
                         "(or use --pcap with a PCAP file).")
    out = []
    def handle(p):
        if IP not in p: return
        sp = dp = 0
        if TCP in p: sp, dp = p[TCP].sport, p[TCP].dport
        elif UDP in p: sp, dp = p[UDP].sport, p[UDP].dport
        out.append({"timestamp": float(p.time), "src_ip": p[IP].src,
                    "dst_ip": p[IP].dst, "protocol": _classify(p[IP].proto, sp, dp),
                    "length": len(p), "src_port": sp, "dst_port": dp})
    sniff(iface=interface, prn=handle, store=False, count=count, timeout=timeout)
    return out
