"""Pure-Python PCAP reader (classic .pcap, Ethernet + IPv4).
Extracts: timestamp, src/dst IP, protocol, length, ports."""
import struct

def _classify(proto, sport, dport):
    if proto == 1:  return "ICMP"
    if proto == 6:
        ports = {sport, dport}
        if 53 in ports:  return "DNS"
        if 80 in ports:  return "HTTP"      # metadata only (port based)
        if 443 in ports: return "HTTPS"     # encrypted - never decrypted
        return "TCP"
    if proto == 17:
        if 53 in (sport, dport): return "DNS"
        return "UDP"
    return f"OTHER({proto})"

def read_pcap(path):
    """Yield one dict per IPv4 packet. Malformed packets are skipped."""
    with open(path, "rb") as f:
        hdr = f.read(24)
        if len(hdr) < 24:
            raise ValueError("Not a valid PCAP file (too short)")
        magic = struct.unpack("<I", hdr[:4])[0]
        if magic in (0xA1B2C3D4, 0xA1B23C4D):   endian = "<"
        elif magic in (0xD4C3B2A1, 0x4D3CB2A1): endian = ">"
        else: raise ValueError("Not a classic PCAP file (bad magic number)")
        nano = magic in (0xA1B23C4D, 0x4D3CB2A1)
        linktype = struct.unpack(endian + "I", hdr[20:24])[0]
        if linktype != 1:
            raise ValueError("Only Ethernet (linktype 1) captures are supported")
        while True:
            ph = f.read(16)
            if len(ph) < 16: break
            ts_s, ts_f, incl, orig = struct.unpack(endian + "IIII", ph)
            data = f.read(incl)
            if len(data) < incl: break
            pkt = parse_ethernet(data, ts_s + ts_f / (1e9 if nano else 1e6), orig)
            if pkt: yield pkt

def parse_ethernet(data, ts, length):
    try:
        if len(data) < 34 or struct.unpack("!H", data[12:14])[0] != 0x0800:
            return None                       # not IPv4
        ip = data[14:]
        ihl = (ip[0] & 0x0F) * 4
        proto = ip[9]
        src = ".".join(map(str, ip[12:16]))
        dst = ".".join(map(str, ip[16:20]))
        sport = dport = 0
        if proto in (6, 17) and len(ip) >= ihl + 4:
            sport, dport = struct.unpack("!HH", ip[ihl:ihl + 4])
        return {"timestamp": ts, "src_ip": src, "dst_ip": dst,
                "protocol": _classify(proto, sport, dport),
                "length": length, "src_port": sport, "dst_port": dport}
    except (struct.error, IndexError):
        return None                           # malformed -> skip, don't crash
