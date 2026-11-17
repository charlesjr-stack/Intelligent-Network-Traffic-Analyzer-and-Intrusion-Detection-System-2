"""Rule-based alerts. Thresholds come from config.json (documented there)."""
import pandas as pd

def detect(df, cfg):
    alerts = []
    if df.empty: return alerts
    win = cfg["window_seconds"]
    thr = cfg["packet_rate_threshold"]

    # Rule 1: packet-rate threshold per source IP per time window
    df = df.copy()
    df["bucket"] = (df["timestamp"] // win).astype(int)
    counts = df.groupby(["src_ip", "bucket"]).size()
    for (ip, b), n in counts.items():
        if n > thr:
            alerts.append({"timestamp": b * win, "rule": "HIGH_PACKET_RATE",
                "severity": "High", "src_ip": ip,
                "detail": f"{n} packets in {win}s window (threshold {thr})"})

    # Rule 2: port-scan indicator (many distinct destination ports)
    for (ip, b), g in df.groupby(["src_ip", "bucket"]):
        ports = g["dst_port"].nunique()
        if ports >= cfg["port_scan_ports"]:
            alerts.append({"timestamp": b * win, "rule": "POSSIBLE_PORT_SCAN",
                "severity": "Medium", "src_ip": ip,
                "detail": f"{ports} different destination ports in {win}s"})

    # Rule 3: protocol not allowed by lab policy
    allowed = set(cfg["allowed_protocols"])
    bad = df[~df["protocol"].isin(allowed)]
    for (ip, proto), g in bad.groupby(["src_ip", "protocol"]):
        alerts.append({"timestamp": float(g["timestamp"].min()),
            "rule": "UNEXPECTED_PROTOCOL", "severity": "Low", "src_ip": ip,
            "detail": f"{len(g)} {proto} packets; not in allowed list"})
    return alerts
