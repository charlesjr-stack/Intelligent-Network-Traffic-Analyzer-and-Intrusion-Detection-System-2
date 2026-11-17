"""Intelligent Network Traffic Analyzer & IDS - entry point.
Usage:  python src/main.py --pcap data/sample_data/lab_traffic.pcap
        python src/main.py --live --iface eth0 --count 200   (authorised labs only)"""
import argparse, json, os, sys, datetime
sys.path.insert(0, os.path.dirname(__file__))
from modules import pcap_reader, analyzer, detector, database, report

def run(packets, cfg, outdir):
    df = analyzer.to_dataframe(packets)
    if df.empty:
        print("No IPv4 packets found."); return None, []
    summary = analyzer.summarize(df)
    alerts = detector.detect(df, cfg)
    os.makedirs(outdir, exist_ok=True)
    con = database.init(os.path.join(outdir, "traffic.db"))
    database.save(con, df, alerts); con.close()
    report.dashboard(df, summary, alerts, os.path.join(outdir, "dashboard.png"))
    report.export(summary, alerts, outdir)
    return summary, alerts

def main():
    ap = argparse.ArgumentParser(description="Network Traffic Analyzer & IDS")
    ap.add_argument("--pcap"); ap.add_argument("--live", action="store_true")
    ap.add_argument("--iface"); ap.add_argument("--count", type=int, default=200)
    ap.add_argument("--config", default=os.path.join(os.path.dirname(__file__), "config.json"))
    ap.add_argument("--out", default="reports")
    a = ap.parse_args()
    cfg = json.load(open(a.config))
    if a.live:
        from modules.capture import live_capture
        packets = live_capture(a.iface, a.count)
    elif a.pcap:
        packets = list(pcap_reader.read_pcap(a.pcap))
    else:
        ap.error("give --pcap FILE or --live")
    s, alerts = run(packets, cfg, a.out)
    if not s: return
    print(f"\n=== TRAFFIC SUMMARY ===\nPackets: {s['total_packets']}  Bytes: {s['total_bytes']:,}  Duration: {s['duration_s']}s")
    print("\nBy protocol:")
    for p, v in s["by_protocol"].items(): print(f"  {p:8} {v['packets']:5} pkts {v['bytes']:8,} bytes")
    print("\nTop sources:", s["top_sources"]); print("Top destinations:", s["top_destinations"])
    print(f"\n=== ALERTS ({len(alerts)}) ===")
    for x in alerts:
        t = datetime.datetime.fromtimestamp(x["timestamp"], datetime.timezone.utc).strftime("%H:%M:%S")
        print(f"[{x['severity']:6}] {t} {x['rule']:20} {x['src_ip']:12} {x['detail']}")
    print(f"\nReports saved in '{a.out}/' (dashboard.png, summary.json, alerts.csv, traffic.db)")

if __name__ == "__main__":
    main()
