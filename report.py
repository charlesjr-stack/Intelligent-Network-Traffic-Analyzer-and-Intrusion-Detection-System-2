"""Dashboard (PNG), JSON and CSV exports."""
import json, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

def dashboard(df, summary, alerts, path):
    fig, ax = plt.subplots(2, 2, figsize=(12, 8))
    fig.suptitle(f"Traffic Dashboard - {summary['total_packets']} packets, "
                 f"{summary['total_bytes']:,} bytes, {len(alerts)} alerts")
    p = df.groupby("protocol").size()
    ax[0,0].pie(p, labels=p.index, autopct="%1.0f%%"); ax[0,0].set_title("Protocol distribution")
    t = df["src_ip"].value_counts().head(5)
    ax[0,1].barh(t.index[::-1], t.values[::-1]); ax[0,1].set_title("Top source IPs (packets)")
    pps = df.set_index("time").resample("1s").size()
    ax[1,0].plot(pps.index, pps.values); ax[1,0].set_title("Packets per second")
    ax[1,0].tick_params(axis="x", rotation=30)
    sev = {}
    for a in alerts: sev[a["rule"]] = sev.get(a["rule"], 0) + 1
    if sev: ax[1,1].bar(sev.keys(), sev.values())
    ax[1,1].set_title("Alerts by rule"); ax[1,1].tick_params(axis="x", rotation=15)
    fig.tight_layout(); fig.savefig(path, dpi=110); plt.close(fig)

def export(summary, alerts, outdir):
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "summary.json"), "w") as f:
        json.dump({"summary": summary, "alerts": alerts}, f, indent=2, default=str)
    import pandas as pd
    pd.DataFrame(alerts).to_csv(os.path.join(outdir, "alerts.csv"), index=False)
