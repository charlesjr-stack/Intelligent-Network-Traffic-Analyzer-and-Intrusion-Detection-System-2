"""Traffic analysis with Pandas."""
import pandas as pd

def to_dataframe(packets):
    df = pd.DataFrame(packets)
    if not df.empty:
        df["time"] = pd.to_datetime(df["timestamp"], unit="s")
    return df

def summarize(df):
    if df.empty:
        return {"total_packets": 0, "total_bytes": 0, "by_protocol": {},
                "top_sources": {}, "top_destinations": {}}
    by_proto = df.groupby("protocol").agg(packets=("length", "size"),
                                          bytes=("length", "sum"))
    return {
        "total_packets": int(len(df)),
        "total_bytes": int(df["length"].sum()),
        "duration_s": round(float(df["timestamp"].max() - df["timestamp"].min()), 2),
        "by_protocol": by_proto.to_dict("index"),
        "top_sources": df["src_ip"].value_counts().head(5).to_dict(),
        "top_destinations": df["dst_ip"].value_counts().head(5).to_dict(),
    }
