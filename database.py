"""SQLite storage for packet metadata and alerts."""
import sqlite3

def init(path):
    con = sqlite3.connect(path)
    con.executescript("""
    DROP TABLE IF EXISTS packets; DROP TABLE IF EXISTS alerts;
    CREATE TABLE packets(timestamp REAL, src_ip TEXT, dst_ip TEXT, protocol TEXT,
                         length INT, src_port INT, dst_port INT);
    CREATE TABLE alerts(timestamp REAL, rule TEXT, severity TEXT, src_ip TEXT, detail TEXT);
    """)
    return con

def save(con, df, alerts):
    cols = ["timestamp","src_ip","dst_ip","protocol","length","src_port","dst_port"]
    con.executemany("INSERT INTO packets VALUES (?,?,?,?,?,?,?)",
                    df[cols].itertuples(index=False, name=None))
    con.executemany("INSERT INTO alerts VALUES (?,?,?,?,?)",
        [(a["timestamp"],a["rule"],a["severity"],a["src_ip"],a["detail"]) for a in alerts])
    con.commit()
