"""
Loads real CICIDS rows (Infiltration + BENIGN) from the raw Thursday
capture and maps them onto the Phase 3 lateral-movement schema.

Two things are pulled from the same CSV:
- the 36 real, labeled Infiltration flows -- the template pool
  `synthesize_infiltration.py` jitters from.
- a sample of real BENIGN flows -- the false-positive population every SOC
  alert queue actually contains. Without it, false-negative rate and
  escalation precision can't be measured: there would be nothing for a
  rule (or an agent) to correctly call benign.
"""
from __future__ import annotations

import pandas as pd

RAW_COLUMNS = {
    "Timestamp": "timestamp",
    "Source IP": "source_ip",
    "Destination IP": "dest_ip",
    "Source Port": "source_port",
    "Destination Port": "dest_port",
    "Protocol": "protocol",
    "Flow Duration": "flow_duration",
    "Total Fwd Packets": "total_fwd_packets",
    "Total Backward Packets": "total_bwd_packets",
    "SYN Flag Count": "syn_flag_count",
    "FIN Flag Count": "fin_flag_count",
    "Average Packet Size": "avg_packet_size",
}

SCHEMA_FIELDS = list(RAW_COLUMNS.values())


def _extract(df: pd.DataFrame) -> pd.DataFrame:
    out = df.rename(columns=RAW_COLUMNS)[SCHEMA_FIELDS].reset_index(drop=True)
    # CICIDS format: "M/D/YYYY H:MM", 24-hour, no seconds -- confirmed
    # against the raw column, not assumed.
    out["timestamp"] = pd.to_datetime(out["timestamp"], format="%m/%d/%Y %H:%M")
    return out


def _read(csv_path: str) -> pd.DataFrame:
    df = pd.read_csv(csv_path)
    df.columns = [c.strip() for c in df.columns]
    return df


def load_real_infiltration_rows(csv_path: str) -> pd.DataFrame:
    """The 36 real, labeled Infiltration flows."""
    df = _read(csv_path)
    return _extract(df[df["Label"] == "Infiltration"])


def sample_real_benign_rows(csv_path: str, n_rows: int, seed: int = 42) -> pd.DataFrame:
    """A random sample of real BENIGN flows from the same capture."""
    df = _read(csv_path)
    benign = df[df["Label"] == "BENIGN"].sample(n=n_rows, random_state=seed)
    return _extract(benign)
