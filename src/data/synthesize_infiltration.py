"""
Generates synthetic Infiltration (lateral-movement) rows by sampling
within the observed ranges of the real CICIDS Infiltration rows.
"""
import pandas as pd
import numpy as np

# Mirrors synthesize_phishing.py's SCENARIO_MAP: ip_reputation_signal is a
# mock fixture standing in for what a threat-intel tool would return for
# dest_ip, deliberately decorrelated from true_label in the "disagree"
# cells so ip_reputation_lookup has the same reasoning gap to expose that
# reputation_lookup does for phishing.
IP_REPUTATION_SCENARIO_MAP = {
    ("malicious", "agree"): "known_malicious",
    ("malicious", "disagree"): "unknown",   # freshly-stood-up infra, no history yet
    ("benign", "agree"): "known_clean",
    ("benign", "disagree"): "suspicious",   # legitimate but looks newly-provisioned
}

NUMERIC_FIELDS = [
    "flow_duration", "total_fwd_packets", "total_bwd_packets",
    "syn_flag_count", "fin_flag_count", "avg_packet_size",
]

COUNT_FIELDS = [
    "total_fwd_packets", "total_bwd_packets",
    "syn_flag_count", "fin_flag_count",
]

# Taken from the template row as a unit; IPs then get last-octet jitter so
# synthetic rows do not recycle the exact same fabricated source/dest IPs.
STRUCTURAL_FIELDS = [
    "source_ip", "dest_ip", "source_port", "dest_port", "protocol",
]


MIN_OCCURRENCE_GAP_DAYS = 1.0
MAX_OCCURRENCE_GAP_DAYS = 14.0


def _assign_synthetic_timestamps(
    template_idxs: np.ndarray,
    rng: np.random.Generator,
    now: pd.Timestamp | None = None,
) -> list[pd.Timestamp]:
    """
    Gives every synthetic row a timestamp, ordered so that repeated
    occurrences of the same template land days apart rather than minutes
    or hours apart.

    This spacing is deliberate, not cosmetic: sql_correlation only has
    something to find if an earlier occurrence of a host has already been
    fully investigated -- verdict computed and written back to
    `investigations` -- before the *next* occurrence of that same host is
    even alerted. Day-scale gaps make that ordering safe regardless of how
    slow the investigation is (Phase 2's own cap is 2 minutes); session-
    scale gaps (same host, same hour) would make it a race the pipeline
    could lose. This also incidentally rules out two occurrences of the
    same template ever landing on the identical instant.

    Returns timestamps in the same row order as template_idxs (position i
    gets the timestamp for that row), ending at or before `now`.
    """
    now = now or pd.Timestamp.now()
    n = len(template_idxs)
    timestamps: list[pd.Timestamp | None] = [None] * n

    positions_by_template: dict[int, list[int]] = {}
    for i, tidx in enumerate(template_idxs):
        positions_by_template.setdefault(int(tidx), []).append(i)

    for positions in positions_by_template.values():
        k = len(positions)
        gaps_days = rng.uniform(MIN_OCCURRENCE_GAP_DAYS, MAX_OCCURRENCE_GAP_DAYS, size=k - 1)
        offsets_days = np.concatenate([[0.0], np.cumsum(gaps_days)])

        # Anchor the *last* occurrence a random buffer before `now`, so the
        # whole increasing sequence still ends up in the past.
        end_buffer_days = rng.uniform(0.0, MAX_OCCURRENCE_GAP_DAYS)
        start = now - pd.Timedelta(days=float(offsets_days[-1]) + end_buffer_days)

        for pos, offset in zip(positions, offsets_days, strict=True):
            timestamps[pos] = start + pd.Timedelta(days=float(offset))

    return timestamps  # type: ignore[return-value]


def _jitter_last_octet(
    ip: str,
    rng: np.random.Generator,
    forbidden: set[str],
    max_attempts: int = 64,
) -> str:
    """
    Vary only the last octet so the /24 stays the same but the host differs.
    Rejects any IP already in `forbidden` (real IPs + previously assigned
    synthetic IPs), so cross-template collisions can't happen by construction.
    """
    parts = str(ip).split(".")
    if len(parts) != 4:
        return str(ip)
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return str(ip)

    prefix = octets[:3]
    original = octets[3]
    candidates = [o for o in range(1, 255) if o != original]
    rng.shuffle(candidates)

    for new_last in candidates[:max_attempts]:
        candidate = ".".join(str(o) for o in prefix + [new_last])
        if candidate not in forbidden:
            return candidate

    # Fallback: scan the full /24 host space if the short sample missed.
    for new_last in candidates:
        candidate = ".".join(str(o) for o in prefix + [new_last])
        if candidate not in forbidden:
            return candidate

    raise RuntimeError(
        f"No free last-octet left in {'.'.join(map(str, prefix))}.0/24 "
        f"outside forbidden set of size {len(forbidden)}"
    )


def generate_synthetic_infiltration_rows(real_infiltration_df: pd.DataFrame,
                                           n_rows: int,
                                           seed: int | None = None) -> pd.DataFrame:
    """
    real_infiltration_df: the 36 real Infiltration rows
    n_rows: how many synthetic rows to generate
    Returns: DataFrame of n_rows synthetic rows concatenated with the real
             rows, tagged with is_synthetic True/False respectively.
    """
    rng = np.random.default_rng(seed)

    # Approach: row-wise template + jitter (not independent field sampling).
    # With only ~36 real rows, independent draws would produce combinations
    # that never co-occurred (e.g. extreme duration with tiny packet counts).
    # Picking a real row and jittering its numerics ±10–20% keeps co-variation
    # plausible because every synthetic starts from something that happened.

    required = set(NUMERIC_FIELDS + STRUCTURAL_FIELDS)
    missing = required - set(real_infiltration_df.columns)
    if missing:
        raise ValueError(f"real_infiltration_df missing columns: {sorted(missing)}")
    if len(real_infiltration_df) == 0:
        raise ValueError("real_infiltration_df is empty")
    if n_rows < 0:
        raise ValueError("n_rows must be >= 0")

    # Sample template indices with replacement from the real rows.
    template_idxs = rng.integers(0, len(real_infiltration_df), size=n_rows)
    templates = real_infiltration_df.iloc[template_idxs].reset_index(drop=True)

    synthetic = templates.copy()
    assert synthetic[STRUCTURAL_FIELDS].equals(templates[STRUCTURAL_FIELDS])

    synthetic["timestamp"] = _assign_synthetic_timestamps(template_idxs, rng)

    # IPs: assign one jittered source/dest per template index, then reuse it
    # whenever that template is sampled again. That lets SQL correlation see
    # a repeat-offender host (same compromised machine, multiple alerts).
    # used_source/used_dest still block different templates from sharing an IP.
    # Ports + protocol stay with the template (still a real co-occurring combo).
    real_ips = set(real_infiltration_df["source_ip"].astype(str)) | set(
        real_infiltration_df["dest_ip"].astype(str)
    )
    used_source: set[str] = set(real_ips)
    used_dest: set[str] = set(real_ips)
    template_source_ip: dict[int, str] = {}
    template_dest_ip: dict[int, str] = {}

    new_source = []
    new_dest = []
    for i, (src, dst) in enumerate(
        zip(templates["source_ip"], templates["dest_ip"], strict=True)
    ):
        tidx = int(template_idxs[i])

        if tidx in template_source_ip:
            candidate_src = template_source_ip[tidx]
        else:
            candidate_src = _jitter_last_octet(str(src), rng, used_source)
            used_source.add(candidate_src)
            template_source_ip[tidx] = candidate_src
        new_source.append(candidate_src)

        if tidx in template_dest_ip:
            candidate_dst = template_dest_ip[tidx]
        else:
            candidate_dst = _jitter_last_octet(str(dst), rng, used_dest)
            used_dest.add(candidate_dst)
            template_dest_ip[tidx] = candidate_dst
        new_dest.append(candidate_dst)

    synthetic["source_ip"] = new_source
    synthetic["dest_ip"] = new_dest

    # Jitter each numeric field within ±15% of its template value, then clamp
    # to the observed real min/max so the synthetic distribution cannot drift
    # outside the real support (relative ±15% near an extreme would otherwise).
    jitter_frac = 0.15
    for col in NUMERIC_FIELDS:
        base = templates[col].to_numpy(dtype=float)
        factors = rng.uniform(1.0 - jitter_frac, 1.0 + jitter_frac, size=n_rows)
        jittered = base * factors

        col_min = float(real_infiltration_df[col].min())
        col_max = float(real_infiltration_df[col].max())
        jittered = np.clip(jittered, col_min, col_max)

        # Packet / flag counts are counts — round, clamp at 0, restore int dtype.
        if col in COUNT_FIELDS:
            jittered = np.maximum(0, np.rint(jittered)).astype(int)
        else:
            jittered = np.maximum(0.0, jittered)

        synthetic[col] = jittered

    synthetic["is_synthetic"] = True

    real = real_infiltration_df.copy()
    real["is_synthetic"] = False

    return pd.concat([real, synthetic], ignore_index=True)


def assign_ip_reputation_signal(
    df: pd.DataFrame, agree_rate: float = 0.5, seed: int | None = None
) -> pd.DataFrame:
    """
    Assigns a mock ip_reputation_signal per row, the same way
    synthesize_phishing.py assigns reputation_signal: drawn from
    (true_label, agreement) via IP_REPUTATION_SCENARIO_MAP, so
    ip_reputation_lookup has real disagreement cells to expose rather than
    a signal that always matches the truth.

    df must already carry a `true_label` column -- this runs on the
    combined malicious + benign population (assigned by the caller once
    both are concatenated), not on the malicious-only output of
    generate_synthetic_infiltration_rows alone.
    """
    if "true_label" not in df.columns:
        raise ValueError("df must already have a true_label column")

    rng = np.random.default_rng(seed)
    agreements = rng.choice(["agree", "disagree"], size=len(df), p=[agree_rate, 1 - agree_rate])

    out = df.copy()
    out["ip_reputation_signal"] = [
        IP_REPUTATION_SCENARIO_MAP[(label, agreement)]
        for label, agreement in zip(out["true_label"], agreements, strict=True)
    ]
    return out
