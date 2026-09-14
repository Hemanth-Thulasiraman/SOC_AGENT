"""
Phase 6b (V2): flow analysis tool for lateral movement alerts.

Reads raw network flow stats directly from raw_evidence and returns
a structured assessment. This is the only tool that doesn't query
an external source -- it reasons over fields already in the alert,
the same way a human analyst would glance at packet counts and flags
before deciding whether to investigate further.

Three signal categories:
- Port-scan / brute-force: high SYN rate, low/no FIN, many packets
- Data staging / exfiltration: high packet volume, high bytes, unusual ports
- Normal traffic: low packet count, clean SYN+FIN handshake, short duration
"""
from __future__ import annotations

# Thresholds derived from CICIDS benign population statistics:
# ~99th percentile of benign flows for packet volume,
# and known attack signatures for flag patterns.
HIGH_PACKET_THRESHOLD = 100      # above this → volumetrically suspicious
LOW_PACKET_THRESHOLD = 20        # below this → likely normal completed connection
HIGH_SYN_THRESHOLD = 3           # repeated SYNs without FIN → scan/brute-force
SENSITIVE_PORTS = {22, 445, 3389, 135, 139}  # SSH, SMB, RDP, RPC


def flow_analysis(
    alert_id: str,
    total_fwd_packets: int | None,
    total_bwd_packets: int | None,
    syn_flag_count: int | None,
    fin_flag_count: int | None,
    avg_packet_size: float | None,
    dest_port: int | None,
) -> str:
    """
    Assesses the flow's traffic pattern and returns a human-readable
    evidence string. Never raises on missing fields -- missing stats
    return a "insufficient flow data" result rather than failing,
    since flow stats are always present in CICIDS-derived alerts but
    may be absent in other sources.
    """
    # Guard missing fields -- return neutral rather than failing
    if any(v is None for v in [
        total_fwd_packets, total_bwd_packets,
        syn_flag_count, fin_flag_count
    ]):
        return "insufficient flow data to assess traffic pattern"

    total_packets = total_fwd_packets + total_bwd_packets
    is_sensitive_port = dest_port in SENSITIVE_PORTS if dest_port else False

    # Port scan / brute-force signal:
    # Many SYN flags, few or no FIN flags -- connection attempts not completing
    if syn_flag_count >= HIGH_SYN_THRESHOLD and fin_flag_count == 0:
        return (
            f"suspicious flag pattern: {syn_flag_count} SYN flags, "
            f"0 FIN flags across {total_packets} packets "
            f"-- consistent with port scan or brute-force attempt"
        )

    # High-volume exfiltration / data staging signal
    if total_packets >= HIGH_PACKET_THRESHOLD:
        port_note = f" on sensitive port {dest_port}" if is_sensitive_port else ""
        return (
            f"high packet volume: {total_packets} total packets{port_note} "
            f"-- consistent with data staging or exfiltration"
        )

    # Normal completed connection signal:
    # Low packet count, balanced SYN/FIN -- looks like routine traffic
    if total_packets <= LOW_PACKET_THRESHOLD and syn_flag_count <= 1 and fin_flag_count >= 1:
        port_note = f" on port {dest_port}" if dest_port else ""
        return (
            f"low volume, normal handshake: {total_packets} packets, "
            f"SYN={syn_flag_count} FIN={fin_flag_count}{port_note} "
            f"-- consistent with legitimate internal traffic"
        )

    # Ambiguous middle ground -- elevated but not clearly malicious
    if is_sensitive_port and total_packets > LOW_PACKET_THRESHOLD:
        return (
            f"moderate traffic on sensitive port {dest_port}: "
            f"{total_packets} packets, SYN={syn_flag_count} FIN={fin_flag_count} "
            f"-- warrants review"
        )

    return (
        f"unremarkable flow: {total_packets} packets, "
        f"SYN={syn_flag_count} FIN={fin_flag_count} "
        f"-- no strong signal either way"
    )