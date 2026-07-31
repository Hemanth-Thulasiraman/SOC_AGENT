"""
Phase 5's locked baseline numbers (docs/05-baseline.md), as a single
importable source of truth -- used by comparison_report.py and the
backend API's /api/baseline endpoint, so the same numbers aren't
duplicated (and able to drift) across Python and the frontend.

Ground-truth-conditioned escalation rates are derived arithmetic from the
already-published per-cell/bucket tables in docs/05-baseline.md, not a
re-run of anything:
  phishing malicious: 0 escalations across both malicious cells (baseline
    never escalates a malicious verdict -- it auto-resolves malicious_agree
    and misreads malicious_disagree as benign) -> 0/789 = 0.0
  phishing benign: 590 escalations, all from benign_disagree (n=590,
    escalation_rate=1.00 for that cell alone) / (621+590) total benign = 0.4872
  lateral_movement malicious: 204 escalations (100% of malicious_syn_no_fin,
    n=204) / 436 total malicious = 0.4679
  lateral_movement benign: 0.039 (reported directly in the bucket table)
"""

BASELINE = {
    "phishing": {
        "escalation_precision": 0.000,
        "false_negative_rate": 0.501,
        "escalation_rate_malicious": 0.000,
        "escalation_rate_benign": 0.4872,
    },
    "lateral_movement": {
        "escalation_precision": 0.753,
        "false_negative_rate": 0.218,
        "escalation_rate_malicious": 0.4679,
        "escalation_rate_benign": 0.039,
    },
}
