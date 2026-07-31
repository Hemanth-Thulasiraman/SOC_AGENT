# Phase 5: Baseline Solution

## How to read these numbers

Five metrics were specified in Phase 1, but they don't all referee the same
contest. **Cost per investigation, time-to-verdict, and throughput are a
budget, not a comparison** — a pure Python `if/else` with no I/O has a
mathematical floor of ~$0 and sub-millisecond latency that no LLM-driving
agent making real tool calls will ever beat. Reporting "the agent lost on
cost/latency" in Phase 8 would be misleading; those three numbers exist so
Phase 8 can check the agent stayed inside the caps already fixed in Phase 2
(≤$0.10/investigation, <2 min time-to-verdict), not so it can "win" them.

**Escalation precision and false-negative rate are the real contest.**
These are the numbers a rule scorer structurally cannot fix — no threshold
tuning closes the gap, because the failure comes from the rule's inability
to reason across evidence sources or across time, not from a poorly chosen
constant. The story Phase 8 should tell is: *the agent trades bounded cost
and latency for a large, structural accuracy gain the baseline cannot
reach* — not "5/5 metrics won."

## Approach (both alert types)

Hand-written threshold/rule scorers, plain Python, using only the evidence
fields the agent itself will see — no access to `true_label`. Each rule is
the shape a real analyst/SIEM-correlation rule would actually write, and
each is deliberately **perfect on the easy cases** (so the failure is
provably structural, not the baseline being tuned weak) and **fails only on
the cases that require fusing evidence sources or correlating across
time/alerts** — capabilities a fixed rule cannot have by construction.

---

## Phishing

`src/baseline/phishing_rules.py`, run via `src/baseline/run_phishing_baseline.py`
against `src/data/synthesize_phishing.py` (n=2000, seed=42).

Reads `reputation_signal` straight into verdict + confidence
(`known_malicious`→malicious/0.95, `known_clean`→benign/0.95,
`suspicious`→malicious/0.55, `unknown`→benign/0.80; confidence < 0.7
escalates). `click_action` is visible evidence but never fused in — a rule
has no mechanism to combine "no reputation history" with "user entered
credentials" into one verdict.

### Results (n=2000)

| Metric | Value | Contest? |
|---|---|---|
| time-to-verdict (median / p95) | 0.00013 ms / 0.00017 ms | budget only |
| throughput | ~2.9×10^10 alerts/hour | budget only |
| cost per investigation | $0.00 | budget only |
| **escalation precision** | **0.000** (0/590 escalations were true positives) | **real contest** |
| **false-negative rate** | **0.501** (395/789 actual-malicious verdicted benign) | **real contest** |

### Scenario-cell breakdown

| cell | n | verdict=malicious rate | escalation rate |
|---|---|---|---|
| malicious_agree (known_malicious + entered_credentials) | 394 | 1.00 | 0.00 |
| benign_agree (known_clean + viewed_only) | 621 | 0.00 | 0.00 |
| malicious_disagree (unknown + entered_credentials) | 395 | 0.00 | 0.00 |
| benign_disagree (suspicious + viewed_only) | 590 | 1.00 | 1.00 |

Perfect (1.00) on both agree cells. Fails **completely and only** on the
two disagreement cells: `unknown` reputation always reads as benign
regardless of credential entry (100% miss → drives the 0.501 overall FN
rate), and `suspicious` reputation always escalates regardless of click
behavior (100% of escalations from this cell are actually benign → drives
escalation precision to 0.000).

---

## Lateral movement / infiltration

`src/baseline/lateral_movement_rules.py`, run via
`src/baseline/run_lateral_movement_baseline.py`. Dataset: 36 real CICIDS
Infiltration flows + 400 template-jitter synthetic Infiltration flows
(`synthesize_infiltration.py`, seed=42) as the malicious population, plus
1700 real BENIGN flows sampled from the same capture
(`src/data/load_infiltration.py`) as the false-positive population —
≈20% malicious rate, in line with Phase 1's ~22% genuine-alert figure.
Without a benign population, false-negative rate and escalation precision
aren't measurable at all (there's nothing for the rule to correctly call
benign).

Rule: total-packet-volume threshold (≥100 packets fwd+bwd, ~99th
percentile of real BENIGN flows → malicious/0.90, auto-resolve) with a
weaker secondary signal (bare SYN flag with no FIN → malicious/0.50,
escalate); everything else defaults benign/0.85, auto-resolve. It scores
one flow at a time and has no mechanism to correlate across time or across
alerts (e.g. "this source_ip has made 15 quiet connections to the same
destination this hour") — the exact SQL-correlation capability the
agent's episodic memory (Phase 4) exists to provide.

### Results (n=2136)

| Metric | Value | Contest? |
|---|---|---|
| time-to-verdict (median / p95) | 0.00013 ms / 0.00017 ms | budget only |
| throughput | ~2.6×10^10 alerts/hour | budget only |
| cost per investigation | $0.00 | budget only |
| **escalation precision** | **0.753** (204/271 escalations were true positives) | **real contest** |
| **false-negative rate** | **0.218** (95/436 actual-malicious verdicted benign) | **real contest** |

### Detection-bucket breakdown

| bucket | n | verdict=malicious rate | escalation rate |
|---|---|---|---|
| malicious_high_volume | 137 | 1.00 | 0.00 |
| malicious_syn_no_fin | 204 | 1.00 | 1.00 |
| malicious_quiet_no_syn | 95 | 0.00 | 0.00 |
| benign | 1700 | 0.053 | 0.039 |

Loud, high-volume infiltration is caught with full confidence (137/137).
The SYN-without-FIN bucket is caught but only at low confidence, so it's
escalated wholesale (204/204) — and since real infiltration dominates that
bucket, escalation precision on it is good, pulling the overall precision
to 0.753 (better than phishing's 0.000, because this failure mode is
partial, not total). The 95 "quiet" flows — low packet volume, no bare SYN,
a completed-looking connection — are invisible to a per-flow rule and are
missed 100% of the time; they are the entire 0.218 false-negative rate.
This is the case a single-flow rule structurally cannot catch and
SQL-correlation (repeat contact from the same host over time) is built to.

**Caveat on this result's strength:** every malicious row in this eval set
is either one of the 36 real Infiltration flows or a ±15%-jittered variant
of one of those same 36 templates (`synthesize_infiltration.py`). Jitter
that small essentially never moves a template across the volume
threshold, so "a single global threshold catches 100% of the high-volume
bucket" is really "these 36 underlying source patterns split cleanly
across one threshold" — not independent evidence that packet-volume
thresholding would generalize across the actual diversity of real-world
infiltration techniques. This is a narrower claim than the phishing
result: phishing's scenario matrix was explicitly designed to cover
disagreement space, while lateral-movement's malicious diversity is
bounded by 36 real samples. Read the 0.753/0.218 numbers as "how this rule
performs on this eval set," not as a general claim that rule-based
detection works better on network-flow attacks than on phishing.

---

## What the agent has to beat

| Alert type | Baseline escalation precision | Baseline false-negative rate |
|---|---|---|
| Phishing | 0.000 | 0.501 |
| Lateral movement | 0.753 | 0.218 |

Cost and latency are caps to stay under (Phase 2: ≤$0.10, <2 min), not
numbers to win. Any agent that can't materially improve on these two rows
while remaining inside those caps hasn't earned its complexity.

Note the lateral-movement row is a weaker bar than it looks (see caveat
above) — beating 0.753/0.218 on this eval set is a lower burden of proof
than beating phishing's 0.000/0.501, since this baseline's own strength is
partly an artifact of limited real-sample diversity, not a demonstrated
ceiling on rule-based network-flow detection.

## Locked requirement for Phase 8: eval harness must process alerts in timestamp order

`sql_correlation` (Phase 6b) only has a prior investigation to find if an
earlier occurrence of the same host has already been fully investigated
-- verdict computed and written back to `investigations` -- before the
*next* occurrence of that host is even scored. If Phase 8's eval harness
processes alerts out of order, or in parallel without respecting
timestamp order, episodic-memory correlation finds nothing regardless of
how correct the query is: the tool would look broken (or worse, silently
untested) for reasons that have nothing to do with the tool itself. Every
alert (both alert types) now carries a real `timestamp` field for exactly
this reason -- the eval harness must sort by it and process alerts
sequentially in that order, not in arbitrary or parallel order.
