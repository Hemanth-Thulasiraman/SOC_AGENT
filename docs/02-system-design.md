Phase 2: System Design

Agent Framework

LangGraph, using a ReAct-style loop with a bounded reflection cycle.

Rationale: the investigation plan isn't knowable up front (Phase 1) — the agent needs to reason, act, observe, and re-reason as evidence comes in. LangGraph's explicit graph model supports this natively, and its interrupt() + checkpointing mechanism is what makes the human-in-the-loop gate a clean pause-and-resume rather than a hand-rolled state machine.

Orchestration pattern is ReAct, not Plan-and-Execute — the evidence-gathering plan is discovered as the agent goes (e.g. a phishing alert only reveals it needs sender-reputation lookup once the planner recognizes it's email-based), which a rigid up-front plan can't accommodate.


Loop Bounds (Guardrails)

Two independent hard caps, both required because they bound different things:

CapWhat it countsCheckedOn breachplanning_countnumber of reflection/re-planning cycles (~5–6)before the planner starts another cycleauto-escalatetool_call_counttotal tool calls across the investigation (~10–12)before the tool loop dispatches another callauto-escalate

These are separate because one reflection cycle can trigger multiple tool calls — bounding only cycles wouldn't cap cost, and bounding only tool calls wouldn't cap reasoning overhead.

Derivation of the numbers (not arbitrary): assuming ~3,000 input / ~500 output tokens per reflection cycle at current Claude Sonnet pricing, each cycle costs roughly $0.01–0.02. Targeting ≤$0.10/investigation and <2 minutes time-to-verdict, 5–6 cycles (25–90 seconds at 5–15s/cycle) lands inside both budgets.

Why breach = auto-escalate, not auto-resolve: defaulting to "resolved" on insufficient evidence would silently produce the most dangerous failure mode — a false negative. Escalating is the fail-safe consistent with the project's core metric (false-negative rate on missed true positives).


Tool Execution Loop

One pass:


Planner emits a specific tool call (not "gather more evidence" — an actual tool(args) call, chosen based on what's missing for this alert type)
Tool registry checks circuit-breaker status for that tool before dispatching
Tool executes (or fails — see resilience below)
Result appended to the evidence list in agent state
Control returns to planner/reflection: is this enough to verdict, or continue?
Loop or exit; planning_count increments and is checked against its cap each cycle



Per-Tool Resilience (Circuit Breaker)

On timeout or a garbage/malformed response: retry once. If it fails again:


Trip the circuit breaker for that specific tool, for the remainder of this investigation only
Log the failure explicitly (not a silent empty result — the planner must see "this tool failed" as distinct from "this tool found nothing")
Proceed with remaining tools


State shape: {tool_name: {status: "closed"|"open", failure_count: int, last_attempt: timestamp}} — tracked per tool, not as a single investigation-wide counter, since different tools can independently fail.

Failure handling does not bypass the confidence gate. A tripped circuit breaker is treated as a missing-evidence case: it lowers the confidence score proportional to how load-bearing that evidence source is for this alert type, and the existing confidence gate — not a separate override rule — decides escalate vs. auto-resolve. One mechanism for both "genuine evidentiary ambiguity" and "a tool was unavailable," so an analyst reviewing a trace sees one coherent signal (the confidence score) rather than two different failure paths to interpret.


Confidence Scoring

Not flat/equal weighting — reasoned per evidence source, per alert type, because a fixed rule regardless of alert type reproduces the classifier-style behavior Phase 1 argued against.

Worked example — phishing:


Click history (internal log): high weight. It's always available (not a third-party lookup that can legitimately come back empty), and when present with a damning result (credentials entered), it's strong enough evidence to push toward escalation nearly on its own. Missing it is anomalous — a signal something's wrong in the pipeline, not an expected gap.
Link/sender reputation (external lookup): lower weight. "No history found" is the expected state for freshly-registered malicious infrastructure — an absence here isn't the same evidentiary gap as click history being missing, so it should cost less confidence.


The same reasoning shape applies to lateral-movement evidence sources (to be defined when that path is implemented) — the point is that weighting is derived from what's actually diagnostic for that alert type, not copied as a fixed percentage across types.


State Object

Per investigation, the LangGraph state carries:


alert_id, alert_type, start_timestamp, verdict_timestamp
evidence — list of {tool_name, result_summary, status, timestamp}, generic shape across all tools
circuit_breakers — {tool_name: {status, failure_count, last_attempt}}
planning_count, tool_call_count
confidence_score — running value
escalation_flag
verdict


Time-to-verdict is not stored as median/p95 here — those are aggregate statistics computed across many investigations at the eval/monitoring layer. Each investigation only stores its own two timestamps; time_to_verdict = verdict_timestamp - start_timestamp.


Human-in-the-Loop

One gate, one mechanism. Confidence score below threshold → escalate. Above threshold → auto-resolve. No separate override paths (tool failure does not force escalation independent of the confidence score — see resilience section above).

Escalations are delivered via a durable queue (Postgres table with a status column, or SQS) — not an in-memory return value — so the checkpoint survives across stateless requests. Human decisions on escalated cases are written back to the episodic memory store, tagged by alert type, which is what eventually makes escalation precision a measurable metric rather than a one-off spot check.


Memory Architecture


Short-term (working): LangGraph state object, scoped to one investigation
Long-term / episodic: Postgres + pgvector — needed for both structured SQL correlation (has this IP/user appeared before) and semantic similarity search (has something shaped like this alert happened before). A pure vector store can't do the former; a pure relational store can't do the latter.
Human feedback memory: every escalation's outcome (agent verdict vs. human's actual call) written back to the same Postgres store — the basis for computing escalation precision over time.



LLM Provider

Claude, via the Anthropic API. Reasoning: tool-use reliability and resistance to hallucinated confidence matter more here than in most agent projects — a confidently wrong "benign" verdict on a real intrusion is the single most expensive failure mode this system can produce. Open-source models (via vLLM) are a reasonable cost-optimization to revisit once a working baseline exists to compare against — not before.