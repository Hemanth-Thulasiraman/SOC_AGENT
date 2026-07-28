Option A — Autonomous Alert Triage & Investigation Agent (mini AI SOC analyst). Ingest security alerts (simulated SIEM/log feed — Zeek/Suricata/CloudTrail-style events), agent enriches with threat intel APIs (VirusTotal, AbuseIPDB), correlates related events via SQL against a log store, reasons to a verdict (benign / malicious / needs-human) with a visible evidence trail, and escalates anything above a confidence threshold for human approval before any containment action. This is the closest match to what the industry is actually shipping in 2026 and gives you every agentic component on your list naturally: tool use, planning, episodic memory (has this IP/user shown up before), reflection (does the evidence actually support the verdict), and a hard HITL gate before any irreversible action.
What you need to build: Nothing in code yet. A one-to-two-page written problem framing doc with these five sections:
Persona — who experiences this pain (be specific: Tier-1 SOC analyst, SOC lead, MSSP) 


- Security Operations Center (SOC) analysts in enterprises, banks, healthcare organizations, and technology companies monitor security events around the clock. Their job is to triage alerts, distinguish real threats from false positives, and respond before attackers can cause damage.

Problem statement, with a number — not "alerts are overwhelming," but something like "analyst X handles N alerts/day, spends Y minutes per alert, Z% are false positives"


- Each analyst receives an average of 174 security alerts every day, but only 22% require genuine investigation. Over half of their time (52%) is spent handling false positives, creating alert fatigue and delaying the investigation of real threats. As alert volumes grow, critical incidents can be overlooked, increasing response times and contributing to analyst burnout.  


Why not a simpler solution — could this be solved with SIEM correlation rules, or a fine-tuned binary classifier (malicious/benign)? You need to argue convincingly why it can't, or your "agent" is theater.


- Traditional SIEM correlation rules are effective at detecting known attack patterns. However, they rely on predefined rules and thresholds, making them brittle when attackers change their tactics or when alerts require context from multiple sources. A slightly different attack sequence or a novel threat may not satisfy an existing rule, leaving analysts to investigate manually.
- Similarly, a fine-tuned binary classifier can predict whether an alert is malicious or benign, but it cannot explain why it reached that conclusion, gather additional evidence, correlate information across SIEM, EDR, IAM, and threat intelligence platforms, or decide the next investigative action. It performs a single prediction rather than an end-to-end investigation.
- An AI agent goes beyond detection by iteratively reasoning through an alert: collecting relevant logs, querying multiple security tools, enriching the alert with threat intelligence, validating hypotheses, and deciding the next step until it has enough evidence to recommend or execute a response. In other words, it automates the investigation process, not just the classification.


Why a genuine agent — what makes the evidence-gathering process variable per alert rather than a fixed sequence? (Hint: think about why a phishing alert and a lateral-movement alert need completely different investigation paths, decided at runtime, not hardcoded.)


- Security alerts do not follow a single investigation workflow. A phishing alert requires checking email headers, attachments, URLs, sender reputation, and user activity, whereas a lateral-movement alert requires examining authentication logs, endpoint telemetry, privilege escalation, and network connections. Because every alert type demands a different sequence of evidence gathering, a fixed pipeline or hardcoded workflow is insufficient. An AI agent must first reason about the nature of the alert, decide what information is missing, dynamically select the appropriate investigation tools, evaluate the evidence it receives, and adapt its next actions until it has enough context to determine the correct response.


Success metrics — 3-5 things you could actually measure in this project: e.g. task completion rate, false-negative rate on verdicts (the dangerous kind of error), time-to-verdict, cost per investigation, escalation precision (did HITL escalations actually deserve escalation).


Time-to-verdict: wall-clock time from alert ingestion to final verdict output, per alert (report median + p95, not just average — tail latency matters more here)


Throughput: alerts fully processed (verdict issued) per hour, at a given concurrency level
Escalation precision: (escalations confirmed true-positive by a human) / (total escalations issued) — answers "when the agent asks for help, was it right to ask?"


False-negative rate (missed true positives): (actual-malicious alerts the agent verdicted as benign) / (total actual-malicious alerts in the eval set) — this is your most important number; it's the error that actually costs someone


Cost per investigation: total LLM + threat-intel API spend / number of alerts investigated


