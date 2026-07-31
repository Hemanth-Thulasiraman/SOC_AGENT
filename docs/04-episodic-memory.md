# Phase 4: Datasets + Episodic Memory

## Datasets (done)

- **Lateral movement:** real CICIDS Infiltration (36) + synthetic template+jitter (`src/data/synthesize_infiltration.py`), per-template IP consistency for SQL correlation.
- **Phishing:** fully synthetic 2×2 scenario matrix (`src/data/synthesize_phishing.py`), hidden `true_label`, mocked `reputation_signal` for eval.

## Episodic memory: one table, two query paths

Structured fields and semantic memory sit on the **same row** — not separate stores. Exact lookups (`WHERE source_ip = ...`) and similarity search (`ORDER BY embedding <=> query_vector`) both hit `investigations`.

### Embedding model

**OpenAI `text-embedding-3-small`**, dimension **1536** (default). Cheap, good enough semantic quality for short investigation summaries, same external-API pattern as threat-intel tools. Claude has no embeddings endpoint, so a second provider is required regardless.

### `investigations` table

```sql
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE investigations (
    -- identity / routing
    investigation_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id           TEXT NOT NULL UNIQUE,
    alert_type         TEXT NOT NULL CHECK (alert_type IN ('lateral_movement', 'phishing')),
    source             TEXT NOT NULL,          -- feed / simulated SIEM source

    -- correlation keys (nullable; populated by alert type)
    source_ip          INET,                   -- lateral_movement
    dest_ip            INET,                   -- lateral_movement
    user_id            TEXT,                   -- phishing
    sender_domain      TEXT,                   -- phishing

    -- Phase 2 state fields that persist past the run
    -- verdict = agent's own conclusion only (never "escalated" — that's routing)
    verdict            TEXT CHECK (verdict IN ('malicious', 'benign', 'inconclusive')),
    confidence_score   REAL NOT NULL,
    escalation_flag    BOOLEAN NOT NULL DEFAULT FALSE,  -- true iff human is/was in the loop
    planning_count     INTEGER NOT NULL,
    tool_call_count    INTEGER NOT NULL,
    start_timestamp    TIMESTAMPTZ NOT NULL,
    verdict_timestamp  TIMESTAMPTZ,            -- when the agent finalized its verdict
                                               -- (escalated cases still set this; human_decided_at is separate)

    -- full evidence trail (working-state list, durable copy)
    evidence           JSONB NOT NULL DEFAULT '[]',

    -- human-in-the-loop write-back (null if auto-resolved)
    human_verdict      TEXT CHECK (human_verdict IN ('malicious', 'benign', 'inconclusive')),
    human_decided_at   TIMESTAMPTZ,

    -- eval-only (never shown to the agent)
    is_synthetic       BOOLEAN NOT NULL DEFAULT FALSE,
    true_label         TEXT CHECK (true_label IN ('malicious', 'benign')),

    -- semantic memory (same row)
    summary_text       TEXT,                   -- short structured sentence from post-verdict LLM call
    embedding          vector(1536),           -- text-embedding-3-small of summary_text

    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX investigations_source_ip_idx ON investigations (source_ip);
CREATE INDEX investigations_user_id_idx ON investigations (user_id);
CREATE INDEX investigations_sender_domain_idx ON investigations (sender_domain);
CREATE INDEX investigations_alert_type_idx ON investigations (alert_type);

-- No ivfflat/HNSW index at POC scale (hundreds of rows). Exact sequential
-- scan over a few hundred vectors is fast enough; approximate indexes need
-- enough vectors per list/centroid to help, and lists≈sqrt(n) with n~200
-- would be ~14 lists — not worth the misconfiguration risk. Add a properly
-- sized ANN index later once real investigation volume justifies it.
```

**Concrete escalated case:** agent concludes `verdict='malicious'` with low confidence → `escalation_flag=true`, `human_verdict` still null. Human later confirms malicious → `human_verdict='malicious'`, `human_decided_at` set. Agent `verdict` stays `malicious` (what the agent concluded); it is never rewritten to `'escalated'` or overwritten by the human. Escalation precision = compare `verdict` vs `human_verdict` where `escalation_flag=true`.

Query paths against the same table:

```sql
-- structured (SQL correlation)
SELECT * FROM investigations WHERE source_ip = '192.168.10.118';

-- semantic (prior similar investigations) — exact scan at POC scale
SELECT alert_id, summary_text, verdict,
       embedding <=> $query_vector AS distance
FROM investigations
WHERE embedding IS NOT NULL
ORDER BY embedding <=> $query_vector
LIMIT 5;
```

### Summary generation (after verdict, outside the reflection loop)

One final LLM call once the agent has set `verdict`. Output must stay short and structurally consistent so embeddings are comparable across rows.

#### How `key_evidence` is chosen — deterministic, not LLM

The prompt needs a single finding, but `evidence` is a JSONB list. Selection is **deterministic code**, not another LLM judgment:

1. Use the same per-alert-type confidence weights already defined in Phase 2 (e.g. phishing: click history highest weight; reputation lower).
2. Among evidence entries with `status='ok'` (exclude circuit-breaker failures / empty tool results), pick the entry whose tool has the highest weight for this `alert_type`.
3. If that entry's `result_summary` is empty, fall through to the next-highest weight. If none remain, use the literal `"insufficient evidence"`.
4. Pass that string into `{{key_evidence}}`.

Why not leave it to the LLM: "which evidence mattered most" would then be another inconsistent, unauditable step — two similar investigations could emphasize different signals and produce non-comparable summaries, which defeats the point of the forced template. Deterministic selection reuses the confidence-weighting logic you already committed to, stays cheap, and is reviewable in a trace.

**Prompt template:**

```text
You write one-line investigation summaries for episodic memory retrieval.

Rules:
- Output exactly one sentence, under 30 words.
- Use this structure, filling brackets from the investigation record:
  "[alert_type] alert, [key_signal], [outcome], [verdict_label]."
- alert_type: "Lateral movement" or "Phishing"
- key_signal: copy {{key_evidence}} as-is (already selected; do not re-rank evidence)
- outcome: "auto-resolved" if escalation_flag is false; "escalated to analyst" if true
- verdict_label: from agent verdict only —
    malicious → "agent assessed malicious"
    benign → "agent assessed benign"
    inconclusive → "agent assessed inconclusive"
- No speculation. Use only the fields provided. No paragraph, no bullet list.

Fields:
- alert_type: {{alert_type}}
- key_evidence: {{key_evidence}}          # filled by deterministic weight-based picker
- escalation_flag: {{escalation_flag}}    # true | false
- verdict: {{verdict}}                    # malicious | benign | inconclusive

Summary:
```

Example fills:

- `"Lateral movement alert, elevated SYN flag count on an internal host, escalated to analyst, agent assessed malicious."`
- `"Phishing alert, credentials entered on unknown-reputation link, auto-resolved, agent assessed malicious."`
- `"Phishing alert, suspicious sender reputation with no click, escalated to analyst, agent assessed benign."`

After this call: embed `summary_text` with `text-embedding-3-small`, write both columns on the same `investigations` row.
