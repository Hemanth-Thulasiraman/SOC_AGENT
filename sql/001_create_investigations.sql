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
