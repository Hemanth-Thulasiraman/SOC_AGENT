import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";
import StatTile from "../components/StatTile";
import VerdictBreakdown from "../components/VerdictBreakdown";

const ALERT_TYPES = ["phishing", "lateral_movement", "insider_threat"];
const ALERT_TYPE_LABEL = {
  phishing: "Phishing",
  lateral_movement: "Lateral movement",
  insider_threat: "Insider threat",
};

const REFRESH_MS = 10000;

// Sensible starting evidence per alert type so the Run modal is usable without
// the operator having to remember the shape the agent expects.
const EVIDENCE_TEMPLATES = {
  phishing: {
    sender_domain: "secure-login-update.com",
    sender_email: "it-help@secure-login-update.com",
    url: "http://secure-login-update.com/reset?id=8842",
    user_id: "u_014",
    reputation_signal: "unknown",
  },
  lateral_movement: {
    source_ip: "10.4.12.9",
    dest_ip: "10.4.12.40",
    dest_port: 3389,
    total_fwd_packets: 420,
    total_bwd_packets: 380,
    ip_reputation_signal: "suspicious",
  },
  insider_threat: {
    user_id: "u_207",
    event_type: "large_download",
    resource_id: "res_source_code",
    resource_sensitivity: "restricted",
    bytes_transferred: 4200000000,
    prior_access_count: 1,
  },
};

function emptyCounts() {
  return { malicious: 0, benign: 0, inconclusive: 0 };
}

export default function Dashboard() {
  const [metrics, setMetrics] = useState(null);
  const [distribution, setDistribution] = useState(null);
  const [error, setError] = useState(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [simRunning, setSimRunning] = useState(false);
  const [simBusy, setSimBusy] = useState(false);
  const [lastUpdated, setLastUpdated] = useState(null);

  const load = useCallback(async () => {
    try {
      const [m, list] = await Promise.all([api.metrics(), api.alerts({ limit: 1000 })]);
      const dist = {};
      for (const t of ALERT_TYPES) dist[t] = emptyCounts();
      for (const a of list.alerts) {
        if (!dist[a.alert_type]) dist[a.alert_type] = emptyCounts();
        const v = a.verdict in dist[a.alert_type] ? a.verdict : "inconclusive";
        dist[a.alert_type][v] += 1;
      }
      setMetrics(m);
      setDistribution(dist);
      setLastUpdated(new Date());
      setError(null);
    } catch (e) {
      setError(e.message);
    }
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, REFRESH_MS);
    return () => clearInterval(id);
  }, [load]);

  const toggleSimulation = async () => {
    setSimBusy(true);
    try {
      if (simRunning) {
        await api.stopSimulation();
        setSimRunning(false);
      } else {
        await api.startSimulation(2.0);
        setSimRunning(true);
      }
    } catch (e) {
      setError(e.message);
    } finally {
      setSimBusy(false);
    }
  };

  if (error && !metrics)
    return <div className="mono" style={{ padding: 32, color: "var(--status-critical)" }}>Error: {error}</div>;
  if (!metrics)
    return <div className="mono" style={{ padding: 32, color: "var(--text-secondary)" }}>Loading live metrics…</div>;

  const fnr = metrics.false_negative_rate ?? 0;
  const tiles = [
    <StatTile key="n" label="Investigations" value={metrics.total_alerts ?? 0} />,
    <StatTile
      key="fn"
      label="False-negative rate"
      value={fnr.toFixed(3)}
      status={fnr === 0 ? "good" : "critical"}
    />,
    <StatTile
      key="ep"
      label="Escalation precision"
      value={metrics.escalation_precision != null ? metrics.escalation_precision.toFixed(3) : "—"}
    />,
    <StatTile
      key="med"
      label="Median time to verdict"
      value={`${(metrics.median_time_to_verdict ?? 0).toFixed(1)}s`}
    />,
    <StatTile
      key="p95"
      label="p95 time to verdict"
      value={`${(metrics.p95_time_to_verdict ?? 0).toFixed(1)}s`}
    />,
  ];

  return (
    <div className="page">
      <div style={{ marginBottom: "var(--space-7)" }}>
        <div className="section-label" style={{ marginBottom: 18 }}>Operations overview</div>
        <h1 style={{ fontSize: "clamp(24px, 5vw, 30px)", margin: "0 0 14px", letterSpacing: "-0.02em", fontWeight: 700, lineHeight: 1.15 }}>
          Autonomous SOC Triage Agent
        </h1>
        <p style={{ fontSize: 15.5, color: "var(--text-secondary)", margin: 0, maxWidth: 660, lineHeight: 1.65 }}>
          A LangGraph agent that investigates phishing, lateral-movement, and insider-threat alerts —
          gathering evidence through tool calls, reasoning to a verdict, and escalating what it isn't
          confident about. Metrics below are computed live from the investigation store.
        </p>
      </div>

      {/* controls */}
      <div className="toolbar" style={{ marginBottom: "var(--space-6)" }}>
        <button className="btn btn-accent" onClick={() => setModalOpen(true)}>
          <span style={{ fontSize: 15, lineHeight: 0 }}>▶</span> Run investigation
        </button>
        <button
          className={`btn ${simRunning ? "btn-danger" : ""}`}
          onClick={toggleSimulation}
          disabled={simBusy}
        >
          {simRunning ? (
            <><span className="live-dot" style={{ background: "var(--status-critical)", boxShadow: "none" }} /> Stop simulation</>
          ) : (
            <>Start simulation</>
          )}
        </button>
        <div style={{ flex: 1 }} />
        <div className="mono" style={{ display: "inline-flex", alignItems: "center", gap: 8, fontSize: 11.5, color: "var(--text-muted)" }}>
          <span className="live-dot" />
          {lastUpdated ? `updated ${lastUpdated.toLocaleTimeString()}` : "…"}
        </div>
      </div>

      <div className="section-label" style={{ marginBottom: 14 }}>Key metrics</div>
      <div className="panel metrics-grid" style={{ marginBottom: "var(--space-6)" }}>
        {tiles.map((tile, i) => (
          <div key={i} className="metrics-cell">{tile}</div>
        ))}
      </div>

      <div className="section-label" style={{ marginBottom: 14 }}>Verdict distribution by alert type</div>
      <div className="dist-grid" style={{ marginBottom: "var(--space-6)" }}>
        {ALERT_TYPES.map((t) => (
          <VerdictBreakdown
            key={t}
            title={ALERT_TYPE_LABEL[t]}
            counts={(distribution && distribution[t]) || emptyCounts()}
          />
        ))}
      </div>

      {error && (
        <div className="mono" style={{ fontSize: 12, color: "var(--status-serious)" }}>
          ▲ {error}
        </div>
      )}

      {modalOpen && (
        <RunInvestigationModal
          onClose={() => setModalOpen(false)}
          onDone={load}
        />
      )}
    </div>
  );
}

function RunInvestigationModal({ onClose, onDone }) {
  const navigate = useNavigate();
  const [alertType, setAlertType] = useState("phishing");
  const [source, setSource] = useState("manual");
  const [rawEvidence, setRawEvidence] = useState(
    JSON.stringify(EVIDENCE_TEMPLATES.phishing, null, 2)
  );
  const [submitting, setSubmitting] = useState(false);
  const [err, setErr] = useState(null);
  const [result, setResult] = useState(null);
  const touched = useRef(false);

  // Swap the evidence template when the alert type changes, unless the analyst
  // has already edited the textarea (don't clobber their work).
  const onTypeChange = (t) => {
    setAlertType(t);
    if (!touched.current) {
      setRawEvidence(JSON.stringify(EVIDENCE_TEMPLATES[t], null, 2));
    }
  };

  const submit = async () => {
    setErr(null);
    let parsed;
    try {
      parsed = JSON.parse(rawEvidence);
    } catch {
      setErr("raw_evidence is not valid JSON.");
      return;
    }
    if (typeof parsed !== "object" || Array.isArray(parsed) || parsed === null) {
      setErr("raw_evidence must be a JSON object.");
      return;
    }
    setSubmitting(true);
    try {
      const res = await api.runAlert({ alert_type: alertType, source, raw_evidence: parsed });
      setResult(res);
      onDone?.();
    } catch (e) {
      setErr(e.message || "Request failed.");
    } finally {
      setSubmitting(false);
    }
  };

  const resultId = result && (result.alert_id || result.id);

  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <div className="modal" onMouseDown={(e) => e.stopPropagation()}>
        <div style={{ padding: "18px 22px", borderBottom: "1px solid var(--gridline)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div className="section-label">Run investigation</div>
          <button className="btn" style={{ padding: "5px 10px" }} onClick={onClose}>✕</button>
        </div>

        {result ? (
          <div style={{ padding: 22 }}>
            <div className="badge" style={{ color: "var(--status-good)", marginBottom: 12 }}>
              <span className="badge-dot" style={{ background: "var(--status-good)" }} /> Investigation {result.status || "queued"}
            </div>
            <div className="mono" style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.7, wordBreak: "break-all" }}>
              {resultId ? (
                <>alert_id: <span style={{ color: "var(--text-primary)" }}>{resultId}</span>{result.routed_to ? <> · routed to <span style={{ color: "var(--text-primary)" }}>{result.routed_to}</span></> : null}</>
              ) : (
                <pre style={{ margin: 0, whiteSpace: "pre-wrap" }}>{JSON.stringify(result, null, 2)}</pre>
              )}
            </div>
            <div style={{ fontSize: 12.5, color: "var(--text-muted)", marginTop: 10, lineHeight: 1.6 }}>
              The agent processes runs asynchronously — the verdict and evidence
              appear once it finishes. Open the investigation to watch for it.
            </div>
            <div className="toolbar" style={{ marginTop: 20 }}>
              {resultId && (
                <button className="btn btn-accent" onClick={() => navigate(`/alerts/${resultId}`)}>
                  View investigation →
                </button>
              )}
              <button className="btn" onClick={onClose}>Close</button>
            </div>
          </div>
        ) : (
          <div style={{ padding: 22 }}>
            <div style={{ marginBottom: 16 }}>
              <label className="field-label">Alert type</label>
              <select className="field-select" value={alertType} onChange={(e) => onTypeChange(e.target.value)}>
                {ALERT_TYPES.map((t) => (
                  <option key={t} value={t}>{ALERT_TYPE_LABEL[t]}</option>
                ))}
              </select>
            </div>
            <div style={{ marginBottom: 16 }}>
              <label className="field-label">Source</label>
              <input
                className="field-input"
                value={source}
                onChange={(e) => setSource(e.target.value)}
                placeholder="e.g. edr, email_gateway, manual"
              />
            </div>
            <div style={{ marginBottom: 4 }}>
              <label className="field-label">Raw evidence (JSON)</label>
              <textarea
                className="field-textarea mono"
                value={rawEvidence}
                onChange={(e) => { touched.current = true; setRawEvidence(e.target.value); }}
                spellCheck={false}
              />
            </div>

            {err && (
              <div className="mono" style={{ color: "var(--status-critical)", fontSize: 12.5, marginTop: 10 }}>
                ✕ {err}
              </div>
            )}

            <div className="toolbar" style={{ marginTop: 20 }}>
              <button className="btn btn-accent" onClick={submit} disabled={submitting}>
                {submitting ? "Running…" : "Run investigation"}
              </button>
              <button className="btn" onClick={onClose} disabled={submitting}>Cancel</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
