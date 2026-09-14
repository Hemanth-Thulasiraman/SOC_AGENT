import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api";

const STATUS_COLOR = {
  malicious: "var(--status-critical)",
  benign: "var(--status-good)",
  inconclusive: "var(--status-warning)",
  success: "var(--status-good)",
  failure: "var(--status-critical)",
};

function fmt(ts) {
  if (!ts) return "—";
  const d = new Date(ts);
  return isNaN(d) ? String(ts) : d.toLocaleString();
}

// A freshly-run investigation is queued and processed asynchronously by the
// backend, so its detail record can 404 for a while after /run returns. Poll a
// few times before giving up, and present that state as "processing" rather
// than as a hard error.
const MAX_RETRIES = 6;
const RETRY_MS = 4000;

export default function AlertDetail() {
  const { alertId } = useParams();
  const [alert, setAlert] = useState(null);
  const [error, setError] = useState(null);
  const [pending, setPending] = useState(false);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let cancelled = false;
    let timer;
    setAlert(null);
    setError(null);
    setPending(false);

    const tryFetch = (n) => {
      api
        .alert(alertId)
        .then((a) => { if (!cancelled) setAlert(a); })
        .catch(() => {
          if (cancelled) return;
          if (n < MAX_RETRIES) {
            setPending(true);
            setAttempt(n + 1);
            timer = setTimeout(() => tryFetch(n + 1), RETRY_MS);
          } else {
            setPending(false);
            setError(`Investigation ${alertId} isn't available. If you just ran it, the agent may still be processing — or the backend worker hasn't picked it up.`);
          }
        });
    };
    tryFetch(0);
    return () => { cancelled = true; clearTimeout(timer); };
  }, [alertId]);

  if (error)
    return (
      <div className="page" style={{ maxWidth: 860 }}>
        <Link to="/alerts" style={{ color: "var(--text-muted)", fontSize: 13.5 }}>← Back to investigations</Link>
        <div className="panel" style={{ padding: 24, marginTop: 20, borderLeft: "3px solid var(--status-serious)" }}>
          <div className="mono" style={{ color: "var(--status-serious)", fontSize: 13.5, fontWeight: 600, marginBottom: 8 }}>Not available</div>
          <div style={{ color: "var(--text-secondary)", fontSize: 14, lineHeight: 1.6 }}>{error}</div>
        </div>
      </div>
    );
  if (pending)
    return (
      <div className="page mono" style={{ maxWidth: 860, color: "var(--text-secondary)" }}>
        <span className="live-dot" style={{ display: "inline-block", marginRight: 10 }} />
        Investigation queued — waiting for the agent to finish (attempt {attempt}/{MAX_RETRIES})…
      </div>
    );
  if (!alert) return <div className="mono" style={{ padding: 32, color: "var(--text-secondary)" }}>loading…</div>;

  const verdictColor = STATUS_COLOR[alert.verdict] || "var(--text-secondary)";
  const conf = alert.confidence_score ?? 0;
  const ttv =
    alert.start_timestamp && alert.verdict_timestamp
      ? (new Date(alert.verdict_timestamp) - new Date(alert.start_timestamp)) / 1000
      : null;

  return (
    <div className="page" style={{ maxWidth: 860 }}>
      <Link to="/alerts" style={{ color: "var(--text-muted)", fontSize: 13.5 }}>
        ← Back to investigations
      </Link>
      <h1 className="mono" style={{ fontSize: "clamp(20px, 5vw, 24px)", margin: "18px 0 6px", letterSpacing: "-0.01em", fontWeight: 600, color: "var(--text-primary)", wordBreak: "break-all" }}>
        {alert.alert_id}
      </h1>
      <div className="mono" style={{ color: "var(--text-secondary)", fontSize: 13.5, marginBottom: "var(--space-5)" }}>
        {alert.alert_type} · source: {alert.source || "unknown"}
      </div>

      {/* Escalation status — the single most operationally important fact, shown
          as a full-width banner so it can't be missed. */}
      <div
        style={{
          display: "flex", alignItems: "center", gap: 12,
          padding: "14px 18px", marginBottom: "var(--space-5)",
          borderRadius: "var(--radius)",
          background: alert.escalation_flag ? "rgba(232, 134, 63, 0.10)" : "var(--surface-1)",
          border: `1px solid ${alert.escalation_flag ? "rgba(232,134,63,0.4)" : "var(--gridline)"}`,
          borderLeft: `3px solid ${alert.escalation_flag ? "var(--status-serious)" : "var(--status-good)"}`,
        }}
      >
        <span style={{ fontSize: 18 }}>{alert.escalation_flag ? "⚠" : "✓"}</span>
        <div>
          <div className="mono" style={{ fontSize: 13.5, fontWeight: 600, color: alert.escalation_flag ? "var(--status-serious)" : "var(--status-good)" }}>
            {alert.escalation_flag ? "Escalated to analyst" : "Auto-resolved by agent"}
          </div>
          <div style={{ fontSize: 12.5, color: "var(--text-secondary)", marginTop: 2 }}>
            {alert.escalation_flag
              ? "The agent was not confident enough to close this alert on its own."
              : "The agent reached a confident verdict without human review."}
          </div>
        </div>
      </div>

      {/* verdict + confidence */}
      <div className="panel" style={{ padding: "var(--space-5)", marginBottom: "var(--space-5)" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", gap: 16, flexWrap: "wrap", marginBottom: 14 }}>
          <div>
            <div className="field-label">Verdict</div>
            <span className="mono" style={{ fontSize: 20, fontWeight: 700, color: verdictColor }}>{alert.verdict || "—"}</span>
          </div>
          <div style={{ textAlign: "right" }}>
            <div className="field-label" style={{ textAlign: "right" }}>Confidence</div>
            <span className="mono" style={{ fontSize: 20, fontWeight: 700, color: "var(--text-primary)" }}>{conf.toFixed(2)}</span>
          </div>
        </div>
        <div className="meter-track">
          <div className="meter-fill" style={{ width: `${Math.max(0, Math.min(1, conf)) * 100}%`, background: verdictColor, boxShadow: alert.verdict === "benign" ? "0 0 10px rgba(61,220,132,0.4)" : "none" }} />
        </div>
      </div>

      {/* key fields */}
      <div className="panel" style={{ padding: "var(--space-5)", marginBottom: "var(--space-5)" }}>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 20 }}>
          <Field label="User">{alert.user_id ?? "—"}</Field>
          <Field label="Sender domain">{alert.sender_domain ?? "—"}</Field>
          <Field label="Source IP">{alert.source_ip ?? "—"}</Field>
          <Field label="Dest IP">{alert.dest_ip ?? "—"}</Field>
          <Field label="Planning cycles">{alert.planning_count ?? "—"}</Field>
          <Field label="Tool calls">{alert.tool_call_count ?? "—"}</Field>
          <Field label="Time to verdict">{ttv != null ? `${ttv.toFixed(1)}s` : "—"}</Field>
          <Field label="Analyst verdict">{alert.human_verdict ?? "Not reviewed"}</Field>
          <Field label="Ground truth">{alert.true_label ?? "—"}</Field>
          <Field label="Started">{fmt(alert.start_timestamp)}</Field>
          <Field label="Verdict at">{fmt(alert.verdict_timestamp)}</Field>
          <Field label="Synthetic">{alert.is_synthetic ? "yes" : "no"}</Field>
        </div>
      </div>

      <div className="section-label" style={{ marginBottom: 12 }}>Summary</div>
      <div
        className="panel"
        style={{ padding: "var(--space-4) var(--space-5)", fontSize: 14.5, lineHeight: 1.6, marginBottom: "var(--space-6)", color: "var(--text-primary)" }}
      >
        {alert.summary_text || "—"}
      </div>

      <div className="section-label" style={{ marginBottom: 12 }}>
        Evidence trail{alert.evidence?.length ? ` · ${alert.evidence.length} step${alert.evidence.length === 1 ? "" : "s"}` : ""}
      </div>
      <div style={{ display: "flex", flexDirection: "column" }}>
        {(alert.evidence || []).map((e, i) => {
          const last = i === alert.evidence.length - 1;
          const color = STATUS_COLOR[e.status] || "var(--text-muted)";
          return (
            <div key={i} style={{ display: "flex", gap: 14 }}>
              <div style={{ display: "flex", flexDirection: "column", alignItems: "center", paddingTop: 18 }}>
                <span style={{ width: 9, height: 9, borderRadius: "50%", background: color, boxShadow: e.status === "success" ? "var(--accent-glow)" : "none", flexShrink: 0 }} />
                {!last && <span style={{ flex: 1, width: 1, background: "var(--gridline)", marginTop: 4 }} />}
              </div>
              <div className="panel" style={{ padding: "13px 18px", fontSize: 13.5, marginBottom: 8, flex: 1, minWidth: 0 }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", gap: 12, marginBottom: 6, flexWrap: "wrap" }}>
                  <span className="mono" style={{ fontWeight: 600, color: "var(--text-primary)" }}>{e.tool_name}</span>
                  <span className="badge" style={{ color, fontSize: 12 }}>
                    <span className="badge-dot" style={{ background: color, borderRadius: "50%" }} />
                    {e.status}
                  </span>
                </div>
                <div style={{ color: "var(--text-secondary)", lineHeight: 1.55, wordBreak: "break-word" }}>
                  {e.result_summary ?? "(no result returned)"}
                </div>
                {e.timestamp && (
                  <div className="mono" style={{ color: "var(--text-muted)", fontSize: 11.5, marginTop: 8 }}>
                    {fmt(e.timestamp)}
                  </div>
                )}
              </div>
            </div>
          );
        })}
        {(!alert.evidence || alert.evidence.length === 0) && (
          <div className="panel mono" style={{ color: "var(--text-muted)", fontSize: 13, padding: 16 }}>
            no evidence gathered.
          </div>
        )}
      </div>
    </div>
  );
}

function Field({ label, children }) {
  return (
    <div>
      <div className="field-label">{label}</div>
      <div className="mono" style={{ fontSize: 14, color: "var(--text-primary)", wordBreak: "break-word" }}>{children}</div>
    </div>
  );
}
