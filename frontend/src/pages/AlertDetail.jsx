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

export default function AlertDetail() {
  const { alertId } = useParams();
  const [alert, setAlert] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    api.alert(alertId).then(setAlert).catch((e) => setError(e.message));
  }, [alertId]);

  if (error) return <div className="mono" style={{ padding: 32, color: "var(--status-critical)" }}>{error}</div>;
  if (!alert) return <div className="mono" style={{ padding: 32, color: "var(--text-secondary)" }}>loading…</div>;

  return (
    <div style={{ maxWidth: 820, margin: "0 auto", padding: "var(--space-7) 32px 64px" }}>
      <Link to="/alerts" style={{ color: "var(--text-muted)", fontSize: 13.5 }}>
        ← Back to investigations
      </Link>
      <h1 className="mono" style={{ fontSize: 24, margin: "18px 0 6px", letterSpacing: "-0.01em", fontWeight: 600, color: "var(--text-primary)" }}>
        {alert.alert_id}
      </h1>
      <div className="mono" style={{ color: "var(--text-secondary)", fontSize: 13.5, marginBottom: "var(--space-6)" }}>
        {alert.alert_type} · source: {alert.source}
      </div>

      <div className="panel" style={{ padding: "var(--space-5)", marginBottom: "var(--space-5)" }}>
        <div style={{ display: "flex", gap: 32, marginBottom: 22, flexWrap: "wrap" }}>
          <Field label="Verdict">
            <span className="mono" style={{ color: STATUS_COLOR[alert.verdict], fontWeight: 700 }}>{alert.verdict}</span>
          </Field>
          <Field label="Confidence">{alert.confidence_score?.toFixed(3)}</Field>
          <Field label="Escalated">
            <span style={{ color: alert.escalation_flag ? "var(--status-serious)" : "var(--text-primary)" }}>
              {alert.escalation_flag ? "Yes" : "No"}
            </span>
          </Field>
          <Field label="Ground truth (eval only)">{alert.true_label ?? "—"}</Field>
          <Field label="Analyst verdict">{alert.human_verdict ?? "Not reviewed"}</Field>
        </div>
        <div style={{ display: "flex", gap: 32, flexWrap: "wrap", paddingTop: 20, borderTop: "1px solid var(--gridline)" }}>
          <Field label="Planning cycles">{alert.planning_count}</Field>
          <Field label="Tool calls">{alert.tool_call_count}</Field>
          <Field label="Started">{new Date(alert.start_timestamp).toLocaleString()}</Field>
          <Field label="Verdict at">
            {alert.verdict_timestamp ? new Date(alert.verdict_timestamp).toLocaleString() : "—"}
          </Field>
        </div>
      </div>

      <div className="section-label" style={{ marginBottom: 12 }}>Summary</div>
      <div
        className="panel"
        style={{
          padding: "var(--space-4) var(--space-5)",
          fontSize: 14.5,
          lineHeight: 1.6,
          marginBottom: "var(--space-6)",
          color: "var(--text-primary)",
        }}
      >
        {alert.summary_text || "—"}
      </div>

      <div className="section-label" style={{ marginBottom: 12 }}>Evidence trail</div>
      <div style={{ display: "flex", flexDirection: "column" }}>
        {(alert.evidence || []).map((e, i) => {
          const last = i === alert.evidence.length - 1;
          return (
            <div key={i} style={{ display: "flex", gap: 14 }}>
              {/* console-log rail: a phosphor node + connector line */}
              <div style={{ display: "flex", flexDirection: "column", alignItems: "center", paddingTop: 18 }}>
                <span
                  style={{
                    width: 9,
                    height: 9,
                    borderRadius: "50%",
                    background: STATUS_COLOR[e.status] || "var(--text-muted)",
                    boxShadow: e.status === "success" ? "var(--accent-glow)" : "none",
                    flexShrink: 0,
                  }}
                />
                {!last && <span style={{ flex: 1, width: 1, background: "var(--gridline)", marginTop: 4 }} />}
              </div>
              <div
                className="panel"
                style={{ padding: "13px 18px", fontSize: 13.5, marginBottom: 8, flex: 1 }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                  <span className="mono" style={{ fontWeight: 600, color: "var(--text-primary)" }}>
                    {e.tool_name}
                  </span>
                  <span className="mono" style={{ color: STATUS_COLOR[e.status] || "var(--text-muted)", fontWeight: 500, fontSize: 12 }}>
                    {e.status}
                  </span>
                </div>
                <div style={{ color: "var(--text-secondary)", lineHeight: 1.55 }}>{e.result_summary ?? "(no result)"}</div>
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
      <div
        className="mono"
        style={{ fontSize: 10.5, color: "var(--text-muted)", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.08em" }}
      >
        {label}
      </div>
      <div className="mono" style={{ fontSize: 14.5, color: "var(--text-primary)" }}>{children}</div>
    </div>
  );
}
