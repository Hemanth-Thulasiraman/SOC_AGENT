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

  if (error) return <div style={{ padding: 32, color: "var(--status-critical)" }}>{error}</div>;
  if (!alert) return <div style={{ padding: 32, color: "var(--text-secondary)" }}>Loading…</div>;

  return (
    <div style={{ maxWidth: 780, margin: "0 auto", padding: "var(--space-7) 32px 64px" }}>
      <Link to="/alerts" style={{ color: "var(--text-muted)", fontSize: 13.5 }}>
        ← back to alerts
      </Link>
      <h1 style={{ fontSize: 24, margin: "16px 0 6px", letterSpacing: -0.4, fontWeight: 650 }}>{alert.alert_id}</h1>
      <div style={{ color: "var(--text-secondary)", fontSize: 14, marginBottom: "var(--space-6)" }}>
        {alert.alert_type} · source: {alert.source}
      </div>

      <div style={{ background: "var(--surface-1)", borderRadius: "var(--radius)", padding: "var(--space-5)", marginBottom: "var(--space-5)" }}>
        <div style={{ display: "flex", gap: 32, marginBottom: 20, flexWrap: "wrap" }}>
          <Field label="Verdict">
            <span style={{ color: STATUS_COLOR[alert.verdict], fontWeight: 700 }}>{alert.verdict}</span>
          </Field>
          <Field label="Confidence">{alert.confidence_score?.toFixed(3)}</Field>
          <Field label="Escalated">{alert.escalation_flag ? "yes" : "no"}</Field>
          <Field label="True label (eval only)">{alert.true_label ?? "—"}</Field>
          <Field label="Human verdict">{alert.human_verdict ?? "not reviewed"}</Field>
        </div>
        <div style={{ display: "flex", gap: 32, flexWrap: "wrap" }}>
          <Field label="Planning cycles">{alert.planning_count}</Field>
          <Field label="Tool calls">{alert.tool_call_count}</Field>
          <Field label="Started">{new Date(alert.start_timestamp).toLocaleString()}</Field>
          <Field label="Verdict at">
            {alert.verdict_timestamp ? new Date(alert.verdict_timestamp).toLocaleString() : "—"}
          </Field>
        </div>
      </div>

      <h2 style={sectionH2}>Summary</h2>
      <div
        style={{
          background: "var(--surface-1)",
          borderRadius: "var(--radius)",
          padding: "var(--space-4) var(--space-5)",
          fontSize: 14.5,
          lineHeight: 1.55,
          marginBottom: "var(--space-6)",
        }}
      >
        {alert.summary_text || "—"}
      </div>

      <h2 style={sectionH2}>Evidence trail</h2>
      <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
        {(alert.evidence || []).map((e, i) => (
          <div
            key={i}
            style={{
              background: "var(--surface-1)",
              padding: "14px 20px",
              fontSize: 13.5,
              borderRadius: i === 0 && alert.evidence.length === 1
                ? "var(--radius)"
                : i === 0
                ? "var(--radius) var(--radius) 0 0"
                : i === alert.evidence.length - 1
                ? "0 0 var(--radius) var(--radius)"
                : 0,
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 5 }}>
              <span style={{ fontWeight: 600 }}>{e.tool_name}</span>
              <span style={{ color: STATUS_COLOR[e.status] || "var(--text-muted)", fontWeight: 500 }}>{e.status}</span>
            </div>
            <div style={{ color: "var(--text-secondary)" }}>{e.result_summary ?? "(no result)"}</div>
          </div>
        ))}
        {(!alert.evidence || alert.evidence.length === 0) && (
          <div style={{ color: "var(--text-muted)", fontSize: 13, background: "var(--surface-1)", padding: 16, borderRadius: "var(--radius)" }}>
            No evidence gathered.
          </div>
        )}
      </div>
    </div>
  );
}

const sectionH2 = { fontSize: 14.5, margin: "0 0 12px", fontWeight: 600, color: "var(--text-primary)" };

function Field({ label, children }) {
  return (
    <div>
      <div style={{ fontSize: 11.5, color: "var(--text-muted)", marginBottom: 4, textTransform: "uppercase", letterSpacing: 0.3 }}>
        {label}
      </div>
      <div style={{ fontSize: 14.5 }}>{children}</div>
    </div>
  );
}
