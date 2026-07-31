import { useEffect, useState } from "react";
import { api } from "../api";
import StatTile from "../components/StatTile";
import VerdictBreakdown from "../components/VerdictBreakdown";

const ALERT_TYPE_LABEL = { phishing: "Phishing", lateral_movement: "Lateral movement" };

export default function Dashboard() {
  const [metrics, setMetrics] = useState(null);
  const [baseline, setBaseline] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    Promise.all([api.metrics(), api.baseline()])
      .then(([m, b]) => {
        setMetrics(m);
        setBaseline(b);
      })
      .catch((e) => setError(e.message));
  }, []);

  if (error) return <div style={{ padding: 32, color: "var(--status-critical)" }}>Error: {error}</div>;
  if (!metrics) return <div style={{ padding: 32, color: "var(--text-secondary)" }}>Loading…</div>;
  if (!metrics.overall) return <div style={{ padding: 32 }}>No eval data yet — run the eval harness first.</div>;

  const o = metrics.overall;

  return (
    <div style={{ maxWidth: 1100, margin: "0 auto", padding: "var(--space-7) 32px 64px" }}>
      <div style={{ marginBottom: "var(--space-7)" }}>
        <h1 style={{ fontSize: 28, margin: "0 0 12px", letterSpacing: -0.6, fontWeight: 650 }}>
          Autonomous SOC Triage Agent
        </h1>
        <p style={{ fontSize: 15, color: "var(--text-secondary)", margin: 0, maxWidth: 620, lineHeight: 1.6 }}>
          A LangGraph agent that investigates phishing and lateral-movement alerts — gathering evidence
          through tool calls, reasoning to a verdict, and escalating what it isn't confident about —
          measured against {o.n_alerts} real, held-out alerts and a rule-based baseline.
        </p>
        {metrics.generated_at && (
          <div style={{ fontSize: 12.5, color: "var(--text-muted)", marginTop: 14 }}>
            Snapshot generated {new Date(metrics.generated_at).toLocaleString()}
          </div>
        )}
      </div>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(5, 1fr)",
          background: "var(--surface-1)",
          borderRadius: "var(--radius)",
          marginBottom: "var(--space-6)",
        }}
      >
        {[
          <StatTile key="n" label="Alerts evaluated" value={o.n_alerts} />,
          <StatTile
            key="fn"
            label="False-negative rate"
            value={o.false_negative_rate.toFixed(3)}
            status={o.false_negative_rate === 0 ? "good" : "critical"}
            sub={`${o.n_false_negatives}/${o.n_actual_malicious} missed`}
          />,
          <StatTile
            key="ep"
            label="Escalation precision"
            value={o.escalation_precision?.toFixed(3) ?? "—"}
            sub={`${o.n_escalations} escalations`}
          />,
          <StatTile
            key="tv"
            label="Median time-to-verdict"
            value={`${o.time_to_verdict_median_s.toFixed(1)}s`}
            sub={`p95: ${o.time_to_verdict_p95_s.toFixed(1)}s`}
          />,
          <StatTile
            key="cost"
            label="Cost / investigation"
            value={o.cost_per_investigation_usd != null ? `$${o.cost_per_investigation_usd.toFixed(4)}` : "—"}
          />,
        ].map((tile, i) => (
          <div key={i} style={{ padding: "var(--space-5)", borderLeft: i === 0 ? "none" : "1px solid var(--gridline)" }}>
            {tile}
          </div>
        ))}
      </div>

      {o.n_inconclusive_on_malicious > 0 && (
        <div
          style={{
            background: "var(--surface-1)",
            borderRadius: "var(--radius)",
            borderLeft: "3px solid var(--status-warning)",
            padding: "16px 20px",
            fontSize: 13.5,
            color: "var(--text-secondary)",
            marginBottom: "var(--space-6)",
            lineHeight: 1.55,
          }}
        >
          <strong style={{ color: "var(--text-primary)" }}>Caveat — </strong>
          {o.n_inconclusive_on_malicious}/{o.n_actual_malicious} actual-malicious alerts got
          verdict="inconclusive" (escalated, not counted as a miss, but not a confident correct call either).
          The baseline never has this third option — see the eval report for the full nuance.
        </div>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "var(--space-4)", marginBottom: "var(--space-6)" }}>
        {Object.entries(metrics.by_alert_type).map(([alertType, m]) => (
          <VerdictBreakdown
            key={alertType}
            title={`${ALERT_TYPE_LABEL[alertType] ?? alertType} — verdict distribution`}
            counts={m.verdict_counts}
          />
        ))}
      </div>

      {baseline && (
        <div>
          <h2 style={{ fontSize: 15.5, margin: "0 0 14px", fontWeight: 600, color: "var(--text-primary)" }}>
            Escalation rate — agent vs. baseline
          </h2>
          <div style={{ background: "var(--surface-1)", borderRadius: "var(--radius)", overflow: "hidden" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13.5 }}>
              <thead>
                <tr style={{ textAlign: "left", color: "var(--text-muted)" }}>
                  <th style={th}>Alert type</th>
                  <th style={th}>On malicious — baseline</th>
                  <th style={th}>On malicious — agent</th>
                  <th style={th}>On benign — baseline</th>
                  <th style={th}>On benign — agent</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(metrics.by_alert_type).map(([alertType, m]) => {
                  const b = baseline[alertType];
                  const flagged = m.escalation_rate_benign - b.escalation_rate_benign > 0.1;
                  return (
                    <tr key={alertType} style={{ borderTop: "1px solid var(--gridline)" }}>
                      <td style={{ ...td, fontWeight: 500 }}>{ALERT_TYPE_LABEL[alertType] ?? alertType}</td>
                      <td style={{ ...td, fontVariantNumeric: "tabular-nums" }}>
                        {(b.escalation_rate_malicious * 100).toFixed(1)}%
                      </td>
                      <td style={{ ...td, fontVariantNumeric: "tabular-nums" }}>
                        {(m.escalation_rate_malicious * 100).toFixed(1)}%
                      </td>
                      <td style={{ ...td, fontVariantNumeric: "tabular-nums" }}>
                        {(b.escalation_rate_benign * 100).toFixed(1)}%
                      </td>
                      <td
                        style={{
                          ...td,
                          fontVariantNumeric: "tabular-nums",
                          color: flagged ? "var(--status-serious)" : "var(--text-primary)",
                          fontWeight: flagged ? 700 : 400,
                        }}
                      >
                        {(m.escalation_rate_benign * 100).toFixed(1)}%
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          {Object.entries(metrics.by_alert_type).some(
            ([alertType, m]) => m.escalation_rate_benign - baseline[alertType].escalation_rate_benign > 0.1
          ) && (
            <div style={{ fontSize: 12.5, color: "var(--status-serious)", marginTop: 10, lineHeight: 1.5 }}>
              Escalation rate on benign alerts rose sharply for at least one alert type — flat escalation
              precision can mask a real increase in false-alarm volume, not a clean win. See the eval report.
            </div>
          )}
        </div>
      )}
    </div>
  );
}

const th = { padding: "14px 18px", fontWeight: 500, fontSize: 12.5, textTransform: "uppercase", letterSpacing: 0.3 };
const td = { padding: "12px 18px" };
