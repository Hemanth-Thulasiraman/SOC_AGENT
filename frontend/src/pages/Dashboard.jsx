import { useEffect, useState } from "react";
import { api } from "../api";
import StatTile from "../components/StatTile";
import VerdictBreakdown from "../components/VerdictBreakdown";

const ALERT_TYPE_LABEL = { phishing: "phishing", lateral_movement: "lateral_movement" };

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

  if (error) return <div className="mono" style={{ padding: 32, color: "var(--status-critical)" }}>error: {error}</div>;
  if (!metrics) return <div className="mono" style={{ padding: 32, color: "var(--text-secondary)" }}>loading…</div>;
  if (!metrics.overall) return <div className="mono" style={{ padding: 32 }}>no eval data yet — run the eval harness first.</div>;

  const o = metrics.overall;

  return (
    <div style={{ maxWidth: 1100, margin: "0 auto", padding: "var(--space-7) 32px 64px" }}>
      <div style={{ marginBottom: "var(--space-7)" }}>
        <div
          className="mono"
          style={{ fontSize: 12.5, color: "var(--accent)", letterSpacing: "0.06em", marginBottom: 16 }}
        >
          <span style={{ color: "var(--text-muted)" }}>~/soc_agent $ </span>
          run triage --eval --held-out
        </div>
        <h1 style={{ fontSize: 30, margin: "0 0 14px", letterSpacing: "-0.02em", fontWeight: 700, lineHeight: 1.15 }}>
          Autonomous SOC triage agent
        </h1>
        <p style={{ fontSize: 15, color: "var(--text-secondary)", margin: 0, maxWidth: 640, lineHeight: 1.65 }}>
          A LangGraph agent that investigates phishing and lateral-movement alerts — gathering evidence
          through tool calls, reasoning to a verdict, and escalating what it isn't confident about —
          measured against{" "}
          <span className="mono" style={{ color: "var(--text-primary)" }}>{o.n_alerts}</span> real, held-out
          alerts and a rule-based baseline.
        </p>
        {metrics.generated_at && (
          <div className="mono" style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 16 }}>
            snapshot: {new Date(metrics.generated_at).toLocaleString()}
          </div>
        )}
      </div>

      <div className="section-label" style={{ marginBottom: 14 }}>headline metrics</div>
      <div
        className="panel"
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(5, 1fr)",
          marginBottom: "var(--space-6)",
          overflow: "hidden",
        }}
      >
        {[
          <StatTile key="n" label="alerts evaluated" value={o.n_alerts} />,
          <StatTile
            key="fn"
            label="false-negative rate"
            value={o.false_negative_rate.toFixed(3)}
            status={o.false_negative_rate === 0 ? "good" : "critical"}
            sub={`${o.n_false_negatives}/${o.n_actual_malicious} missed`}
          />,
          <StatTile
            key="ep"
            label="escalation precision"
            value={o.escalation_precision?.toFixed(3) ?? "—"}
            sub={`${o.n_escalations} escalations`}
          />,
          <StatTile
            key="tv"
            label="median time-to-verdict"
            value={`${o.time_to_verdict_median_s.toFixed(1)}s`}
            sub={`p95: ${o.time_to_verdict_p95_s.toFixed(1)}s`}
          />,
          <StatTile
            key="cost"
            label="cost / investigation"
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
            border: "1px solid var(--gridline)",
            borderLeft: "3px solid var(--status-warning)",
            borderRadius: "var(--radius)",
            padding: "16px 20px",
            fontSize: 13.5,
            color: "var(--text-secondary)",
            marginBottom: "var(--space-6)",
            lineHeight: 1.6,
          }}
        >
          <strong className="mono" style={{ color: "var(--status-warning)", fontSize: 12, letterSpacing: "0.06em" }}>
            CAVEAT&nbsp;&nbsp;
          </strong>
          <span className="mono" style={{ color: "var(--text-primary)" }}>{o.n_inconclusive_on_malicious}/{o.n_actual_malicious}</span>{" "}
          actual-malicious alerts got verdict=<span className="mono" style={{ color: "var(--status-warning)" }}>inconclusive</span>{" "}
          (escalated, not counted as a miss, but not a confident correct call either). The baseline never has
          this third option — see the eval report for the full nuance.
        </div>
      )}

      <div className="section-label" style={{ marginBottom: 14 }}>verdict distribution by alert type</div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "var(--space-4)", marginBottom: "var(--space-6)" }}>
        {Object.entries(metrics.by_alert_type).map(([alertType, m]) => (
          <VerdictBreakdown
            key={alertType}
            title={ALERT_TYPE_LABEL[alertType] ?? alertType}
            counts={m.verdict_counts}
          />
        ))}
      </div>

      {baseline && (
        <div>
          <div className="section-label" style={{ marginBottom: 14 }}>escalation rate — agent vs. baseline</div>
          <div className="panel" style={{ overflow: "hidden" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13.5 }}>
              <thead>
                <tr style={{ textAlign: "left", color: "var(--text-muted)", background: "var(--surface-2)" }}>
                  <th style={th}>alert type</th>
                  <th style={th}>malicious · baseline</th>
                  <th style={th}>malicious · agent</th>
                  <th style={th}>benign · baseline</th>
                  <th style={th}>benign · agent</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(metrics.by_alert_type).map(([alertType, m]) => {
                  const b = baseline[alertType];
                  const flagged = m.escalation_rate_benign - b.escalation_rate_benign > 0.1;
                  return (
                    <tr key={alertType} style={{ borderTop: "1px solid var(--gridline)" }}>
                      <td className="mono" style={{ ...td, fontWeight: 500, color: "var(--text-primary)" }}>
                        {ALERT_TYPE_LABEL[alertType] ?? alertType}
                      </td>
                      <td className="mono" style={td}>{(b.escalation_rate_malicious * 100).toFixed(1)}%</td>
                      <td className="mono" style={td}>{(m.escalation_rate_malicious * 100).toFixed(1)}%</td>
                      <td className="mono" style={td}>{(b.escalation_rate_benign * 100).toFixed(1)}%</td>
                      <td
                        className="mono"
                        style={{
                          ...td,
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
            <div className="mono" style={{ fontSize: 12, color: "var(--status-serious)", marginTop: 12, lineHeight: 1.55 }}>
              ▲ escalation rate on benign alerts rose sharply for at least one alert type — flat escalation
              precision can mask a real increase in false-alarm volume, not a clean win. See the eval report.
            </div>
          )}
        </div>
      )}
    </div>
  );
}

const th = {
  padding: "13px 18px",
  fontFamily: "var(--font-mono)",
  fontWeight: 500,
  fontSize: 11,
  textTransform: "uppercase",
  letterSpacing: "0.08em",
};
const td = { padding: "13px 18px", color: "var(--text-secondary)" };
