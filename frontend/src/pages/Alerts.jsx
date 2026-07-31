import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";

const STATUS_COLOR = {
  malicious: "var(--status-critical)",
  benign: "var(--status-good)",
  inconclusive: "var(--status-warning)",
};

function VerdictBadge({ verdict }) {
  return (
    <span className="mono" style={{ display: "inline-flex", alignItems: "center", gap: 7, fontSize: 13, color: STATUS_COLOR[verdict] || "var(--text-secondary)" }}>
      <span
        style={{ width: 7, height: 7, borderRadius: 2, background: STATUS_COLOR[verdict] || "var(--text-muted)" }}
      />
      {verdict}
    </span>
  );
}

const PAGE_SIZE = 25;

export default function Alerts() {
  const [data, setData] = useState(null);
  const [filters, setFilters] = useState({ alert_type: "", verdict: "", escalation_flag: "" });
  const [page, setPage] = useState(0);
  const [error, setError] = useState(null);

  useEffect(() => {
    setPage(0);
  }, [filters]);

  useEffect(() => {
    api
      .alerts({ ...filters, limit: PAGE_SIZE, offset: page * PAGE_SIZE })
      .then(setData)
      .catch((e) => setError(e.message));
  }, [filters, page]);

  return (
    <div style={{ maxWidth: 1100, margin: "0 auto", padding: "var(--space-7) 32px 64px" }}>
      <div className="section-label" style={{ marginBottom: 18 }}>Alert triage</div>
      <h1 style={{ fontSize: 26, margin: "0 0 8px", letterSpacing: "-0.02em", fontWeight: 700 }}>Investigations</h1>
      <div style={{ fontSize: 14.5, color: "var(--text-secondary)", marginBottom: "var(--space-5)", lineHeight: 1.6 }}>
        {data
          ? <>Every alert the agent triaged in this evaluation snapshot — <span className="mono" style={{ color: "var(--text-primary)" }}>{data.total}</span> in total. Filter by type, verdict, or escalation, and open any row for the full evidence trail.</>
          : "Loading…"}
      </div>

      <div style={{ display: "flex", gap: 8, marginBottom: "var(--space-5)", flexWrap: "wrap" }}>
        <select style={selectStyle} value={filters.alert_type} onChange={(e) => setFilters({ ...filters, alert_type: e.target.value })}>
          <option value="">All alert types</option>
          <option value="phishing">Phishing</option>
          <option value="lateral_movement">Lateral movement</option>
        </select>
        <select style={selectStyle} value={filters.verdict} onChange={(e) => setFilters({ ...filters, verdict: e.target.value })}>
          <option value="">All verdicts</option>
          <option value="malicious">Malicious</option>
          <option value="benign">Benign</option>
          <option value="inconclusive">Inconclusive</option>
        </select>
        <select
          style={selectStyle}
          value={filters.escalation_flag}
          onChange={(e) => setFilters({ ...filters, escalation_flag: e.target.value })}
        >
          <option value="">Escalation: any</option>
          <option value="true">Escalated only</option>
          <option value="false">Auto-resolved only</option>
        </select>
      </div>

      {error && <div className="mono" style={{ color: "var(--status-critical)" }}>{error}</div>}

      {data && (
        <div className="panel" style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13.5 }}>
            <thead>
              <tr style={{ textAlign: "left", color: "var(--text-muted)", background: "var(--surface-2)" }}>
                <th style={th}>Alert ID</th>
                <th style={th}>Type</th>
                <th style={th}>Verdict</th>
                <th style={th}>Confidence</th>
                <th style={th}>Escalated</th>
                <th style={th}>Ground truth</th>
                <th style={th}>Summary</th>
              </tr>
            </thead>
            <tbody>
              {data.alerts.map((a) => (
                <tr key={a.alert_id} className="alert-row" style={{ borderTop: "1px solid var(--gridline)" }}>
                  <td style={td}>
                    <Link to={`/alerts/${a.alert_id}`} className="mono" style={{ color: "var(--series-1)", fontWeight: 500 }}>
                      {a.alert_id}
                    </Link>
                  </td>
                  <td className="mono" style={{ ...td, color: "var(--text-secondary)" }}>{a.alert_type}</td>
                  <td style={td}>
                    <VerdictBadge verdict={a.verdict} />
                  </td>
                  <td className="mono" style={{ ...td, color: "var(--text-secondary)" }}>
                    {a.confidence_score?.toFixed(2)}
                  </td>
                  <td className="mono" style={{ ...td, color: a.escalation_flag ? "var(--status-serious)" : "var(--text-muted)" }}>
                    {a.escalation_flag ? "yes" : "no"}
                  </td>
                  <td className="mono" style={{ ...td, color: "var(--text-secondary)" }}>{a.true_label}</td>
                  <td style={{ ...td, color: "var(--text-muted)", maxWidth: 360 }}>{a.summary_text}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {data && data.total > 0 && (
        <div className="mono" style={{ display: "flex", alignItems: "center", gap: 14, marginTop: 18, fontSize: 13, color: "var(--text-secondary)" }}>
          <button style={pageBtn} disabled={page === 0} onClick={() => setPage((p) => p - 1)}>
            ← prev
          </button>
          <span>
            {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, data.total)} of {data.total}
          </span>
          <button
            style={pageBtn}
            disabled={(page + 1) * PAGE_SIZE >= data.total}
            onClick={() => setPage((p) => p + 1)}
          >
            next →
          </button>
        </div>
      )}
    </div>
  );
}

const th = {
  padding: "12px 16px",
  fontFamily: "var(--font-mono)",
  fontWeight: 500,
  fontSize: 11,
  textTransform: "uppercase",
  letterSpacing: "0.07em",
};
const td = { padding: "12px 16px" };
const selectStyle = {
  fontFamily: "var(--font-mono)",
  border: "1px solid var(--gridline)",
  background: "var(--surface-2)",
  color: "var(--text-primary)",
  borderRadius: 7,
  padding: "8px 12px",
  fontSize: 12.5,
};
const pageBtn = {
  fontFamily: "var(--font-mono)",
  border: "1px solid var(--gridline)",
  background: "var(--surface-2)",
  color: "var(--text-primary)",
  borderRadius: 7,
  padding: "7px 13px",
  cursor: "pointer",
  fontSize: 12.5,
};
