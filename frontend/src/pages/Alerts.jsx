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
    <span style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: 13 }}>
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
      <h1 style={{ fontSize: 26, margin: "0 0 6px", letterSpacing: -0.5, fontWeight: 650 }}>Alerts</h1>
      <div style={{ fontSize: 14, color: "var(--text-secondary)", marginBottom: "var(--space-5)" }}>
        {data ? `${data.total} in this eval snapshot` : "loading…"}
      </div>

      <div style={{ display: "flex", gap: 8, marginBottom: "var(--space-5)" }}>
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
          <option value="">Escalated: any</option>
          <option value="true">Escalated only</option>
          <option value="false">Auto-resolved only</option>
        </select>
      </div>

      {error && <div style={{ color: "var(--status-critical)" }}>{error}</div>}

      {data && (
        <div style={{ overflowX: "auto", background: "var(--surface-1)", borderRadius: "var(--radius)" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13.5 }}>
            <thead>
              <tr style={{ textAlign: "left", color: "var(--text-muted)" }}>
                <th style={th}>Alert ID</th>
                <th style={th}>Type</th>
                <th style={th}>Verdict</th>
                <th style={th}>Confidence</th>
                <th style={th}>Escalated</th>
                <th style={th}>True label</th>
                <th style={th}>Summary</th>
              </tr>
            </thead>
            <tbody>
              {data.alerts.map((a) => (
                <tr key={a.alert_id} className="alert-row" style={{ borderTop: "1px solid var(--gridline)" }}>
                  <td style={td}>
                    <Link to={`/alerts/${a.alert_id}`} style={{ color: "var(--series-1)", fontWeight: 500 }}>
                      {a.alert_id}
                    </Link>
                  </td>
                  <td style={{ ...td, color: "var(--text-secondary)" }}>{a.alert_type}</td>
                  <td style={td}>
                    <VerdictBadge verdict={a.verdict} />
                  </td>
                  <td style={{ ...td, fontVariantNumeric: "tabular-nums", color: "var(--text-secondary)" }}>
                    {a.confidence_score?.toFixed(2)}
                  </td>
                  <td style={{ ...td, color: "var(--text-secondary)" }}>{a.escalation_flag ? "yes" : "no"}</td>
                  <td style={{ ...td, color: "var(--text-secondary)" }}>{a.true_label}</td>
                  <td style={{ ...td, color: "var(--text-muted)", maxWidth: 360 }}>{a.summary_text}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {data && data.total > 0 && (
        <div style={{ display: "flex", alignItems: "center", gap: 14, marginTop: 18, fontSize: 13, color: "var(--text-secondary)" }}>
          <button style={pageBtn} disabled={page === 0} onClick={() => setPage((p) => p - 1)}>
            ← prev
          </button>
          <span style={{ fontVariantNumeric: "tabular-nums" }}>
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

const th = { padding: "12px 16px", fontWeight: 500, fontSize: 12, textTransform: "uppercase", letterSpacing: 0.3 };
const td = { padding: "11px 16px" };
const selectStyle = {
  border: "none",
  background: "var(--surface-2)",
  color: "var(--text-primary)",
  borderRadius: 8,
  padding: "7px 12px",
  fontSize: 13,
};
const pageBtn = {
  border: "none",
  background: "var(--surface-2)",
  color: "var(--text-primary)",
  borderRadius: 8,
  padding: "6px 12px",
  cursor: "pointer",
  fontSize: 13,
};
