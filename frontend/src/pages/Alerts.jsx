import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";

const STATUS_COLOR = {
  malicious: "var(--status-critical)",
  benign: "var(--status-good)",
  inconclusive: "var(--status-warning)",
};

const REFRESH_MS = 10000;

function VerdictBadge({ verdict }) {
  const color = STATUS_COLOR[verdict] || "var(--text-secondary)";
  return (
    <span className="badge" style={{ color }}>
      <span className="badge-dot" style={{ background: color }} />
      {verdict || "—"}
    </span>
  );
}

function ttv(a) {
  if (!a.start_timestamp || !a.verdict_timestamp) return null;
  return (new Date(a.verdict_timestamp) - new Date(a.start_timestamp)) / 1000;
}

export default function Alerts() {
  const navigate = useNavigate();
  const [data, setData] = useState(null);
  const [filters, setFilters] = useState({ alert_type: "", verdict: "", escalation_flag: "" });
  const [error, setError] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);
  const filtersRef = useRef(filters);
  filtersRef.current = filters;

  const load = useCallback(async () => {
    try {
      const res = await api.alerts({ ...filtersRef.current, limit: 500 });
      setData(res);
      setLastUpdated(new Date());
      setError(null);
    } catch (e) {
      setError(e.message);
    }
  }, []);

  // reload immediately when filters change, then poll on an interval
  useEffect(() => {
    load();
    const id = setInterval(load, REFRESH_MS);
    return () => clearInterval(id);
  }, [load, filters]);

  return (
    <div className="page">
      <div className="section-label" style={{ marginBottom: 18 }}>Alert triage</div>
      <h1 style={{ fontSize: "clamp(22px, 5vw, 26px)", margin: "0 0 8px", letterSpacing: "-0.02em", fontWeight: 700 }}>
        Investigations
      </h1>
      <div style={{ fontSize: 14.5, color: "var(--text-secondary)", marginBottom: "var(--space-5)", lineHeight: 1.6 }}>
        {data
          ? <>Live view of every alert the agent has triaged — <span className="mono" style={{ color: "var(--text-primary)" }}>{data.total}</span> in total. Filter by type, verdict, or escalation, and open any row for the full evidence trail.</>
          : "Loading…"}
      </div>

      <div className="toolbar" style={{ marginBottom: "var(--space-5)" }}>
        <select className="filter-select" value={filters.alert_type} onChange={(e) => setFilters({ ...filters, alert_type: e.target.value })}>
          <option value="">All alert types</option>
          <option value="phishing">Phishing</option>
          <option value="lateral_movement">Lateral movement</option>
          <option value="insider_threat">Insider threat</option>
        </select>
        <select className="filter-select" value={filters.verdict} onChange={(e) => setFilters({ ...filters, verdict: e.target.value })}>
          <option value="">All verdicts</option>
          <option value="malicious">Malicious</option>
          <option value="benign">Benign</option>
          <option value="inconclusive">Inconclusive</option>
        </select>
        <select
          className="filter-select"
          value={filters.escalation_flag}
          onChange={(e) => setFilters({ ...filters, escalation_flag: e.target.value })}
        >
          <option value="">Escalation: any</option>
          <option value="true">Escalated only</option>
        </select>
        <div style={{ flex: 1 }} />
        <div className="mono" style={{ display: "inline-flex", alignItems: "center", gap: 8, fontSize: 11.5, color: "var(--text-muted)" }}>
          <span className="live-dot" />
          {lastUpdated ? `updated ${lastUpdated.toLocaleTimeString()}` : "…"}
        </div>
      </div>

      {error && <div className="mono" style={{ color: "var(--status-critical)", marginBottom: 12 }}>{error}</div>}

      {data && (
        <div className="panel table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th>Alert ID</th>
                <th>Type</th>
                <th>Verdict</th>
                <th>Confidence</th>
                <th>Escalated</th>
                <th>Time to verdict</th>
                <th className="hide-sm">Started</th>
              </tr>
            </thead>
            <tbody>
              {data.alerts.map((a) => {
                const t = ttv(a);
                return (
                  <tr
                    key={a.alert_id}
                    className="alert-row click-row"
                    onClick={() => navigate(`/alerts/${a.alert_id}`)}
                  >
                    <td>
                      <span className="mono" style={{ color: "var(--series-1)", fontWeight: 500 }}>{a.alert_id}</span>
                    </td>
                    <td className="mono" style={{ color: "var(--text-secondary)" }}>{a.alert_type}</td>
                    <td><VerdictBadge verdict={a.verdict} /></td>
                    <td className="mono" style={{ color: "var(--text-secondary)" }}>
                      {a.confidence_score != null ? a.confidence_score.toFixed(2) : "—"}
                    </td>
                    <td className="mono" style={{ color: a.escalation_flag ? "var(--status-serious)" : "var(--text-muted)" }}>
                      {a.escalation_flag ? "yes" : "no"}
                    </td>
                    <td className="mono" style={{ color: "var(--text-secondary)" }}>
                      {t != null ? `${t.toFixed(1)}s` : "—"}
                    </td>
                    <td className="mono hide-sm" style={{ color: "var(--text-muted)", whiteSpace: "nowrap" }}>
                      {a.start_timestamp ? new Date(a.start_timestamp).toLocaleString() : "—"}
                    </td>
                  </tr>
                );
              })}
              {data.alerts.length === 0 && (
                <tr>
                  <td colSpan={7} className="mono" style={{ color: "var(--text-muted)", padding: 24, textAlign: "center" }}>
                    No investigations match these filters yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
