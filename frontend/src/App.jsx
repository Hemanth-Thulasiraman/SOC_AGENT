import { NavLink, Route, HashRouter as Router, Routes } from "react-router-dom";
import Dashboard from "./pages/Dashboard";
import Alerts from "./pages/Alerts";
import AlertDetail from "./pages/AlertDetail";

const navLink = ({ isActive }) => ({
  fontFamily: "var(--font-sans)",
  fontSize: 14,
  fontWeight: isActive ? 600 : 500,
  letterSpacing: "0.01em",
  textDecoration: "none",
  padding: "6px 2px",
  color: isActive ? "var(--text-primary)" : "var(--text-muted)",
  borderBottom: isActive ? "2px solid var(--accent)" : "2px solid transparent",
  transition: "color 120ms ease",
});

function Wordmark() {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
      <span
        style={{
          width: 10,
          height: 10,
          borderRadius: 3,
          background: "var(--accent)",
          boxShadow: "var(--accent-glow)",
        }}
      />
      <strong style={{ fontSize: 15.5, fontWeight: 700, letterSpacing: "-0.01em", color: "var(--text-primary)" }}>
        SOC&nbsp;Agent
      </strong>
    </div>
  );
}

// Environment badge — honest about what this is (a read-only snapshot of a
// real eval run), presented like the env pill on a production dashboard.
function EnvBadge() {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 8,
        fontSize: 12,
        color: "var(--text-secondary)",
        background: "var(--surface-2)",
        border: "1px solid var(--gridline)",
        borderRadius: 20,
        padding: "5px 13px",
      }}
    >
      <span
        style={{
          width: 7,
          height: 7,
          borderRadius: "50%",
          background: "var(--accent)",
          boxShadow: "var(--accent-glow)",
        }}
      />
      <span style={{ fontWeight: 500, color: "var(--text-primary)" }}>Production</span>
      <span style={{ color: "var(--text-muted)" }}>·</span>
      <span style={{ color: "var(--text-muted)" }}>read-only</span>
    </div>
  );
}

export default function App() {
  return (
    <Router>
      <header
        style={{
          position: "sticky",
          top: 0,
          zIndex: 10,
          background: "color-mix(in srgb, var(--page-plane) 82%, transparent)",
          backdropFilter: "blur(12px)",
          borderBottom: "1px solid var(--gridline)",
        }}
      >
        <div
          style={{
            maxWidth: 1100,
            margin: "0 auto",
            padding: "0 32px",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            height: 60,
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 36 }}>
            <Wordmark />
            <nav style={{ display: "flex", gap: 24 }}>
              <NavLink to="/" end style={navLink}>
                Overview
              </NavLink>
              <NavLink to="/alerts" style={navLink}>
                Investigations
              </NavLink>
            </nav>
          </div>
          <EnvBadge />
        </div>
      </header>

      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/alerts" element={<Alerts />} />
        <Route path="/alerts/:alertId" element={<AlertDetail />} />
      </Routes>
    </Router>
  );
}
