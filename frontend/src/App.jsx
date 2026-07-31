import { NavLink, Route, HashRouter as Router, Routes } from "react-router-dom";
import Dashboard from "./pages/Dashboard";
import Alerts from "./pages/Alerts";
import AlertDetail from "./pages/AlertDetail";

const navLink = ({ isActive }) => ({
  fontFamily: "var(--font-mono)",
  fontSize: 13,
  letterSpacing: "0.02em",
  textDecoration: "none",
  padding: "6px 2px",
  color: isActive ? "var(--accent)" : "var(--text-muted)",
  borderBottom: isActive ? "2px solid var(--accent)" : "2px solid transparent",
  transition: "color 120ms ease",
});

function Wordmark() {
  return (
    <div style={{ display: "flex", alignItems: "baseline", gap: 1, fontFamily: "var(--font-mono)" }}>
      <span style={{ color: "var(--text-muted)", fontSize: 15 }}>~/</span>
      <strong style={{ fontSize: 15, fontWeight: 600, color: "var(--text-primary)", letterSpacing: "0.01em" }}>
        soc_agent
      </strong>
      <span className="caret" style={{ marginLeft: 3 }} />
    </div>
  );
}

// A live-looking status pill that's honest about what the site is: a static
// snapshot of a real eval run, not a live-streaming console.
function SnapshotPill() {
  return (
    <div
      className="mono"
      style={{
        display: "flex",
        alignItems: "center",
        gap: 8,
        fontSize: 11.5,
        letterSpacing: "0.08em",
        textTransform: "uppercase",
        color: "var(--text-secondary)",
        background: "var(--surface-2)",
        border: "1px solid var(--gridline)",
        borderRadius: 20,
        padding: "5px 12px",
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
      eval snapshot
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
            <nav style={{ display: "flex", gap: 22 }}>
              <NavLink to="/" end style={navLink}>
                dashboard
              </NavLink>
              <NavLink to="/alerts" style={navLink}>
                alerts
              </NavLink>
            </nav>
          </div>
          <SnapshotPill />
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
