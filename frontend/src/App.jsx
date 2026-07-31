import { useEffect, useState } from "react";
import { NavLink, Route, HashRouter as Router, Routes } from "react-router-dom";
import Dashboard from "./pages/Dashboard";
import Alerts from "./pages/Alerts";
import AlertDetail from "./pages/AlertDetail";

const navLink = ({ isActive }) => ({
  padding: "18px 0",
  textDecoration: "none",
  fontSize: 14,
  fontWeight: isActive ? 600 : 400,
  color: isActive ? "var(--text-primary)" : "var(--text-muted)",
  borderBottom: isActive ? "2px solid var(--text-primary)" : "2px solid transparent",
  transition: "color 120ms ease",
});

function ThemeToggle() {
  const [theme, setTheme] = useState(localStorage.getItem("theme") || "auto");

  useEffect(() => {
    if (theme === "auto") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("theme", theme);
  }, [theme]);

  const icon = theme === "dark" ? "🌙" : theme === "light" ? "☀️" : "◐";

  return (
    <button
      onClick={() => setTheme(theme === "dark" ? "light" : theme === "light" ? "auto" : "dark")}
      style={{
        border: "none",
        background: "var(--surface-2)",
        color: "var(--text-secondary)",
        borderRadius: 20,
        padding: "6px 14px",
        fontSize: 12.5,
        cursor: "pointer",
        display: "flex",
        alignItems: "center",
        gap: 6,
      }}
    >
      <span>{icon}</span> {theme}
    </button>
  );
}

export default function App() {
  return (
    <Router>
      <div
        style={{
          position: "sticky",
          top: 0,
          zIndex: 10,
          background: "color-mix(in srgb, var(--page-plane) 88%, transparent)",
          backdropFilter: "blur(10px)",
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
            height: 58,
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 32 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span
                style={{
                  width: 7,
                  height: 7,
                  borderRadius: 2,
                  background: "var(--series-2)",
                  display: "inline-block",
                }}
              />
              <strong style={{ fontSize: 14.5, letterSpacing: 0.1 }}>SOC Agent</strong>
            </div>
            <nav style={{ display: "flex", gap: 24 }}>
              <NavLink to="/" end style={navLink}>
                Dashboard
              </NavLink>
              <NavLink to="/alerts" style={navLink}>
                Alerts
              </NavLink>
            </nav>
          </div>
          <ThemeToggle />
        </div>
      </div>

      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/alerts" element={<Alerts />} />
        <Route path="/alerts/:alertId" element={<AlertDetail />} />
      </Routes>
    </Router>
  );
}
