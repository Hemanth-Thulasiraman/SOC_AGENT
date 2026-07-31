export default function StatTile({ label, value, sub, status }) {
  const statusColor = status ? `var(--status-${status})` : "var(--text-primary)";
  return (
    <div style={{ padding: "var(--space-4) 0" }}>
      <div
        style={{
          fontFamily: "var(--font-mono)",
          fontSize: 11,
          fontWeight: 500,
          color: "var(--text-muted)",
          marginBottom: 12,
          textTransform: "uppercase",
          letterSpacing: "0.12em",
        }}
      >
        {label}
      </div>
      <div
        className="mono"
        style={{
          fontSize: 30,
          fontWeight: 600,
          color: statusColor,
          lineHeight: 1.05,
          letterSpacing: "-0.02em",
        }}
      >
        {value}
      </div>
      {sub && (
        <div className="mono" style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 8 }}>
          {sub}
        </div>
      )}
    </div>
  );
}
