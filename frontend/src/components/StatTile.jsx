export default function StatTile({ label, value, sub, status }) {
  const statusColor = status ? `var(--status-${status})` : "var(--text-primary)";
  return (
    <div style={{ padding: "var(--space-4) 0" }}>
      <div
        style={{
          fontSize: 12.5,
          fontWeight: 500,
          color: "var(--text-muted)",
          marginBottom: 10,
          textTransform: "uppercase",
          letterSpacing: 0.4,
        }}
      >
        {label}
      </div>
      <div style={{ fontSize: 32, fontWeight: 600, color: statusColor, lineHeight: 1.1, letterSpacing: -0.5 }}>
        {value}
      </div>
      {sub && <div style={{ fontSize: 13, color: "var(--text-muted)", marginTop: 6 }}>{sub}</div>}
    </div>
  );
}
