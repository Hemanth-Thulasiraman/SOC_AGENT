const STATUS = {
  malicious: { color: "var(--status-critical)", label: "Malicious" },
  benign: { color: "var(--status-good)", label: "Benign" },
  inconclusive: { color: "var(--status-warning)", label: "Inconclusive" },
};

// Status colors never carry meaning alone -- every segment ships with a
// visible text label (count + %), not just a hover tooltip, since two of
// the four status steps fall below 3:1 contrast on the light surface by
// the palette's own design (relief rule: labels are the mitigation).
export default function VerdictBreakdown({ title, counts }) {
  const total = Object.values(counts).reduce((a, b) => a + b, 0) || 1;
  const order = ["malicious", "inconclusive", "benign"];

  return (
    <div style={{ background: "var(--surface-1)", borderRadius: "var(--radius)", padding: "var(--space-5)" }}>
      <div style={{ fontSize: 13.5, fontWeight: 500, color: "var(--text-secondary)", marginBottom: 14 }}>{title}</div>
      <div style={{ display: "flex", height: 8, borderRadius: 4, overflow: "hidden", gap: 2 }}>
        {order.map((k) =>
          counts[k] ? (
            <div key={k} style={{ background: STATUS[k].color, width: `${(counts[k] / total) * 100}%` }} />
          ) : null
        )}
      </div>
      <div style={{ display: "flex", gap: 20, marginTop: 14, flexWrap: "wrap" }}>
        {order.map((k) => (
          <div key={k} style={{ display: "flex", alignItems: "center", gap: 7, fontSize: 13 }}>
            <span style={{ width: 7, height: 7, borderRadius: 2, background: STATUS[k].color, display: "inline-block" }} />
            <span style={{ color: "var(--text-secondary)" }}>{STATUS[k].label}</span>
            <span style={{ color: "var(--text-primary)", fontWeight: 500, fontVariantNumeric: "tabular-nums" }}>
              {counts[k] || 0} ({(((counts[k] || 0) / total) * 100).toFixed(0)}%)
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
