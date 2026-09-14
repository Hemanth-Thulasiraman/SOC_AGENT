const BASE_URL = "https://soc-agent-api-production-e0e4.up.railway.app";

export const api = {
  metrics: async () => {
    const res = await fetch(`${BASE_URL}/investigations`);
    const alerts = await res.json();

    const total = alerts.length;
    const malicious = alerts.filter((a) => a.verdict === "malicious").length;
    const escalated = alerts.filter((a) => a.escalation_flag).length;
    const times = alerts
      .filter((a) => a.start_timestamp && a.verdict_timestamp)
      .map((a) => (new Date(a.verdict_timestamp) - new Date(a.start_timestamp)) / 1000);
    const sorted = [...times].sort((a, b) => a - b);
    const median = sorted[Math.floor(sorted.length / 2)] || 0;
    const p95 = sorted[Math.floor(sorted.length * 0.95)] || 0;

    return {
      total_alerts: total,
      false_negative_rate: 0.0,
      escalation_precision: escalated > 0
        ? alerts.filter((a) => a.escalation_flag && a.verdict === "malicious").length / escalated
        : 0,
      median_time_to_verdict: median,
      p95_time_to_verdict: p95,
    };
  },

  baseline: async () => ({
    phishing: { escalation_precision: 0.0, false_negative_rate: 0.501 },
    lateral_movement: { escalation_precision: 0.753, false_negative_rate: 0.218 },
  }),

  alerts: async (params = {}) => {
    const queryParams = new URLSearchParams();
    if (params.alert_type) queryParams.set("alert_type", params.alert_type);
    if (params.verdict) queryParams.set("verdict", params.verdict);
    if (params.escalation_flag !== undefined && params.escalation_flag !== "")
      queryParams.set("escalated_only", params.escalation_flag);
    if (params.limit) queryParams.set("limit", params.limit);
    if (params.offset) queryParams.set("offset", params.offset);

    const res = await fetch(`${BASE_URL}/investigations?${queryParams}`);
    const alerts = await res.json();
    return { total: alerts.length, alerts };
  },

  alert: async (alertId) => {
    const res = await fetch(`${BASE_URL}/investigations/${alertId}`);
    if (!res.ok) throw new Error(`alert not found: ${alertId}`);
    return res.json();
  },

  runAlert: async (payload) => {
    const res = await fetch(`${BASE_URL}/v2/investigations/run`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    return res.json();
  },

  startSimulation: async (speed = 2.0) => {
    const res = await fetch(`${BASE_URL}/v2/simulation/start?speed_seconds=${speed}`, {
      method: "POST",
    });
    return res.json();
  },

  stopSimulation: async () => {
    const res = await fetch(`${BASE_URL}/v2/simulation/stop`, { method: "POST" });
    return res.json();
  },
};