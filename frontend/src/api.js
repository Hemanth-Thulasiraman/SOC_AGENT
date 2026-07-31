// Static-snapshot data layer: reads pre-exported JSON (src/eval/export_static_data.py)
// instead of a live backend -- no FastAPI/Postgres exposed publicly. Same
// api.* interface as the live-API version it replaced, so pages didn't
// need to change. To refresh: re-run the export script and redeploy.

let _cache = null;

async function loadAll() {
  if (_cache) return _cache;
  const [metrics, baseline, alerts] = await Promise.all([
    fetch("/data/metrics.json").then((r) => r.json()),
    fetch("/data/baseline.json").then((r) => r.json()),
    fetch("/data/alerts.json").then((r) => r.json()),
  ]);
  _cache = { metrics, baseline, alerts };
  return _cache;
}

export const api = {
  metrics: async () => (await loadAll()).metrics,
  baseline: async () => (await loadAll()).baseline,

  alerts: async (params = {}) => {
    const { alerts } = await loadAll();
    let filtered = alerts;
    if (params.alert_type) filtered = filtered.filter((a) => a.alert_type === params.alert_type);
    if (params.verdict) filtered = filtered.filter((a) => a.verdict === params.verdict);
    if (params.escalation_flag !== undefined && params.escalation_flag !== "") {
      const want = params.escalation_flag === true || params.escalation_flag === "true";
      filtered = filtered.filter((a) => a.escalation_flag === want);
    }
    const total = filtered.length;
    const offset = params.offset || 0;
    const limit = params.limit ?? total;
    return { total, alerts: filtered.slice(offset, offset + limit) };
  },

  alert: async (alertId) => {
    const { alerts } = await loadAll();
    const found = alerts.find((a) => a.alert_id === alertId);
    if (!found) throw new Error(`alert not found: ${alertId}`);
    return found;
  },
};
