# SOC Agent

**Live results: https://frontend-xi-navy-16.vercel.app**

Autonomous alert triage agent (phishing + lateral-movement) built on
LangGraph, with a Postgres/pgvector episodic memory store, a Phase 5
rule-based baseline it's measured against, and a Phase 8 eval harness. Full
phase-by-phase design history and what's actually been verified (not just
designed) is in [docs/00-project-recap.md](docs/00-project-recap.md) —
start there.

**Headline result (160-alert held-out eval, real OpenAI calls, ~$0.0055/alert):**
phishing false-negative rate 0.501 → 0.000 (clean win, near-zero side effects).
Lateral movement false-negative rate 0.218 → 0.000, but escalation rate on
*benign* alerts rose from 3.9% → 81.3% — a real, root-caused trade-off, not
a clean win. Full nuance and the confirmed underlying bug (`confidence.py`'s
lateral-movement weighting) are in the recap doc's Phase 8 section — don't
cite the false-negative number alone without it.

## Project layout

```
src/
  agent/       LangGraph graph, nodes, routing, LLM clients, prompts
  tools/       the four evidence tools (registry-dispatched, alert_id-keyed)
  data/        synthetic dataset generation + real CICIDS loaders
  baseline/    Phase 5 rule-based baseline scorers
  eval/        Phase 8 eval-set builder, runner, metrics, comparison report,
               export_static_data.py (writes frontend/public/data/*.json)
backend/       FastAPI read-only API over `investigations` (local dev / live-dashboard option, not what's deployed)
frontend/      React (Vite), deployed as a static snapshot (see below)
sql/           schema (Phase 4 design, applied as-is)
docs/          phase-by-phase design docs, numbered
eval_runs/     eval run records (*.json) -- gitignored logs, tracked records
```

## What's actually deployed: a static snapshot, not a live backend

The public link serves a **static export** of the real eval results —
`frontend/public/data/{metrics,alerts,baseline}.json`, generated once by
`src.eval.export_static_data` from the real Postgres `investigations`
table and bundled into the Vite build. There is **no live backend or
database exposed to the internet** — deliberately: this is a results
snapshot meant to be shared via a link, not an operational dashboard, so
there's no ongoing hosting cost, no DB security surface to lock down, and
no server to keep alive. Updating the public numbers means re-running the
export, rebuilding, and redeploying (see below) — it does not update
itself.

The FastAPI backend + `docker-compose` stack still exist and work (see
Option A/B below) for local development or if a genuinely live dashboard
is wanted later — they're just not what the public link points at.

### Regenerating and redeploying the snapshot

```bash
source .venv/bin/activate
python3 -m src.eval.export_static_data   # reads the real DB, writes frontend/public/data/*.json

cd frontend
npm run build
npx vercel --prod --yes
```

## Option A: Docker (live dashboard, local only)

```bash
cp .env.example .env   # fill in ANTHROPIC_API_KEY / OPENAI_API_KEY
docker compose up --build
```

- Frontend: http://localhost:5173 (note: this dev build still expects the
  live `/api/*` backend, not the static `/data/*.json` files the deployed
  site uses — the two frontend code paths currently differ; see `src/api.js`)
- Backend: http://localhost:8010
- Postgres: localhost:5433 (see port note below)

This spins up a **fresh, empty** database (schema only, via `sql/` mounted
as a Postgres init script) — until you run the eval harness against it or
generate demo data via `src.agent.demo`.

## Option B: Local Python/Node (for running the agent itself, not just viewing results)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env   # fill in ANTHROPIC_API_KEY / OPENAI_API_KEY

docker run -d --name soc-agent-db \
  -e POSTGRES_PASSWORD=devpassword -e POSTGRES_DB=soc_agent \
  -p 5433:5432 -v soc_agent_pgdata:/var/lib/postgresql/data \
  pgvector/pgvector:pg16
docker exec -i soc-agent-db psql -U postgres -d soc_agent < sql/001_create_investigations.sql

# a couple of hand-picked demo investigations (real LLM calls, real DB writes)
python3 -m src.agent.demo

# the full Phase 8 eval (160 alerts, ~$1, ~10 min against OpenAI)
python3 -m src.eval.run_eval
python3 -m src.eval.metrics
python3 -m src.eval.comparison_report

# static snapshot (what's actually deployed):
python3 -m src.eval.export_static_data
cd frontend && npm install && npm run build && npx vercel --prod --yes
```

**Note the DB port is 5433, not Postgres's default 5432.** A native/Homebrew
Postgres install was already bound to 5432 on the dev machine this was built
on, so `soc-agent-db` publishes on 5433 instead. If you hit `role "postgres"
does not exist` connecting on 5432, that's this conflict — check
`lsof -nP -iTCP:5432 -sTCP:LISTEN` before assuming the container is broken.

## Known gaps

- **A confirmed, root-caused bug in `confidence.py`'s lateral-movement weighting** drives the 81.3% benign-escalation-rate finding above (two distinct issues: a `"suspicious"` signal wrongly mapped to malicious-leaning, and a structural confidence ceiling that keeps even a clean, correct reputation signal under the auto-resolve threshold). Not yet fixed. Full detail in docs/00-project-recap.md's Phase 8 section.
- `tests/` is currently empty. Correctness throughout this project was
  established by direct verification against real data/DB/API at each
  step (see docs/00-project-recap.md for what was actually checked and
  when) rather than an automated test suite — a real gap for anyone
  extending this code without that context.
- The deployed static site and the `docker-compose` live-dashboard path
  use the same page components but two different `src/api.js` data
  layers (static JSON vs. live fetch) — they were not unified, so
  switching between them is a manual code change, not a config flag.
- No auth on the public link. Fine for a read-only eval snapshot with no
  sensitive data; would need addressing before this pattern is reused for
  anything with real alert data.
