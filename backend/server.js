/**
 * Security Operations Dashboard – Backend Collector + API
 * ─────────────────────────────────────────────────────────
 * • Collects data from all 6 security tools every 15 minutes
 * • Stores snapshots, alerts, vulns, KPIs in PostgreSQL
 * • Serves REST endpoints consumed by the React dashboard
 * • Runs daily maintenance (retention, partition management)
 */

"use strict";

const express  = require("express");
const cors     = require("cors");
const cron     = require("node-cron");
const axios    = require("axios");
const { Pool } = require("pg");

// ── Database ──────────────────────────────────────────────────────────────────
const db = new Pool({
  host:     process.env.POSTGRES_HOST     || "db",
  port:     process.env.POSTGRES_PORT     || 5432,
  database: process.env.POSTGRES_DB       || "secops",
  user:     process.env.POSTGRES_USER     || "secops",
  password: process.env.POSTGRES_PASSWORD || "secops_pass",
  max: 10,
  idleTimeoutMillis: 30000,
});

db.on("error", (err) => console.error("[DB] Unexpected error:", err.message));

// ── API Credentials ───────────────────────────────────────────────────────────
const CFG = {
  fortinet:     { host: process.env.FORTINET_HOST,    key: process.env.FORTINET_APIKEY },
  paloalto:     { host: process.env.PALOALTO_HOST,    key: process.env.PALOALTO_APIKEY },
  upguard:      { key:  process.env.UPGUARD_APIKEY },
  azure:        {
    tenantId:       process.env.AZURE_TENANT_ID,
    clientId:       process.env.AZURE_CLIENT_ID,
    clientSecret:   process.env.AZURE_CLIENT_SECRET,
    subscriptionId: process.env.AZURE_SUBSCRIPTION_ID,
  },
  qualys:       { user: process.env.QUALYS_USERNAME, pass: process.env.QUALYS_PASSWORD },
  manageengine: { host: process.env.ME_HOST,         key:  process.env.ME_APIKEY },
};

// ── HTTP helpers ──────────────────────────────────────────────────────────────
async function get(url, headers = {}, params = {}) {
  const res = await axios.get(url, { headers, params, timeout: 15000 });
  return res.data;
}

// ── Collectors ────────────────────────────────────────────────────────────────
async function collectFortinet() {
  const { host, key } = CFG.fortinet;
  if (!host || !key) return null;
  const h = { Authorization: `Bearer ${key}` };
  const [sessions, threats] = await Promise.all([
    get(`${host}/api/v2/monitor/firewall/session`, h),
    get(`${host}/api/v2/monitor/log/threat`, h),
  ]);
  return { activeSessions: sessions?.results?.length ?? 0, threats };
}

async function collectPaloAlto() {
  const { host, key } = CFG.paloalto;
  if (!host || !key) return null;
  const data = await get(`${host}/api/`, {}, { type: "op", cmd: "<show><system><info/></system></show>", key });
  return { raw: data };
}

async function collectUpGuard() {
  const { key } = CFG.upguard;
  if (!key) return null;
  const h = { Authorization: key, Accept: "application/json" };
  const summary = await get("https://cyber-risk.upguard.com/api/v2/risks/summary", h);
  return summary;
}

let _azureToken = null;
async function getAzureToken() {
  if (_azureToken && _azureToken.exp > Date.now()) return _azureToken.value;
  const { tenantId, clientId, clientSecret } = CFG.azure;
  if (!tenantId) return null;
  const res = await axios.post(
    `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`,
    new URLSearchParams({ grant_type: "client_credentials", client_id: clientId, client_secret: clientSecret, scope: "https://management.azure.com/.default" }),
    { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
  );
  _azureToken = { value: res.data.access_token, exp: Date.now() + res.data.expires_in * 1000 - 30000 };
  return _azureToken.value;
}

async function collectAzure() {
  const token = await getAzureToken();
  const { subscriptionId } = CFG.azure;
  if (!token) return null;
  const h = { Authorization: `Bearer ${token}` };
  const base = `https://management.azure.com/subscriptions/${subscriptionId}`;
  const [alerts, score] = await Promise.all([
    get(`${base}/providers/Microsoft.Security/alerts`, h, { "api-version": "2022-01-01" }),
    get(`${base}/providers/Microsoft.Security/secureScores`, h, { "api-version": "2020-01-01" }),
  ]);
  return { alerts: alerts?.value ?? [], score: score?.value ?? [] };
}

async function collectQualys() {
  const { user, pass } = CFG.qualys;
  if (!user) return null;
  const h = {
    Authorization: "Basic " + Buffer.from(`${user}:${pass}`).toString("base64"),
    "X-Requested-With": "NodeCollector",
  };
  const detections = await get(
    "https://qualysapi.qualys.com/api/2.0/fo/asset/host/vm/detection/",
    h, { action: "list", output_format: "JSON" }
  );
  return detections;
}

async function collectManageEngine() {
  const { host, key } = CFG.manageengine;
  if (!host || !key) return null;
  const h = { Authorization: `Zoho-oauthtoken ${key}` };
  const [patch, enc, assets] = await Promise.all([
    get(`${host}/api/1.4/patch/patchsummary`, h),
    get(`${host}/api/1.4/encryption/summary`, h),
    get(`${host}/api/1.4/inventory/computers`, h),
  ]);
  return { patch, enc, assets };
}

// ── Persist snapshot to DB ────────────────────────────────────────────────────
async function saveSnapshot(tool, payload) {
  if (!payload) return;
  await db.query(
    "INSERT INTO snapshots (tool, payload) VALUES ($1, $2)",
    [tool, JSON.stringify(payload)]
  );
}

async function saveKPI(tool, metric, value) {
  if (value == null) return;
  await db.query(
    "INSERT INTO kpi_history (tool, metric_name, metric_value) VALUES ($1, $2, $3)",
    [tool, metric, value]
  );
}

async function saveAlert(tool, alert) {
  const { alert_id = null, severity, title, resource = null, status = "Open", raw } = alert;
  await db.query(
    `INSERT INTO alerts (tool, alert_id, severity, title, resource, status, raw)
     VALUES ($1,$2,$3,$4,$5,$6,$7)
     ON CONFLICT DO NOTHING`,
    [tool, alert_id, severity, title, resource, status, JSON.stringify(raw)]
  );
}

// ── Main collection cycle (runs every 15 min) ─────────────────────────────────
async function runCollectionCycle() {
  const ts = new Date().toISOString();
  console.log(`[${ts}] Collection cycle started`);

  const results = await Promise.allSettled([
    collectFortinet(),
    collectPaloAlto(),
    collectUpGuard(),
    collectAzure(),
    collectQualys(),
    collectManageEngine(),
  ]);

  const [fg, pa, ug, az, ql, me] = results.map((r) =>
    r.status === "fulfilled" ? r.value : null
  );

  // Save snapshots
  await Promise.allSettled([
    saveSnapshot("fortinet",     fg),
    saveSnapshot("paloalto",     pa),
    saveSnapshot("upguard",      ug),
    saveSnapshot("azure",        az),
    saveSnapshot("qualys",       ql),
    saveSnapshot("manageengine", me),
  ]);

  // Save KPIs for trending
  if (az?.score?.[0]) await saveKPI("azure", "secure_score", az.score[0].properties?.score?.current);
  if (me?.patch)       await saveKPI("manageengine", "patch_compliance", me.patch.pct);
  if (me?.enc)         await saveKPI("manageengine", "encryption_coverage", me.enc.pct);
  if (ug?.score)       await saveKPI("upguard", "risk_score", ug.score);

  // Save Azure alerts
  if (az?.alerts?.length) {
    for (const a of az.alerts.slice(0, 50)) {
      await saveAlert("azure", {
        alert_id: a.name,
        severity: a.properties?.severity ?? "Medium",
        title:    a.properties?.alertDisplayName ?? a.name,
        resource: a.properties?.compromisedEntity,
        raw:      a,
      }).catch(() => {});
    }
  }

  console.log(`[${new Date().toISOString()}] Collection cycle complete`);
}

// ── Daily maintenance ─────────────────────────────────────────────────────────
async function runMaintenance() {
  console.log("[maintenance] Running retention purge…");
  await db.query("SELECT purge_old_data()");
  console.log("[maintenance] Done");
}

// ── Express API ───────────────────────────────────────────────────────────────
const app = express();
app.use(cors());
app.use(express.json());

// GET /api/snapshots/latest  – latest snapshot per tool
app.get("/api/snapshots/latest", async (req, res) => {
  try {
    const { rows } = await db.query("SELECT * FROM latest_snapshots");
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/kpis  – current KPI values (latest snapshot payload per tool)
app.get("/api/kpis", async (req, res) => {
  try {
    const { rows } = await db.query("SELECT * FROM latest_snapshots");
    const kpis = {};
    rows.forEach((r) => { kpis[r.tool] = r.payload; });
    res.json(kpis);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/kpis/trend?tool=azure&metric=secure_score&days=30
app.get("/api/kpis/trend", async (req, res) => {
  const { tool, metric, days = 30 } = req.query;
  try {
    const { rows } = await db.query(
      `SELECT DATE_TRUNC('day', recorded_at) AS day,
              AVG(metric_value)::NUMERIC(8,2) AS avg_value
       FROM kpi_history
       WHERE tool = $1 AND metric_name = $2
         AND recorded_at >= NOW() - ($3 || ' days')::INTERVAL
       GROUP BY day ORDER BY day`,
      [tool, metric, days]
    );
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/alerts?tool=azure&severity=Critical&limit=50
app.get("/api/alerts", async (req, res) => {
  const { tool, severity, status = "Open", limit = 50 } = req.query;
  const conditions = ["status = $1"];
  const params = [status];
  if (tool)     { conditions.push(`tool = $${params.length+1}`);     params.push(tool); }
  if (severity) { conditions.push(`severity = $${params.length+1}`); params.push(severity); }
  try {
    const { rows } = await db.query(
      `SELECT * FROM alerts WHERE ${conditions.join(" AND ")}
       ORDER BY detected_at DESC LIMIT $${params.length+1}`,
      [...params, limit]
    );
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/alerts/summary
app.get("/api/alerts/summary", async (req, res) => {
  try {
    const { rows } = await db.query("SELECT * FROM open_alert_summary");
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/vulnerabilities/aging
app.get("/api/vulnerabilities/aging", async (req, res) => {
  try {
    const { rows } = await db.query("SELECT * FROM vuln_aging");
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/vulnerabilities?severity=Critical&limit=100
app.get("/api/vulnerabilities", async (req, res) => {
  const { severity, status = "Open", limit = 100 } = req.query;
  const params = [status];
  let where = "status = $1";
  if (severity) { params.push(severity); where += ` AND severity = $${params.length}`; }
  try {
    const { rows } = await db.query(
      `SELECT * FROM vulnerabilities WHERE ${where}
       ORDER BY cvss_score DESC NULLS LAST LIMIT $${params.length+1}`,
      [...params, limit]
    );
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/patches/latest
app.get("/api/patches/latest", async (req, res) => {
  try {
    const { rows } = await db.query(
      "SELECT * FROM patch_events ORDER BY deployed_at DESC LIMIT 20"
    );
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/encryption/latest
app.get("/api/encryption/latest", async (req, res) => {
  try {
    const { rows } = await db.query(
      "SELECT * FROM encryption_snapshots ORDER BY recorded_at DESC LIMIT 1"
    );
    res.json(rows[0] ?? {});
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/encryption/trend?days=90
app.get("/api/encryption/trend", async (req, res) => {
  const { days = 90 } = req.query;
  try {
    const { rows } = await db.query(
      `SELECT DATE_TRUNC('day', recorded_at) AS day,
              AVG(coverage_pct)::NUMERIC(5,2) AS avg_pct
       FROM encryption_snapshots
       WHERE recorded_at >= NOW() - ($1 || ' days')::INTERVAL
       GROUP BY day ORDER BY day`,
      [days]
    );
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/maintenance  – trigger retention cycle manually
app.post("/api/maintenance", async (req, res) => {
  try {
    await runMaintenance();
    res.json({ ok: true, message: "Maintenance complete" });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/health
app.get("/api/health", async (req, res) => {
  try {
    await db.query("SELECT 1");
    res.json({ status: "ok", db: "connected", ts: new Date().toISOString() });
  } catch (e) { res.status(500).json({ status: "error", db: e.message }); }
});

// ── Cron schedules ────────────────────────────────────────────────────────────
// Every 15 minutes – collect from all tools
cron.schedule("*/15 * * * *", () => runCollectionCycle().catch(console.error));

// Every day at 02:00 – retention maintenance + next partition creation
cron.schedule("0 2 * * *", () => runMaintenance().catch(console.error));

// ── Start ─────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 4000;
app.listen(PORT, async () => {
  console.log(`[backend] API listening on :${PORT}`);
  // Run an initial collection on startup (after 10s to let DB init)
  setTimeout(() => runCollectionCycle().catch(console.error), 10000);
});
