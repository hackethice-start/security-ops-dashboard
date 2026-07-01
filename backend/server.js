const express    = require("express");
const cors       = require("cors");
const { Pool }   = require("pg");
const cron       = require("node-cron");
const axios      = require("axios");
const https      = require("https");

const app  = express();
const PORT = process.env.PORT || 4000;

app.use(cors());
app.use(express.json());

/* ── DB pool ────────────────────────────────────────────────────────────── */
const pool = new Pool({
  host:     process.env.POSTGRES_HOST     || "db",
  port:     parseInt(process.env.POSTGRES_PORT || "5432"),
  database: process.env.POSTGRES_DB       || "secops",
  user:     process.env.POSTGRES_USER     || "secops",
  password: process.env.POSTGRES_PASSWORD || "changeme",
});

const http = axios.create({
  httpsAgent: new https.Agent({ rejectUnauthorized: false }),
  timeout: 15000,
});

/* ── Helpers ────────────────────────────────────────────────────────────── */
async function getCreds(tool) {
  try {
    const r = await pool.query(
      "SELECT credentials, refresh_interval FROM integrations WHERE tool_name=$1 AND enabled=true",
      [tool]
    );
    if (!r.rows.length) return null;
    const c = r.rows[0].credentials;
    if (!c || Object.keys(c).length === 0) return null;
    return { ...c, refresh_interval: r.rows[0].refresh_interval || 300 };
  } catch { return null; }
}

async function setStatus(tool, status, error=null) {
  try {
    await pool.query(
      `UPDATE integrations SET status=$2, last_tested=NOW(), last_error=$3
       WHERE tool_name=$1`,
      [tool, status, error]
    );
  } catch {}
}

async function saveSnapshot(tool, payload) {
  try {
    await pool.query(
      "INSERT INTO snapshots (tool, payload, collected_at) VALUES ($1,$2,NOW())",
      [tool, JSON.stringify(payload)]
    );
  } catch (e) { console.error("snapshot save error:", e.message); }
}

/* ── Collectors ─────────────────────────────────────────────────────────── */
async function collectFortinet() {
  const c = await getCreds("fortinet");
  if (!c) return null;
  try {
    const base = c.host.replace(/\/$/, "");
    const headers = { Authorization: `Bearer ${c.apikey}` };
    const [mon, pol] = await Promise.all([
      http.get(`${base}/api/v2/monitor/firewall/policy-list`, { headers }),
      http.get(`${base}/api/v2/monitor/fortiview/statistics`, { headers }),
    ]);
    const snap = { source:"fortinet", policies: mon.data?.results||[], stats: pol.data?.results||[] };
    await saveSnapshot("fortinet", snap);
    await setStatus("fortinet", "connected");
    return snap;
  } catch(e) {
    await setStatus("fortinet", "error", e.message);
    return null;
  }
}

async function collectPaloAlto() {
  const c = await getCreds("paloalto");
  if (!c) return null;
  try {
    const base = c.host.replace(/\/$/, "");
    const url = `${base}/restapi/v10.1/Objects/SecurityRules`;
    const r = await http.get(url, { headers: { "X-PAN-KEY": c.apikey } });
    const snap = { source:"paloalto", rules: r.data?.result?.entry||[] };
    await saveSnapshot("paloalto", snap);
    await setStatus("paloalto", "connected");
    return snap;
  } catch(e) {
    await setStatus("paloalto", "error", e.message);
    return null;
  }
}

async function collectUpGuard() {
  const c = await getCreds("upguard");
  if (!c) return null;
  try {
    const headers = { Authorization: `Token token=${c.apikey}` };
    const [risks, domain] = await Promise.all([
      http.get("https://cyber-risk.upguard.com/api/public/v1/risks", { headers }),
      http.get("https://cyber-risk.upguard.com/api/public/v1/domains/risks", { headers }),
    ]);
    const snap = { source:"upguard", risks: risks.data||{}, domain_risks: domain.data||{} };
    await saveSnapshot("upguard", snap);
    await setStatus("upguard", "connected");
    return snap;
  } catch(e) {
    await setStatus("upguard", "error", e.message);
    return null;
  }
}

async function collectAzure() {
  const c = await getCreds("azure");
  if (!c) return null;
  try {
    const tokenRes = await http.post(
      `https://login.microsoftonline.com/${c.tenantId}/oauth2/v2.0/token`,
      new URLSearchParams({
        client_id: c.clientId, client_secret: c.clientSecret,
        grant_type: "client_credentials",
        scope: "https://management.azure.com/.default",
      }),
      { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
    );
    const token = tokenRes.data.access_token;
    const sub = c.subscriptionId;
    const headers = { Authorization: `Bearer ${token}` };
    const [alerts, secure] = await Promise.all([
      http.get(`https://management.azure.com/subscriptions/${sub}/providers/Microsoft.Security/alerts?api-version=2022-01-01`, { headers }),
      http.get(`https://management.azure.com/subscriptions/${sub}/providers/Microsoft.Security/secureScores?api-version=2020-01-01`, { headers }),
    ]);
    const snap = {
      source: "azure",
      alerts: alerts.data?.value || [],
      secureScore: secure.data?.value?.[0]?.properties || {},
    };
    await saveSnapshot("azure", snap);
    await setStatus("azure", "connected");
    return snap;
  } catch(e) {
    await setStatus("azure", "error", e.message);
    return null;
  }
}

async function collectQualys() {
  const c = await getCreds("qualys");
  if (!c) return null;
  try {
    const platform = (c.platform||"https://qualysapi.qualys.com").replace(/\/$/, "");
    const auth = Buffer.from(`${c.username}:${c.password}`).toString("base64");
    const headers = { Authorization: `Basic ${auth}`, "X-Requested-With": "SecOpsDashboard" };
    const r = await http.get(
      `${platform}/api/2.0/fo/asset/host/vm/detection/?action=list&status=New,Active&severities=4,5&truncation_limit=100`,
      { headers }
    );
    const snap = { source:"qualys", detections: r.data };
    await saveSnapshot("qualys", snap);
    await setStatus("qualys", "connected");
    return snap;
  } catch(e) {
    await setStatus("qualys", "error", e.message);
    return null;
  }
}

async function collectManageEngine() {
  const c = await getCreds("manageengine");
  if (!c) return null;
  try {
    const base = c.host.replace(/\/$/, "");
    const headers = { AUTHTOKEN: c.apikey };
    const [assets, patches] = await Promise.all([
      http.get(`${base}/api/1.3/patch/allsystems?restype=json`, { headers }),
      http.get(`${base}/api/1.3/patch/systemdetails?restype=json`, { headers }),
    ]);
    const snap = { source:"manageengine", assets: assets.data, patches: patches.data };
    await saveSnapshot("manageengine", snap);
    await setStatus("manageengine", "connected");
    return snap;
  } catch(e) {
    await setStatus("manageengine", "error", e.message);
    return null;
  }
}

async function collectTaegis() {
  const c = await getCreds("taegis");
  if (!c) return null;
  try {
    const region = c.region || "us1";
    const tokenRes = await http.post(
      `https://api.ctpx.secureworks.com/auth/api/v2/auth/token`,
      { client_id: c.clientId, client_secret: c.clientSecret, grant_type: "client_credentials" },
      { headers: { "Content-Type": "application/json" } }
    );
    const token = tokenRes.data.access_token;
    const gql = `query { alerts(first:50, filter:{status:"OPEN"}) { alerts { id severity status message metadata { created_at } } } }`;
    const r = await http.post(
      `https://api.ctpx.secureworks.com/graphql`,
      { query: gql },
      { headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" } }
    );
    const snap = { source:"taegis", alerts: r.data?.data?.alerts?.alerts || [] };
    await saveSnapshot("taegis", snap);
    await setStatus("taegis", "connected");
    return snap;
  } catch(e) {
    await setStatus("taegis", "error", e.message);
    return null;
  }
}

/* ── Collection runner + dynamic scheduling ──────────────────────────────── */
const cronJobs = {};

async function scheduleCollectors() {
  // Clear existing
  Object.values(cronJobs).forEach(j => j.destroy());
  
  for (const tool of ["fortinet","paloalto","upguard","azure","qualys","manageengine","taegis"]) {
    const row = await pool.query(
      "SELECT refresh_interval FROM integrations WHERE tool_name=$1", [tool]
    ).catch(()=>({rows:[]}));
    const interval = row.rows[0]?.refresh_interval || 300; // seconds
    const minutes  = Math.max(1, Math.round(interval / 60));
    const cronExpr = `*/${minutes} * * * *`;
    
    const collectors = {
      fortinet: collectFortinet, paloalto: collectPaloAlto, upguard: collectUpGuard,
      azure: collectAzure, qualys: collectQualys, manageengine: collectManageEngine, taegis: collectTaegis,
    };
    
    if (cronJobs[tool]) cronJobs[tool].destroy();
    cronJobs[tool] = cron.schedule(cronExpr, async () => {
      console.log(`[${new Date().toISOString()}] Collecting ${tool}...`);
      await collectors[tool]();
    });
    console.log(`Scheduled ${tool}: every ${minutes} min (${interval}s)`);
  }
}

/* ── REST API ────────────────────────────────────────────────────────────── */

// Health
app.get("/api/health", (_, res) => res.json({ status:"ok", ts: new Date() }));

// Get all integration statuses (no secrets)
app.get("/api/integrations", async (_, res) => {
  try {
    const r = await pool.query(
      "SELECT tool_name, enabled, status, last_tested, last_error, refresh_interval, updated_at FROM integrations ORDER BY tool_name"
    );
    res.json(r.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Save credentials
app.post("/api/integrations/:tool", async (req, res) => {
  const { tool } = req.params;
  const { credentials, refresh_interval } = req.body;
  try {
    await pool.query(
      `INSERT INTO integrations (tool_name, credentials, refresh_interval, status, updated_at)
       VALUES ($1,$2,$3,'configured',NOW())
       ON CONFLICT (tool_name) DO UPDATE
       SET credentials=$2, refresh_interval=$3, status='configured', updated_at=NOW()`,
      [tool, JSON.stringify(credentials||{}), refresh_interval||300]
    );
    // Reschedule collectors to pick up new interval
    scheduleCollectors().catch(console.error);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Test connection
app.post("/api/integrations/:tool/test", async (req, res) => {
  const { tool } = req.params;
  const collectors = {
    fortinet: collectFortinet, paloalto: collectPaloAlto, upguard: collectUpGuard,
    azure: collectAzure, qualys: collectQualys, manageengine: collectManageEngine, taegis: collectTaegis,
  };
  if (!collectors[tool]) return res.status(404).json({ error: "Unknown tool" });
  try {
    const result = await collectors[tool]();
    if (result) {
      res.json({ success: true, message: "Connection successful" });
    } else {
      const row = await pool.query("SELECT last_error FROM integrations WHERE tool_name=$1", [tool]);
      res.json({ success: false, error: row.rows[0]?.last_error || "No credentials configured" });
    }
  } catch(e) { res.json({ success: false, error: e.message }); }
});

// Delete credentials
app.delete("/api/integrations/:tool", async (req, res) => {
  try {
    await pool.query(
      "UPDATE integrations SET credentials='{}', status='unconfigured', last_error=NULL WHERE tool_name=$1",
      [req.params.tool]
    );
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Latest snapshot per tool (optionally filtered by date range)
app.get("/api/snapshot", async (req, res) => {
  const { from, to } = req.query;
  try {
    let query, params;
    if (from || to) {
      query = `SELECT DISTINCT ON (tool) tool, payload, collected_at
               FROM snapshots WHERE 1=1
               ${from ? "AND collected_at >= $1" : ""} ${to ? `AND collected_at <= $${from?2:1}` : ""}
               ORDER BY tool, collected_at DESC`;
      params = [from, to].filter(Boolean);
    } else {
      query = `SELECT DISTINCT ON (tool) tool, payload, collected_at
               FROM snapshots ORDER BY tool, collected_at DESC`;
      params = [];
    }
    const r = await pool.query(query, params);
    const snap = {};
    r.rows.forEach(row => { snap[row.tool] = { ...row.payload, _collected_at: row.collected_at }; });
    res.json({ data: snap, ts: new Date(), range: { from, to } });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Historical snapshots for a tool
app.get("/api/snapshots/:tool", async (req, res) => {
  const { tool } = req.params;
  const { from, to, limit=100 } = req.query;
  try {
    const r = await pool.query(
      `SELECT id, tool, collected_at, payload FROM snapshots
       WHERE tool=$1 ${from?"AND collected_at>=$2":""} ${to?`AND collected_at<=$${from?3:2}`:""}
       ORDER BY collected_at DESC LIMIT $${from&&to?4:from||to?3:2}`,
      [tool, ...[from, to].filter(Boolean), parseInt(limit)]
    );
    res.json(r.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// KPI trend data
app.get("/api/kpis", async (req, res) => {
  const { days=30 } = req.query;
  try {
    const r = await pool.query(
      `SELECT DATE_TRUNC('day', collected_at) as day, tool, COUNT(*) as count
       FROM snapshots WHERE collected_at >= NOW() - INTERVAL '${parseInt(days)} days'
       GROUP BY 1,2 ORDER BY 1`,
    );
    res.json(r.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Manual collection trigger
app.post("/api/collect", async (_, res) => {
  res.json({ ok: true, message: "Collection triggered" });
  Promise.all([
    collectFortinet(), collectPaloAlto(), collectUpGuard(),
    collectAzure(), collectQualys(), collectManageEngine(), collectTaegis()
  ]).then(results => {
    console.log("Manual collection complete:", results.map(r=>r?.source||"skipped"));
  });
});

/* ── Start ───────────────────────────────────────────────────────────────── */
app.listen(PORT, async () => {
  console.log(`SecOps backend running on :${PORT}`);
  // Wait for DB to be ready
  let retries = 10;
  while (retries > 0) {
    try {
      await pool.query("SELECT 1");
      console.log("DB connected");
      break;
    } catch {
      retries--;
      console.log(`DB not ready, retrying... (${retries} left)`);
      await new Promise(r => setTimeout(r, 3000));
    }
  }
  // Schedule collectors based on per-tool intervals
  await scheduleCollectors();
});
