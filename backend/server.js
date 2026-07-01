const express    = require("express");
const cors       = require("cors");
const { Pool }   = require("pg");
const cron       = require("node-cron");
const axios      = require("axios");
const https      = require("https");
const bcrypt     = require("bcryptjs");
const jwt        = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

const JWT_SECRET  = process.env.JWT_SECRET || "secops-jwt-secret-change-in-prod";
const JWT_EXPIRES = "10h";

const app  = express();
const PORT = process.env.PORT || 4000;

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());

/* ── Auth helpers ───────────────────────────────────────────────────────── */
function requireAuth(req, res, next) {
  const token = req.cookies?.session || req.headers.authorization?.replace("Bearer ", "");
  if (!token) return res.status(401).json({ error: "Authentication required" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.clearCookie("session");
    res.status(401).json({ error: "Session expired — please log in again" });
  }
}

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
/* ── Timeout wrapper ─────────────────────────────────────────────────── */
function withTimeout(promise, ms, label) {
  return Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error(`${label} timed out after ${ms/1000}s`)), ms)
    ),
  ]);
}

/* ── Simple Qualys XML parser ──────────────────────────────────────────── */
function parseQualysXML(xml) {
  if (typeof xml !== "string") return [];
  const detections = [];
  const hostRe = /<HOST>([\s\S]*?)<\/HOST>/g;
  let hostMatch;
  while ((hostMatch = hostRe.exec(xml)) !== null) {
    const hostBlock = hostMatch[1];
    const ip  = (hostBlock.match(/<IP>(.*?)<\/IP>/)    ||[])[1] || "Unknown";
    const dns = (hostBlock.match(/<DNS>(.*?)<\/DNS>/)  ||[])[1] || ip;
    const detRe = /<DETECTION>([\s\S]*?)<\/DETECTION>/g;
    let detMatch;
    while ((detMatch = detRe.exec(hostBlock)) !== null) {
      const d = detMatch[1];
      const get = tag => (d.match(new RegExp(`<${tag}>(.*?)<\/${tag}>`)) ||[])[1] || "";
      const sev = parseInt(get("SEVERITY")) || 0;
      detections.push({
        host:     dns,
        ip:       ip,
        qid:      get("QID"),
        severity: sev >= 5 ? "Critical" : sev === 4 ? "High" : sev === 3 ? "Medium" : "Low",
        type:     get("TYPE"),
        status:   get("STATUS"),
        port:     get("PORT") || "—",
        title:    get("RESULTS") ? get("RESULTS").slice(0,80) : `QID ${get("QID")}`,
        lastFound:get("LAST_FOUND_DATETIME") || "",
        cve:      (d.match(/<CVE_ID>(.*?)<\/CVE_ID>/) ||[])[1] || "",
      });
    }
  }
  return detections;
}

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
  } catch(e) {
    console.error(`[setStatus] Failed to update ${tool} → ${status}:`, e.message);
  }
}

async function saveSnapshot(tool, payload) {
  try {
    await pool.query(
      "INSERT INTO snapshots (tool, payload, collected_at) VALUES ($1,$2,NOW())",
      [tool, JSON.stringify(payload)]
    );
    console.log(`[snapshot] Saved ${tool} (${JSON.stringify(payload).length} bytes)`);
  } catch (e) {
    console.error(`[snapshot] FAILED to save ${tool}:`, e.message);
    // If partition missing, create it and retry once
    if (e.message && e.message.includes("no partition")) {
      console.log(`[snapshot] Attempting to create missing partition for ${tool}...`);
      await ensurePartitions().catch(() => {});
      try {
        await pool.query(
          "INSERT INTO snapshots (tool, payload, collected_at) VALUES ($1,$2,NOW())",
          [tool, JSON.stringify(payload)]
        );
        console.log(`[snapshot] Retry succeeded for ${tool}`);
      } catch(e2) {
        console.error(`[snapshot] Retry also failed for ${tool}:`, e2.message);
      }
    }
  }
}

/* ── Collectors ─────────────────────────────────────────────────────────── */
async function collectFortinetInstance(inst) {
  const base = (inst.host||"").replace(/\/$/, "");
  if (!base) throw new Error("No host configured");
  // FortiGate API key goes in Authorization header as "Bearer <key>"
  // For username/password auth, FortiGate also accepts login session
  const headers = inst.apikey
    ? { Authorization: `Bearer ${inst.apikey}` }
    : { Authorization: `Bearer ${inst.password}` };   // some versions use password field
  // Correct FortiOS REST API v2 endpoints:
  //   /api/v2/cmdb/firewall/policy  — firewall policy list (CMDB config)
  //   /api/v2/monitor/firewall/policy — live stats per policy
  const [cmdbPolicies, monPolicies] = await Promise.all([
    http.get(`${base}/api/v2/cmdb/firewall/policy`, { headers })
      .catch(() => ({ data: {} })),
    http.get(`${base}/api/v2/monitor/firewall/policy`, { headers, params: { policyid: 0 } })
      .catch(() => ({ data: {} })),
  ]);
  const policies = cmdbPolicies.data?.results || cmdbPolicies.data?.result || [];
  const stats    = monPolicies.data?.results  || monPolicies.data?.result  || [];
  return { source:"fortinet", instance: inst.name||base, policies, stats };
}

async function collectFortinet() {
  const c = await getCreds("fortinet");
  if (!c) return null;
  try {
    // Support multi-instance: credentials.instances[]
    const instances = c.instances || [c];
    const results = [];
    for (const inst of instances) {
      try {
        const snap = await collectFortinetInstance(inst);
        await saveSnapshot("fortinet", snap);
        results.push(snap);
      } catch(e) { console.error(`Fortinet instance ${inst.name||inst.host} error:`, e.message); }
    }
    await setStatus("fortinet", results.length > 0 ? "connected" : "error",
      results.length === 0 ? "All instances failed" : null);
    return results;
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
    const headers = { "X-PAN-KEY": c.apikey };
    // PAN-OS REST API requires location + vsys params
    // Try REST API first, fall back to XML API which is more universally supported
    let rules = [];
    try {
      const rest = await http.get(`${base}/restapi/v10.1/Policies/SecurityRules`, {
        headers,
        params: { location: "vsys", vsys: "vsys1" },
      });
      rules = rest.data?.result?.entry || [];
    } catch {
      // Fall back to PAN-OS XML API (works on all versions)
      const xml = await http.get(`${base}/api/`, {
        headers,
        params: {
          type: "config",
          action: "get",
          xpath: "/config/devices/entry/vsys/entry[@name='vsys1']/rulebase/security/rules",
          key: c.apikey,
        },
      });
      // Parse entry list from XML response — axios returns string for XML
      const body = typeof xml.data === "string" ? xml.data : JSON.stringify(xml.data);
      const names = [...body.matchAll(/entry name="([^"]+)"/g)].map(m => ({ "@name": m[1] }));
      rules = names;
    }
    const snap = { source:"paloalto", rules };
    await saveSnapshot("paloalto", snap);
    await setStatus("paloalto", "connected");
    return snap;
  } catch(e) {
    const msg = e.response
      ? `HTTP ${e.response.status} from PAN-OS API`
      : e.message;
    await setStatus("paloalto", "error", msg);
    return null;
  }
}

async function collectUpGuard() {
  const c = await getCreds("upguard");
  if (!c) return null;
  try {
    // Auth: pass API key directly in Authorization header (no "Token token=" prefix)
    // Endpoint: /api/public/risks (no v1 in path)
    const headers = { Authorization: c.apikey };
    const base = "https://cyber-risk.upguard.com/api/public";
    const [risksRes, scoreRes] = await Promise.all([
      http.get(`${base}/risks`, { headers }),
      http.get(`${base}/breachsight`, { headers }).catch(() => ({ data: {} })),
    ]);
    const snap = {
      source: "upguard",
      risks: risksRes.data || {},
      breachsight: scoreRes.data || {},
    };
    await saveSnapshot("upguard", snap);
    await setStatus("upguard", "connected");
    return snap;
  } catch(e) {
    const msg = e.response
      ? e.response.status === 401 ? "HTTP 401 — invalid API key"
      : e.response.status === 403 ? "HTTP 403 — API key lacks required permissions"
      : e.response.status === 404 ? "HTTP 404 — endpoint not found (check API key permissions)"
      : `HTTP ${e.response.status} from UpGuard API`
      : e.message;
    await setStatus("upguard", "error", msg);
    return null;
  }
}

async function collectAzureInstance(inst) {
  const tokenRes = await http.post(
    `https://login.microsoftonline.com/${inst.tenantId}/oauth2/v2.0/token`,
    new URLSearchParams({
      client_id: inst.clientId, client_secret: inst.clientSecret,
      grant_type: "client_credentials",
      scope: "https://management.azure.com/.default",
    }),
    { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
  );
  const token = tokenRes.data.access_token;
  const sub = inst.subscriptionId;
  const headers = { Authorization: `Bearer ${token}` };
  const [alerts, secure] = await Promise.all([
    http.get(`https://management.azure.com/subscriptions/${sub}/providers/Microsoft.Security/alerts?api-version=2022-01-01`, { headers }),
    http.get(`https://management.azure.com/subscriptions/${sub}/providers/Microsoft.Security/secureScores?api-version=2020-01-01`, { headers }),
  ]);
  return {
    source: "azure", instance: inst.name||inst.subscriptionId,
    alerts: alerts.data?.value || [],
    secureScore: secure.data?.value?.[0]?.properties || {},
  };
}

async function collectAzure() {
  const c = await getCreds("azure");
  if (!c) return null;
  try {
    const instances = c.instances || [c];
    const results = [];
    for (const inst of instances) {
      try {
        const snap = await collectAzureInstance(inst);
        await saveSnapshot("azure", snap);
        results.push(snap);
      } catch(e) { console.error(`Azure instance ${inst.name} error:`, e.message); }
    }
    await setStatus("azure", results.length > 0 ? "connected" : "error",
      results.length === 0 ? "All instances failed" : null);
    return results;
  } catch(e) {
    await setStatus("azure", "error", e.message);
    return null;
  }
}

async function collectQualys() {
  const c = await getCreds("qualys");
  if (!c) return null;
  try {
    // Normalise platform URL: accept both qualysguard.* (web UI) and qualysapi.* (API)
    let platform = (c.platform||"https://qualysapi.qualys.com").replace(/\/$/, "");
    platform = platform.replace(/\/\/qualysguard\./, "//qualysapi.");
    if (!/^https?:\/\//.test(platform)) platform = "https://" + platform;
    const auth = Buffer.from(`${c.username}:${c.password}`).toString("base64");
    const headers = { Authorization: `Basic ${auth}`, "X-Requested-With": "SecOpsDashboard" };
    // Single request with extended timeout — Qualys API can be slow
    const qualysHttp = axios.create({
      httpsAgent: new https.Agent({ rejectUnauthorized: false }),
      timeout: 55000,
    });
    const r = await qualysHttp.get(
      `${platform}/api/2.0/fo/asset/host/vm/detection/?action=list&status=New,Active&severities=4,5&truncation_limit=20`,
      { headers }
    );
    const parsed = parseQualysXML(r.data);
    const snap = { source:"qualys", detections: parsed, raw_count: parsed.length };
    await saveSnapshot("qualys", snap);
    await setStatus("qualys", "connected");
    return snap;
  } catch(e) {
    const msg = e.response
      ? `HTTP ${e.response.status} from Qualys API — check platform URL and credentials`
      : e.message;
    await setStatus("qualys", "error", msg);
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

/* ── Ensure users table + seed defaults ─────────────────────────────────── */
async function ensureUsersTable() {
  try {
    // Create table if it doesn't exist (safe to run every startup)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id            UUID        DEFAULT gen_random_uuid() PRIMARY KEY,
        username      VARCHAR(50) UNIQUE NOT NULL,
        password_hash TEXT        NOT NULL,
        role          VARCHAR(20) NOT NULL DEFAULT 'analyst'
                      CHECK (role IN ('admin','analyst','executive')),
        display_name  VARCHAR(100),
        created_at    TIMESTAMPTZ DEFAULT NOW(),
        last_login    TIMESTAMPTZ
      )
    `);

    // Seed default users if they don't exist
    // Passwords: Admin@1234, Analyst@1234, Exec@1234  (bcrypt rounds=10)
    const defaults = [
      ["admin",     "$2b$10$xPVS0SLFABqopxeLLo/Da.uIgFP02UBeJY9j5oSjFfXpvemibFHdG", "admin",     "Administrator"],
      ["analyst",   "$2b$10$BO0KL.LZ2VHVyVlcvcWkA.6Gs7mqAudfQ1Jf7SNwf5xM/7MN3QFtu", "analyst",   "Security Analyst"],
      ["executive", "$2b$10$WYLNd9d7FJmd/sKq4VMyGeUDzzeLSrJgUkfcrj3.7d7d235i4ezOO", "executive", "Executive"],
    ];
    for (const [username, hash, role, display_name] of defaults) {
      await pool.query(
        `INSERT INTO users (username, password_hash, role, display_name)
         VALUES ($1,$2,$3,$4) ON CONFLICT (username) DO NOTHING`,
        [username, hash, role, display_name]
      );
    }
    console.log("Users table ready — default users seeded (admin/analyst/executive)");
  } catch(e) {
    console.error("ensureUsersTable error:", e.message);
  }
}

/* ── Ensure snapshot partitions exist for current + next 13 months ─────────── */
async function ensurePartitions() {
  try {
    const result = await pool.query(`
      DO $$
      DECLARE
          cur_month  DATE := DATE_TRUNC('month', NOW());
          end_month  DATE := DATE_TRUNC('month', NOW()) + INTERVAL '13 months';
          next_month DATE;
          part_name  TEXT;
      BEGIN
          LOOP
              next_month := cur_month + INTERVAL '1 month';
              part_name  := 'snapshots_' || TO_CHAR(cur_month, 'YYYY_MM');
              IF NOT EXISTS (SELECT FROM pg_tables WHERE tablename = part_name) THEN
                  EXECUTE FORMAT(
                      'CREATE TABLE %I PARTITION OF snapshots FOR VALUES FROM (%L) TO (%L)',
                      part_name, cur_month, next_month
                  );
                  RAISE NOTICE 'Created partition: %', part_name;
              END IF;
              cur_month := next_month;
              EXIT WHEN cur_month >= end_month;
          END LOOP;
      END $$;
    `);
    console.log("Snapshot partitions verified/created for current + next 13 months");
  } catch(e) {
    console.error("ensurePartitions error:", e.message);
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

/* ── Auth routes ─────────────────────────────────────────────────────────── */
app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password)
    return res.status(400).json({ error: "Username and password required" });
  try {
    const r = await pool.query(
      "SELECT id, username, password_hash, role, display_name FROM users WHERE username=$1",
      [username.toLowerCase().trim()]
    );
    const u = r.rows[0];
    if (!u) return res.status(401).json({ error: "Invalid username or password" });
    const valid = await bcrypt.compare(password, u.password_hash);
    if (!valid) return res.status(401).json({ error: "Invalid username or password" });
    // Update last_login
    pool.query("UPDATE users SET last_login=NOW() WHERE id=$1", [u.id]).catch(() => {});
    const token = jwt.sign(
      { id: u.id, username: u.username, role: u.role, display_name: u.display_name },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES }
    );
    res.cookie("session", token, {
      httpOnly: true,
      sameSite: "lax",
      maxAge: 10 * 60 * 60 * 1000, // 10h
      path: "/",
    });
    res.json({ username: u.username, role: u.role, display_name: u.display_name });
  } catch(e) {
    console.error("Login error:", e.message);
    res.status(500).json({ error: "Login failed" });
  }
});

app.get("/api/auth/me", requireAuth, (req, res) => {
  res.json({ username: req.user.username, role: req.user.role, display_name: req.user.display_name });
});

app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("session", { path: "/" });
  res.json({ ok: true });
});

// Change own password
app.post("/api/auth/change-password", requireAuth, async (req, res) => {
  const { current_password, new_password } = req.body || {};
  if (!current_password || !new_password)
    return res.status(400).json({ error: "Both current and new password required" });
  if (new_password.length < 8)
    return res.status(400).json({ error: "New password must be at least 8 characters" });
  try {
    const r = await pool.query("SELECT password_hash FROM users WHERE id=$1", [req.user.id]);
    if (!r.rows.length) return res.status(404).json({ error: "User not found" });
    const valid = await bcrypt.compare(current_password, r.rows[0].password_hash);
    if (!valid) return res.status(401).json({ error: "Current password incorrect" });
    const hash = await bcrypt.hash(new_password, 10);
    await pool.query("UPDATE users SET password_hash=$1 WHERE id=$2", [hash, req.user.id]);
    res.json({ ok: true });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// List users (admin only)
app.get("/api/auth/users", requireAuth, async (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Admin only" });
  const r = await pool.query(
    "SELECT id, username, role, display_name, created_at, last_login FROM users ORDER BY username"
  );
  res.json(r.rows);
});

// Create user (admin only)
app.post("/api/auth/users", requireAuth, async (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Admin only" });
  const { username, password, role, display_name } = req.body || {};
  if (!username || !password || !role) return res.status(400).json({ error: "username, password, role required" });
  if (!["admin","analyst","executive"].includes(role)) return res.status(400).json({ error: "Invalid role" });
  if (password.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters" });
  try {
    const hash = await bcrypt.hash(password, 10);
    const r = await pool.query(
      "INSERT INTO users (username, password_hash, role, display_name) VALUES ($1,$2,$3,$4) RETURNING id, username, role, display_name",
      [username.toLowerCase().trim(), hash, role, display_name || username]
    );
    res.json(r.rows[0]);
  } catch(e) {
    if (e.code === "23505") return res.status(409).json({ error: "Username already exists" });
    res.status(500).json({ error: e.message });
  }
});

// Delete user (admin only)
app.delete("/api/auth/users/:id", requireAuth, async (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Admin only" });
  if (req.params.id === req.user.id) return res.status(400).json({ error: "Cannot delete your own account" });
  await pool.query("DELETE FROM users WHERE id=$1", [req.params.id]);
  res.json({ ok: true });
});

// Get all integration statuses — returns safe display info only (no secrets)
app.get("/api/integrations", requireAuth, async (req, res) => {
  try {
    const r = await pool.query(
      "SELECT tool_name, enabled, status, last_tested, last_error, refresh_interval, updated_at, credentials FROM integrations ORDER BY tool_name"
    );
    // Non-secret fields safe to return for form pre-population
    const SAFE_FIELDS = {
      fortinet:     ["name","host"],
      paloalto:     ["host"],
      upguard:      [],
      azure:        ["name","tenantId","subscriptionId","clientId"],
      qualys:       ["platform","username"],
      manageengine: ["host"],
      taegis:       ["clientId","region"],
    };
    const rows = r.rows.map(row => {
      const creds = row.credentials || {};
      const rawInstances = Array.isArray(creds.instances) ? creds.instances : null;
      const safeFields = SAFE_FIELDS[row.tool_name] || [];
      const safe_credentials = {};
      safeFields.forEach(f => { if (creds[f]) safe_credentials[f] = creds[f]; });
      return {
        tool_name:        row.tool_name,
        enabled:          row.enabled,
        status:           row.status,
        last_tested:      row.last_tested,
        last_error:       row.last_error,
        refresh_interval: row.refresh_interval,
        updated_at:       row.updated_at,
        safe_credentials,   // non-secret fields for form pre-population
        instance_count:   rawInstances ? rawInstances.length : 0,
        instances: rawInstances
          ? rawInstances.map(inst => ({
              name: inst.name || "",
              host: inst.host || inst.tenantId || inst.subscriptionId || "",
              // safe fields for multi-instance edit
              tenantId: inst.tenantId || "",
              subscriptionId: inst.subscriptionId || "",
              clientId: inst.clientId || "",
              region: inst.region || "",
            }))
          : null,
      };
    });
    res.json(rows);
  } catch(e) {
    console.error("GET /api/integrations error:", e.message);
    res.status(500).json({ error: e.message });
  }
});

// Save credentials
// Secret credential fields per tool — never returned in GET responses
const SECRET_FIELDS = {
  fortinet:     ["password"],
  paloalto:     ["password"],
  upguard:      ["apikey"],
  azure:        ["clientSecret"],
  qualys:       ["password"],
  manageengine: ["password"],
  taegis:       ["clientSecret"],
};

app.post("/api/integrations/:tool", requireAuth, async (req, res) => {
  const { tool } = req.params;
  const { credentials, refresh_interval } = req.body;
  try {
    // Merge: keep existing secrets if new value is blank/missing
    let mergedCreds = credentials || {};
    const secretFields = SECRET_FIELDS[tool] || [];
    if (secretFields.length > 0) {
      const existing = await pool.query(
        "SELECT credentials FROM integrations WHERE tool_name=$1", [tool]
      );
      if (existing.rows.length > 0) {
        const existingCreds = existing.rows[0].credentials || {};
        secretFields.forEach(f => {
          if (!mergedCreds[f] || mergedCreds[f] === "") {
            if (existingCreds[f]) mergedCreds[f] = existingCreds[f];
          }
        });
        // Also merge instance-level secrets for multi-instance tools
        if (Array.isArray(mergedCreds.instances) && Array.isArray(existingCreds.instances)) {
          mergedCreds.instances = mergedCreds.instances.map((inst, i) => {
            const existInst = existingCreds.instances[i] || {};
            secretFields.forEach(f => {
              if (!inst[f] || inst[f] === "") {
                if (existInst[f]) inst[f] = existInst[f];
              }
            });
            return inst;
          });
        }
      }
    }
    await pool.query(
      `INSERT INTO integrations (tool_name, credentials, refresh_interval, status, updated_at)
       VALUES ($1,$2,$3,'configured',NOW())
       ON CONFLICT (tool_name) DO UPDATE
       SET credentials=$2, refresh_interval=$3, status='configured', updated_at=NOW()`,
      [tool, JSON.stringify(mergedCreds), refresh_interval||300]
    );
    // Reschedule collectors to pick up new interval
    scheduleCollectors().catch(console.error);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Test connection (returns sample data for preview)
app.post("/api/integrations/:tool/test", requireAuth, async (req, res) => {
  const { tool } = req.params;
  const { instance } = req.query; // optional instance index for multi-instance tools
  const instanceIdx = instance !== undefined ? parseInt(instance) : null;

  // Hard 20s timeout — prevents NGINX connection reset on slow external APIs
  const TIMEOUT = tool === 'qualys' ? 60000 : 20000; // Qualys API is slow

  try {
    const c = await withTimeout(getCreds(tool), 5000, "DB lookup");
    if (!c) return res.json({ success: false, error: "No credentials configured" });

    // For multi-instance tools, test a specific instance if requested
    let result = null;
    let sample = null;

    if (tool === "fortinet") {
      const inst = instanceIdx !== null ? (c.instances||[c])[instanceIdx] : (c.instances||[c])[0];
      if (!inst) return res.json({ success: false, error: "Instance not found" });
      try {
        result = await withTimeout(collectFortinetInstance(inst), TIMEOUT, "Fortinet");
        sample = { instance: inst.name, policies: result.policies?.length||0, message: "FortiGate API reachable" };
        await setStatus("fortinet", "connected");
      } catch(e) { return res.json({ success: false, error: e.message }); }

    } else if (tool === "azure") {
      const inst = instanceIdx !== null ? (c.instances||[c])[instanceIdx] : (c.instances||[c])[0];
      if (!inst) return res.json({ success: false, error: "Instance not found" });
      try {
        result = await withTimeout(collectAzureInstance(inst), TIMEOUT, "Azure");
        sample = { instance: inst.name, alerts: result.alerts?.length||0, secureScore: result.secureScore?.score||"N/A" };
        await setStatus("azure", "connected");
      } catch(e) { return res.json({ success: false, error: e.message }); }

    } else if (tool === "paloalto") {
      result = await withTimeout(collectPaloAlto(), TIMEOUT, "Palo Alto");
      if (result) sample = { rules: result.rules?.length||0, message: "PAN-OS API reachable" };

    } else if (tool === "upguard") {
      result = await withTimeout(collectUpGuard(), TIMEOUT, "UpGuard");
      if (result) {
        const risksArr = Array.isArray(result.risks?.risks) ? result.risks.risks : [];
        const score = result.breachsight?.score || result.risks?.score || "N/A";
        sample = {
          score,
          risks_found: risksArr.length,
          message: "UpGuard API reachable"
        };
      }

    } else if (tool === "qualys") {
      result = await withTimeout(collectQualys(), TIMEOUT, "Qualys");
      if (result) sample = { detections: typeof result.detections === "string" ? "XML data received" : result.detections?.length||0, message: "Qualys API reachable" };

    } else if (tool === "manageengine") {
      result = await withTimeout(collectManageEngine(), TIMEOUT, "ManageEngine");
      if (result) sample = { assets: result.assets?.total_count||"connected", message: "ManageEngine API reachable" };

    } else if (tool === "taegis") {
      result = await withTimeout(collectTaegis(), TIMEOUT, "Taegis");
      if (result) sample = { alerts: result.alerts?.length||0, message: "Taegis API reachable" };

    } else {
      return res.status(404).json({ error: "Unknown tool" });
    }

    if (result !== null) {
      res.json({ success: true, message: "Connection successful", sample });
    } else {
      const row = await pool.query("SELECT last_error FROM integrations WHERE tool_name=$1", [tool]);
      res.json({ success: false, error: row.rows[0]?.last_error || "Connection failed" });
    }
  } catch(e) {
    const msg = e.response
      ? `HTTP ${e.response.status}: ${e.response.data?.message || e.response.statusText || "API error"}`
      : e.message;
    res.json({ success: false, error: msg });
  }
});

// Delete credentials
app.delete("/api/integrations/:tool", requireAuth, async (req, res) => {
  try {
    await pool.query(
      "UPDATE integrations SET credentials='{}', status='unconfigured', last_error=NULL WHERE tool_name=$1",
      [req.params.tool]
    );
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Latest snapshot per tool (optionally filtered by date range)
app.get("/api/snapshot", requireAuth, async (req, res) => {
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
app.get("/api/snapshots/:tool", requireAuth, async (req, res) => {
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
app.get("/api/kpis", requireAuth, async (req, res) => {
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

// Collect a single tool on demand
app.post("/api/collect/:tool", requireAuth, async (req, res) => {
  const { tool } = req.params;
  const collectors = {
    fortinet: collectFortinet, paloalto: collectPaloAlto, upguard: collectUpGuard,
    azure: collectAzure, qualys: collectQualys, manageengine: collectManageEngine, taegis: collectTaegis,
  };
  const fn = collectors[tool];
  if (!fn) return res.status(404).json({ error: "Unknown tool" });
  res.json({ ok: true, message: `Collection started for ${tool}` });
  fn().catch(e => console.error(`Manual collect ${tool}:`, e.message));
});

// Manual collection trigger
app.post("/api/collect", requireAuth, async (req, res) => {
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
  // Create users table + seed defaults (safe to run on every startup)
  await ensureUsersTable();
  // Ensure snapshot partitions exist (handles old DBs missing current month)
  await ensurePartitions();
  // Schedule collectors based on per-tool intervals
  await scheduleCollectors();
});
