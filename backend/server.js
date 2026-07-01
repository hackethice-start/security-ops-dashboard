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
    const ip  = (hostBlock.match(/<IP>(.*?)<\/IP>/)                    ||[])[1]?.trim() || "Unknown";
    // Qualys VMDR uses <DNS_DATA><HOSTNAME> or <DNS> depending on API version
    const dns = (hostBlock.match(/<HOSTNAME>(.*?)<\/HOSTNAME>/)         ||
                 hostBlock.match(/<DNS>(.*?)<\/DNS>/)                   ||
                 hostBlock.match(/<NETBIOS>(.*?)<\/NETBIOS>/)           ||[])[1]?.trim() || ip;
    const detRe = /<DETECTION>([\s\S]*?)<\/DETECTION>/g;
    let detMatch;
    while ((detMatch = detRe.exec(hostBlock)) !== null) {
      const d = detMatch[1];
      // get() strips nested tags so <RESULTS><![CDATA[...]]></RESULTS> works too
      const get = tag => {
        const m = d.match(new RegExp(`<${tag}(?:[^>]*)>([\s\S]*?)<\/${tag}>`));
        return m ? m[1].replace(/<!\[CDATA\[|\]\]>/g,"").replace(/<[^>]+>/g,"").trim() : "";
      };
      const sev = parseInt(get("SEVERITY")) || 0;
      const qid = get("QID");
      const results = get("RESULTS");
      const title   = get("QID_TITLE") || (results ? results.slice(0,100) : `QID ${qid}`);
      const cveM    = d.match(/<CVE[^>]*>[\s\S]*?<ID>(.*?)<\/ID>/) ||
                      d.match(/<CVE_ID>(.*?)<\/CVE_ID>/);
      detections.push({
        host:      dns,
        ip,
        qid,
        severity:  sev >= 5 ? "Critical" : sev === 4 ? "High" : sev === 3 ? "Medium" : sev === 2 ? "Low" : "Info",
        type:      get("TYPE"),
        status:    get("STATUS") || "Active",
        port:      get("PORT") || "—",
        protocol:  get("PROTOCOL") || "",
        title,
        lastFound: get("LAST_FOUND_DATETIME") || get("LAST_UPDATE_DATETIME") || "",
        firstFound:get("FIRST_FOUND_DATETIME") || "",
        cve:       cveM ? cveM[1].trim() : "",
        ssl:       get("SSL") === "1",
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
  const headers = inst.apikey
    ? { Authorization: `Bearer ${inst.apikey}` }
    : { Authorization: `Bearer ${inst.password}` };

  const [cmdbPolicies, monPolicies, interfaces, sysInfo, addrGroups] = await Promise.all([
    // CMDB: full policy config (name, action, srcaddr, dstaddr, service, logtraffic, status)
    http.get(`${base}/api/v2/cmdb/firewall/policy`, { headers })
      .catch(() => ({ data: {} })),
    // Monitor: per-policy live hit/byte/packet counters
    http.get(`${base}/api/v2/monitor/firewall/policy`, { headers, params: { policyid: 0 } })
      .catch(() => ({ data: {} })),
    // Monitor: interface bandwidth (in_bps, out_bps, rx_bytes, tx_bytes)
    http.get(`${base}/api/v2/monitor/system/interface`, { headers })
      .catch(() => ({ data: {} })),
    // CMDB: system global settings (hostname, version, management access)
    http.get(`${base}/api/v2/cmdb/system/global`, { headers })
      .catch(() => ({ data: {} })),
    // CMDB: firewall address groups (for CIS check on any/all rules)
    http.get(`${base}/api/v2/cmdb/firewall/addrgrp`, { headers })
      .catch(() => ({ data: {} })),
  ]);

  const policies   = cmdbPolicies.data?.results || cmdbPolicies.data?.result || [];
  const stats      = monPolicies.data?.results  || monPolicies.data?.result  || [];
  const ifaces     = interfaces.data?.results   || interfaces.data?.result   || [];
  const sysGlobal  = sysInfo.data?.results?.[0] || sysInfo.data?.result?.[0] || {};
  const addrgrps   = addrGroups.data?.results   || addrGroups.data?.result   || [];

  return {
    source: "fortinet",
    vendor: "fortinet",
    instance: inst.name || base,
    host: base,
    policies,
    stats,
    interfaces: ifaces,
    sysGlobal,
    addrgrps,
    collectedAt: new Date().toISOString(),
  };
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
        results.push(snap);
      } catch(e) { console.error(`Fortinet instance ${inst.name||inst.host} error:`, e.message); }
    }
    // Save ALL instances together so multi-instance snapshots don't overwrite each other
    if (results.length > 0) {
      await saveSnapshot("fortinet", { source:"fortinet", instances: results });
      await setStatus("fortinet", "connected");
    } else {
      await setStatus("fortinet", "error", "All instances failed to connect");
    }
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
    let interfaces = [];
    let sysInfo = {};
    try {
      const [rulesRes, intfRes] = await Promise.all([
        http.get(`${base}/restapi/v10.1/Policies/SecurityRules`, {
          headers, params: { location: "vsys", vsys: "vsys1" },
        }).catch(() => null),
        http.get(`${base}/restapi/v10.1/Network/EthernetInterfaces`, {
          headers, params: { location: "vsys", vsys: "vsys1" },
        }).catch(() => null),
      ]);
      rules = rulesRes?.data?.result?.entry || [];
      interfaces = intfRes?.data?.result?.entry || [];
    } catch {}
    if (rules.length === 0) {
      // Fall back to PAN-OS XML API
      try {
        const xml = await http.get(`${base}/api/`, {
          headers,
          params: {
            type: "config", action: "get",
            xpath: "/config/devices/entry/vsys/entry[@name='vsys1']/rulebase/security/rules",
            key: c.apikey,
          },
        });
        const body = typeof xml.data === "string" ? xml.data : JSON.stringify(xml.data);
        // Extract full rule entries with action
        const entries = [...body.matchAll(/entry name="([^"]+)"[^]*?<action>([^<]+)<\/action>/g)]
          .map(m => ({ "@name": m[1], action: m[2].trim() }));
        rules = entries.length ? entries
          : [...body.matchAll(/entry name="([^"]+)"/g)].map(m => ({ "@name": m[1] }));
      } catch {}
    }
    // Try XML API for operational data (interface counters)
    try {
      const opXml = await http.get(`${base}/api/`, {
        headers,
        params: { type: "op", cmd: "<show><system><info></info></system></show>", key: c.apikey },
      });
      const body = typeof opXml.data === "string" ? opXml.data : "";
      const ver  = (body.match(/<sw-version>([^<]+)<\/sw-version>/) || [])[1] || "";
      const host = (body.match(/<hostname>([^<]+)<\/hostname>/) || [])[1] || "";
      sysInfo = { version: ver, hostname: host };
    } catch {}
    const snap = { source:"paloalto", vendor:"paloalto", rules, interfaces, sysInfo };
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
    const [risksRes, scoreRes, domainsRes, ipsRes] = await Promise.all([
      http.get(`${base}/risks`, { headers }),
      http.get(`${base}/breachsight`, { headers }).catch(() => ({ data: {} })),
      // domains returns: { domains:[{ hostname, primary_hostname, score, ip_addresses:[],
      //   custom_domain_attributes:{ expiry_date }, typosquats:[] }] }
      http.get(`${base}/domains`, { headers, params: { page_size: 100 } }).catch(() => ({ data: {} })),
      // ips returns: { ips:[{ ip, score, open_ports:[{ port, service, transport }] }] }
      http.get(`${base}/ips`, { headers, params: { page_size: 100 } }).catch(() => ({ data: {} })),
    ]);
    const snap = {
      source:      "upguard",
      risks:       risksRes.data   || {},   // { risks:[{id,finding,severity,hostnames,firstDetected,...}] }
      breachsight: scoreRes.data   || {},   // { score, grade, ranges:{ excellent,... } }
      domains:     domainsRes.data || {},   // { domains:[{hostname, score, ip_addresses, custom_domain_attributes}] }
      ips:         ipsRes.data     || {},   // { ips:[{ip, score, open_ports:[{port,service}]}] }
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
      kali:         ["host","port","username"],
      nessus:       ["host","port","username"],
      zaproxy:      ["host","port"],
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
  kali:         ["password","private_key"],
  nessus:       ["password"],
  zaproxy:      ["api_key"],
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
  // GRC compliance controls table
  await ensureGRCTable().catch(e => console.error("ensureGRCTable:", e.message));
  // Vulnerability assessment scan jobs table
  await ensureVulnTables().catch(e => console.error("ensureVulnTables:", e.message));
  // Schedule collectors based on per-tool intervals
  await scheduleCollectors();
});

/* ═══════════════════════════════════════════════════════════════════════════
   GRC – Compliance Management (DPDPA | PCI DSS 4.0.1 | ISO 27001:2022)
═══════════════════════════════════════════════════════════════════════════ */
async function ensureGRCTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS grc_controls (
      id            SERIAL PRIMARY KEY,
      framework     TEXT NOT NULL,
      control_id    TEXT NOT NULL,
      category      TEXT,
      title         TEXT NOT NULL,
      description   TEXT,
      status        TEXT NOT NULL DEFAULT 'not-assessed',
      evidence      TEXT,
      notes         TEXT,
      owner         TEXT,
      due_date      DATE,
      updated_at    TIMESTAMPTZ DEFAULT NOW(),
      updated_by    TEXT,
      UNIQUE(framework, control_id)
    );
  `);
}

// Seed default controls for all frameworks if table is empty for that framework
const GRC_DEFAULTS = {
  dpdpa: [
    { control_id:"S5",   category:"Data Processing",    title:"Purpose Limitation",              description:"Process personal data only for the specific lawful purpose for which it was collected (Section 5 DPDPA 2023)." },
    { control_id:"S6",   category:"Consent",            title:"Consent Management",              description:"Obtain free, specific, informed, and unambiguous consent from Data Principals. Maintain consent records and provide withdrawal mechanism." },
    { control_id:"S7",   category:"Legitimate Use",     title:"Legitimate Processing Bases",     description:"Document and enforce legitimate bases for processing personal data without consent (legal obligation, vital interests, public interest)." },
    { control_id:"S8.1", category:"Data Quality",       title:"Accuracy and Completeness",       description:"Ensure personal data processed is accurate, complete, and updated where necessary." },
    { control_id:"S8.2", category:"Security",           title:"Data Security Safeguards",        description:"Implement reasonable security safeguards to prevent personal data breach. Conduct risk assessments and maintain security controls." },
    { control_id:"S8.3", category:"Breach Response",    title:"Data Breach Notification",        description:"Notify Data Protection Board and affected Data Principals of personal data breaches in the prescribed manner and timeline." },
    { control_id:"S8.4", category:"Retention",          title:"Data Retention & Erasure",        description:"Erase personal data as soon as the purpose is served or consent is withdrawn. Implement retention schedules." },
    { control_id:"S9",   category:"Children's Data",    title:"Children's Data Protection",      description:"Obtain verifiable parental consent before processing personal data of children under 18. Do not process data that may harm children." },
    { control_id:"S10",  category:"Governance",         title:"Significant Data Fiduciary Obligations", description:"If classified as SDF: appoint DPO, conduct DPIA, implement data audits, register with Data Protection Board." },
    { control_id:"S11",  category:"Data Principal Rights", title:"Right to Information",         description:"Provide Data Principals with information about personal data being processed upon request." },
    { control_id:"S12",  category:"Data Principal Rights", title:"Right to Correction & Erasure", description:"Allow Data Principals to correct inaccurate data and erase personal data upon request." },
    { control_id:"S13",  category:"Data Principal Rights", title:"Grievance Redressal Mechanism", description:"Establish a grievance redressal mechanism with a Data Protection Officer or designated officer." },
    { control_id:"S14",  category:"Data Principal Rights", title:"Right to Nominate",            description:"Allow Data Principals to nominate another person to exercise their rights in case of death or incapacity." },
    { control_id:"S16",  category:"Governance",         title:"Data Protection Officer (DPO)",   description:"Appoint a Data Protection Officer and publish contact details on website." },
    { control_id:"S17",  category:"Cross-Border Transfer", title:"Cross-Border Data Transfers",  description:"Ensure personal data is transferred only to countries/territories permitted by the Central Government. Maintain transfer records." },
    { control_id:"S19",  category:"Third Parties",      title:"Data Processor Agreements",       description:"Ensure Data Processors process personal data only under valid contract and as per Data Fiduciary instructions." },
    { control_id:"S22",  category:"Governance",         title:"Privacy Notice",                  description:"Provide clear, accessible privacy notice describing categories of personal data, purposes, and rights of Data Principals." },
    { control_id:"S29",  category:"Compliance",         title:"Compliance with Board Directions", description:"Comply with all directions, inquiries, and investigations initiated by the Data Protection Board." },
  ],
  pcidss: [
    { control_id:"1.1", category:"Req 1 – Network Security", title:"Network Security Controls Policy", description:"Establish, implement, and maintain network security controls configuration standards." },
    { control_id:"1.2", category:"Req 1 – Network Security", title:"Network Access Controls",          description:"Restrict inbound and outbound traffic to only what is necessary for the cardholder data environment." },
    { control_id:"1.3", category:"Req 1 – Network Security", title:"Network Access Between CDE and Untrusted Networks", description:"Restrict inbound and outbound traffic to that which is necessary for the cardholder data environment." },
    { control_id:"1.4", category:"Req 1 – Network Security", title:"Network Connections Between CDE and Untrusted Networks", description:"Network security controls are implemented between trusted and untrusted networks." },
    { control_id:"1.5", category:"Req 1 – Network Security", title:"Risks to CDE from Computing Devices", description:"Risks to the CDE from computing devices that are able to connect to both untrusted networks and the CDE are addressed." },
    { control_id:"2.1", category:"Req 2 – Secure Config",   title:"Processes for Secure Configuration", description:"Processes and mechanisms for applying secure configurations to all system components are defined and understood." },
    { control_id:"2.2", category:"Req 2 – Secure Config",   title:"System Components Configured Securely", description:"System components are configured and managed securely. Change default vendor-supplied credentials." },
    { control_id:"2.3", category:"Req 2 – Secure Config",   title:"Wireless Environments",               description:"Wireless environments are configured and managed securely." },
    { control_id:"3.1", category:"Req 3 – Stored Data",     title:"Account Data Storage Policies",       description:"Processes and mechanisms for protecting stored account data are defined and understood." },
    { control_id:"3.2", category:"Req 3 – Stored Data",     title:"Storage of SAD",                      description:"Storage of sensitive authentication data is kept to a minimum and only if there is a business need." },
    { control_id:"3.3", category:"Req 3 – Stored Data",     title:"SAD Not Retained After Authorization", description:"Sensitive authentication data (SAD) is not retained after authorization." },
    { control_id:"3.4", category:"Req 3 – Stored Data",     title:"PAN Protection",                      description:"Access to displays of full PAN and ability to copy PAN are restricted." },
    { control_id:"3.5", category:"Req 3 – Stored Data",     title:"Primary Account Number Secured",       description:"PAN is secured wherever stored." },
    { control_id:"4.1", category:"Req 4 – Transmission",   title:"Transmission Security Policies",       description:"Processes and mechanisms for protecting PAN during transmission over open, public networks are defined." },
    { control_id:"4.2", category:"Req 4 – Transmission",   title:"PAN Secured During Transmission",      description:"PAN is protected with strong cryptography during transmission over open, public networks." },
    { control_id:"5.1", category:"Req 5 – Anti-Malware",   title:"Anti-Malware Processes",               description:"Processes to protect against malware are defined and understood." },
    { control_id:"5.2", category:"Req 5 – Anti-Malware",   title:"Anti-Malware Deployed",                description:"Malware is prevented or detected and addressed." },
    { control_id:"5.3", category:"Req 5 – Anti-Malware",   title:"Anti-Malware Mechanisms Active",       description:"Anti-malware mechanisms and processes are active, maintained, and monitored." },
    { control_id:"6.1", category:"Req 6 – Secure Systems", title:"Secure Development Processes",         description:"Processes and mechanisms for developing and maintaining secure systems and software are defined." },
    { control_id:"6.2", category:"Req 6 – Secure Systems", title:"Bespoke and Custom Software Security", description:"Bespoke and custom software are developed securely." },
    { control_id:"6.3", category:"Req 6 – Secure Systems", title:"Security Vulnerabilities Identified",  description:"Security vulnerabilities are identified and addressed." },
    { control_id:"6.4", category:"Req 6 – Secure Systems", title:"Web-Facing Applications Protected",    description:"Public-facing web applications are protected against attacks." },
    { control_id:"6.5", category:"Req 6 – Secure Systems", title:"Changes to System Components Managed", description:"All security vulnerabilities and changes to system components are managed." },
    { control_id:"7.1", category:"Req 7 – Access Control", title:"Access Control Processes",             description:"Processes to restrict access to system components and cardholder data are defined." },
    { control_id:"7.2", category:"Req 7 – Access Control", title:"Access to System Components Restricted", description:"Access to system components and data is appropriately defined and assigned." },
    { control_id:"7.3", category:"Req 7 – Access Control", title:"Access to System Components Managed",  description:"Access to system components and data is managed via an access control system." },
    { control_id:"8.1", category:"Req 8 – Identity & Auth", title:"Identity Management Processes",       description:"Processes for identifying and authenticating all users are defined." },
    { control_id:"8.2", category:"Req 8 – Identity & Auth", title:"User Identification and Authentication", description:"All users are assigned a unique ID before allowing them to access system components or cardholder data." },
    { control_id:"8.3", category:"Req 8 – Identity & Auth", title:"User Authentication Managed",         description:"User authentication for users and administrators is managed via an authentication system." },
    { control_id:"8.4", category:"Req 8 – Identity & Auth", title:"MFA Implemented",                     description:"Multi-factor authentication (MFA) is implemented to secure access into the CDE." },
    { control_id:"8.5", category:"Req 8 – Identity & Auth", title:"Application and System Accounts",     description:"Application and system accounts and related authentication factors are managed." },
    { control_id:"8.6", category:"Req 8 – Identity & Auth", title:"System/Application Accounts Managed", description:"Use of interactive login for application and system accounts is strictly managed." },
    { control_id:"9.1", category:"Req 9 – Physical Access", title:"Physical Access Controls",             description:"Processes to restrict physical access to cardholder data are defined." },
    { control_id:"9.2", category:"Req 9 – Physical Access", title:"Physical Access to CDE Controlled",   description:"Physical access controls manage entry into facilities and systems that contain cardholder data." },
    { control_id:"9.3", category:"Req 9 – Physical Access", title:"Physical Access for Visitors",        description:"Physical access for visitors is authorized and managed." },
    { control_id:"9.4", category:"Req 9 – Physical Access", title:"Media with Cardholder Data Protected", description:"Media with cardholder data is protected." },
    { control_id:"10.1", category:"Req 10 – Logging",       title:"Audit Logging Processes",             description:"Processes to log and monitor all access to network resources and cardholder data are defined." },
    { control_id:"10.2", category:"Req 10 – Logging",       title:"Audit Logs Implemented",              description:"Audit logs that capture user activities, exceptions, and security events are implemented." },
    { control_id:"10.3", category:"Req 10 – Logging",       title:"Audit Logs Protected",                description:"Audit logs are protected from destruction and unauthorized modifications." },
    { control_id:"10.4", category:"Req 10 – Logging",       title:"Audit Logs Reviewed",                 description:"Audit logs are reviewed to identify anomalies or suspicious activity." },
    { control_id:"10.5", category:"Req 10 – Logging",       title:"Audit Log History Retained",          description:"Audit log history is retained and available for analysis." },
    { control_id:"10.6", category:"Req 10 – Logging",       title:"Time Synchronization",                description:"Time-synchronization technology supports consistent time settings across all systems." },
    { control_id:"11.1", category:"Req 11 – Testing",       title:"Security Testing Processes",          description:"Processes to test security of systems and networks are defined." },
    { control_id:"11.2", category:"Req 11 – Testing",       title:"Wireless Access Points Managed",      description:"Authorized and unauthorized wireless access points are managed." },
    { control_id:"11.3", category:"Req 11 – Testing",       title:"Vulnerability Scanning",              description:"External and internal vulnerabilities are regularly identified and resolved." },
    { control_id:"11.4", category:"Req 11 – Testing",       title:"Penetration Testing",                 description:"External and internal penetration testing is regularly performed." },
    { control_id:"11.5", category:"Req 11 – Testing",       title:"Network Intrusion Detection",         description:"Network intrusions and unexpected file changes are detected and responded to." },
    { control_id:"12.1", category:"Req 12 – Policy",        title:"Information Security Policy",         description:"A comprehensive information security policy is defined, published, maintained, and disseminated." },
    { control_id:"12.2", category:"Req 12 – Policy",        title:"Acceptable Use Policies",             description:"Acceptable use policies for end-user technologies are defined and implemented." },
    { control_id:"12.3", category:"Req 12 – Policy",        title:"Risk Management",                     description:"Risks to the cardholder data environment are formally identified, evaluated, and managed." },
    { control_id:"12.4", category:"Req 12 – Policy",        title:"PCI DSS Compliance Managed",          description:"PCI DSS compliance is managed throughout the year." },
    { control_id:"12.5", category:"Req 12 – Policy",        title:"PCI DSS Scope Documented",            description:"PCI DSS scope is documented and validated." },
    { control_id:"12.6", category:"Req 12 – Policy",        title:"Security Awareness Program",          description:"A security awareness program is implemented to make all personnel aware of the cardholder data security policy." },
    { control_id:"12.7", category:"Req 12 – Policy",        title:"Personnel Screening",                 description:"Personnel with access to cardholder data are screened prior to hire." },
    { control_id:"12.8", category:"Req 12 – Policy",        title:"Third-Party Risk Management",         description:"Risks from third-party entities with access to cardholder data are managed." },
    { control_id:"12.9", category:"Req 12 – Policy",        title:"Third-Party Acknowledgement",         description:"Third-party service providers acknowledge their responsibility for protecting cardholder data." },
    { control_id:"12.10", category:"Req 12 – Policy",       title:"Incident Response Plan",              description:"Suspected and confirmed security incidents that could impact the CDE are responded to immediately." },
  ],
  iso27001: [
    // Clause 4-10
    { control_id:"4.1",  category:"Clause 4 – Context",       title:"Understanding the Organisation",      description:"Determine external and internal issues relevant to the ISMS purpose and that affect its ability to achieve intended outcomes." },
    { control_id:"4.2",  category:"Clause 4 – Context",       title:"Interested Parties",                  description:"Determine interested parties relevant to the ISMS and their requirements." },
    { control_id:"4.3",  category:"Clause 4 – Context",       title:"ISMS Scope",                          description:"Determine the boundaries and applicability of the ISMS and document its scope." },
    { control_id:"5.1",  category:"Clause 5 – Leadership",    title:"Leadership and Commitment",           description:"Top management shall demonstrate leadership and commitment to the ISMS." },
    { control_id:"5.2",  category:"Clause 5 – Leadership",    title:"Information Security Policy",         description:"Establish, maintain, and communicate an information security policy." },
    { control_id:"5.3",  category:"Clause 5 – Leadership",    title:"Organisational Roles",                description:"Assign and communicate roles and responsibilities for information security." },
    { control_id:"6.1",  category:"Clause 6 – Planning",      title:"Risk Assessment",                     description:"Define and apply an information security risk assessment process." },
    { control_id:"6.2",  category:"Clause 6 – Planning",      title:"Risk Treatment",                      description:"Define and apply an information security risk treatment process. Produce Statement of Applicability." },
    { control_id:"6.3",  category:"Clause 6 – Planning",      title:"ISMS Objectives",                     description:"Establish information security objectives and plans to achieve them." },
    { control_id:"7.1",  category:"Clause 7 – Support",       title:"Resources",                           description:"Determine and provide resources needed for the ISMS." },
    { control_id:"7.2",  category:"Clause 7 – Support",       title:"Competence",                          description:"Determine, maintain, and document staff competence for information security." },
    { control_id:"7.3",  category:"Clause 7 – Support",       title:"Awareness",                           description:"Ensure persons doing work under the organisation's control are aware of the information security policy and their contribution." },
    { control_id:"7.4",  category:"Clause 7 – Support",       title:"Communication",                       description:"Determine the need for internal and external communications relevant to the ISMS." },
    { control_id:"7.5",  category:"Clause 7 – Support",       title:"Documented Information",              description:"Maintain documented information required by ISO 27001 and determined necessary for the effectiveness of the ISMS." },
    { control_id:"8.1",  category:"Clause 8 – Operation",     title:"Operational Planning and Control",    description:"Plan, implement, control, and review processes needed to meet security requirements." },
    { control_id:"8.2",  category:"Clause 8 – Operation",     title:"Risk Assessment (Operational)",       description:"Perform information security risk assessments at planned intervals or when significant changes occur." },
    { control_id:"8.3",  category:"Clause 8 – Operation",     title:"Risk Treatment (Operational)",        description:"Implement the information security risk treatment plan and retain documented information." },
    { control_id:"9.1",  category:"Clause 9 – Evaluation",    title:"Monitoring, Measurement and Analysis", description:"Evaluate the information security performance and effectiveness of the ISMS." },
    { control_id:"9.2",  category:"Clause 9 – Evaluation",    title:"Internal Audit",                      description:"Conduct internal audits of the ISMS at planned intervals." },
    { control_id:"9.3",  category:"Clause 9 – Evaluation",    title:"Management Review",                   description:"Top management shall review the ISMS at planned intervals." },
    { control_id:"10.1", category:"Clause 10 – Improvement",  title:"Continual Improvement",               description:"Continually improve the suitability, adequacy, and effectiveness of the ISMS." },
    { control_id:"10.2", category:"Clause 10 – Improvement",  title:"Nonconformity and Corrective Action", description:"React to nonconformities, take corrective action, and review effectiveness." },
    // Annex A – Organisational Controls (A.5)
    { control_id:"A.5.1",  category:"A.5 Organisational",  title:"Information Security Policies",       description:"Define, approve, publish, and review information security policies." },
    { control_id:"A.5.2",  category:"A.5 Organisational",  title:"IS Roles & Responsibilities",         description:"Define and allocate information security responsibilities." },
    { control_id:"A.5.3",  category:"A.5 Organisational",  title:"Segregation of Duties",               description:"Conflicting duties and areas of responsibility shall be segregated." },
    { control_id:"A.5.4",  category:"A.5 Organisational",  title:"Management Responsibilities",         description:"Management shall require all personnel to apply information security per established policies." },
    { control_id:"A.5.5",  category:"A.5 Organisational",  title:"Contact with Authorities",            description:"Maintain appropriate contacts with relevant authorities." },
    { control_id:"A.5.6",  category:"A.5 Organisational",  title:"Contact with Special Interest Groups", description:"Maintain appropriate contacts with special interest groups or specialist security forums." },
    { control_id:"A.5.7",  category:"A.5 Organisational",  title:"Threat Intelligence",                 description:"Collect and analyse information relating to information security threats." },
    { control_id:"A.5.8",  category:"A.5 Organisational",  title:"IS in Project Management",           description:"Information security shall be integrated into project management." },
    { control_id:"A.5.9",  category:"A.5 Organisational",  title:"Inventory of Assets",                 description:"Identify assets associated with information and information processing facilities." },
    { control_id:"A.5.10", category:"A.5 Organisational",  title:"Acceptable Use of Assets",            description:"Rules for acceptable use and return of assets shall be identified, documented, and implemented." },
    { control_id:"A.5.11", category:"A.5 Organisational",  title:"Return of Assets",                    description:"Assets shall be returned upon change or termination of employment." },
    { control_id:"A.5.12", category:"A.5 Organisational",  title:"Classification of Information",       description:"Information shall be classified according to security needs of the organisation." },
    { control_id:"A.5.13", category:"A.5 Organisational",  title:"Labelling of Information",            description:"An appropriate set of procedures for information labelling shall be developed." },
    { control_id:"A.5.14", category:"A.5 Organisational",  title:"Information Transfer",                description:"Transfer policies, procedures, and agreements shall be in place for all types of transfer." },
    { control_id:"A.5.15", category:"A.5 Organisational",  title:"Access Control",                      description:"Rules to control physical and logical access to information and assets shall be established." },
    { control_id:"A.5.16", category:"A.5 Organisational",  title:"Identity Management",                 description:"The full life cycle of identities shall be managed." },
    { control_id:"A.5.17", category:"A.5 Organisational",  title:"Authentication Information",          description:"Allocation and management of authentication information shall be controlled." },
    { control_id:"A.5.18", category:"A.5 Organisational",  title:"Access Rights",                       description:"Access rights shall be provisioned, reviewed, modified, and removed." },
    { control_id:"A.5.19", category:"A.5 Organisational",  title:"IS in Supplier Relationships",        description:"Processes and procedures shall be defined to manage information security risks in supplier relationships." },
    { control_id:"A.5.20", category:"A.5 Organisational",  title:"IS in Supplier Agreements",           description:"Relevant IS requirements shall be established with each supplier." },
    { control_id:"A.5.21", category:"A.5 Organisational",  title:"Managing IS in ICT Supply Chain",     description:"Define and implement processes and procedures to manage IS risks in the ICT supply chain." },
    { control_id:"A.5.22", category:"A.5 Organisational",  title:"Monitoring of Supplier Services",     description:"Regularly monitor, review, and audit supplier service delivery." },
    { control_id:"A.5.23", category:"A.5 Organisational",  title:"IS for Use of Cloud Services",        description:"Processes for acquisition, use, management, and exit of cloud services shall be established." },
    { control_id:"A.5.24", category:"A.5 Organisational",  title:"IS Incident Management Planning",     description:"Plan and prepare for managing IS incidents by defining IS incident management processes." },
    { control_id:"A.5.25", category:"A.5 Organisational",  title:"Assess & Decide on IS Events",        description:"Assess IS events and decide if they are to be classified as IS incidents." },
    { control_id:"A.5.26", category:"A.5 Organisational",  title:"Response to IS Incidents",            description:"IS incidents shall be responded to in accordance with documented procedures." },
    { control_id:"A.5.27", category:"A.5 Organisational",  title:"Learning from IS Incidents",          description:"Knowledge gained from IS incidents shall be used to strengthen controls." },
    { control_id:"A.5.28", category:"A.5 Organisational",  title:"Collection of Evidence",              description:"Establish and implement procedures for the identification, collection, and preservation of evidence." },
    { control_id:"A.5.29", category:"A.5 Organisational",  title:"IS During Disruption",                description:"Plan how to maintain IS at an appropriate level during disruption." },
    { control_id:"A.5.30", category:"A.5 Organisational",  title:"ICT Readiness for Business Continuity", description:"ICT readiness shall be planned, implemented, maintained and tested based on BCP." },
    { control_id:"A.5.31", category:"A.5 Organisational",  title:"Legal, Statutory & Regulatory Reqts", description:"Identify, document, and keep up-to-date all legal, statutory, regulatory requirements." },
    { control_id:"A.5.32", category:"A.5 Organisational",  title:"Intellectual Property Rights",        description:"Implement appropriate procedures to protect intellectual property rights." },
    { control_id:"A.5.33", category:"A.5 Organisational",  title:"Protection of Records",               description:"Records shall be protected from loss, destruction, falsification, unauthorised access." },
    { control_id:"A.5.34", category:"A.5 Organisational",  title:"Privacy and PII",                     description:"Identify and meet requirements regarding preservation of privacy and PII protection." },
    { control_id:"A.5.35", category:"A.5 Organisational",  title:"Independent Review of IS",            description:"IS implementation shall be reviewed independently at planned intervals." },
    { control_id:"A.5.36", category:"A.5 Organisational",  title:"Compliance with IS Policies",         description:"Compliance with IS policies, rules, and standards shall be regularly reviewed." },
    { control_id:"A.5.37", category:"A.5 Organisational",  title:"Documented Operating Procedures",     description:"Operating procedures for IS facilities shall be documented and available to staff who need them." },
    // Annex A – People Controls (A.6)
    { control_id:"A.6.1",  category:"A.6 People",           title:"Screening",                           description:"Background verification checks on all candidates for employment shall be carried out." },
    { control_id:"A.6.2",  category:"A.6 People",           title:"Terms and Conditions of Employment",  description:"Employment agreements shall state IS responsibilities." },
    { control_id:"A.6.3",  category:"A.6 People",           title:"IS Awareness, Education and Training", description:"Personnel shall receive appropriate IS awareness and training." },
    { control_id:"A.6.4",  category:"A.6 People",           title:"Disciplinary Process",                description:"A disciplinary process shall be in place for IS policy violations." },
    { control_id:"A.6.5",  category:"A.6 People",           title:"Responsibilities After Termination",  description:"IS responsibilities after change or termination of employment shall be defined." },
    { control_id:"A.6.6",  category:"A.6 People",           title:"Confidentiality Agreements",          description:"Confidentiality and NDA agreements shall be identified, documented, reviewed, and signed." },
    { control_id:"A.6.7",  category:"A.6 People",           title:"Remote Working",                      description:"Security measures shall be implemented when personnel work remotely." },
    { control_id:"A.6.8",  category:"A.6 People",           title:"IS Event Reporting",                  description:"Personnel shall be required to report IS events through appropriate channels." },
    // Annex A – Physical Controls (A.7)
    { control_id:"A.7.1",  category:"A.7 Physical",          title:"Physical Security Perimeters",        description:"Security perimeters shall be defined and used to protect areas containing sensitive information." },
    { control_id:"A.7.2",  category:"A.7 Physical",          title:"Physical Entry",                      description:"Secure areas shall be protected by appropriate entry controls." },
    { control_id:"A.7.3",  category:"A.7 Physical",          title:"Securing Offices and Facilities",     description:"Physical security for offices, rooms, and facilities shall be designed and implemented." },
    { control_id:"A.7.4",  category:"A.7 Physical",          title:"Physical Security Monitoring",        description:"Premises shall be continuously monitored for unauthorised physical access." },
    { control_id:"A.7.5",  category:"A.7 Physical",          title:"Protection Against Physical Threats", description:"Protection against physical and environmental threats shall be designed and implemented." },
    { control_id:"A.7.6",  category:"A.7 Physical",          title:"Working in Secure Areas",             description:"Security measures for working in secure areas shall be designed and implemented." },
    { control_id:"A.7.7",  category:"A.7 Physical",          title:"Clear Desk and Clear Screen",         description:"Clear desk rules for papers and removable storage media and clear screen rules shall be defined." },
    { control_id:"A.7.8",  category:"A.7 Physical",          title:"Equipment Siting and Protection",     description:"Equipment shall be sited securely and protected." },
    { control_id:"A.7.9",  category:"A.7 Physical",          title:"Security of Assets Off-Premises",     description:"Off-site assets shall be protected." },
    { control_id:"A.7.10", category:"A.7 Physical",          title:"Storage Media",                       description:"Storage media shall be managed through their life cycle in accordance with classification and handling requirements." },
    { control_id:"A.7.11", category:"A.7 Physical",          title:"Supporting Utilities",                description:"IS facilities shall be protected from power failures and other disruptions." },
    { control_id:"A.7.12", category:"A.7 Physical",          title:"Cabling Security",                    description:"Cables carrying power, data, or supporting IS services shall be protected." },
    { control_id:"A.7.13", category:"A.7 Physical",          title:"Equipment Maintenance",               description:"Equipment shall be maintained correctly to ensure availability and integrity." },
    { control_id:"A.7.14", category:"A.7 Physical",          title:"Secure Disposal or Re-Use",           description:"Items of equipment containing storage media shall be verified to ensure sensitive data is removed." },
    // Annex A – Technological Controls (A.8, key subset)
    { control_id:"A.8.1",  category:"A.8 Technological",     title:"User Endpoint Devices",               description:"Information stored on, processed by, or accessible via user endpoint devices shall be protected." },
    { control_id:"A.8.2",  category:"A.8 Technological",     title:"Privileged Access Rights",            description:"Allocation and use of privileged access rights shall be restricted and managed." },
    { control_id:"A.8.3",  category:"A.8 Technological",     title:"Information Access Restriction",      description:"Access to information and systems shall be restricted in accordance with the access control policy." },
    { control_id:"A.8.4",  category:"A.8 Technological",     title:"Access to Source Code",               description:"Read and write access to source code, development tools, and software libraries shall be managed." },
    { control_id:"A.8.5",  category:"A.8 Technological",     title:"Secure Authentication",               description:"Secure authentication technologies and procedures shall be implemented." },
    { control_id:"A.8.6",  category:"A.8 Technological",     title:"Capacity Management",                 description:"The use of resources shall be monitored and adjusted to meet capacity requirements." },
    { control_id:"A.8.7",  category:"A.8 Technological",     title:"Protection Against Malware",          description:"Protection against malware shall be implemented and supported by appropriate user awareness." },
    { control_id:"A.8.8",  category:"A.8 Technological",     title:"Management of Technical Vulnerabilities", description:"Timely identification and remediation of technical vulnerabilities." },
    { control_id:"A.8.9",  category:"A.8 Technological",     title:"Configuration Management",            description:"Configurations, including security configurations, shall be established, documented, and managed." },
    { control_id:"A.8.10", category:"A.8 Technological",     title:"Information Deletion",                description:"Information stored in IS or on media shall be deleted when no longer required." },
    { control_id:"A.8.11", category:"A.8 Technological",     title:"Data Masking",                        description:"Data masking shall be used in accordance with the organisation's topic-specific policy." },
    { control_id:"A.8.12", category:"A.8 Technological",     title:"Data Leakage Prevention",             description:"Measures to prevent data leakage shall be applied to systems, networks, and devices." },
    { control_id:"A.8.13", category:"A.8 Technological",     title:"Information Backup",                  description:"Backup copies of information shall be maintained and regularly tested." },
    { control_id:"A.8.14", category:"A.8 Technological",     title:"Redundancy of IS Facilities",         description:"IS processing facilities shall be implemented with redundancy." },
    { control_id:"A.8.15", category:"A.8 Technological",     title:"Logging",                             description:"Logs recording activities, exceptions, faults, and events shall be produced, stored, and reviewed." },
    { control_id:"A.8.16", category:"A.8 Technological",     title:"Monitoring Activities",               description:"Networks, systems, and applications shall be monitored for anomalous behaviour." },
    { control_id:"A.8.17", category:"A.8 Technological",     title:"Clock Synchronisation",               description:"Clocks of IS processing systems shall be synchronised to approved time sources." },
    { control_id:"A.8.18", category:"A.8 Technological",     title:"Use of Privileged Utility Programs",  description:"Use of utility programs capable of overriding system and application controls shall be restricted." },
    { control_id:"A.8.19", category:"A.8 Technological",     title:"Installation of Software on Systems", description:"Procedures and measures shall be implemented to securely manage software installation." },
    { control_id:"A.8.20", category:"A.8 Technological",     title:"Networks Security",                   description:"Networks and network devices shall be secured, managed, and controlled." },
    { control_id:"A.8.21", category:"A.8 Technological",     title:"Security of Network Services",        description:"Security mechanisms, service levels, and service requirements of network services shall be identified." },
    { control_id:"A.8.22", category:"A.8 Technological",     title:"Segregation of Networks",             description:"Groups of IS, users, and systems shall be segregated in networks." },
    { control_id:"A.8.23", category:"A.8 Technological",     title:"Web Filtering",                       description:"Access to external websites shall be managed to reduce exposure to malicious content." },
    { control_id:"A.8.24", category:"A.8 Technological",     title:"Use of Cryptography",                 description:"Rules for effective use of cryptography, including cryptographic key management, shall be defined." },
    { control_id:"A.8.25", category:"A.8 Technological",     title:"Secure Development Life Cycle",       description:"Rules for secure development of software and systems shall be established and applied." },
    { control_id:"A.8.26", category:"A.8 Technological",     title:"Application Security Requirements",   description:"IS requirements shall be identified, specified, and approved when developing applications." },
    { control_id:"A.8.27", category:"A.8 Technological",     title:"Secure System Architecture",          description:"Principles for engineering secure systems shall be established, documented, and applied." },
    { control_id:"A.8.28", category:"A.8 Technological",     title:"Secure Coding",                       description:"Secure coding principles shall be applied to software development." },
    { control_id:"A.8.29", category:"A.8 Technological",     title:"Security Testing in Development",     description:"Security testing processes shall be defined and implemented in the development life cycle." },
    { control_id:"A.8.30", category:"A.8 Technological",     title:"Outsourced Development",              description:"The organisation shall supervise and monitor activities related to outsourced system development." },
    { control_id:"A.8.31", category:"A.8 Technological",     title:"Separation of Development Environments", description:"Development, testing, and production environments shall be separated and secured." },
    { control_id:"A.8.32", category:"A.8 Technological",     title:"Change Management",                   description:"Changes to IS processing facilities and IS shall be subject to change management procedures." },
    { control_id:"A.8.33", category:"A.8 Technological",     title:"Test Information",                    description:"Test information shall be appropriately selected, protected, and managed." },
    { control_id:"A.8.34", category:"A.8 Technological",     title:"Protection of IS During Audit Testing", description:"Audit tests and other assurance activities involving assessment of systems shall be planned and agreed." },
  ],
};

async function seedGRCControls(framework) {
  const defaults = GRC_DEFAULTS[framework];
  if (!defaults) return;
  for (const c of defaults) {
    await pool.query(
      `INSERT INTO grc_controls (framework, control_id, category, title, description)
       VALUES ($1,$2,$3,$4,$5) ON CONFLICT (framework, control_id) DO NOTHING`,
      [framework, c.control_id, c.category, c.title, c.description]
    );
  }
}

// GET /api/grc/:framework — return all controls for a framework
app.get("/api/grc/:framework", requireAuth, async (req, res) => {
  const fw = req.params.framework.toLowerCase();
  try {
    // Seed if empty
    const cnt = await pool.query("SELECT COUNT(*) FROM grc_controls WHERE framework=$1", [fw]);
    if (parseInt(cnt.rows[0].count) === 0) await seedGRCControls(fw);
    const r = await pool.query(
      "SELECT * FROM grc_controls WHERE framework=$1 ORDER BY control_id", [fw]
    );
    res.json(r.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// PUT /api/grc/:framework/:controlId — update a control's status/evidence/notes
app.put("/api/grc/:framework/:controlId", requireAuth, async (req, res) => {
  const fw = req.params.framework.toLowerCase();
  const cid = req.params.controlId;
  const { status, evidence, notes, owner, due_date } = req.body;
  try {
    const r = await pool.query(
      `UPDATE grc_controls SET status=COALESCE($1,status), evidence=COALESCE($2,evidence),
       notes=COALESCE($3,notes), owner=COALESCE($4,owner), due_date=COALESCE($5::date,due_date),
       updated_at=NOW(), updated_by=$6
       WHERE framework=$7 AND control_id=$8 RETURNING *`,
      [status, evidence, notes, owner, due_date || null, req.user.username, fw, cid]
    );
    if (r.rowCount === 0) return res.status(404).json({ error: "Control not found" });
    res.json(r.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// POST /api/grc/:framework/reset — re-seed from defaults (resets status to not-assessed)
app.post("/api/grc/:framework/reset", requireAuth, async (req, res) => {
  const fw = req.params.framework.toLowerCase();
  try {
    await pool.query("DELETE FROM grc_controls WHERE framework=$1", [fw]);
    await seedGRCControls(fw);
    const r = await pool.query("SELECT * FROM grc_controls WHERE framework=$1 ORDER BY control_id", [fw]);
    res.json(r.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* ═══════════════════════════════════════════════════════════════════════════
   VULNERABILITY ASSESSMENT — Orchestrated scanning via Kali / Nmap / ZAP /
   Nessus / Qualys + Claude AI analysis + PDF export
═══════════════════════════════════════════════════════════════════════════ */
const { exec, spawn } = require("child_process");
const fs   = require("fs");
const path = require("path");
const os   = require("os");

async function ensureVulnTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS scan_jobs (
      id           SERIAL PRIMARY KEY,
      target       TEXT NOT NULL,
      scan_type    TEXT NOT NULL DEFAULT 'standard',
      tools        JSONB NOT NULL DEFAULT '[]',
      status       TEXT NOT NULL DEFAULT 'queued',
      progress     INT  NOT NULL DEFAULT 0,
      started_at   TIMESTAMPTZ,
      completed_at TIMESTAMPTZ,
      created_at   TIMESTAMPTZ DEFAULT NOW(),
      created_by   TEXT,
      results      JSONB DEFAULT '{}',
      ai_analysis  TEXT,
      error        TEXT
    );
  `);
}

function runShellCommand(cmd, opts = {}) {
  return new Promise((resolve, reject) => {
    exec(cmd, { timeout: opts.timeout || 300000, ...opts }, (err, stdout, stderr) => {
      if (err && !opts.ignoreError) reject(new Error(stderr || err.message));
      else resolve({ stdout: stdout || "", stderr: stderr || "" });
    });
  });
}

async function updateScanJob(id, fields) {
  const sets = Object.keys(fields).map((k, i) => `${k}=$${i + 2}`).join(", ");
  const vals = Object.values(fields);
  await pool.query(`UPDATE scan_jobs SET ${sets} WHERE id=$1`, [id, ...vals]).catch(() => {});
}

async function runNmapScan(target, profile) {
  const flags = profile === "deep"
    ? `-sV -sC -O -A --script vuln -T4`
    : profile === "quick"
    ? `-sV -T4 --top-ports 100`
    : `-sV -sC -T4 --top-ports 1000`;
  try {
    const { stdout } = await runShellCommand(`nmap ${flags} ${target} 2>&1`, { timeout: 600000, ignoreError: true });
    // Parse basic open ports from nmap output
    const ports = [];
    const portRx = /^(\d+)\/(tcp|udp)\s+(\w+)\s+(.*)$/gm;
    let m;
    while ((m = portRx.exec(stdout)) !== null) {
      ports.push({ port: parseInt(m[1]), protocol: m[2], state: m[3], service: m[4].trim() });
    }
    const osMatch = stdout.match(/OS details: (.+)/);
    return { tool: "nmap", success: true, ports, os: osMatch?.[1] || null, raw: stdout.slice(0, 8000) };
  } catch(e) {
    return { tool: "nmap", success: false, error: e.message };
  }
}

async function runZAPScan(target, profile) {
  // ZAP REST API — requires ZAP running (configured via integration)
  const creds = await getIntegrationCreds("zaproxy").catch(() => null);
  if (!creds) return { tool: "zaproxy", success: false, error: "ZAProxy not configured in Settings" };
  const zapUrl = `http://${creds.host || "localhost"}:${creds.port || 8080}`;
  const apiKey = creds.api_key || "";
  try {
    // Start spider
    await axios.get(`${zapUrl}/JSON/spider/action/scan/?apikey=${apiKey}&url=${encodeURIComponent(target)}&maxChildren=10`);
    await new Promise(r => setTimeout(r, profile === "quick" ? 15000 : 30000)); // wait for spider
    // Start active scan
    const scanR = await axios.get(`${zapUrl}/JSON/ascan/action/scan/?apikey=${apiKey}&url=${encodeURIComponent(target)}&recurse=true`);
    const scanId = scanR.data?.scan;
    // Poll for completion (max 3 min)
    const deadline = Date.now() + 180000;
    while (Date.now() < deadline) {
      const statusR = await axios.get(`${zapUrl}/JSON/ascan/view/status/?apikey=${apiKey}&scanId=${scanId}`);
      if (parseInt(statusR.data?.status) >= 100) break;
      await new Promise(r => setTimeout(r, 5000));
    }
    // Get alerts
    const alertsR = await axios.get(`${zapUrl}/JSON/alert/view/alerts/?apikey=${apiKey}&baseurl=${encodeURIComponent(target)}&start=0&count=200`);
    const alerts = (alertsR.data?.alerts || []).map(a => ({
      name: a.alert, risk: a.risk, confidence: a.confidence,
      url: a.url, description: a.description?.slice(0, 300), solution: a.solution?.slice(0, 300),
      cweid: a.cweid, wascid: a.wascid,
    }));
    return { tool: "zaproxy", success: true, alerts, alertCount: alerts.length };
  } catch(e) {
    return { tool: "zaproxy", success: false, error: e.message };
  }
}

async function runNessusScan(target) {
  const creds = await getIntegrationCreds("nessus").catch(() => null);
  if (!creds) return { tool: "nessus", success: false, error: "Nessus not configured in Settings" };
  const base = `https://${creds.host || "localhost"}:${creds.port || 8834}`;
  const agent = new https.Agent({ rejectUnauthorized: false });
  try {
    // Login
    const loginR = await axios.post(`${base}/session`, { username: creds.username, password: creds.password },
      { httpsAgent: agent, headers: { "Content-Type": "application/json" } });
    const token = loginR.data.token;
    const authH = { "X-Cookie": `token=${token}`, "Content-Type": "application/json" };
    // Create scan
    const createR = await axios.post(`${base}/scans`, {
      uuid: "ad629e16-7ef5-4db9-b2b0-7c769f8c98a1", // Basic Network Scan template
      settings: { name: `SecOps-AutoScan-${Date.now()}`, text_targets: target, launch: "ON_DEMAND" }
    }, { httpsAgent: agent, headers: authH });
    const scanId = createR.data?.scan?.id;
    // Launch
    await axios.post(`${base}/scans/${scanId}/launch`, {}, { httpsAgent: agent, headers: authH });
    // Poll (max 5 min)
    const deadline = Date.now() + 300000;
    while (Date.now() < deadline) {
      const sR = await axios.get(`${base}/scans/${scanId}`, { httpsAgent: agent, headers: authH });
      const st = sR.data?.info?.status;
      if (st === "completed" || st === "canceled") break;
      await new Promise(r => setTimeout(r, 10000));
    }
    // Get vulnerabilities
    const rptR = await axios.get(`${base}/scans/${scanId}`, { httpsAgent: agent, headers: authH });
    const vulns = (rptR.data?.vulnerabilities || []).map(v => ({
      plugin_id: v.plugin_id, name: v.plugin_name,
      severity: ["Info","Low","Medium","High","Critical"][v.severity] || "Unknown",
      count: v.count,
    }));
    // Logout
    await axios.delete(`${base}/session`, { httpsAgent: agent, headers: authH }).catch(() => {});
    return { tool: "nessus", success: true, vulns, vulnCount: vulns.length };
  } catch(e) {
    return { tool: "nessus", success: false, error: e.message };
  }
}

async function runQualysScan(target) {
  const creds = await getIntegrationCreds("qualys").catch(() => null);
  if (!creds) return { tool: "qualys", success: false, error: "Qualys not configured in Settings" };
  // Use existing Qualys scan API
  const base = `https://${creds.api_url || "qualysapi.qualys.com"}`;
  const auth = Buffer.from(`${creds.username}:${creds.password}`).toString("base64");
  const headers = { Authorization: `Basic ${auth}`, "X-Requested-With": "SecOpsDashboard", "Content-Type": "text/xml" };
  try {
    // Launch VM scan
    const launchBody = `<ServiceRequest><data><ScannerScan><name>SecOps-AutoScan-${Date.now()}</name><type>IP</type><target><userInput>${target}</userInput></target></ScannerScan></data></ServiceRequest>`;
    const launchR = await axios.post(`${base}/qps/rest/2.0/launch/was/wasscanner`, launchBody, { headers });
    return { tool: "qualys", success: true, launched: true, raw: String(launchR.data).slice(0, 2000) };
  } catch(e) {
    return { tool: "qualys", success: false, error: e.message };
  }
}

async function runKaliScan(target, profile, customCmd) {
  const creds = await getIntegrationCreds("kali").catch(() => null);
  if (!creds) return { tool: "kali", success: false, error: "Kali not configured in Settings" };
  // SSH to Kali and run command
  const sshBase = `ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -p ${creds.port || 22} ${creds.username}@${creds.host}`;
  const cmd = customCmd || (profile === "web"
    ? `nikto -h ${target} 2>&1 | head -100`
    : `nmap -sV -sC --script vuln -T4 ${target} 2>&1 | head -200`);
  try {
    const { stdout } = await runShellCommand(`${sshBase} "${cmd}"`, { timeout: 300000, ignoreError: true });
    return { tool: "kali", success: true, output: stdout.slice(0, 8000), command: cmd };
  } catch(e) {
    return { tool: "kali", success: false, error: e.message };
  }
}

async function analyzeWithClaude(scanResults, target) {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) return "Claude AI analysis requires ANTHROPIC_API_KEY environment variable. Add it to your .env file to enable AI-powered scan analysis.";
  const summary = JSON.stringify(scanResults, null, 2).slice(0, 12000);
  try {
    const r = await axios.post("https://api.anthropic.com/v1/messages", {
      model: "claude-haiku-4-5-20251001",
      max_tokens: 2048,
      messages: [{
        role: "user",
        content: `You are a cybersecurity expert. Analyze the following vulnerability scan results for target: ${target}\n\nScan Results:\n${summary}\n\nProvide:\n1. **Executive Summary** (2-3 sentences)\n2. **Critical Findings** (list the most severe issues)\n3. **Attack Surface Analysis** (what's exposed and how risky)\n4. **Top 5 Remediation Priorities** (numbered, actionable)\n5. **Risk Rating**: Overall risk level (Critical/High/Medium/Low) with justification\n\nBe concise and actionable. Focus on business risk.`
      }],
      system: "You are a senior cybersecurity analyst providing clear, concise vulnerability assessment reports for a security operations dashboard."
    }, {
      headers: { "x-api-key": apiKey, "anthropic-version": "2023-06-01", "Content-Type": "application/json" }
    });
    return r.data.content?.[0]?.text || "No analysis returned.";
  } catch(e) {
    return `Claude AI analysis failed: ${e.message}`;
  }
}

// Helper to get integration credentials by tool name
async function getIntegrationCreds(tool) {
  const r = await pool.query("SELECT credentials FROM integrations WHERE tool=$1", [tool]);
  if (!r.rows.length) throw new Error(`${tool} not configured`);
  return r.rows[0].credentials || {};
}

// POST /api/vuln/scan — launch a new scan job
app.post("/api/vuln/scan", requireAuth, async (req, res) => {
  const { target, scan_type = "standard", tools = ["nmap"] } = req.body;
  if (!target) return res.status(400).json({ error: "target is required" });
  try {
    const r = await pool.query(
      `INSERT INTO scan_jobs (target, scan_type, tools, status, created_by) VALUES ($1,$2,$3,'queued',$4) RETURNING id`,
      [target, scan_type, JSON.stringify(tools), req.user.username]
    );
    const jobId = r.rows[0].id;
    res.json({ ok: true, job_id: jobId });
    // Run scan async
    (async () => {
      await updateScanJob(jobId, { status: "running", started_at: new Date(), progress: 5 });
      const results = {};
      const toolList = Array.isArray(tools) ? tools : [tools];
      const step = Math.floor(80 / toolList.length);
      let prog = 10;
      for (const t of toolList) {
        await updateScanJob(jobId, { progress: prog });
        if (t === "nmap")     results.nmap     = await runNmapScan(target, scan_type);
        if (t === "zaproxy")  results.zaproxy  = await runZAPScan(target, scan_type);
        if (t === "nessus")   results.nessus   = await runNessusScan(target);
        if (t === "qualys")   results.qualys   = await runQualysScan(target);
        if (t === "kali")     results.kali     = await runKaliScan(target, scan_type);
        prog += step;
      }
      await updateScanJob(jobId, { progress: 90 });
      const aiAnalysis = await analyzeWithClaude(results, target);
      await updateScanJob(jobId, {
        status: "completed", progress: 100,
        completed_at: new Date(),
        results: JSON.stringify(results),
        ai_analysis: aiAnalysis,
      });
    })().catch(async (e) => {
      await updateScanJob(jobId, { status: "failed", error: e.message });
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// GET /api/vuln/scans — list recent scan jobs
app.get("/api/vuln/scans", requireAuth, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT id, target, scan_type, tools, status, progress, started_at, completed_at, created_at, created_by, ai_analysis,
       LEFT(error,200) as error FROM scan_jobs ORDER BY created_at DESC LIMIT 50`
    );
    res.json(r.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// GET /api/vuln/scan/:id — get full scan results + AI analysis
app.get("/api/vuln/scan/:id", requireAuth, async (req, res) => {
  try {
    const r = await pool.query("SELECT * FROM scan_jobs WHERE id=$1", [req.params.id]);
    if (!r.rows.length) return res.status(404).json({ error: "Scan not found" });
    const row = r.rows[0];
    if (typeof row.results === "string") row.results = JSON.parse(row.results || "{}");
    if (typeof row.tools === "string") row.tools = JSON.parse(row.tools || "[]");
    res.json(row);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// DELETE /api/vuln/scan/:id — delete a scan job
app.delete("/api/vuln/scan/:id", requireAuth, async (req, res) => {
  try {
    await pool.query("DELETE FROM scan_jobs WHERE id=$1", [req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// GET /api/vuln/scan/:id/pdf — generate and stream PDF report
app.get("/api/vuln/scan/:id/pdf", requireAuth, async (req, res) => {
  try {
    const r = await pool.query("SELECT * FROM scan_jobs WHERE id=$1", [req.params.id]);
    if (!r.rows.length) return res.status(404).json({ error: "Scan not found" });
    const job = r.rows[0];
    if (typeof job.results === "string") job.results = JSON.parse(job.results || "{}");
    if (typeof job.tools === "string") job.tools = JSON.parse(job.tools || "[]");

    // Build HTML report then convert via wkhtmltopdf or return HTML for browser print
    const html = buildScanReportHTML(job);
    // Try wkhtmltopdf; fall back to sending HTML with print stylesheet
    const tmpHtml = path.join(os.tmpdir(), `scan-${job.id}-${Date.now()}.html`);
    const tmpPdf  = tmpHtml.replace(".html", ".pdf");
    fs.writeFileSync(tmpHtml, html);
    try {
      await runShellCommand(`wkhtmltopdf --quiet --page-size A4 --margin-top 15mm --margin-bottom 15mm --margin-left 15mm --margin-right 15mm "${tmpHtml}" "${tmpPdf}"`, { timeout: 60000 });
      res.setHeader("Content-Type", "application/pdf");
      res.setHeader("Content-Disposition", `attachment; filename="vuln-scan-${job.id}.pdf"`);
      fs.createReadStream(tmpPdf).pipe(res).on("finish", () => {
        fs.unlink(tmpHtml, ()=>{});
        fs.unlink(tmpPdf, ()=>{});
      });
    } catch {
      // wkhtmltopdf not available — send HTML with print styles
      fs.unlink(tmpHtml, ()=>{});
      res.setHeader("Content-Type", "text/html");
      res.setHeader("Content-Disposition", `inline; filename="vuln-scan-${job.id}-report.html"`);
      res.send(html);
    }
  } catch(e) { res.status(500).json({ error: e.message }); }
});

function buildScanReportHTML(job) {
  const res = job.results || {};
  const sevColor = { Critical:"#dc2626", High:"#ea580c", Medium:"#d97706", Low:"#16a34a", Info:"#6b7280" };
  const now = new Date().toLocaleString("en-GB");
  // Count all findings
  let totalFindings = 0;
  const sections = [];
  if (res.nmap?.ports?.length) {
    totalFindings += res.nmap.ports.filter(p=>p.state==="open").length;
    sections.push(`<h2 style="color:#1e40af;border-bottom:2px solid #e5e7eb;padding-bottom:8px">Nmap Port Scan</h2>
      <table style="width:100%;border-collapse:collapse;margin-bottom:24px">
        <tr style="background:#f1f5f9"><th style="padding:8px;text-align:left">Port</th><th style="padding:8px;text-align:left">Protocol</th><th style="padding:8px;text-align:left">State</th><th style="padding:8px;text-align:left">Service</th></tr>
        ${res.nmap.ports.map(p=>`<tr style="border-bottom:1px solid #e5e7eb"><td style="padding:8px;font-family:monospace">${p.port}</td><td style="padding:8px">${p.protocol}</td><td style="padding:8px;color:${p.state==="open"?"#dc2626":"#16a34a"};font-weight:700">${p.state}</td><td style="padding:8px">${p.service}</td></tr>`).join("")}
      </table>${res.nmap.os ? `<p><strong>OS Detection:</strong> ${res.nmap.os}</p>` : ""}`);
  }
  if (res.zaproxy?.alerts?.length) {
    totalFindings += res.zaproxy.alerts.length;
    sections.push(`<h2 style="color:#1e40af;border-bottom:2px solid #e5e7eb;padding-bottom:8px">OWASP ZAProxy – Web Application Scan</h2>
      <table style="width:100%;border-collapse:collapse;margin-bottom:24px">
        <tr style="background:#f1f5f9"><th style="padding:8px;text-align:left">Risk</th><th style="padding:8px;text-align:left">Alert</th><th style="padding:8px;text-align:left">URL</th></tr>
        ${res.zaproxy.alerts.map(a=>`<tr style="border-bottom:1px solid #e5e7eb"><td style="padding:8px;color:${sevColor[a.risk]||"#6b7280"};font-weight:700">${a.risk}</td><td style="padding:8px">${a.name}</td><td style="padding:8px;font-family:monospace;font-size:11px">${(a.url||"").slice(0,80)}</td></tr>`).join("")}
      </table>`);
  }
  if (res.nessus?.vulns?.length) {
    totalFindings += res.nessus.vulns.length;
    sections.push(`<h2 style="color:#1e40af;border-bottom:2px solid #e5e7eb;padding-bottom:8px">Nessus Vulnerability Scan</h2>
      <table style="width:100%;border-collapse:collapse;margin-bottom:24px">
        <tr style="background:#f1f5f9"><th style="padding:8px;text-align:left">Severity</th><th style="padding:8px;text-align:left">Plugin</th><th style="padding:8px;text-align:left">Count</th></tr>
        ${res.nessus.vulns.map(v=>`<tr style="border-bottom:1px solid #e5e7eb"><td style="padding:8px;color:${sevColor[v.severity]||"#6b7280"};font-weight:700">${v.severity}</td><td style="padding:8px">${v.name}</td><td style="padding:8px">${v.count}</td></tr>`).join("")}
      </table>`);
  }
  if (res.kali?.output) {
    sections.push(`<h2 style="color:#1e40af;border-bottom:2px solid #e5e7eb;padding-bottom:8px">Kali Linux Scan Output</h2>
      <pre style="background:#f8fafc;padding:16px;border-radius:8px;font-size:11px;overflow:auto;white-space:pre-wrap">${res.kali.output.slice(0,4000)}</pre>`);
  }
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Vulnerability Assessment Report</title>
  <style>body{font-family:Arial,sans-serif;margin:0;padding:32px;color:#1f2937;font-size:13px}
  h1{color:#1e40af}table{width:100%;border-collapse:collapse}th{background:#f1f5f9;text-align:left;padding:8px}
  @media print{body{padding:0}}</style></head><body>
  <div style="border-bottom:3px solid #1e40af;margin-bottom:24px;padding-bottom:16px">
    <h1 style="margin:0;font-size:24px">🛡️ Vulnerability Assessment Report</h1>
    <div style="color:#6b7280;margin-top:8px">Target: <strong>${job.target}</strong> &nbsp;|&nbsp; Scan Type: <strong>${job.scan_type}</strong> &nbsp;|&nbsp; Generated: <strong>${now}</strong> &nbsp;|&nbsp; Tools: <strong>${(job.tools||[]).join(", ")}</strong></div>
  </div>
  <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:32px">
    <div style="padding:16px;background:#fef2f2;border-radius:8px;border-left:4px solid #dc2626"><div style="font-size:28px;font-weight:800;color:#dc2626">${totalFindings}</div><div style="color:#6b7280;font-size:12px">Total Findings</div></div>
    <div style="padding:16px;background:#f0fdf4;border-radius:8px;border-left:4px solid #16a34a"><div style="font-size:28px;font-weight:800;color:#16a34a">${(job.tools||[]).length}</div><div style="color:#6b7280;font-size:12px">Tools Used</div></div>
    <div style="padding:16px;background:#eff6ff;border-radius:8px;border-left:4px solid #1e40af"><div style="font-size:28px;font-weight:800;color:#1e40af">${job.status}</div><div style="color:#6b7280;font-size:12px">Scan Status</div></div>
  </div>
  ${job.ai_analysis ? `<div style="background:#eff6ff;border:1px solid #bfdbfe;border-radius:10px;padding:20px;margin-bottom:32px">
    <h2 style="color:#1e40af;margin-top:0">🤖 AI Security Analysis (Claude)</h2>
    <div style="white-space:pre-wrap;line-height:1.6">${job.ai_analysis}</div>
  </div>` : ""}
  ${sections.join("")}
  <div style="margin-top:32px;padding-top:16px;border-top:1px solid #e5e7eb;color:#9ca3af;font-size:11px;text-align:center">
    Generated by SecOps Dashboard &nbsp;|&nbsp; ${now} &nbsp;|&nbsp; CONFIDENTIAL – For internal use only
  </div></body></html>`;
}
