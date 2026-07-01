/**
 * Vulnerability Assessment Microservice — port 4002
 * Orchestrates Nmap, OWASP ZAProxy, Nessus, Qualys, Kali Linux scans
 * Claude AI analysis of combined results + PDF report export
 */
const express      = require("express");
const cors         = require("cors");
const { Pool }     = require("pg");
const axios        = require("axios");
const https        = require("https");
const jwt          = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const { exec }     = require("child_process");
const fs           = require("fs");
const path         = require("path");
const os           = require("os");

const PORT       = process.env.VULN_PORT || 4002;
const JWT_SECRET = process.env.JWT_SECRET || "secops-jwt-secret-change-in-prod";

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());

const pool = new Pool({
  host:     process.env.POSTGRES_HOST     || "postgres",
  port:     parseInt(process.env.POSTGRES_PORT || "5432"),
  database: process.env.POSTGRES_DB       || "secops",
  user:     process.env.POSTGRES_USER     || "secops",
  password: process.env.POSTGRES_PASSWORD || "secops_pass",
});

/* ── Auth ─────────────────────────────────────────────────────────────────── */
function requireAuth(req, res, next) {
  const token = req.cookies?.session || req.headers.authorization?.replace("Bearer ", "");
  if (!token) return res.status(401).json({ error: "Authentication required" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Session expired" });
  }
}

/* ── DB Setup ─────────────────────────────────────────────────────────────── */
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

/* ── Helpers ──────────────────────────────────────────────────────────────── */
function runCmd(cmd, opts = {}) {
  return new Promise((resolve, reject) => {
    exec(cmd, { timeout: opts.timeout || 300000, ...opts }, (err, stdout, stderr) => {
      if (err && !opts.ignoreError) reject(new Error(stderr || err.message));
      else resolve({ stdout: stdout || "", stderr: stderr || "" });
    });
  });
}

async function updateJob(id, fields) {
  const sets = Object.keys(fields).map((k, i) => `${k}=$${i + 2}`).join(", ");
  await pool.query(`UPDATE scan_jobs SET ${sets} WHERE id=$1`, [id, ...Object.values(fields)]).catch(() => {});
}

async function getCreds(tool) {
  const r = await pool.query("SELECT credentials FROM integrations WHERE tool_name=$1", [tool]);
  if (!r.rows.length) throw new Error(`${tool} not configured in Settings`);
  return r.rows[0].credentials || {};
}

/* ── Scan Engines ─────────────────────────────────────────────────────────── */
async function runNmap(target, profile) {
  const flags = {
    quick:    `-sV -T4 --top-ports 100`,
    deep:     `-sV -sC -O -A --script vuln -T4`,
    standard: `-sV -sC -T4 --top-ports 1000`,
  }[profile] || `-sV -sC -T4 --top-ports 1000`;
  try {
    const { stdout } = await runCmd(`nmap ${flags} ${target} 2>&1`, { timeout: 600000, ignoreError: true });
    const ports = [];
    const rx = /^(\d+)\/(tcp|udp)\s+(\w+)\s+(.*)$/gm;
    let m;
    while ((m = rx.exec(stdout)) !== null) {
      ports.push({ port: parseInt(m[1]), protocol: m[2], state: m[3], service: m[4].trim() });
    }
    const osMatch = stdout.match(/OS details: (.+)/);
    return { tool:"nmap", success:true, ports, os: osMatch?.[1] || null, raw: stdout.slice(0, 8000) };
  } catch(e) {
    return { tool:"nmap", success:false, error: e.message };
  }
}

async function runZAP(target, profile) {
  const creds = await getCreds("zaproxy").catch(() => null);
  if (!creds) return { tool:"zaproxy", success:false, error:"ZAProxy not configured in Settings" };
  const zapUrl = `http://${creds.host || "localhost"}:${creds.port || 8080}`;
  const apiKey = creds.api_key || "";
  try {
    await axios.get(`${zapUrl}/JSON/spider/action/scan/?apikey=${apiKey}&url=${encodeURIComponent(target)}&maxChildren=10`);
    await new Promise(r => setTimeout(r, profile === "quick" ? 15000 : 30000));
    const scanR = await axios.get(`${zapUrl}/JSON/ascan/action/scan/?apikey=${apiKey}&url=${encodeURIComponent(target)}&recurse=true`);
    const scanId = scanR.data?.scan;
    const deadline = Date.now() + 180000;
    while (Date.now() < deadline) {
      const st = await axios.get(`${zapUrl}/JSON/ascan/view/status/?apikey=${apiKey}&scanId=${scanId}`);
      if (parseInt(st.data?.status) >= 100) break;
      await new Promise(r => setTimeout(r, 5000));
    }
    const alertsR = await axios.get(`${zapUrl}/JSON/alert/view/alerts/?apikey=${apiKey}&baseurl=${encodeURIComponent(target)}&start=0&count=200`);
    const alerts = (alertsR.data?.alerts || []).map(a => ({
      name: a.alert, risk: a.risk, confidence: a.confidence,
      url: a.url, description: a.description?.slice(0, 300), solution: a.solution?.slice(0, 300),
      cweid: a.cweid, wascid: a.wascid,
    }));
    return { tool:"zaproxy", success:true, alerts, alertCount: alerts.length };
  } catch(e) {
    return { tool:"zaproxy", success:false, error: e.message };
  }
}

async function runNessus(target) {
  const creds = await getCreds("nessus").catch(() => null);
  if (!creds) return { tool:"nessus", success:false, error:"Nessus not configured in Settings" };
  const base = `https://${creds.host || "localhost"}:${creds.port || 8834}`;
  const agent = new https.Agent({ rejectUnauthorized: false });
  try {
    const loginR = await axios.post(`${base}/session`,
      { username: creds.username, password: creds.password },
      { httpsAgent: agent, headers: { "Content-Type": "application/json" } }
    );
    const token = loginR.data.token;
    const authH = { "X-Cookie": `token=${token}`, "Content-Type": "application/json" };
    const createR = await axios.post(`${base}/scans`, {
      uuid: "ad629e16-7ef5-4db9-b2b0-7c769f8c98a1",
      settings: { name: `SecOps-VulnScan-${Date.now()}`, text_targets: target, launch: "ON_DEMAND" }
    }, { httpsAgent: agent, headers: authH });
    const scanId = createR.data?.scan?.id;
    await axios.post(`${base}/scans/${scanId}/launch`, {}, { httpsAgent: agent, headers: authH });
    const deadline = Date.now() + 300000;
    while (Date.now() < deadline) {
      const sR = await axios.get(`${base}/scans/${scanId}`, { httpsAgent: agent, headers: authH });
      if (["completed","canceled"].includes(sR.data?.info?.status)) break;
      await new Promise(r => setTimeout(r, 10000));
    }
    const rptR = await axios.get(`${base}/scans/${scanId}`, { httpsAgent: agent, headers: authH });
    const vulns = (rptR.data?.vulnerabilities || []).map(v => ({
      plugin_id: v.plugin_id, name: v.plugin_name,
      severity: ["Info","Low","Medium","High","Critical"][v.severity] || "Unknown",
      count: v.count,
    }));
    await axios.delete(`${base}/session`, { httpsAgent: agent, headers: authH }).catch(() => {});
    return { tool:"nessus", success:true, vulns, vulnCount: vulns.length };
  } catch(e) {
    return { tool:"nessus", success:false, error: e.message };
  }
}

async function runQualys(target) {
  const creds = await getCreds("qualys").catch(() => null);
  if (!creds) return { tool:"qualys", success:false, error:"Qualys not configured in Settings" };
  const base = `https://${creds.platform || "qualysapi.qualys.com"}`;
  const auth  = Buffer.from(`${creds.username}:${creds.password}`).toString("base64");
  try {
    const body = `action=launch&scan_title=SecOps-AutoScan-${Date.now()}&target_from=assets&ip=${encodeURIComponent(target)}&option_id=1`;
    const r = await axios.post(`${base}/api/2.0/fo/scan/`, body, {
      headers: { Authorization:`Basic ${auth}`, "X-Requested-With":"SecOpsDashboard", "Content-Type":"application/x-www-form-urlencoded" }
    });
    return { tool:"qualys", success:true, launched:true, ref: String(r.data).match(/scan_ref>([\w/.-]+)/)?.[1] || null };
  } catch(e) {
    return { tool:"qualys", success:false, error: e.message };
  }
}

async function runKali(target, profile, customCmd) {
  const creds = await getCreds("kali").catch(() => null);
  if (!creds) return { tool:"kali", success:false, error:"Kali Linux not configured in Settings" };
  const sshBase = `ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -p ${creds.port || 22} ${creds.username}@${creds.host}`;
  const cmd = customCmd || (profile === "web"
    ? `nikto -h ${target} 2>&1 | head -100`
    : `nmap -sV -sC --script vuln -T4 ${target} 2>&1 | head -200`);
  try {
    const { stdout } = await runCmd(`${sshBase} "${cmd}"`, { timeout: 300000, ignoreError: true });
    return { tool:"kali", success:true, output: stdout.slice(0, 8000), command: cmd };
  } catch(e) {
    return { tool:"kali", success:false, error: e.message };
  }
}

async function analyzeWithClaude(results, target) {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) return "Claude AI analysis requires ANTHROPIC_API_KEY in environment variables. Add it to your .env file.";
  try {
    const r = await axios.post("https://api.anthropic.com/v1/messages", {
      model: "claude-haiku-4-5-20251001",
      max_tokens: 2048,
      messages: [{
        role: "user",
        content: `You are a cybersecurity expert. Analyse these vulnerability scan results for: ${target}\n\n${JSON.stringify(results, null, 2).slice(0, 12000)}\n\nProvide:\n1. **Executive Summary** (2-3 sentences)\n2. **Critical Findings** (most severe issues)\n3. **Attack Surface Analysis** (what is exposed and how risky)\n4. **Top 5 Remediation Priorities** (numbered, actionable)\n5. **Overall Risk Rating** (Critical/High/Medium/Low with justification)`
      }],
      system: "You are a senior cybersecurity analyst providing concise vulnerability assessment reports."
    }, {
      headers: { "x-api-key": apiKey, "anthropic-version": "2023-06-01", "Content-Type": "application/json" }
    });
    return r.data.content?.[0]?.text || "No analysis returned.";
  } catch(e) {
    return `Claude AI analysis failed: ${e.message}`;
  }
}

/* ── PDF/HTML Report Builder ─────────────────────────────────────────────── */
function buildReportHTML(job) {
  const res = job.results || {};
  const now = new Date().toLocaleString("en-GB");
  const sevColor = { Critical:"#dc2626", High:"#ea580c", Medium:"#d97706", Low:"#16a34a", Info:"#6b7280" };
  let totalFindings = 0;
  const sections = [];

  if (res.nmap?.ports?.length) {
    const open = res.nmap.ports.filter(p => p.state === "open");
    totalFindings += open.length;
    sections.push(`
      <h2>🗺️ Nmap Port Scan Results</h2>
      ${res.nmap.os ? `<p><strong>OS Detection:</strong> ${res.nmap.os}</p>` : ""}
      <table>
        <tr><th>Port</th><th>Protocol</th><th>State</th><th>Service</th></tr>
        ${open.map(p=>`<tr><td class="mono">${p.port}/${p.protocol}</td><td>${p.protocol}</td><td style="color:#dc2626;font-weight:700">${p.state}</td><td>${p.service}</td></tr>`).join("")}
      </table>`);
  }
  if (res.zaproxy?.alerts?.length) {
    totalFindings += res.zaproxy.alerts.length;
    sections.push(`
      <h2>🕷️ OWASP ZAProxy — Web Application Vulnerabilities</h2>
      <table>
        <tr><th>Risk</th><th>Alert</th><th>URL</th><th>CWE</th></tr>
        ${res.zaproxy.alerts.map(a=>`<tr><td style="color:${sevColor[a.risk]||"#6b7280"};font-weight:700">${a.risk}</td><td>${a.name}</td><td class="mono small">${(a.url||"").slice(0,80)}</td><td>${a.cweid||"—"}</td></tr>`).join("")}
      </table>`);
  }
  if (res.nessus?.vulns?.length) {
    totalFindings += res.nessus.vulns.length;
    const sorted = [...res.nessus.vulns].sort((a,b)=>["Critical","High","Medium","Low","Info"].indexOf(a.severity)-["Critical","High","Medium","Low","Info"].indexOf(b.severity));
    sections.push(`
      <h2>🔬 Nessus Vulnerability Results</h2>
      <table>
        <tr><th>Severity</th><th>Vulnerability</th><th>Count</th></tr>
        ${sorted.map(v=>`<tr><td style="color:${sevColor[v.severity]||"#6b7280"};font-weight:700">${v.severity}</td><td>${v.name}</td><td>${v.count}</td></tr>`).join("")}
      </table>`);
  }
  if (res.kali?.output) {
    sections.push(`
      <h2>🐉 Kali Linux Scan Output</h2>
      <pre>${res.kali.output.slice(0, 4000)}</pre>`);
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Vulnerability Assessment Report — ${job.target}</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 0; padding: 32px; color: #1f2937; font-size: 13px; }
    h1   { color: #1e40af; margin: 0 0 8px; font-size: 22px; }
    h2   { color: #1e40af; border-bottom: 2px solid #e5e7eb; padding-bottom: 8px; margin-top: 32px; }
    table { width: 100%; border-collapse: collapse; margin-bottom: 24px; }
    th  { background: #f1f5f9; padding: 8px 12px; text-align: left; font-size: 11px; text-transform: uppercase; }
    td  { padding: 8px 12px; border-bottom: 1px solid #e5e7eb; }
    pre { background: #0f172a; color: #e2e8f0; padding: 16px; border-radius: 8px; font-size: 11px; white-space: pre-wrap; overflow: auto; }
    .mono  { font-family: monospace; }
    .small { font-size: 11px; }
    .summary { display: flex; gap: 16px; margin: 24px 0; }
    .card    { flex: 1; padding: 16px; border-radius: 8px; text-align: center; }
    .ai-box  { background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 10px; padding: 20px; margin: 24px 0; }
    .ai-box h2 { border: none; color: #1e40af; margin-top: 0; }
    .header-bar { border-bottom: 3px solid #1e40af; margin-bottom: 24px; padding-bottom: 16px; }
    .meta { color: #6b7280; margin-top: 8px; font-size: 12px; }
    .footer { margin-top: 32px; padding-top: 16px; border-top: 1px solid #e5e7eb; color: #9ca3af; font-size: 11px; text-align: center; }
    @media print { body { padding: 0; } }
  </style>
</head>
<body>
  <div class="header-bar">
    <h1>🛡️ Vulnerability Assessment Report</h1>
    <div class="meta">
      <strong>Target:</strong> ${job.target} &nbsp;|&nbsp;
      <strong>Scan Type:</strong> ${job.scan_type} &nbsp;|&nbsp;
      <strong>Tools:</strong> ${(job.tools || []).join(", ")} &nbsp;|&nbsp;
      <strong>Generated:</strong> ${now}
    </div>
  </div>

  <div class="summary">
    <div class="card" style="background:#fef2f2;border-left:4px solid #dc2626">
      <div style="font-size:28px;font-weight:800;color:#dc2626">${totalFindings}</div>
      <div style="color:#6b7280;font-size:12px">Total Findings</div>
    </div>
    <div class="card" style="background:#f0fdf4;border-left:4px solid #16a34a">
      <div style="font-size:28px;font-weight:800;color:#16a34a">${(job.tools || []).length}</div>
      <div style="color:#6b7280;font-size:12px">Tools Used</div>
    </div>
    <div class="card" style="background:#eff6ff;border-left:4px solid #1e40af">
      <div style="font-size:28px;font-weight:800;color:#1e40af">${job.status}</div>
      <div style="color:#6b7280;font-size:12px">Scan Status</div>
    </div>
    <div class="card" style="background:#fffbeb;border-left:4px solid #d97706">
      <div style="font-size:28px;font-weight:800;color:#d97706">${job.scan_type}</div>
      <div style="color:#6b7280;font-size:12px">Scan Profile</div>
    </div>
  </div>

  ${job.ai_analysis ? `
  <div class="ai-box">
    <h2>🤖 Claude AI Security Analysis</h2>
    <div style="white-space:pre-wrap;line-height:1.8">${job.ai_analysis}</div>
  </div>` : ""}

  ${sections.join("\n")}

  <div class="footer">
    Generated by SecOps Vulnerability Assessment Service &nbsp;|&nbsp; ${now} &nbsp;|&nbsp;
    <strong>CONFIDENTIAL — For internal use only</strong>
  </div>
</body>
</html>`;
}

/* ── Health ───────────────────────────────────────────────────────────────── */
app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, service: "vuln-assessment", port: PORT });
  } catch(e) { res.status(503).json({ ok: false, error: e.message }); }
});

/* ── Scan Routes ──────────────────────────────────────────────────────────── */
app.post("/api/vuln/scan", requireAuth, async (req, res) => {
  const { target, scan_type = "standard", tools = ["nmap"] } = req.body;
  if (!target) return res.status(400).json({ error: "target is required" });
  try {
    const r = await pool.query(
      `INSERT INTO scan_jobs (target, scan_type, tools, status, created_by)
       VALUES ($1,$2,$3,'queued',$4) RETURNING id`,
      [target, scan_type, JSON.stringify(tools), req.user.username]
    );
    const jobId = r.rows[0].id;
    res.json({ ok: true, job_id: jobId });

    // Async scan execution
    (async () => {
      await updateJob(jobId, { status:"running", started_at: new Date(), progress: 5 });
      const results = {};
      const toolList = Array.isArray(tools) ? tools : [tools];
      const step = Math.floor(80 / toolList.length);
      let prog = 10;
      for (const t of toolList) {
        await updateJob(jobId, { progress: prog });
        if (t === "nmap")    results.nmap    = await runNmap(target, scan_type);
        if (t === "zaproxy") results.zaproxy = await runZAP(target, scan_type);
        if (t === "nessus")  results.nessus  = await runNessus(target);
        if (t === "qualys")  results.qualys  = await runQualys(target);
        if (t === "kali")    results.kali    = await runKali(target, scan_type);
        prog += step;
      }
      await updateJob(jobId, { progress: 90 });
      const aiAnalysis = await analyzeWithClaude(results, target);
      await updateJob(jobId, {
        status: "completed", progress: 100,
        completed_at: new Date(),
        results: JSON.stringify(results),
        ai_analysis: aiAnalysis,
      });
    })().catch(async (e) => {
      await updateJob(jobId, { status:"failed", error: e.message });
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get("/api/vuln/scans", requireAuth, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT id, target, scan_type, tools, status, progress, started_at, completed_at,
              created_at, created_by, ai_analysis, LEFT(error,200) AS error
       FROM scan_jobs ORDER BY created_at DESC LIMIT 50`
    );
    res.json(r.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get("/api/vuln/scan/:id", requireAuth, async (req, res) => {
  try {
    const r = await pool.query("SELECT * FROM scan_jobs WHERE id=$1", [req.params.id]);
    if (!r.rows.length) return res.status(404).json({ error: "Scan not found" });
    const row = r.rows[0];
    if (typeof row.results === "string") row.results = JSON.parse(row.results || "{}");
    if (typeof row.tools   === "string") row.tools   = JSON.parse(row.tools   || "[]");
    res.json(row);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete("/api/vuln/scan/:id", requireAuth, async (req, res) => {
  try {
    await pool.query("DELETE FROM scan_jobs WHERE id=$1", [req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get("/api/vuln/scan/:id/pdf", requireAuth, async (req, res) => {
  try {
    const r = await pool.query("SELECT * FROM scan_jobs WHERE id=$1", [req.params.id]);
    if (!r.rows.length) return res.status(404).json({ error: "Scan not found" });
    const job = r.rows[0];
    if (typeof job.results === "string") job.results = JSON.parse(job.results || "{}");
    if (typeof job.tools   === "string") job.tools   = JSON.parse(job.tools   || "[]");
    const html   = buildReportHTML(job);
    const tmpHtml = path.join(os.tmpdir(), `vuln-${job.id}-${Date.now()}.html`);
    const tmpPdf  = tmpHtml.replace(".html", ".pdf");
    fs.writeFileSync(tmpHtml, html);
    exec(`wkhtmltopdf --quiet --page-size A4 --margin-top 15mm --margin-bottom 15mm --margin-left 15mm --margin-right 15mm "${tmpHtml}" "${tmpPdf}"`,
      { timeout: 60000 },
      (err) => {
        fs.unlink(tmpHtml, () => {});
        if (!err && fs.existsSync(tmpPdf)) {
          res.setHeader("Content-Type", "application/pdf");
          res.setHeader("Content-Disposition", `attachment; filename="vuln-scan-${job.id}.pdf"`);
          fs.createReadStream(tmpPdf).pipe(res).on("finish", () => fs.unlink(tmpPdf, () => {}));
        } else {
          // wkhtmltopdf not available — serve printable HTML
          res.setHeader("Content-Type", "text/html");
          res.setHeader("Content-Disposition", `inline; filename="vuln-scan-${job.id}-report.html"`);
          res.send(html);
        }
      }
    );
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* ── Start ────────────────────────────────────────────────────────────────── */
app.listen(PORT, async () => {
  console.log(`Vuln Assessment Service running on :${PORT}`);
  let retries = 10;
  while (retries > 0) {
    try { await pool.query("SELECT 1"); console.log("DB connected"); break; }
    catch { retries--; await new Promise(r => setTimeout(r, 3000)); }
  }
  await ensureVulnTables().catch(e => console.error("ensureVulnTables:", e.message));
  console.log("Vuln Assessment Service ready — tools: Nmap, ZAProxy, Nessus, Qualys, Kali, Claude AI");
});
