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
  // First try Docker-internal ZAProxy container; fall back to user-configured creds
  const creds = await getCreds("zaproxy").catch(() => null);
  const zapUrl = (creds?.host && creds.host !== "localhost")
    ? `http://${creds.host}:${creds.port || 8080}`
    : ZAP_URL;
  const apiKey = creds?.api_key || ZAP_API_KEY;
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

// ── ZAProxy ───────────────────────────────────────────────────────────────
const ZAP_URL     = process.env.ZAP_URL     || "http://zaproxy:8080";
const ZAP_API_KEY = process.env.ZAP_API_KEY || "secops-zap-key";

// ── Kali SSH — connect to external Kali server via SSH ────────────────────
const { Client: SshClient } = require("ssh2");

// Read Kali SSH credentials from DB (stored via Settings → Kali integration)
// Falls back to env vars for initial bootstrap
async function getKaliCreds() {
  try {
    const r = await pool.query(
      "SELECT creds FROM credentials WHERE tool='kali' LIMIT 1"
    );
    if (r.rows.length) {
      const c = r.rows[0].creds;
      return {
        host:     c.host     || process.env.KALI_HOST || "192.168.101.6",
        port:     parseInt(c.port || process.env.KALI_PORT || "22"),
        username: c.username || process.env.KALI_USER || "kali",
        password: c.password || process.env.KALI_PASS || "kali",
      };
    }
  } catch(e) {}
  return {
    host:     process.env.KALI_HOST || "192.168.101.6",
    port:     parseInt(process.env.KALI_PORT || "22"),
    username: process.env.KALI_USER || "kali",
    password: process.env.KALI_PASS || "kali",
  };
}

// Execute a command on the remote Kali server via SSH
function sshExec(creds, command, timeoutMs = 300000) {
  return new Promise((resolve) => {
    const conn = new SshClient();
    let stdout = "", stderr = "";
    let done = false;

    const finish = (timedOut = false) => {
      if (done) return;
      done = true;
      conn.end();
      resolve({ stdout, stderr, timedOut, success: !timedOut && stderr.length < stdout.length + 1 });
    };

    const timer = setTimeout(() => finish(true), timeoutMs);

    conn.on("ready", () => {
      conn.exec(command, (err, stream) => {
        if (err) { clearTimeout(timer); finish(); return; }
        stream.on("data", d => { stdout += d.toString(); });
        stream.stderr.on("data", d => { stderr += d.toString(); });
        stream.on("close", () => { clearTimeout(timer); finish(); });
      });
    });
    conn.on("error", () => { clearTimeout(timer); finish(); });
    conn.connect({ ...creds, readyTimeout: 15000, keepaliveInterval: 10000 });
  });
}

// Tool command templates — adjusted per profile
const KALI_CMDS = {
  nmap:     { quick:"nmap -F --open -T4 {t}",      standard:"nmap -sV --open -T4 {t}",      deep:"nmap -sV -sC -O --open -T4 {t}" },
  nikto:    { quick:"nikto -h {t} -Tuning x 6",    standard:"nikto -h {t}",                 deep:"nikto -h {t} -Tuning 1234567890ab" },
  gobuster: { quick:"gobuster dir -u http://{t} -w /usr/share/wordlists/dirb/common.txt -q --no-error -t 20",
              standard:"gobuster dir -u http://{t} -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -q --no-error -t 30",
              deep:"gobuster dir -u http://{t} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -q --no-error -t 50" },
  sslscan:  { quick:"sslscan --no-colour {t}", standard:"sslscan --no-colour {t}", deep:"sslscan --no-colour --show-certificate {t}" },
  sqlmap:   { quick:"sqlmap -u 'http://{t}' --batch --level=1 --risk=1 --forms -q",
              standard:"sqlmap -u 'http://{t}' --batch --level=2 --risk=2 --forms -q",
              deep:"sqlmap -u 'http://{t}' --batch --level=3 --risk=3 --forms -q" },
  whatweb:  { quick:"whatweb {t} --log-brief=/dev/stdout 2>/dev/null",
              standard:"whatweb -a 3 {t} --log-brief=/dev/stdout 2>/dev/null",
              deep:"whatweb -a 4 {t} --log-brief=/dev/stdout 2>/dev/null" },
  masscan:  { quick:"masscan {t} -p80,443,22,21,8080,8443 --rate=500 2>/dev/null",
              standard:"masscan {t} -p1-10000 --rate=1000 2>/dev/null",
              deep:"masscan {t} -p1-65535 --rate=2000 2>/dev/null" },
  dnsenum:  { quick:"dnsenum --noreverse --nocolor {t} 2>/dev/null",
              standard:"dnsenum --nocolor {t} 2>/dev/null",
              deep:"dnsenum --nocolor --threads 5 {t} 2>/dev/null" },
};

// Parse structured output from each tool
function parseKaliOutput(tool, raw) {
  const out = raw.stdout || "";
  const base = { tool, success: true, output: out.slice(0, 8000) };
  try {
    if (tool === "nmap") {
      const ports = [];
      for (const line of out.split("\n")) {
        const m = line.match(/^(\d+)\/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)(?:\s+(.*))?/);
        if (m) ports.push({ port: m[1], protocol: m[2], state: m[3], service: m[4], version: (m[5]||"").trim() });
      }
      const osMatch = out.match(/OS details?: (.+)/i);
      return { ...base, open_ports: ports.filter(p=>p.state==="open"), os_guess: osMatch?.[1] || null };
    }
    if (tool === "nikto") {
      const findings = [];
      for (const line of out.split("\n")) {
        if (line.startsWith("+ ") && !line.startsWith("+ Target") && !line.startsWith("+ Start") && !line.startsWith("+ End") && !line.includes("requests:")) {
          findings.push({ msg: line.slice(2).trim() });
        }
      }
      const serverMatch = out.match(/\+ Server: (.+)/);
      return { ...base, findings, server: serverMatch?.[1] || null };
    }
    if (tool === "gobuster") {
      const found_paths = [];
      for (const line of out.split("\n")) {
        const m = line.match(/^(\/\S+)\s+\(Status:\s*(\d+)\)(?:.*\[Size:\s*(\d+)\])?/);
        if (m) found_paths.push({ path: m[1], status: parseInt(m[2]), size: m[3] ? parseInt(m[3]) : null });
      }
      return { ...base, found_paths };
    }
    if (tool === "sslscan") {
      const issues = [];
      if (/SSLv2|SSLv3|TLSv1\.0|TLSv1\.1/.test(out)) issues.push({ description: "Weak/deprecated protocol enabled" });
      if (/RC4|DES|NULL|EXPORT|anon/.test(out))        issues.push({ description: "Weak cipher suite detected" });
      if (/Self-signed/.test(out))                     issues.push({ description: "Self-signed certificate" });
      if (/expired/i.test(out))                        issues.push({ description: "Certificate expired" });
      const protocols = (out.match(/TLSv[\d.]+|SSLv[\d.]+/g) || []).filter((v,i,a)=>a.indexOf(v)===i);
      const certSubj  = (out.match(/Subject:\s+(.+)/)||[])[1] || null;
      const certIssue = (out.match(/Issuer:\s+(.+)/)||[])[1] || null;
      const certExp   = (out.match(/Not valid after:\s+(.+)/)||[])[1] || null;
      return { ...base, issues, supported_protocols: protocols,
               certificate: certSubj ? { subject: certSubj, issuer: certIssue, expiry: certExp } : null };
    }
    if (tool === "sqlmap") {
      const vulnerable = /is vulnerable|Parameter.*is vulnerable|sqlmap identified/i.test(out);
      const params = (out.match(/Parameter: (\S+) \(/g)||[]).map(m=>m.replace(/Parameter: | \($/g,""));
      return { ...base, vulnerable, injectable_params: params };
    }
    if (tool === "whatweb") {
      const tech = {};
      const m = out.match(/\[(.+?)\]/g) || [];
      m.forEach(t => { const [k,...v]=t.slice(1,-1).split(" "); tech[k]=(v.join(" ")||"detected"); });
      return { ...base, tech };
    }
    if (tool === "masscan") {
      const open_ports = [];
      for (const line of out.split("\n")) {
        const m = line.match(/Discovered open port (\d+)\/(tcp|udp)/);
        if (m) open_ports.push({ port: m[1], protocol: m[2], state: "open", service: "" });
      }
      return { ...base, open_ports };
    }
    if (tool === "dnsenum") {
      const hostnames = (out.match(/^\S+\.\S+\s+\d+\s+IN\s+A\s+\S+/gm)||[]).map(l=>l.split(/\s+/)[0]);
      return { ...base, hostnames };
    }
  } catch(e) {}
  return base;
}

async function runKali(target, profile, selectedTools) {
  const tools = Array.isArray(selectedTools) && selectedTools.length
    ? selectedTools : ["nmap", "nikto", "sslscan", "whatweb"];

  const creds = await getKaliCreds();
  const results = {};

  for (const t of tools) {
    try {
      const tpl = KALI_CMDS[t];
      if (!tpl) { results[t] = { tool:t, success:false, error:`Unknown tool: ${t}` }; continue; }
      const cmd = (tpl[profile] || tpl.standard).replace(/\{t\}/g, target);
      const timeoutMs = profile==="quick" ? 120000 : profile==="deep" ? 540000 : 300000;
      const raw = await sshExec(creds, cmd, timeoutMs);
      results[t] = parseKaliOutput(t, raw);
      if (raw.timedOut) results[t].warning = "Command timed out — partial results";
    } catch(e) {
      results[t] = { tool:t, success:false, error:e.message };
    }
  }

  const summary = Object.entries(results)
    .map(([t,r]) => `=== ${t.toUpperCase()} ===\n${(r.output || r.error || "no output").slice(0,3000)}`)
    .join("\n\n");

  return {
    tool: "kali",
    success: Object.values(results).some(r => r.success !== false),
    tools_run: tools,
    tool_results: results,
    output: summary.slice(0, 15000),
  };
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
    // Also check Kali SSH
    const kaliCreds = await getKaliCreds();
    const kaliOk = await sshExec(kaliCreds, "echo ok", 8000)
      .then(r => r.stdout.includes("ok")).catch(() => false);
    // Also check ZAProxy
    const zapOk = await axios.get(`${ZAP_URL}/JSON/core/view/version/?apikey=${ZAP_API_KEY}`, { timeout: 5000 })
      .then(() => true).catch(() => false);
    res.json({ ok: true, service: "vuln-assessment", port: PORT,
               kali_agent: kaliOk, zaproxy: zapOk });
  } catch(e) { res.status(503).json({ ok: false, error: e.message }); }
});

/* ── Kali SSH tool list ───────────────────────────────────────────────────── */
app.get("/api/vuln/kali/tools", requireAuth, async (req, res) => {
  const tools = {};
  for (const [name, profiles] of Object.entries(KALI_CMDS)) {
    tools[name] = { profiles: Object.keys(profiles), description: name };
  }
  res.json({ ok: true, tools, mode: "ssh" });
});

/* ── Kali SSH health check ────────────────────────────────────────────────── */
app.get("/api/vuln/kali/health", async (req, res) => {
  try {
    const creds = await getKaliCreds();
    const result = await sshExec(creds, "echo ok && uname -a && which nmap nikto gobuster sslscan sqlmap 2>/dev/null | wc -l", 12000);
    const toolCount = parseInt((result.stdout.match(/^(\d+)/m)||["0"])[0]);
    const ok = result.stdout.includes("ok") && !result.timedOut;
    const info = result.stdout.split("\n").filter(Boolean);
    res.json({
      kali: {
        ok,
        host: creds.host,
        mode: "ssh",
        uname: info[1] || null,
        tools_available: toolCount || Object.keys(KALI_CMDS).length,
      },
      ok,
    });
  } catch(e) {
    res.status(503).json({ kali: { ok: false }, ok: false, error: e.message });
  }
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
      const kaliTools = req.body.kali_tools || null; // optional sub-tool list for Kali agent
      const step = Math.floor(80 / toolList.length);
      let prog = 10;
      for (const t of toolList) {
        await updateJob(jobId, { progress: prog });
        if (t === "nmap")    results.nmap    = await runNmap(target, scan_type);
        if (t === "zaproxy") results.zaproxy = await runZAP(target, scan_type);
        if (t === "nessus")  results.nessus  = await runNessus(target);
        if (t === "qualys")  results.qualys  = await runQualys(target);
        if (t === "kali")    results.kali    = await runKali(target, scan_type, kaliTools);
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
