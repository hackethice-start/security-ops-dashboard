import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, AreaChart, Area, LineChart, Line, Legend } from 'recharts';

// CybersecurityDashboard.jsx
// Production-ready SecOps Command Center — single-file React 18 + Recharts


/* ── Colour tokens ─────────────────────────────────────────────────────── */
const C = {
  primary:   "#1e40af",
  primaryLt: "#dbeafe",
  bg:        "#f1f5f9",
  card:      "#ffffff",
  sidebar:   "#0f172a",
  sidebarAc: "#1e3a5f",
  header:    "#0f172a",
  text:      "#0f172a",
  textSm:    "#475569",
  muted:     "#94a3b8",
  border:    "#e2e8f0",
  critical:  "#dc2626",
  high:      "#ea580c",
  warn:      "#d97706",
  ok:        "#16a34a",
  info:      "#2563eb",
  purple:    "#7c3aed",
};

/* ── API helpers ────────────────────────────────────────────────────────── */
const API = `http://${window.location.hostname}:4000`;
async function apiFetch(url, opts = {}) {
  return fetch(url, { credentials: "include", ...opts });
}

/* ── Severity helpers ───────────────────────────────────────────────────── */
function severityLabel(n) {
  if (n >= 5) return "Critical";
  if (n === 4) return "High";
  if (n === 3) return "Medium";
  if (n === 2) return "Low";
  return "Info";
}
function severityColor(label) {
  const m = { Critical: C.critical, High: C.high, Medium: C.warn, Low: C.ok, Info: C.info };
  return m[label] || C.muted;
}
function gradeColor(g) {
  return g === "A" ? C.ok : g === "B" ? "#65a30d" : g === "C" ? C.warn : g === "D" ? C.high : C.critical;
}

/* ── Data transformer ───────────────────────────────────────────────────── */
function transformSnapshot(raw) {
  if (!raw || typeof raw !== "object") return { _hasData: false };
  const has = (k) => !!raw[k];
  const _hasData = Object.keys(raw).length > 0;
  const _collectedAt = {};
  const _integrationStatus = {};

  // ── Firewall ──────────────────────────────────────────────────────────
  const fwInstances = [];

  if (has("fortinet")) {
    const fo = raw.fortinet;
    _integrationStatus.fortinet = "connected";
    const insts = fo.instances || [];
    insts.forEach((inst) => {
      if (inst.collectedAt) _collectedAt.fortinet = inst.collectedAt;
      const policies = inst.policies || [];
      const allowCount = policies.filter((p) => (p.action || "").toLowerCase() === "accept").length;
      const denyCount  = policies.filter((p) => (p.action || "").toLowerCase() === "deny").length;
      const enabledCount = policies.filter((p) => p.status === "enable" || p.enabled === true).length;
      const bandwidth = (inst.interfaces || []).map((iface) => ({
        name:     iface.name || iface.interface || "Unknown",
        in_bps:   iface.in_bps  || iface.rxbps  || 0,
        out_bps:  iface.out_bps || iface.txbps  || 0,
        rx_bytes: iface.rx_bytes || 0,
        tx_bytes: iface.tx_bytes || 0,
      }));
      const topApps = (inst.topApps || []).map((a) => ({
        name:     a.name || a.app || "",
        sessions: a.sessions || a.session || 0,
        bytes:    a.bytes || 0,
        risk:     a.risk || a.riskLevel || "",
      }));
      const topWebCategories = (inst.topWeb || []).map((w) => ({
        name:     w.name || w.category || "",
        sessions: w.sessions || 0,
        bytes:    w.bytes || 0,
      }));
      const cisBenchmark = (inst.stats || []).map((s, i) => ({
        id:    s.id || `CIS-${i + 1}`,
        title: s.title || s.name || `Check ${i + 1}`,
        pass:  s.pass != null ? s.pass : null,
      }));
      fwInstances.push({
        vendor:      "fortinet",
        hostname:    (inst.sysGlobal && inst.sysGlobal.hostname) || inst.host || "Fortinet",
        host:        inst.host || "",
        version:     (inst.sysGlobal && inst.sysGlobal.version) || "",
        policyCount: policies.length,
        allowCount,
        denyCount,
        enabledCount,
        bandwidth,
        topApps,
        topWebCategories,
        cisBenchmark,
        collectedAt: inst.collectedAt || "",
      });
    });
  } else {
    _integrationStatus.fortinet = "no-data";
  }

  if (has("paloalto")) {
    const pa = raw.paloalto;
    _integrationStatus.paloalto = "connected";
    if (pa.collectedAt) _collectedAt.paloalto = pa.collectedAt;
    const rules = pa.rules || [];
    const allowCount   = rules.filter((r) => (r.action || "").toLowerCase() === "allow").length;
    const denyCount    = rules.filter((r) => (r.action || "").toLowerCase() === "deny").length;
    const enabledCount = rules.filter((r) => r.disabled !== true && r.disabled !== "yes").length;
    const bandwidth = (pa.interfaces || []).map((iface) => ({
      name:     iface.name || "",
      in_bps:   iface.in_bps || 0,
      out_bps:  iface.out_bps || 0,
      rx_bytes: iface.rx_bytes || 0,
      tx_bytes: iface.tx_bytes || 0,
    }));
    fwInstances.push({
      vendor:         "paloalto",
      hostname:       (pa.sysInfo && pa.sysInfo.hostname) || "Palo Alto",
      host:           pa.host || "",
      version:        (pa.sysInfo && pa.sysInfo.version) || "",
      policyCount:    rules.length,
      allowCount,
      denyCount,
      enabledCount,
      bandwidth,
      topApps:        [],
      topWebCategories: [],
      cisBenchmark:   [],
      collectedAt:    pa.collectedAt || "",
    });
  } else {
    _integrationStatus.paloalto = "no-data";
  }

  const firewall = {
    instances:     fwInstances,
    totalDevices:  fwInstances.length,
    fortinetCount: fwInstances.filter((f) => f.vendor === "fortinet").length,
    paloAltoCount: fwInstances.filter((f) => f.vendor === "paloalto").length,
    totalPolicies: fwInstances.reduce((s, f) => s + f.policyCount, 0),
    highRiskRules: fwInstances.reduce((s, f) => s + (f.denyCount || 0), 0),
  };

  // ── Attack Surface ─────────────────────────────────────────────────────
  let surface = { score: 0, grade: "F", risks: [], criticalRisks: 0, highRisks: 0, domains: [], ips: [], domainCount: 0, ipCount: 0 };
  if (has("upguard")) {
    const ug = raw.upguard;
    _integrationStatus.upguard = "connected";
    if (ug.collectedAt) _collectedAt.upguard = ug.collectedAt;
    const bs = ug.breachsight || {};
    const rawRisks = (ug.risks && ug.risks.risks) || [];
    const risks = rawRisks.map((r) => ({
      id:            r.id || r.risk_id || "",
      finding:       r.title || r.description || r.finding || "",
      severity:      r.severity || r.risk_level || "low",
      hostnames:     r.hostnames || r.affected_hosts || [],
      firstDetected: r.first_seen || r.firstDetected || "",
    }));
    surface = {
      score:         bs.score || 0,
      grade:         bs.grade || "F",
      risks,
      criticalRisks: risks.filter((r) => r.severity === "critical" || r.severity === "Critical").length,
      highRisks:     risks.filter((r) => r.severity === "high" || r.severity === "High").length,
      domains:       (ug.domains && ug.domains.domains) || [],
      ips:           (ug.ips && ug.ips.ips) || [],
      domainCount:   ((ug.domains && ug.domains.domains) || []).length,
      ipCount:       ((ug.ips && ug.ips.ips) || []).length,
    };
  } else {
    _integrationStatus.upguard = "no-data";
  }

  // ── Vulnerabilities ────────────────────────────────────────────────────
  let vulnerabilities = [];
  let vulnSummary = { total: 0, critical: 0, high: 0, medium: 0, low: 0, uniqueHosts: 0 };
  if (has("qualys")) {
    const q = raw.qualys;
    _integrationStatus.qualys = "connected";
    if (q.collectedAt) _collectedAt.qualys = q.collectedAt;
    const detections = q.detections || [];
    vulnerabilities = detections.map((d) => {
      const sev = parseInt(d.SEVERITY || d.severity || 0, 10);
      return {
        qid:          String(d.QID || d.qid || ""),
        title:        d.TITLE || d.title || "",
        severity:     sev,
        severityLabel: severityLabel(sev),
        host:         d.IP || d.ip || d.DNS || d.dns || "",
        os:           d.OS || d.os || "",
        firstFound:   d.FIRST_FOUND_DATETIME || d.firstFound || "",
        lastFound:    d.LAST_FOUND_DATETIME  || d.lastFound  || "",
        details:      d.RESULTS || d.results || "",
      };
    });
    const hosts = new Set(vulnerabilities.map((v) => v.host).filter(Boolean));
    vulnSummary = {
      total:       vulnerabilities.length,
      critical:    vulnerabilities.filter((v) => v.severity >= 5).length,
      high:        vulnerabilities.filter((v) => v.severity === 4).length,
      medium:      vulnerabilities.filter((v) => v.severity === 3).length,
      low:         vulnerabilities.filter((v) => v.severity <= 2 && v.severity > 0).length,
      uniqueHosts: hosts.size,
    };
  } else {
    _integrationStatus.qualys = "no-data";
  }

  // ── Assets ────────────────────────────────────────────────────────────
  let assets = { total: 0, online: 0, offline: 0, patchCompliant: 0, patchNonCompliant: 0, patchCompliancePct: 0, list: [], patches: [] };
  if (has("manageengine")) {
    const me = raw.manageengine;
    _integrationStatus.manageengine = "connected";
    if (me.collectedAt) _collectedAt.manageengine = me.collectedAt;
    const assetList = (me.assets && (me.assets.list || me.assets.assets)) || [];
    const patchList = (me.patches && (me.patches.list || me.patches.patches)) || [];
    const online    = assetList.filter((a) => a.status === "online"  || a.agentStatus === "Active").length;
    const offline   = assetList.filter((a) => a.status === "offline" || a.agentStatus !== "Active").length;
    const compliant = assetList.filter((a) => a.patchCompliant || a.patch_status === "compliant").length;
    const nonComp   = assetList.length - compliant;
    assets = {
      total:              assetList.length,
      online,
      offline,
      patchCompliant:     compliant,
      patchNonCompliant:  nonComp,
      patchCompliancePct: assetList.length ? Math.round((compliant / assetList.length) * 100) : 0,
      list:    assetList,
      patches: patchList,
    };
  } else {
    _integrationStatus.manageengine = "no-data";
  }

  // ── Azure ─────────────────────────────────────────────────────────────
  let azure = { secureScore: 0, maxScore: 0, currentScore: 0, alerts: [], alertSummary: { high: 0, medium: 0, low: 0 } };
  if (has("azure")) {
    const az = raw.azure;
    _integrationStatus.azure = "connected";
    if (az.collectedAt) _collectedAt.azure = az.collectedAt;
    const ss = az.secureScore || {};
    const rawAlerts = az.alerts || [];
    const alerts = rawAlerts.map((a) => {
      const p = a.properties || {};
      return {
        displayName: p.alertDisplayName || a.name || "",
        severity:    p.severity || a.severity || "",
        status:      p.status || a.status || "",
        description: p.description || "",
        entity:      p.compromisedEntity || a.entity || "",
      };
    });
    const alertSummary = {
      high:   alerts.filter((a) => a.severity === "High").length,
      medium: alerts.filter((a) => a.severity === "Medium").length,
      low:    alerts.filter((a) => a.severity === "Low").length,
    };
    azure = {
      secureScore:  ss.percentage || 0,
      maxScore:     ss.max || 0,
      currentScore: ss.current || 0,
      alerts,
      alertSummary,
    };
  } else {
    _integrationStatus.azure = "no-data";
  }

  // ── Overall Security Score ─────────────────────────────────────────────
  let scoreSum = 0, scoreCnt = 0;
  if (surface.score) { scoreSum += surface.score; scoreCnt++; }
  if (azure.secureScore) { scoreSum += azure.secureScore; scoreCnt++; }
  if (vulnSummary.total > 0) {
    const vscore = Math.max(0, 100 - (vulnSummary.critical * 10 + vulnSummary.high * 3 + vulnSummary.medium));
    scoreSum += vscore; scoreCnt++;
  }
  const securityScore = scoreCnt ? Math.round(scoreSum / scoreCnt) : 0;
  const securityGrade =
    securityScore >= 90 ? "A" :
    securityScore >= 75 ? "B" :
    securityScore >= 60 ? "C" :
    securityScore >= 45 ? "D" : "F";

  return {
    _hasData,
    _collectedAt,
    _integrationStatus,
    securityScore,
    securityGrade,
    firewall,
    surface,
    vulnerabilities,
    vulnSummary,
    assets,
    azure,
  };
}

/* ════════════════════════════════════════════════════════════════════════
   SHARED UI COMPONENTS
════════════════════════════════════════════════════════════════════════ */

function Card({ children, style = {} }) {
  return (
    <div style={{
      background: C.card, borderRadius: 12, border: `1px solid ${C.border}`,
      padding: "20px 24px", boxShadow: "0 1px 4px rgba(0,0,0,0.06)",
      ...style,
    }}>
      {children}
    </div>
  );
}

function Badge({ label, color, bg }) {
  return (
    <span style={{
      display: "inline-block", padding: "2px 10px", borderRadius: 99,
      fontSize: 11, fontWeight: 700, letterSpacing: 0.4,
      color: color || "#fff",
      background: bg || C.primary,
    }}>
      {label}
    </span>
  );
}

function SeverityBadge({ label }) {
  return <Badge label={label} bg={severityColor(label)} />;
}

function StatusBadge({ status }) {
  const connected = status === "connected";
  return (
    <Badge
      label={connected ? "Connected" : "No Data"}
      bg={connected ? C.ok : C.muted}
    />
  );
}

function KpiCard({ title, value, sub, color, icon }) {
  return (
    <Card style={{ flex: 1, minWidth: 160 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
        {icon && <span style={{ fontSize: 22 }}>{icon}</span>}
        <span style={{ fontSize: 12, color: C.textSm, fontWeight: 600, textTransform: "uppercase", letterSpacing: 0.5 }}>{title}</span>
      </div>
      <div style={{ fontSize: 32, fontWeight: 800, color: color || C.text, lineHeight: 1 }}>{value}</div>
      {sub && <div style={{ fontSize: 12, color: C.muted, marginTop: 4 }}>{sub}</div>}
    </Card>
  );
}

function Spinner() {
  return (
    <div style={{ display: "flex", justifyContent: "center", alignItems: "center", padding: 60 }}>
      <div style={{
        width: 40, height: 40, border: `4px solid ${C.border}`,
        borderTop: `4px solid ${C.primary}`, borderRadius: "50%",
        animation: "spin 0.8s linear infinite",
      }} />
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}

function CollectButton({ tool, label, collecting, onCollect, style = {} }) {
  const loading = collecting === tool;
  return (
    <button
      onClick={() => onCollect(tool, label)}
      disabled={loading}
      style={{
        padding: "8px 18px", borderRadius: 8, border: "none", cursor: loading ? "wait" : "pointer",
        background: loading ? C.muted : C.primary, color: "#fff", fontSize: 13, fontWeight: 600,
        ...style,
      }}
    >
      {loading ? "Collecting…" : `Collect ${label} Data Now`}
    </button>
  );
}

function CollectMsg({ msg }) {
  if (!msg) return null;
  const color = msg.startsWith("✅") ? C.ok : msg.startsWith("🔄") ? C.warn : C.critical;
  return <div style={{ marginTop: 10, fontSize: 13, color, fontWeight: 600 }}>{msg}</div>;
}

function EmptyState({ icon, title, sub, children }) {
  return (
    <div style={{ textAlign: "center", padding: "60px 20px", color: C.muted }}>
      <div style={{ fontSize: 48, marginBottom: 12 }}>{icon || "📭"}</div>
      <div style={{ fontSize: 20, fontWeight: 700, color: C.text, marginBottom: 6 }}>{title}</div>
      <div style={{ fontSize: 14, marginBottom: 20 }}>{sub}</div>
      {children}
    </div>
  );
}

/* Circular gauge */
function ScoreGauge({ score, max = 100, size = 140, label }) {
  const pct = Math.min(1, score / max);
  const r = (size - 16) / 2;
  const circ = 2 * Math.PI * r;
  const dash = circ * pct;
  const color = score >= 75 ? C.ok : score >= 50 ? C.warn : C.critical;
  return (
    <div style={{ position: "relative", width: size, height: size }}>
      <svg width={size} height={size}>
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={C.border} strokeWidth={10} />
        <circle
          cx={size/2} cy={size/2} r={r} fill="none"
          stroke={color} strokeWidth={10} strokeLinecap="round"
          strokeDasharray={`${dash} ${circ - dash}`}
          strokeDashoffset={circ / 4}
          transform={`rotate(-90 ${size/2} ${size/2})`}
        />
      </svg>
      <div style={{
        position: "absolute", inset: 0, display: "flex", flexDirection: "column",
        alignItems: "center", justifyContent: "center",
      }}>
        <span style={{ fontSize: size * 0.22, fontWeight: 800, color }}>{score}</span>
        {label && <span style={{ fontSize: 11, color: C.muted }}>{label}</span>}
      </div>
    </div>
  );
}

function SortableTable({ columns, rows, onRowClick, style = {} }) {
  const [sortCol, setSortCol] = useState(null);
  const [sortDir, setSortDir] = useState("asc");
  const sorted = useMemo(() => {
    if (!sortCol) return rows;
    return [...rows].sort((a, b) => {
      const av = a[sortCol], bv = b[sortCol];
      if (av === bv) return 0;
      const cmp = av < bv ? -1 : 1;
      return sortDir === "asc" ? cmp : -cmp;
    });
  }, [rows, sortCol, sortDir]);

  function handleSort(col) {
    if (sortCol === col) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else { setSortCol(col); setSortDir("asc"); }
  }

  return (
    <div style={{ overflowX: "auto", ...style }}>
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
        <thead>
          <tr>
            {columns.map((col) => (
              <th
                key={col.key}
                onClick={() => handleSort(col.key)}
                style={{
                  padding: "10px 12px", textAlign: "left", borderBottom: `2px solid ${C.border}`,
                  color: C.textSm, fontWeight: 700, fontSize: 11, textTransform: "uppercase",
                  letterSpacing: 0.5, cursor: "pointer", whiteSpace: "nowrap",
                  background: C.bg,
                }}
              >
                {col.label} {sortCol === col.key ? (sortDir === "asc" ? "▲" : "▼") : ""}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.length === 0 ? (
            <tr>
              <td colSpan={columns.length} style={{ textAlign: "center", padding: 32, color: C.muted }}>
                No data available
              </td>
            </tr>
          ) : sorted.map((row, i) => (
            <tr
              key={i}
              onClick={() => onRowClick && onRowClick(row)}
              style={{
                background: i % 2 === 0 ? "#fff" : "#f8fafc",
                cursor: onRowClick ? "pointer" : "default",
                transition: "background 0.15s",
              }}
              onMouseEnter={(e) => { if (onRowClick) e.currentTarget.style.background = C.primaryLt; }}
              onMouseLeave={(e) => { e.currentTarget.style.background = i % 2 === 0 ? "#fff" : "#f8fafc"; }}
            >
              {columns.map((col) => (
                <td key={col.key} style={{ padding: "10px 12px", borderBottom: `1px solid ${C.border}`, verticalAlign: "middle" }}>
                  {col.render ? col.render(row[col.key], row) : row[col.key]}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function TabBar({ tabs, active, onSelect }) {
  return (
    <div style={{ display: "flex", gap: 4, borderBottom: `2px solid ${C.border}`, marginBottom: 20 }}>
      {tabs.map((t) => (
        <button
          key={t}
          onClick={() => onSelect(t)}
          style={{
            padding: "8px 18px", border: "none", background: "none", cursor: "pointer",
            fontSize: 13, fontWeight: 600, color: active === t ? C.primary : C.textSm,
            borderBottom: active === t ? `2px solid ${C.primary}` : "2px solid transparent",
            marginBottom: -2, transition: "all 0.15s",
          }}
        >
          {t}
        </button>
      ))}
    </div>
  );
}

function Modal({ title, onClose, children }) {
  return (
    <div
      onClick={onClose}
      style={{
        position: "fixed", inset: 0, background: "rgba(0,0,0,0.4)",
        display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000,
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          background: C.card, borderRadius: 14, padding: 28, maxWidth: 600, width: "90%",
          maxHeight: "80vh", overflowY: "auto", boxShadow: "0 20px 60px rgba(0,0,0,0.3)",
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
          <h3 style={{ margin: 0, color: C.text }}>{title}</h3>
          <button onClick={onClose} style={{ border: "none", background: "none", fontSize: 22, cursor: "pointer", color: C.muted }}>✕</button>
        </div>
        {children}
      </div>
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════════
   LOGIN PAGE
════════════════════════════════════════════════════════════════════════ */

function LoginPage({ onLogin }) {
  const [user, setUser] = useState("");
  const [pass, setPass] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setLoading(true); setError("");
    try {
      const res = await apiFetch(`${API}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: user, password: pass }),
      });
      const j = await res.json().catch(() => ({}));
      if (res.ok && j.username) {
        onLogin(j);
      } else {
        setError(j.error || "Invalid credentials. Please try again.");
      }
    } catch (err) {
      setError("Cannot reach server. Please check your connection.");
    }
    setLoading(false);
  }

  return (
    <div style={{
      minHeight: "100vh", background: `linear-gradient(135deg, ${C.sidebar} 0%, #1e3a5f 100%)`,
      display: "flex", alignItems: "center", justifyContent: "center",
    }}>
      <div style={{
        background: C.card, borderRadius: 16, padding: "48px 40px", width: 380,
        boxShadow: "0 24px 80px rgba(0,0,0,0.4)",
      }}>
        <div style={{ textAlign: "center", marginBottom: 32 }}>
          <div style={{ fontSize: 48, marginBottom: 10 }}>🛡️</div>
          <h1 style={{ margin: 0, fontSize: 22, fontWeight: 800, color: C.text }}>SecOps Command Center</h1>
          <p style={{ margin: "6px 0 0", color: C.muted, fontSize: 14 }}>Security Operations Dashboard</p>
        </div>
        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: 16 }}>
            <label style={{ fontSize: 12, fontWeight: 700, color: C.textSm, display: "block", marginBottom: 6 }}>USERNAME</label>
            <input
              value={user} onChange={(e) => setUser(e.target.value)}
              placeholder="Enter username" required
              style={{
                width: "100%", padding: "10px 14px", borderRadius: 8, border: `1px solid ${C.border}`,
                fontSize: 14, outline: "none", boxSizing: "border-box", color: C.text,
              }}
            />
          </div>
          <div style={{ marginBottom: 20 }}>
            <label style={{ fontSize: 12, fontWeight: 700, color: C.textSm, display: "block", marginBottom: 6 }}>PASSWORD</label>
            <input
              type="password" value={pass} onChange={(e) => setPass(e.target.value)}
              placeholder="Enter password" required
              style={{
                width: "100%", padding: "10px 14px", borderRadius: 8, border: `1px solid ${C.border}`,
                fontSize: 14, outline: "none", boxSizing: "border-box", color: C.text,
              }}
            />
          </div>
          {error && (
            <div style={{ background: "#fef2f2", border: `1px solid ${C.critical}`, borderRadius: 8, padding: "10px 14px", marginBottom: 16, fontSize: 13, color: C.critical }}>
              {error}
            </div>
          )}
          <button
            type="submit" disabled={loading}
            style={{
              width: "100%", padding: "12px", borderRadius: 8, border: "none",
              background: loading ? C.muted : C.primary, color: "#fff",
              fontSize: 15, fontWeight: 700, cursor: loading ? "wait" : "pointer",
            }}
          >
            {loading ? "Signing in…" : "Sign In"}
          </button>
        </form>
        <p style={{ textAlign: "center", marginTop: 20, fontSize: 12, color: C.muted }}>
          Roles: admin · analyst · executive
        </p>
      </div>
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════════
   EXECUTIVE DASHBOARD
════════════════════════════════════════════════════════════════════════ */

function ExecutiveDashboard({ data, collecting, onCollect, collectMsg }) {
  const score = data.securityScore || 0;
  const grade = data.securityGrade || "F";
  const status = data._integrationStatus || {};

  const postureSentence =
    score >= 90 ? "Your organisation's security posture is excellent with minimal risk exposure." :
    score >= 75 ? "Security posture is good. Some areas need attention to reduce risk." :
    score >= 60 ? "Moderate risk exposure detected. Prioritise remediation of critical findings." :
    score >= 45 ? "Significant vulnerabilities present. Immediate action recommended." :
    "Critical security gaps identified. Urgent remediation required across multiple domains.";

  // Dummy trend data for area chart
  const trendData = useMemo(() => {
    const base = score;
    return ["Jan","Feb","Mar","Apr","May","Jun"].map((month, i) => ({
      month,
      score: Math.max(0, Math.min(100, base - 15 + i * 3 + Math.round(Math.random() * 4))),
    }));
  }, [score]);

  const topRisks = useMemo(() => {
    const items = [];
    (data.vulnerabilities || []).filter((v) => v.severity >= 5).slice(0, 3).forEach((v) => {
      items.push({ source: "Qualys", finding: v.title, severity: "Critical", host: v.host });
    });
    (data.surface && data.surface.risks || []).filter((r) => r.severity === "critical" || r.severity === "Critical").slice(0, 2).forEach((r) => {
      items.push({ source: "UpGuard", finding: r.finding, severity: "Critical", host: (r.hostnames || []).join(", ") });
    });
    return items.slice(0, 5);
  }, [data]);

  const toolStrip = [
    { key: "fortinet",     icon: "🔥", name: "Fortinet",     metric: `${(data.firewall || {}).fortinetCount || 0} devices` },
    { key: "paloalto",     icon: "🔥", name: "Palo Alto",    metric: `${(data.firewall || {}).paloAltoCount || 0} devices` },
    { key: "upguard",      icon: "🌐", name: "UpGuard",      metric: `Score: ${(data.surface || {}).score || "–"}` },
    { key: "qualys",       icon: "🔍", name: "Qualys",       metric: `${(data.vulnSummary || {}).total || 0} findings` },
    { key: "manageengine", icon: "📦", name: "ManageEngine", metric: `${(data.assets || {}).total || 0} assets` },
    { key: "azure",        icon: "☁️", name: "Azure",        metric: `Score: ${(data.azure || {}).secureScore || 0}%` },
  ];

  const toolLabels = { fortinet: "Fortinet", paloalto: "Palo Alto", upguard: "UpGuard", qualys: "Qualys", manageengine: "ManageEngine", azure: "Azure" };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>
      <h2 style={{ margin: 0, fontSize: 22, fontWeight: 800, color: C.text }}>Executive Security Dashboard</h2>

      {/* Score Hero */}
      <Card>
        <div style={{ display: "flex", alignItems: "center", gap: 40, flexWrap: "wrap" }}>
          <ScoreGauge score={score} size={160} label="/ 100" />
          <div>
            <div style={{ display: "flex", alignItems: "baseline", gap: 16, marginBottom: 8 }}>
              <span style={{ fontSize: 64, fontWeight: 900, color: gradeColor(grade), lineHeight: 1 }}>{grade}</span>
              <span style={{ fontSize: 18, color: C.textSm }}>Security Grade</span>
            </div>
            <p style={{ margin: 0, fontSize: 15, color: C.text, maxWidth: 480 }}>{postureSentence}</p>
            <CollectMsg msg={collectMsg} />
          </div>
        </div>
      </Card>

      {/* KPI Row */}
      <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
        <KpiCard title="Critical Vulnerabilities" value={(data.vulnSummary || {}).critical || 0}
          color={C.critical} icon="🔴" sub={`${(data.vulnSummary || {}).high || 0} High`} />
        <KpiCard title="Attack Surface Score" value={(data.surface || {}).score || "–"}
          color={C.info} icon="🌐" sub={(data.surface || {}).grade ? `Grade ${(data.surface || {}).grade}` : "No data"} />
        <KpiCard title="Firewall Coverage" value={`${(data.firewall || {}).totalDevices || 0}`}
          color={C.primary} icon="🔥" sub={`${(data.firewall || {}).totalPolicies || 0} policies`} />
        <KpiCard title="Cloud Security Score" value={`${(data.azure || {}).secureScore || 0}%`}
          color={C.ok} icon="☁️" sub={`${(data.azure && data.azure.alertSummary && data.azure.alertSummary.high) || 0} high alerts`} />
      </div>

      {/* Tool Strip */}
      <Card>
        <h3 style={{ margin: "0 0 16px", fontSize: 14, fontWeight: 700, color: C.text }}>Integration Status</h3>
        <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
          {toolStrip.map((t) => {
            const st = status[t.key] || "no-data";
            return (
              <div key={t.key} style={{
                display: "flex", flexDirection: "column", alignItems: "center", gap: 6,
                padding: "14px 18px", borderRadius: 10, border: `1px solid ${C.border}`,
                background: st === "connected" ? "#f0fdf4" : "#fafafa", minWidth: 110,
              }}>
                <span style={{ fontSize: 24 }}>{t.icon}</span>
                <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>{t.name}</span>
                <StatusBadge status={st} />
                <span style={{ fontSize: 11, color: C.muted }}>{t.metric}</span>
                {st !== "connected" && (
                  <button
                    onClick={() => onCollect(t.key, toolLabels[t.key])}
                    disabled={collecting === t.key}
                    style={{ fontSize: 10, padding: "3px 8px", border: `1px solid ${C.primary}`, borderRadius: 6, background: "none", color: C.primary, cursor: "pointer", marginTop: 2 }}
                  >
                    {collecting === t.key ? "…" : "Collect"}
                  </button>
                )}
              </div>
            );
          })}
        </div>
      </Card>

      {/* Top Risks */}
      <Card>
        <h3 style={{ margin: "0 0 16px", fontSize: 14, fontWeight: 700, color: C.text }}>Top Risks for Board Attention</h3>
        {topRisks.length === 0 ? (
          <div style={{ color: C.muted, fontSize: 14, padding: "20px 0" }}>No critical risks detected — security posture is healthy.</div>
        ) : (
          <SortableTable
            columns={[
              { key: "source",   label: "Source" },
              { key: "finding",  label: "Finding" },
              { key: "severity", label: "Severity", render: (v) => <SeverityBadge label={v} /> },
              { key: "host",     label: "Affected Host" },
            ]}
            rows={topRisks}
          />
        )}
      </Card>

      {/* Trend */}
      <Card>
        <h3 style={{ margin: "0 0 16px", fontSize: 14, fontWeight: 700, color: C.text }}>Security Posture Trend (Estimated)</h3>
        <ResponsiveContainer width="100%" height={220}>
          <AreaChart data={trendData}>
            <defs>
              <linearGradient id="scoreFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={C.primary} stopOpacity={0.2} />
                <stop offset="95%" stopColor={C.primary} stopOpacity={0} />
              </linearGradient>
            </defs>
            <XAxis dataKey="month" tick={{ fontSize: 12 }} />
            <YAxis domain={[0, 100]} tick={{ fontSize: 12 }} />
            <Tooltip />
            <Area type="monotone" dataKey="score" stroke={C.primary} fill="url(#scoreFill)" strokeWidth={2} dot={{ r: 4 }} />
          </AreaChart>
        </ResponsiveContainer>
      </Card>
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════════
   THREAT SURFACE PAGE
════════════════════════════════════════════════════════════════════════ */

function ThreatSurfacePage({ data, collecting, onCollect, collectMsg }) {
  const [tab, setTab] = useState("Overview");
  const [sevFilter, setSevFilter] = useState("All");
  const surface = data.surface || {};
  const hasData = (data._integrationStatus || {}).upguard === "connected";

  const riskCounts = useMemo(() => {
    const risks = surface.risks || [];
    return {
      critical: risks.filter((r) => r.severity === "critical" || r.severity === "Critical").length,
      high:     risks.filter((r) => r.severity === "high"     || r.severity === "High").length,
      medium:   risks.filter((r) => r.severity === "medium"   || r.severity === "Medium").length,
      low:      risks.filter((r) => r.severity === "low"      || r.severity === "Low").length,
    };
  }, [surface.risks]);

  const pieData = [
    { name: "Critical", value: riskCounts.critical, fill: C.critical },
    { name: "High",     value: riskCounts.high,     fill: C.high },
    { name: "Medium",   value: riskCounts.medium,   fill: C.warn },
    { name: "Low",      value: riskCounts.low,       fill: C.ok },
  ].filter((d) => d.value > 0);

  const filteredRisks = useMemo(() => {
    const r = surface.risks || [];
    if (sevFilter === "All") return r;
    return r.filter((risk) => risk.severity && risk.severity.toLowerCase() === sevFilter.toLowerCase());
  }, [surface.risks, sevFilter]);

  if (!hasData) {
    return (
      <EmptyState icon="🌐" title="No Threat Surface Data" sub="Connect UpGuard to monitor your external attack surface.">
        <CollectButton tool="upguard" label="UpGuard" collecting={collecting} onCollect={onCollect} />
        <CollectMsg msg={collectMsg} />
      </EmptyState>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      <h2 style={{ margin: 0, fontSize: 22, fontWeight: 800 }}>Threat Surface</h2>
      <TabBar tabs={["Overview", "Domains", "IPs", "Risk Details"]} active={tab} onSelect={setTab} />

      {tab === "Overview" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
          <div style={{ display: "flex", gap: 20, flexWrap: "wrap", alignItems: "flex-start" }}>
            <Card style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 10, minWidth: 200 }}>
              <ScoreGauge score={surface.score || 0} size={160} label="/ 100" />
              <div style={{ fontSize: 28, fontWeight: 800, color: gradeColor(surface.grade || "F") }}>
                Grade {surface.grade || "F"}
              </div>
              <div style={{ display: "flex", gap: 10, flexWrap: "wrap", justifyContent: "center" }}>
                <KpiCard title="Domains" value={surface.domainCount || 0} style={{ minWidth: 90 }} />
                <KpiCard title="IPs" value={surface.ipCount || 0} style={{ minWidth: 90 }} />
              </div>
            </Card>
            <Card style={{ flex: 1, minWidth: 280 }}>
              <h3 style={{ margin: "0 0 16px", fontSize: 14, fontWeight: 700 }}>Risk Breakdown</h3>
              {pieData.length > 0 ? (
                <ResponsiveContainer width="100%" height={220}>
                  <PieChart>
                    <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80} label={({ name, value }) => `${name}: ${value}`}>
                      {pieData.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
                    </Pie>
                    <Tooltip />
                    <Legend />
                  </PieChart>
                </ResponsiveContainer>
              ) : <div style={{ color: C.muted }}>No risks detected.</div>}
            </Card>
          </div>
          <div style={{ display: "flex", gap: 16 }}>
            {[
              { label: "Critical", value: riskCounts.critical, color: C.critical },
              { label: "High",     value: riskCounts.high,     color: C.high },
              { label: "Medium",   value: riskCounts.medium,   color: C.warn },
              { label: "Low",      value: riskCounts.low,       color: C.ok },
            ].map((k) => (
              <KpiCard key={k.label} title={k.label} value={k.value} color={k.color} />
            ))}
          </div>
        </div>
      )}

      {tab === "Domains" && (
        <Card>
          <SortableTable
            columns={[
              { key: "hostname", label: "Hostname" },
              { key: "score",    label: "Score", render: (v) => <span style={{ fontWeight: 700, color: v >= 700 ? C.ok : v >= 500 ? C.warn : C.critical }}>{v}</span> },
            ]}
            rows={surface.domains || []}
          />
        </Card>
      )}

      {tab === "IPs" && (
        <Card>
          <SortableTable
            columns={[
              { key: "ip",         label: "IP Address" },
              { key: "score",      label: "Score" },
              { key: "open_ports", label: "Open Ports", render: (v) => (v || []).length > 0 ? (v || []).slice(0,5).join(", ") + ((v || []).length > 5 ? "…" : "") : "None" },
            ]}
            rows={surface.ips || []}
          />
        </Card>
      )}

      {tab === "Risk Details" && (
        <Card>
          <div style={{ display: "flex", gap: 8, marginBottom: 16, flexWrap: "wrap" }}>
            {["All","Critical","High","Medium","Low"].map((s) => (
              <button key={s} onClick={() => setSevFilter(s)} style={{
                padding: "5px 14px", borderRadius: 20, border: `1px solid ${s === sevFilter ? C.primary : C.border}`,
                background: s === sevFilter ? C.primary : "white", color: s === sevFilter ? "#fff" : C.text,
                cursor: "pointer", fontSize: 13, fontWeight: 600,
              }}>{s}</button>
            ))}
          </div>
          <SortableTable
            columns={[
              { key: "finding",       label: "Finding" },
              { key: "severity",      label: "Severity", render: (v) => <SeverityBadge label={v} /> },
              { key: "hostnames",     label: "Hosts Affected", render: (v) => (v || []).join(", ") || "—" },
              { key: "firstDetected", label: "First Detected" },
            ]}
            rows={filteredRisks}
          />
        </Card>
      )}
      <CollectMsg msg={collectMsg} />
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════════
   VULNERABILITY PAGE
════════════════════════════════════════════════════════════════════════ */

function VulnerabilityPage({ data, collecting, onCollect, collectMsg }) {
  const [tab, setTab] = useState("Summary");
  const [search, setSearch] = useState("");
  const [sevFilter, setSevFilter] = useState("All");
  const [modal, setModal] = useState(null);

  const vulns = data.vulnerabilities || [];
  const summary = data.vulnSummary || {};
  const hasData = (data._integrationStatus || {}).qualys === "connected";

  const pieData = [
    { name: "Critical", value: summary.critical || 0, fill: C.critical },
    { name: "High",     value: summary.high     || 0, fill: C.high },
    { name: "Medium",   value: summary.medium   || 0, fill: C.warn },
    { name: "Low",      value: summary.low      || 0, fill: C.ok },
  ].filter((d) => d.value > 0);

  const topCritical = useMemo(() =>
    [...vulns].filter((v) => v.severity >= 4).sort((a, b) => b.severity - a.severity).slice(0, 10),
    [vulns]
  );

  const hostCounts = useMemo(() => {
    const counts = {};
    vulns.forEach((v) => { if (v.host) counts[v.host] = (counts[v.host] || 0) + 1; });
    return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([host, count]) => ({ host, count }));
  }, [vulns]);

  const filtered = useMemo(() => {
    return vulns.filter((v) => {
      const matchSev = sevFilter === "All" || v.severityLabel === sevFilter;
      const matchSearch = !search || v.title.toLowerCase().includes(search.toLowerCase()) || v.host.includes(search);
      return matchSev && matchSearch;
    });
  }, [vulns, sevFilter, search]);

  if (!hasData) {
    return (
      <EmptyState icon="🔍" title="No Vulnerability Data" sub="Connect Qualys to scan and track vulnerabilities across your environment.">
        <CollectButton tool="qualys" label="Qualys" collecting={collecting} onCollect={onCollect} />
        <CollectMsg msg={collectMsg} />
      </EmptyState>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      {modal && (
        <Modal title={modal.title || "Vulnerability Detail"} onClose={() => setModal(null)}>
          <div style={{ display: "flex", flexDirection: "column", gap: 10, fontSize: 13 }}>
            <div><strong>QID:</strong> {modal.qid}</div>
            <div><strong>Severity:</strong> <SeverityBadge label={modal.severityLabel} /></div>
            <div><strong>Host:</strong> {modal.host}</div>
            <div><strong>OS:</strong> {modal.os || "—"}</div>
            <div><strong>First Found:</strong> {modal.firstFound || "—"}</div>
            <div><strong>Last Found:</strong> {modal.lastFound || "—"}</div>
            <div><strong>Details:</strong></div>
            <pre style={{ background: C.bg, padding: 12, borderRadius: 8, whiteSpace: "pre-wrap", maxHeight: 200, overflowY: "auto", fontSize: 12 }}>
              {modal.details || "No additional details."}
            </pre>
          </div>
        </Modal>
      )}

      <h2 style={{ margin: 0, fontSize: 22, fontWeight: 800 }}>Vulnerabilities</h2>
      <TabBar tabs={["Summary", "All Vulnerabilities"]} active={tab} onSelect={setTab} />

      {tab === "Summary" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
          <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
            <KpiCard title="Total" value={summary.total || 0} icon="🔍" />
            <KpiCard title="Critical" value={summary.critical || 0} color={C.critical} icon="🔴" />
            <KpiCard title="High" value={summary.high || 0} color={C.high} icon="🟠" />
            <KpiCard title="Medium" value={summary.medium || 0} color={C.warn} icon="🟡" />
            <KpiCard title="Unique Hosts" value={summary.uniqueHosts || 0} icon="💻" />
          </div>
          <div style={{ display: "flex", gap: 20, flexWrap: "wrap" }}>
            <Card style={{ flex: 1, minWidth: 280 }}>
              <h3 style={{ margin: "0 0 16px", fontSize: 14, fontWeight: 700 }}>Severity Breakdown</h3>
              <ResponsiveContainer width="100%" height={220}>
                <PieChart>
                  <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80}>
                    {pieData.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
                  </Pie>
                  <Tooltip />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            </Card>
            <Card style={{ flex: 1, minWidth: 280 }}>
              <h3 style={{ margin: "0 0 16px", fontSize: 14, fontWeight: 700 }}>Top 10 Affected Hosts</h3>
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={hostCounts} layout="vertical">
                  <XAxis type="number" tick={{ fontSize: 11 }} />
                  <YAxis type="category" dataKey="host" width={120} tick={{ fontSize: 10 }} />
                  <Tooltip />
                  <Bar dataKey="count" fill={C.primary} />
                </BarChart>
              </ResponsiveContainer>
            </Card>
          </div>
          <Card>
            <h3 style={{ margin: "0 0 12px", fontSize: 14, fontWeight: 700 }}>Top 10 Most Critical Findings</h3>
            <SortableTable
              columns={[
                { key: "severityLabel", label: "Severity", render: (v) => <SeverityBadge label={v} /> },
                { key: "title",  label: "Title" },
                { key: "host",   label: "Host" },
              ]}
              rows={topCritical}
              onRowClick={setModal}
            />
          </Card>
        </div>
      )}

      {tab === "All Vulnerabilities" && (
        <Card>
          <div style={{ display: "flex", gap: 10, marginBottom: 16, flexWrap: "wrap" }}>
            <input
              value={search} onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by title or host…"
              style={{ padding: "8px 12px", borderRadius: 8, border: `1px solid ${C.border}`, fontSize: 13, flex: 1, minWidth: 200 }}
            />
            {["All","Critical","High","Medium","Low"].map((s) => (
              <button key={s} onClick={() => setSevFilter(s)} style={{
                padding: "5px 14px", borderRadius: 20, border: `1px solid ${s === sevFilter ? C.primary : C.border}`,
                background: s === sevFilter ? C.primary : "white", color: s === sevFilter ? "#fff" : C.text,
                cursor: "pointer", fontSize: 13, fontWeight: 600,
              }}>{s}</button>
            ))}
          </div>
          <SortableTable
            columns={[
              { key: "severityLabel", label: "Severity", render: (v) => <SeverityBadge label={v} /> },
              { key: "title",      label: "Title" },
              { key: "host",       label: "Host" },
              { key: "qid",        label: "QID" },
              { key: "firstFound", label: "First Found" },
            ]}
            rows={filtered}
            onRowClick={setModal}
          />
        </Card>
      )}
      <CollectMsg msg={collectMsg} />
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════════
   FIREWALL PAGE
════════════════════════════════════════════════════════════════════════ */

function FirewallPage({ data, collecting, onCollect, collectMsg }) {
  const firewall = data.firewall || {};
  const instances = firewall.instances || [];
  const [selectedIdx, setSelectedIdx] = useState(0);
  const [tab, setTab] = useState("Overview");
  const [policySearch, setPolicySearch] = useState("");
  const hasData = instances.length > 0;

  const inst = instances[selectedIdx] || null;

  const filteredPolicies = useMemo(() => {
    if (!inst) return [];
    const allPolicies = inst._policies || [];
    if (!policySearch) return allPolicies;
    const q = policySearch.toLowerCase();
    return allPolicies.filter((p) =>
      (p.name || "").toLowerCase().includes(q) ||
      (p.action || "").toLowerCase().includes(q) ||
      (p.srcaddr || "").toLowerCase().includes(q) ||
      (p.dstaddr || "").toLowerCase().includes(q)
    );
  }, [inst, policySearch]);

  if (!hasData) {
    return (
      <EmptyState icon="🔥" title="No Firewall Data" sub="Connect Fortinet or Palo Alto to monitor firewall policies and traffic.">
        <div style={{ display: "flex", gap: 12, justifyContent: "center", flexWrap: "wrap" }}>
          <CollectButton tool="fortinet" label="Fortinet" collecting={collecting} onCollect={onCollect} />
          <CollectButton tool="paloalto" label="Palo Alto" collecting={collecting} onCollect={onCollect} />
        </div>
        <CollectMsg msg={collectMsg} />
      </EmptyState>
    );
  }

  const bwTop = (inst ? inst.bandwidth || [] : []).slice(0, 10);
  const appsTop = (inst ? inst.topApps || [] : []).slice(0, 10);
  const webTop = (inst ? inst.topWebCategories || [] : []).slice(0, 10);
  const cis = inst ? inst.cisBenchmark || [] : [];
  const cisPass = cis.filter((c) => c.pass === true).length;
  const cisFail = cis.filter((c) => c.pass === false).length;
  const cisUnk  = cis.filter((c) => c.pass === null).length;
  const cisPct  = cis.length ? Math.round((cisPass / cis.length) * 100) : 0;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      <h2 style={{ margin: 0, fontSize: 22, fontWeight: 800 }}>Firewalls</h2>

      {/* Device Selector */}
      <div style={{ display: "flex", gap: 8, overflowX: "auto", paddingBottom: 4 }}>
        {instances.map((inst2, i) => (
          <button
            key={i}
            onClick={() => { setSelectedIdx(i); setTab("Overview"); }}
            style={{
              padding: "8px 18px", borderRadius: 20, border: `2px solid ${selectedIdx === i ? C.primary : C.border}`,
              background: selectedIdx === i ? C.primary : C.card, color: selectedIdx === i ? "#fff" : C.text,
              cursor: "pointer", fontSize: 13, fontWeight: 600, whiteSpace: "nowrap",
              display: "flex", alignItems: "center", gap: 6,
            }}
          >
            {inst2.vendor === "fortinet" ? "🔥" : "🛡️"} {inst2.hostname || inst2.host}
          </button>
        ))}
      </div>

      {inst && (
        <>
          <TabBar tabs={["Overview","Policies","Bandwidth","Top Applications","Top Web Categories","CIS Benchmark"]} active={tab} onSelect={setTab} />

          {tab === "Overview" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
                <KpiCard title="Total Policies" value={inst.policyCount} icon="📋" />
                <KpiCard title="Allow Rules"    value={inst.allowCount}  icon="✅" color={C.ok} />
                <KpiCard title="Deny Rules"     value={inst.denyCount}   icon="🚫" color={C.critical} />
                <KpiCard title="Enabled Rules"  value={inst.enabledCount} icon="🟢" color={C.info} />
              </div>
              <Card>
                <div style={{ display: "flex", gap: 20, flexWrap: "wrap", fontSize: 14 }}>
                  <div><strong>Vendor:</strong> {inst.vendor}</div>
                  <div><strong>Host:</strong> {inst.host}</div>
                  <div><strong>Version:</strong> {inst.version || "—"}</div>
                  <div><strong>Collected:</strong> {inst.collectedAt ? new Date(inst.collectedAt).toLocaleString() : "—"}</div>
                </div>
              </Card>
            </div>
          )}

          {tab === "Policies" && (
            <Card>
              <input
                value={policySearch} onChange={(e) => setPolicySearch(e.target.value)}
                placeholder="Search policies…"
                style={{ padding: "8px 12px", borderRadius: 8, border: `1px solid ${C.border}`, fontSize: 13, width: "100%", boxSizing: "border-box", marginBottom: 12 }}
              />
              {filteredPolicies.length === 0 ? (
                <div style={{ color: C.muted, textAlign: "center", padding: 24 }}>
                  {inst.policyCount > 0 ? "No policies match search." : "No policy detail available — raw policy data not included in snapshot."}
                </div>
              ) : (
                <SortableTable
                  columns={[
                    { key: "name",    label: "Name" },
                    { key: "action",  label: "Action", render: (v) => <Badge label={v || "—"} bg={(v||"").toLowerCase()==="accept"||(v||"").toLowerCase()==="allow" ? C.ok : C.critical} /> },
                    { key: "srcaddr", label: "Source" },
                    { key: "dstaddr", label: "Destination" },
                    { key: "service", label: "Service" },
                    { key: "status",  label: "Status", render: (v) => <Badge label={v === "enable" || v === "enabled" ? "Enabled" : "Disabled"} bg={v === "enable" || v === "enabled" ? C.ok : C.muted} /> },
                  ]}
                  rows={filteredPolicies}
                />
              )}
            </Card>
          )}

          {tab === "Bandwidth" && (
            <Card>
              <h3 style={{ margin: "0 0 16px", fontSize: 14, fontWeight: 700 }}>Top 10 Interfaces by Throughput</h3>
              {bwTop.length === 0 ? (
                <div style={{ color: C.muted, textAlign: "center", padding: 24 }}>No bandwidth data available.</div>
              ) : (
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={bwTop}>
                    <XAxis dataKey="name" tick={{ fontSize: 11 }} />
                    <YAxis tick={{ fontSize: 11 }} />
                    <Tooltip />
                    <Legend />
                    <Bar dataKey="in_bps"  name="In bps"  fill={C.primary} />
                    <Bar dataKey="out_bps" name="Out bps" fill={C.info} />
                  </BarChart>
                </ResponsiveContainer>
              )}
            </Card>
          )}

          {tab === "Top Applications" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              <Card>
                <h3 style={{ margin: "0 0 16px", fontSize: 14, fontWeight: 700 }}>Top Applications by Sessions</h3>
                {appsTop.length === 0 ? (
                  <div style={{ color: C.muted, textAlign: "center", padding: 24 }}>No application data available.</div>
                ) : (
                  <ResponsiveContainer width="100%" height={260}>
                    <BarChart data={appsTop}>
                      <XAxis dataKey="name" tick={{ fontSize: 11 }} />
                      <YAxis tick={{ fontSize: 11 }} />
                      <Tooltip />
                      <Bar dataKey="sessions" fill={C.primary} />
                    </BarChart>
                  </ResponsiveContainer>
                )}
              </Card>
              {appsTop.length > 0 && (
                <Card>
                  <SortableTable
                    columns={[
                      { key: "name",     label: "Application" },
                      { key: "sessions", label: "Sessions" },
                      { key: "bytes",    label: "Bytes" },
                      { key: "risk",     label: "Risk", render: (v) => v ? <Badge label={v} bg={v === "critical" ? C.critical : v === "high" ? C.high : C.warn} /> : "—" },
                    ]}
                    rows={appsTop}
                  />
                </Card>
              )}
            </div>
          )}

          {tab === "Top Web Categories" && (
            <Card>
              <h3 style={{ margin: "0 0 16px", fontSize: 14, fontWeight: 700 }}>Top Web Categories</h3>
              {webTop.length === 0 ? (
                <div style={{ color: C.muted, textAlign: "center", padding: 24 }}>No web category data available.</div>
              ) : (
                <ResponsiveContainer width="100%" height={280}>
                  <BarChart data={webTop} layout="vertical">
                    <XAxis type="number" tick={{ fontSize: 11 }} />
                    <YAxis type="category" dataKey="name" width={140} tick={{ fontSize: 11 }} />
                    <Tooltip />
                    <Bar dataKey="sessions" fill={C.purple} />
                  </BarChart>
                </ResponsiveContainer>
              )}
            </Card>
          )}

          {tab === "CIS Benchmark" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
                <KpiCard title="Pass"    value={cisPass} color={C.ok}       icon="✅" sub={`${cisPct}% pass rate`} />
                <KpiCard title="Fail"    value={cisFail} color={C.critical}  icon="❌" />
                <KpiCard title="Unknown" value={cisUnk}  color={C.muted}     icon="❓" />
              </div>
              {cis.length > 0 && (
                <Card>
                  <div style={{ marginBottom: 12 }}>
                    <div style={{ height: 10, background: C.border, borderRadius: 5, overflow: "hidden" }}>
                      <div style={{ height: "100%", width: `${cisPct}%`, background: cisPct >= 80 ? C.ok : cisPct >= 60 ? C.warn : C.critical, transition: "width 0.5s" }} />
                    </div>
                    <div style={{ fontSize: 12, color: C.muted, marginTop: 4 }}>{cisPct}% compliance</div>
                  </div>
                  <SortableTable
                    columns={[
                      { key: "id",    label: "Check ID" },
                      { key: "title", label: "Title" },
                      { key: "pass",  label: "Status", render: (v) => v === true ? <Badge label="Pass" bg={C.ok} /> : v === false ? <Badge label="Fail" bg={C.critical} /> : <Badge label="Unknown" bg={C.muted} /> },
                    ]}
                    rows={cis}
                  />
                </Card>
              )}
              {cis.length === 0 && <Card><div style={{ color: C.muted, textAlign: "center", padding: 24 }}>No CIS benchmark data available for this device.</div></Card>}
            </div>
          )}
        </>
      )}
      <CollectMsg msg={collectMsg} />
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════════
   ASSETS PAGE
════════════════════════════════════════════════════════════════════════ */

function AssetPage({ data, collecting, onCollect, collectMsg }) {
  const assets = data.assets || {};
  const hasData = (data._integrationStatus || {}).manageengine === "connected";

  const compliancePie = [
    { name: "Compliant",     value: assets.patchCompliant    || 0, fill: C.ok },
    { name: "Non-Compliant", value: assets.patchNonCompliant || 0, fill: C.critical },
  ].filter((d) => d.value > 0);

  if (!hasData) {
    return (
      <EmptyState icon="📦" title="No Asset Data" sub="Connect ManageEngine to track assets and patch compliance.">
        <CollectButton tool="manageengine" label="ManageEngine" collecting={collecting} onCollect={onCollect} />
        <CollectMsg msg={collectMsg} />
      </EmptyState>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      <h2 style={{ margin: 0, fontSize: 22, fontWeight: 800 }}>Assets & Patches</h2>
      <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
        <KpiCard title="Total Assets"     value={assets.total || 0}           icon="📦" />
        <KpiCard title="Online"           value={assets.online || 0}          icon="🟢" color={C.ok} />
        <KpiCard title="Offline"          value={assets.offline || 0}         icon="🔴" color={C.muted} />
        <KpiCard title="Patch Compliant"  value={`${assets.patchCompliancePct || 0}%`} icon="✅" color={C.ok} />
        <KpiCard title="Non-Compliant"    value={assets.patchNonCompliant || 0} icon="❌" color={C.critical} />
      </div>
      <div style={{ display: "flex", gap: 20, flexWrap: "wrap" }}>
        <Card style={{ flex: 1, minWidth: 260 }}>
          <h3 style={{ margin: "0 0 16px", fontSize: 14, fontWeight: 700 }}>Patch Compliance</h3>
          {compliancePie.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie data={compliancePie} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={70} label={({ name, percent }) => `${name} ${Math.round(percent * 100)}%`}>
                  {compliancePie.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          ) : <div style={{ color: C.muted }}>No compliance data.</div>}
        </Card>
      </div>
      <Card>
        <h3 style={{ margin: "0 0 12px", fontSize: 14, fontWeight: 700 }}>Asset List</h3>
        {(assets.list || []).length === 0 ? (
          <div style={{ color: C.muted, textAlign: "center", padding: 24 }}>No asset details available in snapshot.</div>
        ) : (
          <SortableTable
            columns={[
              { key: "name",          label: "Name" },
              { key: "ip",            label: "IP" },
              { key: "os",            label: "OS" },
              { key: "status",        label: "Status", render: (v) => <Badge label={v || "Unknown"} bg={v === "online" || v === "Active" ? C.ok : C.muted} /> },
              { key: "patchCompliant", label: "Patch Status", render: (v) => <Badge label={v ? "Compliant" : "Non-Compliant"} bg={v ? C.ok : C.critical} /> },
            ]}
            rows={assets.list}
          />
        )}
      </Card>
      {(assets.patches || []).length > 0 && (
        <Card>
          <h3 style={{ margin: "0 0 12px", fontSize: 14, fontWeight: 700 }}>Patch Details</h3>
          <SortableTable
            columns={[
              { key: "name",     label: "Patch Name" },
              { key: "severity", label: "Severity" },
              { key: "status",   label: "Status" },
              { key: "released", label: "Released" },
            ]}
            rows={assets.patches}
          />
        </Card>
      )}
      <CollectMsg msg={collectMsg} />
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════════
   CLOUD PAGE
════════════════════════════════════════════════════════════════════════ */

function CloudPage({ data, collecting, onCollect, collectMsg }) {
  const azure = data.azure || {};
  const hasData = (data._integrationStatus || {}).azure === "connected";

  if (!hasData) {
    return (
      <EmptyState icon="☁️" title="No Cloud Security Data" sub="Connect Azure to monitor cloud security posture and alerts.">
        <CollectButton tool="azure" label="Azure" collecting={collecting} onCollect={onCollect} />
        <CollectMsg msg={collectMsg} />
      </EmptyState>
    );
  }

  const sum = azure.alertSummary || {};

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      <h2 style={{ margin: 0, fontSize: 22, fontWeight: 800 }}>Cloud Security</h2>
      <div style={{ display: "flex", gap: 20, flexWrap: "wrap", alignItems: "flex-start" }}>
        <Card style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 12, minWidth: 200 }}>
          <h3 style={{ margin: 0, fontSize: 14, fontWeight: 700 }}>Azure Secure Score</h3>
          <ScoreGauge score={azure.secureScore || 0} size={160} label="%" />
          <div style={{ fontSize: 13, color: C.muted }}>
            {azure.currentScore} / {azure.maxScore} points
          </div>
        </Card>
        <div style={{ display: "flex", flexDirection: "column", gap: 12, flex: 1, minWidth: 200 }}>
          <div style={{ display: "flex", gap: 12 }}>
            <KpiCard title="High Alerts"   value={sum.high   || 0} color={C.critical} icon="🔴" />
            <KpiCard title="Medium Alerts" value={sum.medium || 0} color={C.warn}     icon="🟡" />
            <KpiCard title="Low Alerts"    value={sum.low    || 0} color={C.ok}       icon="🟢" />
          </div>
          <KpiCard title="Total Alerts" value={(azure.alerts || []).length} icon="🔔" />
        </div>
      </div>
      <Card>
        <h3 style={{ margin: "0 0 12px", fontSize: 14, fontWeight: 700 }}>Security Alerts</h3>
        <SortableTable
          columns={[
            { key: "displayName", label: "Alert Name" },
            { key: "severity",    label: "Severity", render: (v) => <Badge label={v || "—"} bg={v === "High" ? C.critical : v === "Medium" ? C.warn : C.ok} /> },
            { key: "status",      label: "Status",   render: (v) => <Badge label={v || "—"} bg={v === "Resolved" ? C.ok : C.muted} /> },
            { key: "entity",      label: "Affected Entity" },
          ]}
          rows={azure.alerts || []}
        />
      </Card>
      <CollectMsg msg={collectMsg} />
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════════
   SETTINGS PAGE
════════════════════════════════════════════════════════════════════════ */

const TOOLS_CONFIG = [
  {
    key: "upguard",
    icon: "🌐",
    name: "UpGuard",
    description: "External attack surface monitoring and breach detection.",
    fields: [{ key: "apikey", label: "API Key", type: "password" }],
  },
  {
    key: "qualys",
    icon: "🔍",
    name: "Qualys",
    description: "Vulnerability management and compliance scanning.",
    fields: [
      { key: "platform", label: "Platform URL", type: "text" },
      { key: "username", label: "Username",     type: "text" },
      { key: "password", label: "Password",     type: "password" },
    ],
  },
  {
    key: "fortinet",
    icon: "🔥",
    name: "Fortinet",
    description: "FortiGate next-generation firewall management.",
    multiInstance: true,
    instanceFields: [
      { key: "name",   label: "Label",   type: "text" },
      { key: "host",   label: "Host",    type: "text" },
      { key: "apikey", label: "API Key", type: "password" },
    ],
  },
  {
    key: "paloalto",
    icon: "🛡️",
    name: "Palo Alto",
    description: "Palo Alto Networks NGFW and Panorama integration.",
    fields: [
      { key: "host",   label: "Host",    type: "text" },
      { key: "apikey", label: "API Key", type: "password" },
    ],
  },
  {
    key: "manageengine",
    icon: "📦",
    name: "ManageEngine",
    description: "IT asset management and patch compliance.",
    fields: [
      { key: "host",   label: "Host",    type: "text" },
      { key: "apikey", label: "API Key", type: "password" },
    ],
  },
  {
    key: "azure",
    icon: "☁️",
    name: "Azure",
    description: "Microsoft Azure Security Center and Secure Score.",
    fields: [
      { key: "tenantId",       label: "Tenant ID",       type: "text" },
      { key: "clientId",       label: "Client ID",       type: "text" },
      { key: "clientSecret",   label: "Client Secret",   type: "password" },
      { key: "subscriptionId", label: "Subscription ID", type: "text" },
    ],
  },
];

function SettingsToolCard({ tool, status, collectedAt, collecting, onCollect, collectMsg }) {
  const [expanded, setExpanded] = useState(false);
  const [formValues, setFormValues] = useState({});
  const [instances, setInstances] = useState([{ name: "", host: "", apikey: "" }]);
  const [testResult, setTestResult] = useState(null);
  const [saving, setSaving] = useState(false);

  function setField(key, val) {
    setFormValues((prev) => ({ ...prev, [key]: val }));
  }

  async function handleSave() {
    setSaving(true);
    try {
      const body = tool.multiInstance ? { instances } : formValues;
      const res = await apiFetch(`${API}/api/settings/${tool.key}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const j = await res.json().catch(() => ({}));
      setTestResult(j.ok ? { ok: true, msg: "Settings saved successfully." } : { ok: false, msg: j.error || "Save failed." });
    } catch (err) {
      setTestResult({ ok: false, msg: err.message || "Network error." });
    }
    setSaving(false);
  }

  async function handleTest() {
    setTestResult({ ok: null, msg: "Testing connection…" });
    try {
      const res = await apiFetch(`${API}/api/settings/${tool.key}/test`, { method: "POST" });
      const j = await res.json().catch(() => ({}));
      setTestResult(j.ok ? { ok: true, msg: j.message || "Connection successful." } : { ok: false, msg: j.error || "Test failed." });
    } catch (err) {
      setTestResult({ ok: false, msg: err.message || "Network error." });
    }
  }

  return (
    <Card style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <span style={{ fontSize: 28 }}>{tool.icon}</span>
        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: 700, fontSize: 15 }}>{tool.name}</div>
          <div style={{ fontSize: 12, color: C.textSm }}>{tool.description}</div>
        </div>
        <StatusBadge status={status} />
      </div>
      {collectedAt && (
        <div style={{ fontSize: 11, color: C.muted }}>Last collected: {new Date(collectedAt).toLocaleString()}</div>
      )}
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
        <button onClick={() => setExpanded(!expanded)} style={{ padding: "6px 14px", borderRadius: 8, border: `1px solid ${C.primary}`, background: "none", color: C.primary, cursor: "pointer", fontSize: 13, fontWeight: 600 }}>
          {expanded ? "Close" : "Configure"}
        </button>
        <button onClick={handleTest} style={{ padding: "6px 14px", borderRadius: 8, border: `1px solid ${C.info}`, background: "none", color: C.info, cursor: "pointer", fontSize: 13, fontWeight: 600 }}>
          Test Connection
        </button>
        <CollectButton tool={tool.key} label={tool.name} collecting={collecting} onCollect={onCollect} style={{ padding: "6px 14px", fontSize: 13 }} />
      </div>

      {testResult && (
        <div style={{ fontSize: 13, color: testResult.ok === true ? C.ok : testResult.ok === false ? C.critical : C.warn, fontWeight: 600 }}>
          {testResult.msg}
        </div>
      )}

      {expanded && (
        <div style={{ borderTop: `1px solid ${C.border}`, paddingTop: 14, display: "flex", flexDirection: "column", gap: 10 }}>
          {tool.multiInstance ? (
            <>
              {instances.map((inst, i) => (
                <div key={i} style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "flex-end", background: C.bg, borderRadius: 8, padding: 10 }}>
                  {tool.instanceFields.map((f) => (
                    <div key={f.key} style={{ flex: 1, minWidth: 120 }}>
                      <label style={{ fontSize: 11, fontWeight: 700, color: C.textSm, display: "block", marginBottom: 4 }}>{f.label}</label>
                      <input
                        type={f.type} value={inst[f.key] || ""}
                        onChange={(e) => {
                          const next = [...instances];
                          next[i] = { ...next[i], [f.key]: e.target.value };
                          setInstances(next);
                        }}
                        style={{ width: "100%", padding: "7px 10px", borderRadius: 6, border: `1px solid ${C.border}`, fontSize: 13, boxSizing: "border-box" }}
                      />
                    </div>
                  ))}
                  <button onClick={() => setInstances(instances.filter((_, j) => j !== i))} style={{ padding: "7px 10px", borderRadius: 6, border: `1px solid ${C.critical}`, background: "none", color: C.critical, cursor: "pointer", fontSize: 12 }}>✕</button>
                </div>
              ))}
              <button onClick={() => setInstances([...instances, { name: "", host: "", apikey: "" }])} style={{ alignSelf: "flex-start", padding: "6px 14px", borderRadius: 8, border: `1px solid ${C.ok}`, background: "none", color: C.ok, cursor: "pointer", fontSize: 13 }}>
                + Add Instance
              </button>
            </>
          ) : (
            (tool.fields || []).map((f) => (
              <div key={f.key}>
                <label style={{ fontSize: 11, fontWeight: 700, color: C.textSm, display: "block", marginBottom: 4 }}>{f.label}</label>
                <input
                  type={f.type} value={formValues[f.key] || ""}
                  onChange={(e) => setField(f.key, e.target.value)}
                  style={{ width: "100%", padding: "8px 12px", borderRadius: 8, border: `1px solid ${C.border}`, fontSize: 13, boxSizing: "border-box" }}
                />
              </div>
            ))
          )}
          <button onClick={handleSave} disabled={saving} style={{ alignSelf: "flex-start", padding: "8px 20px", borderRadius: 8, border: "none", background: C.primary, color: "#fff", cursor: saving ? "wait" : "pointer", fontSize: 13, fontWeight: 700 }}>
            {saving ? "Saving…" : "Save Settings"}
          </button>
        </div>
      )}
    </Card>
  );
}

function SettingsPage({ data, collecting, onCollect, collectMsg }) {
  const status = data._integrationStatus || {};
  const collectedAt = data._collectedAt || {};

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      <h2 style={{ margin: 0, fontSize: 22, fontWeight: 800 }}>Settings</h2>
      <p style={{ margin: 0, color: C.textSm, fontSize: 14 }}>Configure integrations, test connections, and collect data from each security tool.</p>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(380px, 1fr))", gap: 16 }}>
        {TOOLS_CONFIG.map((tool) => (
          <SettingsToolCard
            key={tool.key}
            tool={tool}
            status={status[tool.key] || "no-data"}
            collectedAt={collectedAt[tool.key]}
            collecting={collecting}
            onCollect={onCollect}
            collectMsg={collectMsg}
          />
        ))}
      </div>
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════════
   APP ROOT
════════════════════════════════════════════════════════════════════════ */

export default function App() {
  const [session, setSession] = useState(null);
  const [page, setPage] = useState("dashboard");
  const [data, setData] = useState({});
  const [loading, setLoading] = useState(true);
  const [collecting, setCollecting] = useState(null);
  const [collectMsg, setCollectMsg] = useState("");
  const [sidebarOpen, setSidebarOpen] = useState(true);

  const role = session && session.role;

  /* Auth check + snapshot load */
  const loadAll = useCallback(async () => {
    try {
      const meRes = await apiFetch(`${API}/api/auth/me`);
      if (!meRes.ok) { setSession(null); setLoading(false); return; }
      const me = await meRes.json().catch(() => null);
      if (!me || !me.username) { setSession(null); setLoading(false); return; }
      setSession(me);

      const snapRes = await apiFetch(`${API}/api/snapshot`);
      if (snapRes.ok) {
        const raw = await snapRes.json().catch(() => ({}));
        setData(transformSnapshot(raw.data || raw));
      }
    } catch (err) {
      // server unreachable — keep whatever we have
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    loadAll();
    const timer = setInterval(loadAll, 5 * 60 * 1000);
    return () => clearInterval(timer);
  }, [loadAll]);

  /* collectNow */
  const collectNow = useCallback(async (tool, label) => {
    setCollecting(tool); setCollectMsg("");
    try {
      const res = await apiFetch(`${API}/api/collect/${tool}`, { method: "POST" });
      const j = await res.json().catch(() => ({}));
      if (j.ok) {
        setCollectMsg(`✅ ${label} data collected! Reloading…`);
        setTimeout(() => window.location.reload(), 1200);
      } else {
        setCollectMsg("❌ " + (j.error || "Collection failed — check Settings"));
        setCollecting(null);
      }
    } catch (e) {
      setCollectMsg("❌ " + (e.message || "Network error"));
      setCollecting(null);
    }
  }, []);

  /* Nav items */
  const navItems = useMemo(() => {
    if (role === "executive") {
      return [{ id: "dashboard", icon: "🏛️", label: "Executive Dashboard" }];
    }
    const items = [
      { id: "dashboard",    icon: "🏛️", label: "Dashboard" },
      { id: "surface",      icon: "🌐", label: "Threat Surface" },
      { id: "vulns",        icon: "🔍", label: "Vulnerabilities" },
      { id: "firewall",     icon: "🔥", label: "Firewalls" },
      { id: "assets",       icon: "📦", label: "Assets & Patches" },
      { id: "cloud",        icon: "☁️", label: "Cloud Security" },
      { id: "settings",     icon: "⚙️", label: "Settings" },
    ];
    return items;
  }, [role]);

  async function handleLogout() {
    await apiFetch(`${API}/api/auth/logout`, { method: "POST" }).catch(() => {});
    setSession(null);
    setPage("dashboard");
  }

  /* Guard — login */
  if (loading) {
    return (
      <div style={{ minHeight: "100vh", background: C.bg, display: "flex", alignItems: "center", justifyContent: "center" }}>
        <Spinner />
      </div>
    );
  }

  if (!session) {
    return <LoginPage onLogin={(u) => { setSession(u); setLoading(true); loadAll(); }} />;
  }

  /* Page routing */
  const pageProps = { data, collecting, onCollect: collectNow, collectMsg };

  function renderPage() {
    if (role === "executive") return <ExecutiveDashboard {...pageProps} />;
    switch (page) {
      case "dashboard": return <ExecutiveDashboard {...pageProps} />;
      case "surface":   return <ThreatSurfacePage {...pageProps} />;
      case "vulns":     return <VulnerabilityPage {...pageProps} />;
      case "firewall":  return <FirewallPage {...pageProps} />;
      case "assets":    return <AssetPage {...pageProps} />;
      case "cloud":     return <CloudPage {...pageProps} />;
      case "settings":  return <SettingsPage {...pageProps} />;
      default:          return <ExecutiveDashboard {...pageProps} />;
    }
  }

  const SIDEBAR_W = sidebarOpen ? 230 : 62;

  return (
    <div style={{ display: "flex", minHeight: "100vh", background: C.bg, fontFamily: "'Inter','Segoe UI',system-ui,sans-serif", color: C.text }}>
      <style>{`
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { background: ${C.bg}; }
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: ${C.border}; border-radius: 3px; }
        @keyframes spin { to { transform: rotate(360deg); } }
      `}</style>

      {/* Sidebar */}
      <aside style={{
        width: SIDEBAR_W, minHeight: "100vh", background: C.sidebar,
        display: "flex", flexDirection: "column",
        transition: "width 0.2s ease", overflow: "hidden", flexShrink: 0,
        position: "sticky", top: 0, height: "100vh",
      }}>
        {/* Logo */}
        <div style={{ padding: "20px 16px 16px", display: "flex", alignItems: "center", gap: 10, borderBottom: `1px solid rgba(255,255,255,0.08)` }}>
          <span style={{ fontSize: 22, flexShrink: 0 }}>🛡️</span>
          {sidebarOpen && <span style={{ fontSize: 13, fontWeight: 700, color: "#fff", lineHeight: 1.2 }}>SecOps<br /><span style={{ fontSize: 10, fontWeight: 400, opacity: 0.6 }}>Command Center</span></span>}
          <button onClick={() => setSidebarOpen(!sidebarOpen)} style={{ marginLeft: "auto", background: "none", border: "none", color: "rgba(255,255,255,0.5)", cursor: "pointer", fontSize: 16, flexShrink: 0 }}>
            {sidebarOpen ? "◀" : "▶"}
          </button>
        </div>

        {/* Nav */}
        <nav style={{ flex: 1, padding: "12px 8px", display: "flex", flexDirection: "column", gap: 2 }}>
          {navItems.map((item) => {
            const active = page === item.id || (role === "executive");
            return (
              <button
                key={item.id}
                onClick={() => setPage(item.id)}
                style={{
                  display: "flex", alignItems: "center", gap: 10, padding: "10px 10px",
                  borderRadius: 8, border: "none", cursor: "pointer", textAlign: "left",
                  background: active ? C.sidebarAc : "transparent",
                  color: active ? "#fff" : "rgba(255,255,255,0.65)",
                  fontSize: 13, fontWeight: active ? 700 : 500,
                  transition: "background 0.15s",
                }}
                onMouseEnter={(e) => { if (!active) e.currentTarget.style.background = "rgba(255,255,255,0.06)"; }}
                onMouseLeave={(e) => { if (!active) e.currentTarget.style.background = "transparent"; }}
              >
                <span style={{ fontSize: 18, flexShrink: 0 }}>{item.icon}</span>
                {sidebarOpen && <span style={{ whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{item.label}</span>}
              </button>
            );
          })}
        </nav>

        {/* User */}
        <div style={{ padding: "12px 10px", borderTop: `1px solid rgba(255,255,255,0.08)`, display: "flex", alignItems: "center", gap: 8 }}>
          <div style={{ width: 32, height: 32, borderRadius: "50%", background: C.primary, display: "flex", alignItems: "center", justifyContent: "center", color: "#fff", fontSize: 13, fontWeight: 700, flexShrink: 0 }}>
            {(session.username || session.name || "U")[0].toUpperCase()}
          </div>
          {sidebarOpen && (
            <div style={{ flex: 1, overflow: "hidden" }}>
              <div style={{ fontSize: 12, fontWeight: 700, color: "#fff", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{session.username || session.name}</div>
              <div style={{ fontSize: 10, color: "rgba(255,255,255,0.5)", textTransform: "capitalize" }}>{session.role}</div>
            </div>
          )}
          {sidebarOpen && (
            <button onClick={handleLogout} title="Logout" style={{ background: "none", border: "none", color: "rgba(255,255,255,0.4)", cursor: "pointer", fontSize: 16 }}>⏻</button>
          )}
        </div>
      </aside>

      {/* Main */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0 }}>
        {/* Header */}
        <header style={{
          height: 56, background: C.header, display: "flex", alignItems: "center",
          padding: "0 24px", gap: 16, position: "sticky", top: 0, zIndex: 100,
          borderBottom: `1px solid rgba(255,255,255,0.08)`,
        }}>
          <h1 style={{ flex: 1, fontSize: 15, fontWeight: 700, color: "#fff", margin: 0 }}>
            {navItems.find((n) => n.id === page)?.label || "Dashboard"}
          </h1>
          {collecting && (
            <div style={{ fontSize: 12, color: "rgba(255,255,255,0.6)", display: "flex", alignItems: "center", gap: 6 }}>
              <div style={{ width: 8, height: 8, borderRadius: "50%", background: C.warn, animation: "spin 1s linear infinite" }} />
              Collecting…
            </div>
          )}
          <div style={{ fontSize: 12, color: "rgba(255,255,255,0.5)" }}>
            {new Date().toLocaleDateString("en-AU", { day: "2-digit", month: "short", year: "numeric" })}
          </div>
        </header>

        {/* Content */}
        <main style={{ flex: 1, padding: 28, overflowY: "auto" }}>
          {renderPage()}
        </main>
      </div>
    </div>
  );
}