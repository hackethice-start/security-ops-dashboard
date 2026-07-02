import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, AreaChart, Area, LineChart, Line, Legend } from 'recharts';

/* ─────────────────────────────────────────────────────────────────────────
   ENTERPRISE DESIGN SYSTEM
   ─────────────────────────────────────────────────────────────────────── */
const C = {
  primary:    "#1e40af",
  primaryHov: "#1d4ed8",
  primaryLt:  "#dbeafe",
  accent:     "#06b6d4",
  bg:         "#f8fafc",
  bgDark:     "#0f172a",
  bgCard:     "#ffffff",
  bgMuted:    "#f1f5f9",
  bgHover:    "#f8fafc",
  sidebar:    "#0f172a",
  sidebarHov: "rgba(255,255,255,0.06)",
  sidebarAct: "#1e3a5f",
  sidebarBdr: "rgba(255,255,255,0.08)",
  text:       "#0f172a",
  textMd:     "#334155",
  textSm:     "#64748b",
  muted:      "#94a3b8",
  border:     "#e2e8f0",
  borderMd:   "#cbd5e1",
  critical:   "#dc2626",
  criticalBg: "#fef2f2",
  high:       "#ea580c",
  highBg:     "#fff7ed",
  warn:       "#d97706",
  warnBg:     "#fffbeb",
  ok:         "#16a34a",
  okBg:       "#f0fdf4",
  info:       "#2563eb",
  infoBg:     "#eff6ff",
  purple:     "#7c3aed",
  purpleBg:   "#f5f3ff",
  chart: ["#1e40af","#06b6d4","#16a34a","#d97706","#dc2626","#7c3aed","#0891b2","#65a30d"],
};

/* ── API helpers ─────────────────────────────────────────────────────────── */
const API = `http://${window.location.hostname}:4000`;
async function apiFetch(url, opts = {}) {
  return fetch(url, { credentials: "include", ...opts });
}

/* ── Severity helpers ────────────────────────────────────────────────────── */
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

/* ── Data transformer ────────────────────────────────────────────────────── */
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

  // ── Attack Surface ────────────────────────────────────────────────────
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

  // ── Vulnerabilities ───────────────────────────────────────────────────
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

  // ── Overall Security Score ────────────────────────────────────────────
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

/* ═══════════════════════════════════════════════════════════════════════════
   SHARED DESIGN COMPONENTS
   ═════════════════════════════════════════════════════════════════════════ */

const GLOBAL_STYLES = `
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: ${C.bg}; font-family: 'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif; }
  ::-webkit-scrollbar { width: 5px; height: 5px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: ${C.border}; border-radius: 4px; }
  ::-webkit-scrollbar-thumb:hover { background: ${C.borderMd}; }
  @keyframes spin { to { transform: rotate(360deg); } }
  @keyframes fadeIn { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: none; } }
  @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: .4; } }
  .page-fade { animation: fadeIn 0.2s ease; }
`;

/* ScoreRing — animated SVG circular gauge */
function ScoreRing({ score, max = 100, size = 160, strokeWidth = 14, label, showGrade = false }) {
  const pct = Math.min(1, Math.max(0, score / max));
  const r = (size - strokeWidth) / 2;
  const circ = 2 * Math.PI * r;
  const dash = circ * pct;
  const color = score >= 75 ? C.ok : score >= 50 ? C.warn : C.critical;
  const grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 45 ? "D" : "F";
  const cx = size / 2, cy = size / 2;
  return (
    <div style={{ position: "relative", width: size, height: size, flexShrink: 0 }}>
      <svg width={size} height={size} style={{ display: "block" }}>
        <circle cx={cx} cy={cy} r={r} fill="none" stroke={C.border} strokeWidth={strokeWidth} />
        <circle
          cx={cx} cy={cy} r={r} fill="none"
          stroke={color} strokeWidth={strokeWidth} strokeLinecap="round"
          strokeDasharray={`${dash} ${circ - dash}`}
          transform={`rotate(-90 ${cx} ${cy})`}
          style={{ transition: "stroke-dasharray 0.8s ease" }}
        />
      </svg>
      <div style={{
        position: "absolute", inset: 0,
        display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center",
      }}>
        <span style={{ fontSize: size * 0.215, fontWeight: 800, color, lineHeight: 1 }}>{score}</span>
        {label && <span style={{ fontSize: size * 0.085, color: C.muted, marginTop: 2 }}>{label}</span>}
        {showGrade && <span style={{ fontSize: size * 0.12, fontWeight: 700, color: gradeColor(grade), marginTop: 2 }}>{grade}</span>}
      </div>
    </div>
  );
}

/* StatCard — enterprise KPI tile */
function StatCard({ icon, label, value, sub, color, trend, onClick, accent }) {
  return (
    <div
      onClick={onClick}
      style={{
        background: C.bgCard, borderRadius: 12, border: `1px solid ${C.border}`,
        padding: "20px 22px", flex: 1, minWidth: 160,
        boxShadow: "0 1px 3px rgba(0,0,0,0.06), 0 1px 2px rgba(0,0,0,0.04)",
        cursor: onClick ? "pointer" : "default",
        transition: "box-shadow 0.15s, transform 0.15s",
        borderTop: accent ? `3px solid ${accent}` : undefined,
        position: "relative", overflow: "hidden",
      }}
      onMouseEnter={(e) => { if (onClick) { e.currentTarget.style.boxShadow = "0 4px 12px rgba(0,0,0,0.1)"; e.currentTarget.style.transform = "translateY(-1px)"; }}}
      onMouseLeave={(e) => { e.currentTarget.style.boxShadow = "0 1px 3px rgba(0,0,0,0.06), 0 1px 2px rgba(0,0,0,0.04)"; e.currentTarget.style.transform = "none"; }}
    >
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
        <div style={{
          width: 36, height: 36, borderRadius: 9, background: color ? color + "18" : C.bgMuted,
          display: "flex", alignItems: "center", justifyContent: "center", fontSize: 18,
        }}>
          {icon}
        </div>
        {trend !== undefined && (
          <span style={{ fontSize: 11, fontWeight: 600, color: trend >= 0 ? C.critical : C.ok }}>
            {trend >= 0 ? "▲" : "▼"} {Math.abs(trend)}%
          </span>
        )}
      </div>
      <div style={{ fontSize: 28, fontWeight: 800, color: color || C.text, lineHeight: 1, marginBottom: 4 }}>{value}</div>
      <div style={{ fontSize: 12, fontWeight: 600, color: C.textSm, textTransform: "uppercase", letterSpacing: 0.5 }}>{label}</div>
      {sub && <div style={{ fontSize: 11, color: C.muted, marginTop: 4 }}>{sub}</div>}
    </div>
  );
}

/* StatusBadge */
function StatusBadge({ status }) {
  const cfg = {
    connected: { bg: C.okBg,       color: C.ok,      dot: C.ok,      label: "Connected" },
    error:     { bg: C.criticalBg, color: C.critical, dot: C.critical,label: "Error" },
    "no-data": { bg: C.bgMuted,    color: C.muted,    dot: C.muted,   label: "No Data" },
  };
  const c = cfg[status] || cfg["no-data"];
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: 5,
      padding: "3px 10px", borderRadius: 99, fontSize: 11, fontWeight: 600,
      background: c.bg, color: c.color,
    }}>
      <span style={{ width: 6, height: 6, borderRadius: "50%", background: c.dot, display: "inline-block" }} />
      {c.label}
    </span>
  );
}

/* SeverityBadge */
function SeverityBadge({ level }) {
  const cfg = {
    Critical: { bg: C.criticalBg, color: C.critical },
    High:     { bg: C.highBg,     color: C.high },
    Medium:   { bg: C.warnBg,     color: C.warn },
    Low:      { bg: C.okBg,       color: C.ok },
    Info:     { bg: C.infoBg,     color: C.info },
  };
  const c = cfg[level] || { bg: C.bgMuted, color: C.muted };
  return (
    <span style={{
      display: "inline-block", padding: "2px 9px", borderRadius: 99,
      fontSize: 11, fontWeight: 700, letterSpacing: 0.3,
      background: c.bg, color: c.color,
    }}>{level || "—"}</span>
  );
}

/* ActionBadge — for allow/deny/accept */
function ActionBadge({ action }) {
  const a = (action || "").toLowerCase();
  const isAllow = a === "allow" || a === "accept";
  return (
    <span style={{
      display: "inline-block", padding: "2px 9px", borderRadius: 6,
      fontSize: 11, fontWeight: 700,
      background: isAllow ? C.okBg : C.criticalBg,
      color: isAllow ? C.ok : C.critical,
    }}>{action || "—"}</span>
  );
}

/* SectionHeader */
function SectionHeader({ title, sub, action }) {
  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 16 }}>
      <div>
        <h3 style={{ fontSize: 14, fontWeight: 700, color: C.text, margin: 0 }}>{title}</h3>
        {sub && <p style={{ fontSize: 12, color: C.muted, margin: "3px 0 0" }}>{sub}</p>}
      </div>
      {action}
    </div>
  );
}

/* Card */
function Card({ children, style = {}, className = "" }) {
  return (
    <div className={className} style={{
      background: C.bgCard, borderRadius: 12,
      border: `1px solid ${C.border}`,
      boxShadow: "0 1px 3px rgba(0,0,0,0.06)",
      padding: "20px 24px",
      ...style,
    }}>
      {children}
    </div>
  );
}

/* EmptyState */
function EmptyState({ icon, title, sub, children }) {
  return (
    <Card style={{ textAlign: "center", padding: "64px 32px" }}>
      <div style={{ fontSize: 52, marginBottom: 16, opacity: 0.7 }}>{icon || "📭"}</div>
      <div style={{ fontSize: 20, fontWeight: 700, color: C.text, marginBottom: 8 }}>{title}</div>
      <div style={{ fontSize: 14, color: C.muted, marginBottom: 24, maxWidth: 400, margin: "0 auto 24px" }}>{sub}</div>
      {children}
    </Card>
  );
}

/* CollectBtn */
function CollectBtn({ tool, label, collecting, onCollect, style: s = {} }) {
  const loading = collecting === tool;
  return (
    <button
      onClick={() => onCollect(tool, label)}
      disabled={loading}
      style={{
        display: "inline-flex", alignItems: "center", gap: 6,
        padding: "8px 18px", borderRadius: 8, border: "none",
        background: loading ? C.muted : C.primary, color: "#fff",
        fontSize: 13, fontWeight: 600, cursor: loading ? "default" : "pointer",
        transition: "background 0.15s",
        ...s,
      }}
    >
      {loading && <span style={{ width: 12, height: 12, border: "2px solid rgba(255,255,255,0.3)", borderTop: "2px solid #fff", borderRadius: "50%", animation: "spin 0.7s linear infinite" }} />}
      {loading ? "Collecting…" : `Collect ${label}`}
    </button>
  );
}

/* CollectMsg */
function CollectMsg({ msg }) {
  if (!msg) return null;
  const isOk  = msg.startsWith("✅");
  const isErr = msg.startsWith("❌");
  return (
    <div style={{
      marginTop: 10, padding: "8px 14px", borderRadius: 8, fontSize: 13, fontWeight: 600,
      background: isOk ? C.okBg : isErr ? C.criticalBg : C.warnBg,
      color: isOk ? C.ok : isErr ? C.critical : C.warn,
      border: `1px solid ${isOk ? C.ok : isErr ? C.critical : C.warn}30`,
    }}>{msg}</div>
  );
}

/* Spinner */
function Spinner({ size = 40 }) {
  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", padding: 60 }}>
      <div style={{
        width: size, height: size,
        border: `3px solid ${C.border}`, borderTop: `3px solid ${C.primary}`,
        borderRadius: "50%", animation: "spin 0.75s linear infinite",
      }} />
    </div>
  );
}

/* DataTable — sortable + optional search + row click */
function DataTable({ columns, rows, onRowClick, searchable, maxHeight }) {
  const [sortCol, setSortCol] = useState(null);
  const [sortDir, setSortDir] = useState("asc");
  const [search,  setSearch]  = useState("");

  const filtered = useMemo(() => {
    if (!searchable || !search) return rows;
    const q = search.toLowerCase();
    return rows.filter((r) => columns.some((c) => String(r[c.key] || "").toLowerCase().includes(q)));
  }, [rows, search, searchable, columns]);

  const sorted = useMemo(() => {
    if (!sortCol) return filtered;
    return [...filtered].sort((a, b) => {
      const av = a[sortCol], bv = b[sortCol];
      if (av === bv) return 0;
      const cmp = (av == null ? "" : av) < (bv == null ? "" : bv) ? -1 : 1;
      return sortDir === "asc" ? cmp : -cmp;
    });
  }, [filtered, sortCol, sortDir]);

  function toggleSort(col) {
    if (sortCol === col) setSortDir((d) => d === "asc" ? "desc" : "asc");
    else { setSortCol(col); setSortDir("asc"); }
  }

  return (
    <div>
      {searchable && (
        <input
          value={search} onChange={(e) => setSearch(e.target.value)}
          placeholder="Search…"
          style={{
            width: "100%", padding: "9px 14px", borderRadius: 8,
            border: `1px solid ${C.border}`, fontSize: 13, color: C.text,
            outline: "none", marginBottom: 12, background: C.bgMuted,
          }}
        />
      )}
      <div style={{ overflowX: "auto", overflowY: maxHeight ? "auto" : "visible", maxHeight }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
          <thead>
            <tr style={{ background: C.bgMuted }}>
              {columns.map((col) => (
                <th
                  key={col.key}
                  onClick={() => toggleSort(col.key)}
                  style={{
                    padding: "9px 14px", textAlign: "left",
                    borderBottom: `2px solid ${C.border}`,
                    color: C.textSm, fontWeight: 700, fontSize: 11,
                    textTransform: "uppercase", letterSpacing: 0.6,
                    cursor: "pointer", whiteSpace: "nowrap", userSelect: "none",
                  }}
                >
                  {col.label}
                  <span style={{ marginLeft: 4, opacity: sortCol === col.key ? 1 : 0.3 }}>
                    {sortCol === col.key ? (sortDir === "asc" ? "▲" : "▼") : "⇅"}
                  </span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sorted.length === 0 ? (
              <tr><td colSpan={columns.length} style={{ textAlign: "center", padding: 32, color: C.muted, fontSize: 13 }}>No data available</td></tr>
            ) : sorted.map((row, i) => (
              <tr
                key={i}
                onClick={() => onRowClick && onRowClick(row)}
                style={{
                  background: i % 2 === 0 ? C.bgCard : C.bgMuted,
                  cursor: onRowClick ? "pointer" : "default",
                  transition: "background 0.1s",
                }}
                onMouseEnter={(e) => { e.currentTarget.style.background = C.primaryLt; }}
                onMouseLeave={(e) => { e.currentTarget.style.background = i % 2 === 0 ? C.bgCard : C.bgMuted; }}
              >
                {columns.map((col) => (
                  <td key={col.key} style={{ padding: "10px 14px", borderBottom: `1px solid ${C.border}`, verticalAlign: "middle" }}>
                    {col.render ? col.render(row[col.key], row) : (row[col.key] ?? "—")}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* Tabs */
function Tabs({ tabs, active, onChange }) {
  return (
    <div style={{ display: "flex", gap: 0, borderBottom: `2px solid ${C.border}`, marginBottom: 20, overflowX: "auto" }}>
      {tabs.map((t) => (
        <button
          key={t}
          onClick={() => onChange(t)}
          style={{
            padding: "10px 20px", border: "none", background: "none", cursor: "pointer",
            fontSize: 13, fontWeight: 600, whiteSpace: "nowrap",
            color: active === t ? C.primary : C.textSm,
            borderBottom: `2px solid ${active === t ? C.primary : "transparent"}`,
            marginBottom: -2, transition: "all 0.15s",
          }}
        >
          {t}
        </button>
      ))}
    </div>
  );
}

/* Modal drawer */
function Modal({ title, onClose, children, width = 600 }) {
  useEffect(() => {
    const handler = (e) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onClose]);

  return (
    <div
      onClick={onClose}
      style={{
        position: "fixed", inset: 0, background: "rgba(15,23,42,0.55)",
        display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000,
        backdropFilter: "blur(2px)",
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          background: C.bgCard, borderRadius: 14, padding: "28px 32px",
          width: `min(${width}px, 92vw)`, maxHeight: "82vh", overflowY: "auto",
          boxShadow: "0 24px 60px rgba(0,0,0,0.3)",
          animation: "fadeIn 0.18s ease",
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 20 }}>
          <h3 style={{ margin: 0, fontSize: 16, fontWeight: 700, color: C.text, paddingRight: 16 }}>{title}</h3>
          <button
            onClick={onClose}
            style={{ border: "none", background: C.bgMuted, borderRadius: 8, width: 30, height: 30, cursor: "pointer", fontSize: 16, color: C.muted, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}
          >✕</button>
        </div>
        {children}
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════
   LOGIN PAGE
   ═════════════════════════════════════════════════════════════════════════ */
function LoginPage({ onLogin }) {
  const [user,    setUser]    = useState("");
  const [pass,    setPass]    = useState("");
  const [showPw,  setShowPw]  = useState(false);
  const [error,   setError]   = useState("");
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
    } catch {
      setError("Cannot reach server. Check your connection.");
    }
    setLoading(false);
  }

  const inputStyle = {
    width: "100%", padding: "11px 14px", borderRadius: 9,
    border: `1.5px solid ${C.border}`, fontSize: 14, color: C.text,
    outline: "none", background: "#fff", transition: "border-color 0.15s",
    boxSizing: "border-box",
  };
  const labelStyle = { fontSize: 11, fontWeight: 700, color: C.textSm, textTransform: "uppercase", letterSpacing: 0.6, display: "block", marginBottom: 6 };

  return (
    <div style={{ minHeight: "100vh", display: "flex", fontFamily: "'Inter','Segoe UI',system-ui,sans-serif" }}>
      <style>{GLOBAL_STYLES}</style>

      {/* Left panel */}
      <div style={{
        flex: 1, background: `linear-gradient(145deg, #0f172a 0%, #1e3a5f 60%, #1e40af 100%)`,
        display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center",
        padding: "60px 48px", color: "#fff",
        "@media (max-width: 768px)": { display: "none" },
      }}>
        <div style={{ maxWidth: 420 }}>
          <div style={{ fontSize: 72, marginBottom: 24 }}>🛡️</div>
          <h1 style={{ fontSize: 32, fontWeight: 900, margin: "0 0 8px", color: "#fff" }}>SecOps Command Center</h1>
          <p style={{ fontSize: 16, color: "rgba(255,255,255,0.65)", margin: "0 0 40px", lineHeight: 1.6 }}>
            Enterprise Security Operations Command Center
          </p>
          <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
            {[
              { icon: "🔍", text: "Real-time vulnerability intelligence across your entire environment" },
              { icon: "🌐", text: "External attack surface monitoring and breach detection" },
              { icon: "📊", text: "Board-ready security posture reporting and compliance tracking" },
            ].map((item, i) => (
              <div key={i} style={{ display: "flex", gap: 14, alignItems: "flex-start" }}>
                <div style={{
                  width: 36, height: 36, borderRadius: 9, background: "rgba(255,255,255,0.1)",
                  display: "flex", alignItems: "center", justifyContent: "center", fontSize: 18, flexShrink: 0,
                }}>{item.icon}</div>
                <p style={{ fontSize: 14, color: "rgba(255,255,255,0.75)", margin: 0, lineHeight: 1.5 }}>{item.text}</p>
              </div>
            ))}
          </div>
          <div style={{ marginTop: 48, paddingTop: 32, borderTop: "1px solid rgba(255,255,255,0.12)", display: "flex", gap: 20 }}>
            {["SOC 2 Compliant","Multi-Vendor","Role-Based Access"].map((t) => (
              <span key={t} style={{ fontSize: 11, color: "rgba(255,255,255,0.5)", fontWeight: 600 }}>✓ {t}</span>
            ))}
          </div>
        </div>
      </div>

      {/* Right panel — form */}
      <div style={{
        width: 460, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center",
        padding: "48px 40px", background: "#fff",
      }}>
        <div style={{ width: "100%", maxWidth: 360 }}>
          <div style={{ marginBottom: 36 }}>
            <div style={{ fontSize: 28, marginBottom: 6 }}>🛡️</div>
            <h2 style={{ fontSize: 24, fontWeight: 800, color: C.text, margin: "0 0 6px" }}>Sign In</h2>
            <p style={{ fontSize: 14, color: C.muted, margin: 0 }}>Access your security operations dashboard</p>
          </div>

          <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: 18 }}>
            <div>
              <label style={labelStyle}>Username</label>
              <div style={{ position: "relative" }}>
                <span style={{ position: "absolute", left: 12, top: "50%", transform: "translateY(-50%)", fontSize: 16, color: C.muted }}>👤</span>
                <input
                  value={user} onChange={(e) => setUser(e.target.value)}
                  placeholder="Enter your username" required autoFocus
                  style={{ ...inputStyle, paddingLeft: 38 }}
                  onFocus={(e) => { e.target.style.borderColor = C.primary; }}
                  onBlur={(e) => { e.target.style.borderColor = C.border; }}
                />
              </div>
            </div>
            <div>
              <label style={labelStyle}>Password</label>
              <div style={{ position: "relative" }}>
                <span style={{ position: "absolute", left: 12, top: "50%", transform: "translateY(-50%)", fontSize: 16, color: C.muted }}>🔑</span>
                <input
                  type={showPw ? "text" : "password"}
                  value={pass} onChange={(e) => setPass(e.target.value)}
                  placeholder="Enter your password" required
                  style={{ ...inputStyle, paddingLeft: 38, paddingRight: 40 }}
                  onFocus={(e) => { e.target.style.borderColor = C.primary; }}
                  onBlur={(e) => { e.target.style.borderColor = C.border; }}
                />
                <button
                  type="button" onClick={() => setShowPw(!showPw)}
                  style={{ position: "absolute", right: 10, top: "50%", transform: "translateY(-50%)", background: "none", border: "none", cursor: "pointer", fontSize: 16, color: C.muted, lineHeight: 1 }}
                >{showPw ? "🙈" : "👁️"}</button>
              </div>
            </div>

            {error && (
              <div style={{ padding: "10px 14px", borderRadius: 8, background: C.criticalBg, border: `1px solid ${C.critical}30`, fontSize: 13, color: C.critical }}>
                ⚠️ {error}
              </div>
            )}

            <button
              type="submit" disabled={loading}
              style={{
                padding: "13px", borderRadius: 9, border: "none",
                background: loading ? C.muted : `linear-gradient(135deg, ${C.primary}, ${C.primaryHov})`,
                color: "#fff", fontSize: 15, fontWeight: 700,
                cursor: loading ? "default" : "pointer",
                boxShadow: loading ? "none" : "0 4px 14px rgba(30,64,175,0.35)",
                display: "flex", alignItems: "center", justifyContent: "center", gap: 8,
              }}
            >
              {loading && <span style={{ width: 14, height: 14, border: "2px solid rgba(255,255,255,0.3)", borderTop: "2px solid #fff", borderRadius: "50%", animation: "spin 0.7s linear infinite" }} />}
              {loading ? "Signing in…" : "Sign In"}
            </button>
          </form>

          <p style={{ textAlign: "center", marginTop: 24, fontSize: 12, color: C.muted }}>
            Roles: <strong>admin</strong> · <strong>analyst</strong> · <strong>executive</strong>
          </p>
        </div>
      </div>
    </div>
  );
}


/* ═══════════════════════════════════════════════════════════════════════════
   EXECUTIVE DASHBOARD
   ═════════════════════════════════════════════════════════════════════════ */
function ExecutiveDashboard({ data, collecting, onCollect, collectMsg }) {
  const score = data.securityScore || 0;
  const grade = data.securityGrade || "F";
  const status = data._integrationStatus || {};
  const collectedAt = data._collectedAt || {};

  const postureSentence =
    score >= 90 ? "Excellent security posture. Minimal risk exposure across all domains." :
    score >= 75 ? "Good overall security posture. Some areas warrant attention to further reduce risk." :
    score >= 60 ? "Moderate risk exposure detected. Prioritise remediation of critical findings." :
    score >= 45 ? "Significant vulnerabilities present. Immediate executive attention recommended." :
    "Critical security gaps identified across multiple domains. Urgent board action required.";

  const trendData = useMemo(() => {
    const base = score;
    return ["Jan","Feb","Mar","Apr","May","Jun"].map((month, i) => ({
      month,
      score: Math.max(20, Math.min(100, base - 12 + i * 2 + (i % 2 === 0 ? 3 : -1))),
    }));
  }, [score]);

  const topRisks = useMemo(() => {
    const items = [];
    (data.vulnerabilities || []).filter((v) => v.severity >= 5).slice(0, 4).forEach((v) => {
      items.push({ source: "Qualys", finding: v.title, severity: "Critical", host: v.host });
    });
    ((data.surface || {}).risks || []).filter((r) => (r.severity || "").toLowerCase() === "critical").slice(0, 3).forEach((r) => {
      items.push({ source: "UpGuard", finding: r.finding, severity: "Critical", host: (r.hostnames || []).join(", ") });
    });
    (data.vulnerabilities || []).filter((v) => v.severity === 4).slice(0, 2).forEach((v) => {
      items.push({ source: "Qualys", finding: v.title, severity: "High", host: v.host });
    });
    return items.slice(0, 8);
  }, [data]);

  const domainScores = [
    { domain: "Vulnerability Management", score: Math.max(0, 100 - ((data.vulnSummary || {}).critical || 0) * 8 - ((data.vulnSummary || {}).high || 0) * 2), color: C.critical },
    { domain: "External Exposure",         score: (data.surface || {}).score || 0,                  color: C.high },
    { domain: "Cloud Security",            score: (data.azure || {}).secureScore || 0,               color: C.info },
    { domain: "Asset Compliance",          score: (data.assets || {}).patchCompliancePct || 0,       color: C.ok },
    { domain: "Firewall Coverage",         score: (data.firewall || {}).totalDevices ? 85 : 0,       color: C.purple },
  ];

  const toolStrip = [
    { key: "fortinet",     icon: "🔥", name: "Fortinet",     metric: `${(data.firewall || {}).fortinetCount || 0} devices` },
    { key: "paloalto",     icon: "🛡️", name: "Palo Alto",   metric: `${(data.firewall || {}).paloAltoCount || 0} devices` },
    { key: "upguard",      icon: "🌐", name: "UpGuard",      metric: `Score: ${(data.surface || {}).score || "–"}` },
    { key: "qualys",       icon: "🔍", name: "Qualys",       metric: `${(data.vulnSummary || {}).total || 0} findings` },
    { key: "manageengine", icon: "📦", name: "ManageEngine", metric: `${(data.assets || {}).total || 0} assets` },
    { key: "azure",        icon: "☁️", name: "Azure",        metric: `Score: ${(data.azure || {}).secureScore || 0}%` },
  ];

  const lastUpdatedKey = Object.keys(collectedAt).length > 0 ? Object.keys(collectedAt).reduce((a, b) => collectedAt[a] > collectedAt[b] ? a : b) : null;
  const lastUpdated = lastUpdatedKey ? new Date(collectedAt[lastUpdatedKey]).toLocaleString() : "Never";

  return (
    <div className="page-fade" style={{ display: "flex", flexDirection: "column", gap: 24 }}>

      {/* Row 1: Security Score Hero */}
      <div style={{
        background: `linear-gradient(135deg, #0f172a 0%, #1e3a5f 60%, #1e40af 100%)`,
        borderRadius: 14, padding: "28px 32px",
        boxShadow: "0 4px 24px rgba(15,23,42,0.2)",
        display: "flex", gap: 32, flexWrap: "wrap", alignItems: "center",
      }}>
        {/* Score ring */}
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 8 }}>
          <ScoreRing score={score} size={180} strokeWidth={16} showGrade />
          <span style={{ fontSize: 11, color: "rgba(255,255,255,0.5)", fontWeight: 600, textTransform: "uppercase", letterSpacing: 0.8 }}>Security Score</span>
        </div>

        {/* Centre: posture text */}
        <div style={{ flex: 1, minWidth: 260 }}>
          <h2 style={{ fontSize: 22, fontWeight: 800, color: "#fff", margin: "0 0 10px" }}>Overall Security Posture</h2>
          <p style={{ fontSize: 15, color: "rgba(255,255,255,0.75)", margin: "0 0 12px", lineHeight: 1.6, maxWidth: 480 }}>{postureSentence}</p>
          <p style={{ fontSize: 12, color: "rgba(255,255,255,0.4)", margin: "0 0 18px" }}>
            As of {new Date().toLocaleDateString("en-AU", { day: "numeric", month: "long", year: "numeric" })}
          </p>
          {/* Data source icons */}
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
            {toolStrip.map((t) => {
              const st = status[t.key] || "no-data";
              return (
                <div key={t.key} style={{
                  display: "flex", alignItems: "center", gap: 6,
                  padding: "5px 10px", borderRadius: 99,
                  background: st === "connected" ? "rgba(22,163,74,0.15)" : "rgba(255,255,255,0.08)",
                  border: `1px solid ${st === "connected" ? "rgba(22,163,74,0.3)" : "rgba(255,255,255,0.1)"}`,
                }}>
                  <span style={{ fontSize: 14 }}>{t.icon}</span>
                  <span style={{ fontSize: 11, color: st === "connected" ? "#86efac" : "rgba(255,255,255,0.45)", fontWeight: 600 }}>{t.name}</span>
                  <span style={{ width: 6, height: 6, borderRadius: "50%", background: st === "connected" ? C.ok : C.muted }} />
                </div>
              );
            })}
          </div>
        </div>

        {/* Right: Quick actions */}
        <div style={{ display: "flex", flexDirection: "column", gap: 12, minWidth: 180 }}>
          <button
            onClick={() => onCollect("all", "All")}
            disabled={!!collecting}
            style={{
              padding: "12px 20px", borderRadius: 9,
              background: collecting ? "rgba(255,255,255,0.15)" : "rgba(255,255,255,0.15)",
              color: "#fff", fontSize: 13, fontWeight: 700, cursor: collecting ? "default" : "pointer",
              backdropFilter: "blur(4px)",
              border: "1px solid rgba(255,255,255,0.2)",
              transition: "background 0.15s",
            }}
            onMouseEnter={(e) => { if (!collecting) e.currentTarget.style.background = "rgba(255,255,255,0.22)"; }}
            onMouseLeave={(e) => { e.currentTarget.style.background = "rgba(255,255,255,0.15)"; }}
          >
            🔄 Collect All Data
          </button>
          <div style={{ fontSize: 11, color: "rgba(255,255,255,0.4)", textAlign: "center" }}>
            Last scan: {lastUpdated}
          </div>
          {collectMsg && <CollectMsg msg={collectMsg} />}
        </div>
      </div>

      {/* Row 2: 5 KPI cards */}
      <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
        <StatCard
          icon="🔴" label="Critical Vulnerabilities"
          value={(data.vulnSummary || {}).critical || 0}
          sub={`${(data.vulnSummary || {}).high || 0} high severity`}
          color={C.critical} accent={C.critical}
        />
        <StatCard
          icon="🌐" label="Attack Surface Score"
          value={(data.surface || {}).score || "—"}
          sub={`Grade ${(data.surface || {}).grade || "F"}`}
          color={C.info} accent={C.info}
        />
        <StatCard
          icon="🔥" label="Active Firewalls"
          value={(data.firewall || {}).totalDevices || 0}
          sub={`${(data.firewall || {}).totalPolicies || 0} policies managed`}
          color={C.primary} accent={C.primary}
        />
        <StatCard
          icon="📦" label="Patch Compliance"
          value={`${(data.assets || {}).patchCompliancePct || 0}%`}
          sub={`${(data.assets || {}).total || 0} total assets`}
          color={C.ok} accent={C.ok}
        />
        <StatCard
          icon="☁️" label="Cloud Secure Score"
          value={`${(data.azure || {}).secureScore || 0}%`}
          sub={`${((data.azure || {}).alertSummary || {}).high || 0} high alerts`}
          color={C.purple} accent={C.purple}
        />
      </div>

      {/* Row 3: Risks + Domain scores */}
      <div style={{ display: "flex", gap: 20, flexWrap: "wrap", alignItems: "flex-start" }}>
        {/* Top risks table */}
        <Card style={{ flex: "1 1 55%", minWidth: 320, padding: "20px 0 0" }}>
          <div style={{ padding: "0 24px 16px" }}>
            <SectionHeader
              title="Top Security Risks Requiring Attention"
              sub="Sorted by severity — critical findings requiring immediate action"
            />
          </div>
          {topRisks.length === 0 ? (
            <div style={{ padding: "32px 24px", textAlign: "center", color: C.muted, fontSize: 14 }}>
              No critical risks detected — security posture is healthy 🎉
            </div>
          ) : (
            <DataTable
              columns={[
                { key: "severity", label: "Severity", render: (v) => <SeverityBadge level={v} /> },
                { key: "source",   label: "Source" },
                { key: "finding",  label: "Finding" },
                { key: "host",     label: "Affected Asset" },
              ]}
              rows={topRisks}
            />
          )}
        </Card>

        {/* Domain scores */}
        <Card style={{ flex: "1 1 35%", minWidth: 260 }}>
          <SectionHeader title="Security Score by Domain" sub="Score per security domain (0–100)" />
          <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
            {domainScores.map((d) => (
              <div key={d.domain}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 5 }}>
                  <span style={{ fontSize: 13, color: C.textMd, fontWeight: 500 }}>{d.domain}</span>
                  <span style={{ fontSize: 13, fontWeight: 700, color: d.score >= 75 ? C.ok : d.score >= 50 ? C.warn : C.critical }}>{d.score || "—"}</span>
                </div>
                <div style={{ height: 8, background: C.bgMuted, borderRadius: 4, overflow: "hidden" }}>
                  <div style={{
                    height: "100%", borderRadius: 4,
                    width: `${d.score}%`,
                    background: d.score >= 75 ? C.ok : d.score >= 50 ? C.warn : C.critical,
                    transition: "width 0.8s ease",
                  }} />
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* Row 4: Integration health strip */}
      <Card style={{ padding: "20px 24px" }}>
        <SectionHeader title="Integration Health" sub="Data collection status for all connected security tools" />
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(180px, 1fr))", gap: 12 }}>
          {toolStrip.map((t) => {
            const st = status[t.key] || "no-data";
            const ca = collectedAt[t.key];
            return (
              <div key={t.key} style={{
                padding: "14px 16px", borderRadius: 10, border: `1px solid ${C.border}`,
                background: st === "connected" ? C.okBg : C.bgMuted,
                display: "flex", flexDirection: "column", gap: 6,
              }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{ fontSize: 20 }}>{t.icon}</span>
                  <span style={{ fontSize: 13, fontWeight: 700, color: C.text }}>{t.name}</span>
                </div>
                <StatusBadge status={st} />
                <span style={{ fontSize: 11, color: C.muted }}>{t.metric}</span>
                {ca && <span style={{ fontSize: 10, color: C.muted }}>Updated {new Date(ca).toLocaleDateString()}</span>}
                {st !== "connected" && (
                  <button
                    onClick={() => onCollect(t.key, t.name)}
                    disabled={collecting === t.key}
                    style={{ fontSize: 11, padding: "4px 8px", border: `1px solid ${C.primary}`, borderRadius: 6, background: "none", color: C.primary, cursor: "pointer", fontWeight: 600 }}
                  >
                    {collecting === t.key ? "…" : "Collect Now"}
                  </button>
                )}
              </div>
            );
          })}
        </div>
      </Card>

      {/* Row 5: Trend chart */}
      <Card>
        <SectionHeader title="Security Posture Trend" sub="Estimated 6-month trend based on available data" />
        <ResponsiveContainer width="100%" height={220}>
          <AreaChart data={trendData} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
            <defs>
              <linearGradient id="scoreFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%"  stopColor={C.primary} stopOpacity={0.18} />
                <stop offset="95%" stopColor={C.primary} stopOpacity={0} />
              </linearGradient>
            </defs>
            <XAxis dataKey="month" tick={{ fontSize: 12, fill: C.muted }} axisLine={false} tickLine={false} />
            <YAxis domain={[0,100]} tick={{ fontSize: 11, fill: C.muted }} axisLine={false} tickLine={false} />
            <Tooltip contentStyle={{ borderRadius: 9, border: `1px solid ${C.border}`, fontSize: 13 }} />
            <Area type="monotone" dataKey="score" stroke={C.primary} strokeWidth={2.5} fill="url(#scoreFill)" dot={{ r: 4, fill: C.primary }} activeDot={{ r: 6 }} />
          </AreaChart>
        </ResponsiveContainer>
      </Card>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════
   THREAT SURFACE PAGE (UpGuard)
   ═════════════════════════════════════════════════════════════════════════ */
function ThreatSurfacePage({ data, collecting, onCollect, collectMsg }) {
  const [tab, setTab] = useState("Overview");
  const [sevFilter, setSevFilter] = useState("All");
  const [domainSearch, setDomainSearch] = useState("");
  const surface = data.surface || {};
  const hasData = (data._integrationStatus || {}).upguard === "connected";

  const riskCounts = useMemo(() => {
    const risks = surface.risks || [];
    return {
      critical: risks.filter((r) => (r.severity || "").toLowerCase() === "critical").length,
      high:     risks.filter((r) => (r.severity || "").toLowerCase() === "high").length,
      medium:   risks.filter((r) => (r.severity || "").toLowerCase() === "medium").length,
      low:      risks.filter((r) => (r.severity || "").toLowerCase() === "low").length,
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
    return r.filter((risk) => (risk.severity || "").toLowerCase() === sevFilter.toLowerCase());
  }, [surface.risks, sevFilter]);

  const filteredDomains = useMemo(() => {
    const d = surface.domains || [];
    if (!domainSearch) return d;
    return d.filter((dom) => (dom.hostname || dom.domain || "").toLowerCase().includes(domainSearch.toLowerCase()));
  }, [surface.domains, domainSearch]);

  if (!hasData) {
    return (
      <EmptyState icon="🌐" title="No Threat Surface Data" sub="Connect UpGuard to monitor your external attack surface, domain risks, and IP exposure.">
        <CollectBtn tool="upguard" label="UpGuard" collecting={collecting} onCollect={onCollect} />
        <CollectMsg msg={collectMsg} />
      </EmptyState>
    );
  }

  return (
    <div className="page-fade" style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      {/* Header card */}
      <Card style={{
        background: `linear-gradient(135deg, #0f172a, #1e3a5f)`,
        border: "none", padding: "24px 32px",
      }}>
        <div style={{ display: "flex", gap: 32, flexWrap: "wrap", alignItems: "center" }}>
          <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 6 }}>
            <ScoreRing score={surface.score || 0} size={140} strokeWidth={14} />
            <span style={{ fontSize: 20, fontWeight: 800, color: gradeColor(surface.grade || "F") }}>Grade {surface.grade || "F"}</span>
            <span style={{ fontSize: 11, color: "rgba(255,255,255,0.4)", textTransform: "uppercase", letterSpacing: 0.6 }}>UpGuard Score</span>
          </div>
          <div style={{ flex: 1, display: "flex", gap: 16, flexWrap: "wrap" }}>
            {[
              { label: "Critical Risks", value: riskCounts.critical, color: C.critical, bg: C.criticalBg },
              { label: "High Risks",     value: riskCounts.high,     color: C.high,     bg: C.highBg },
              { label: "Medium Risks",   value: riskCounts.medium,   color: C.warn,     bg: C.warnBg },
              { label: "Domains",        value: surface.domainCount || 0, color: C.info, bg: C.infoBg },
              { label: "IP Addresses",   value: surface.ipCount || 0,     color: C.purple, bg: C.purpleBg },
            ].map((c) => (
              <div key={c.label} style={{
                padding: "14px 18px", borderRadius: 10,
                background: "rgba(255,255,255,0.08)", backdropFilter: "blur(4px)",
                border: "1px solid rgba(255,255,255,0.12)", minWidth: 100,
              }}>
                <div style={{ fontSize: 24, fontWeight: 800, color: "#fff" }}>{c.value}</div>
                <div style={{ fontSize: 11, color: "rgba(255,255,255,0.5)", fontWeight: 600 }}>{c.label}</div>
              </div>
            ))}
          </div>
        </div>
      </Card>

      <Tabs tabs={["Overview", "Domains", "IP Addresses", "Risk Details"]} active={tab} onChange={setTab} />

      {tab === "Overview" && (
        <div style={{ display: "flex", gap: 20, flexWrap: "wrap", alignItems: "flex-start" }}>
          <Card style={{ flex: "1 1 45%", minWidth: 280 }}>
            <SectionHeader title="Risk Severity Distribution" />
            {pieData.length > 0 ? (
              <ResponsiveContainer width="100%" height={240}>
                <PieChart>
                  <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={90} innerRadius={50} paddingAngle={3}
                    label={({ name, value }) => `${name} (${value})`} labelLine={false}>
                    {pieData.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
                  </Pie>
                  <Tooltip />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            ) : <div style={{ textAlign: "center", color: C.muted, padding: 32 }}>No risks detected</div>}
          </Card>
          <Card style={{ flex: "1 1 45%", minWidth: 280 }}>
            <SectionHeader title="Most At-Risk Domains" sub="Top 5 by risk score" />
            <DataTable
              columns={[
                { key: "hostname", label: "Domain", render: (v, row) => v || row.domain || "—" },
                { key: "score", label: "Score", render: (v) => (
                  <span style={{ fontWeight: 700, color: v >= 700 ? C.ok : v >= 400 ? C.warn : C.critical }}>{v || "—"}</span>
                )},
              ]}
              rows={(surface.domains || []).slice(0, 5)}
            />
          </Card>
        </div>
      )}

      {tab === "Domains" && (
        <Card style={{ padding: "20px 24px 0" }}>
          <SectionHeader title="Domain Inventory" sub={`${surface.domainCount || 0} domains monitored`}
            action={
              <input
                value={domainSearch} onChange={(e) => setDomainSearch(e.target.value)}
                placeholder="Search domains…"
                style={{ padding: "7px 12px", borderRadius: 8, border: `1px solid ${C.border}`, fontSize: 13 }}
              />
            }
          />
          <DataTable
            columns={[
              { key: "hostname", label: "Domain", render: (v, row) => v || row.domain || "—" },
              { key: "score", label: "Score", render: (v) => (
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <div style={{ width: 60, height: 6, background: C.bgMuted, borderRadius: 3, overflow: "hidden" }}>
                    <div style={{ height: "100%", width: `${Math.min(100, (v || 0) / 10)}%`, background: (v||0) >= 700 ? C.ok : (v||0) >= 400 ? C.warn : C.critical }} />
                  </div>
                  <span style={{ fontSize: 12, fontWeight: 700, color: (v||0) >= 700 ? C.ok : (v||0) >= 400 ? C.warn : C.critical }}>{v || "—"}</span>
                </div>
              )},
              { key: "ip_count", label: "IPs", render: (v) => v || "—" },
              { key: "risk_level", label: "Risk", render: (v) => v ? <SeverityBadge level={v} /> : "—" },
            ]}
            rows={filteredDomains}
            maxHeight={400}
          />
        </Card>
      )}

      {tab === "IP Addresses" && (
        <Card style={{ padding: "20px 24px 0" }}>
          <SectionHeader title="IP Address Inventory" sub={`${surface.ipCount || 0} IPs monitored`} />
          <DataTable
            columns={[
              { key: "ip",         label: "IP Address", render: (v, row) => v || row.ipAddress || "—" },
              { key: "score",      label: "Score", render: (v) => <span style={{ fontWeight: 700, color: (v||0) >= 700 ? C.ok : (v||0) >= 400 ? C.warn : C.critical }}>{v || "—"}</span> },
              { key: "open_ports", label: "Open Ports", render: (v) => Array.isArray(v) ? (v.slice(0,6).join(", ") + (v.length > 6 ? "…" : "")) : (v || "None") },
              { key: "risk_level", label: "Risk", render: (v) => v ? <SeverityBadge level={v} /> : "—" },
            ]}
            rows={surface.ips || []}
            maxHeight={400}
          />
        </Card>
      )}

      {tab === "Risk Details" && (
        <Card style={{ padding: "20px 24px 0" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 16, flexWrap: "wrap" }}>
            <SectionHeader title="Risk Findings" sub={`${filteredRisks.length} findings`} />
            <div style={{ display: "flex", gap: 6, marginLeft: "auto", flexWrap: "wrap" }}>
              {["All","Critical","High","Medium","Low"].map((s) => (
                <button key={s} onClick={() => setSevFilter(s)} style={{
                  padding: "5px 14px", borderRadius: 99, border: `1px solid ${s === sevFilter ? C.primary : C.border}`,
                  background: s === sevFilter ? C.primary : "transparent", color: s === sevFilter ? "#fff" : C.textSm,
                  cursor: "pointer", fontSize: 12, fontWeight: 600, transition: "all 0.15s",
                }}>{s}</button>
              ))}
            </div>
          </div>
          <DataTable
            columns={[
              { key: "severity",      label: "Severity",      render: (v) => <SeverityBadge level={v || "Low"} /> },
              { key: "finding",       label: "Finding" },
              { key: "hostnames",     label: "Affected Hosts", render: (v) => (Array.isArray(v) ? v.slice(0,2).join(", ") : v) || "—" },
              { key: "firstDetected", label: "First Detected", render: (v) => v ? new Date(v).toLocaleDateString() : "—" },
            ]}
            rows={filteredRisks}
            maxHeight={480}
          />
        </Card>
      )}
      {collectMsg && <CollectMsg msg={collectMsg} />}
    </div>
  );
}


/* ═══════════════════════════════════════════════════════════════════════════
   VULNERABILITY PAGE (Qualys)
   ═════════════════════════════════════════════════════════════════════════ */
function VulnerabilityPage({ data, collecting, onCollect, collectMsg }) {
  const [tab, setTab]         = useState("Summary");
  const [search, setSearch]   = useState("");
  const [sevFilter, setSevFilter] = useState("All");
  const [modal, setModal]     = useState(null);
  const [sortCol, setSortCol] = useState("severity");
  const [sortDir, setSortDir] = useState("desc");

  const vulns   = data.vulnerabilities || [];
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
    [vulns]);

  const hostCounts = useMemo(() => {
    const counts = {};
    vulns.forEach((v) => { if (v.host) counts[v.host] = (counts[v.host] || 0) + 1; });
    return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 12).map(([host, count]) => ({ host, count }));
  }, [vulns]);

  const filtered = useMemo(() => {
    let r = vulns.filter((v) => {
      const matchSev = sevFilter === "All" || v.severityLabel === sevFilter;
      const matchSearch = !search || (v.title || "").toLowerCase().includes(search.toLowerCase()) || (v.host || "").includes(search) || (v.qid || "").includes(search);
      return matchSev && matchSearch;
    });
    r = [...r].sort((a, b) => {
      const av = a[sortCol], bv = b[sortCol];
      if (av === bv) return 0;
      const cmp = av < bv ? -1 : 1;
      return sortDir === "desc" ? -cmp : cmp;
    });
    return r;
  }, [vulns, sevFilter, search, sortCol, sortDir]);

  if (!hasData) {
    return (
      <EmptyState icon="🔍" title="No Vulnerability Data" sub="Connect Qualys to scan and track vulnerabilities across your environment.">
        <CollectBtn tool="qualys" label="Qualys" collecting={collecting} onCollect={onCollect} />
        <CollectMsg msg={collectMsg} />
      </EmptyState>
    );
  }

  return (
    <div className="page-fade" style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      {modal && (
        <Modal title={modal.title || "Vulnerability Detail"} onClose={() => setModal(null)}>
          <div style={{ display: "flex", flexDirection: "column", gap: 14, fontSize: 13 }}>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
              {[
                { label: "QID", value: modal.qid },
                { label: "Severity", value: <SeverityBadge level={modal.severityLabel} /> },
                { label: "Host", value: modal.host },
                { label: "OS", value: modal.os || "—" },
                { label: "First Found", value: modal.firstFound ? new Date(modal.firstFound).toLocaleDateString() : "—" },
                { label: "Last Found",  value: modal.lastFound  ? new Date(modal.lastFound).toLocaleDateString()  : "—" },
              ].map((item) => (
                <div key={item.label} style={{ background: C.bgMuted, padding: "10px 14px", borderRadius: 8 }}>
                  <div style={{ fontSize: 10, fontWeight: 700, color: C.muted, textTransform: "uppercase", letterSpacing: 0.6, marginBottom: 4 }}>{item.label}</div>
                  <div style={{ fontWeight: 600, color: C.text }}>{item.value}</div>
                </div>
              ))}
            </div>
            {modal.details && (
              <>
                <div style={{ fontSize: 12, fontWeight: 700, color: C.textSm, textTransform: "uppercase", letterSpacing: 0.6 }}>Technical Details</div>
                <pre style={{
                  background: "#0f172a", color: "#e2e8f0", padding: "14px 16px", borderRadius: 9,
                  fontSize: 12, whiteSpace: "pre-wrap", wordBreak: "break-all",
                  maxHeight: 220, overflowY: "auto", fontFamily: "'JetBrains Mono','Courier New',monospace",
                }}>{modal.details}</pre>
              </>
            )}
          </div>
        </Modal>
      )}

      {/* Summary strip */}
      <div style={{ display: "flex", gap: 14, flexWrap: "wrap" }}>
        {[
          { label: "Total",    value: summary.total    || 0, color: C.primary, icon: "🔍", accent: C.primary },
          { label: "Critical", value: summary.critical || 0, color: C.critical,icon: "🔴", accent: C.critical },
          { label: "High",     value: summary.high     || 0, color: C.high,    icon: "🟠", accent: C.high },
          { label: "Medium",   value: summary.medium   || 0, color: C.warn,    icon: "🟡", accent: C.warn },
          { label: "Low",      value: summary.low      || 0, color: C.ok,      icon: "🟢", accent: C.ok },
          { label: "Hosts Affected", value: summary.uniqueHosts || 0, color: C.purple, icon: "💻", accent: C.purple },
        ].map((c) => <StatCard key={c.label} {...c} />)}
      </div>

      <Tabs tabs={["Summary", "All Vulnerabilities"]} active={tab} onChange={setTab} />

      {tab === "Summary" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
          <div style={{ display: "flex", gap: 20, flexWrap: "wrap" }}>
            <Card style={{ flex: "1 1 42%", minWidth: 280 }}>
              <SectionHeader title="Severity Distribution" />
              {pieData.length > 0 ? (
                <ResponsiveContainer width="100%" height={240}>
                  <PieChart>
                    <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={90} innerRadius={50} paddingAngle={3}>
                      {pieData.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
                    </Pie>
                    <Tooltip contentStyle={{ borderRadius: 9, border: `1px solid ${C.border}`, fontSize: 13 }} />
                    <Legend />
                  </PieChart>
                </ResponsiveContainer>
              ) : <div style={{ textAlign: "center", color: C.muted, padding: 40 }}>No vulnerability data</div>}
            </Card>
            <Card style={{ flex: "1 1 52%", minWidth: 280 }}>
              <SectionHeader title="Most Affected Hosts" sub="Top hosts by vulnerability count" />
              {hostCounts.length > 0 ? (
                <ResponsiveContainer width="100%" height={240}>
                  <BarChart data={hostCounts} layout="vertical" margin={{ left: 0, right: 10, top: 0, bottom: 0 }}>
                    <XAxis type="number" tick={{ fontSize: 11, fill: C.muted }} axisLine={false} tickLine={false} />
                    <YAxis type="category" dataKey="host" width={130} tick={{ fontSize: 11, fill: C.textSm }} axisLine={false} tickLine={false} />
                    <Tooltip contentStyle={{ borderRadius: 9, border: `1px solid ${C.border}`, fontSize: 13 }} />
                    <Bar dataKey="count" fill={C.primary} radius={[0,4,4,0]} />
                  </BarChart>
                </ResponsiveContainer>
              ) : <div style={{ textAlign: "center", color: C.muted, padding: 40 }}>No host data</div>}
            </Card>
          </div>
          <Card style={{ padding: "20px 24px 0" }}>
            <SectionHeader title="Top Critical & High Findings" sub="Click a row for full details" />
            <DataTable
              columns={[
                { key: "severityLabel", label: "Severity", render: (v) => <SeverityBadge level={v} /> },
                { key: "title",  label: "Finding Title" },
                { key: "host",   label: "Host" },
                { key: "qid",    label: "QID" },
                { key: "firstFound", label: "First Found", render: (v) => v ? new Date(v).toLocaleDateString() : "—" },
              ]}
              rows={topCritical}
              onRowClick={setModal}
            />
          </Card>
        </div>
      )}

      {tab === "All Vulnerabilities" && (
        <Card style={{ padding: "20px 24px 0" }}>
          <div style={{ display: "flex", gap: 10, marginBottom: 16, flexWrap: "wrap", alignItems: "center" }}>
            <input
              value={search} onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by title, host or QID…"
              style={{
                padding: "9px 14px", borderRadius: 8, border: `1px solid ${C.border}`,
                fontSize: 13, flex: 1, minWidth: 200, background: C.bgMuted, color: C.text,
              }}
            />
            <div style={{ display: "flex", gap: 6 }}>
              {["All","Critical","High","Medium","Low"].map((s) => (
                <button key={s} onClick={() => setSevFilter(s)} style={{
                  padding: "6px 14px", borderRadius: 99, border: `1px solid ${s === sevFilter ? C.primary : C.border}`,
                  background: s === sevFilter ? C.primary : "transparent", color: s === sevFilter ? "#fff" : C.textSm,
                  cursor: "pointer", fontSize: 12, fontWeight: 600, transition: "all 0.15s",
                }}>{s}</button>
              ))}
            </div>
            <span style={{ fontSize: 12, color: C.muted, whiteSpace: "nowrap" }}>{filtered.length} results</span>
          </div>
          <DataTable
            columns={[
              { key: "severityLabel", label: "Severity", render: (v) => <SeverityBadge level={v} /> },
              { key: "title",      label: "Vulnerability Title" },
              { key: "host",       label: "Host" },
              { key: "os",         label: "OS" },
              { key: "qid",        label: "QID" },
              { key: "firstFound", label: "First Found", render: (v) => v ? new Date(v).toLocaleDateString() : "—" },
              { key: "lastFound",  label: "Last Found",  render: (v) => v ? new Date(v).toLocaleDateString() : "—" },
            ]}
            rows={filtered}
            onRowClick={setModal}
            maxHeight={520}
          />
        </Card>
      )}
      {collectMsg && <CollectMsg msg={collectMsg} />}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════
   FIREWALL PAGE (Fortinet + PaloAlto)
   ═════════════════════════════════════════════════════════════════════════ */
function FirewallPage({ data, collecting, onCollect, collectMsg }) {
  const firewall  = data.firewall || {};
  const instances = firewall.instances || [];
  const [selectedIdx, setSelectedIdx] = useState(0);
  const [tab, setTab]   = useState("Overview");
  const [policySearch, setPolicySearch] = useState("");
  const [policyFilter, setPolicyFilter] = useState("All");
  const hasData = instances.length > 0;

  const inst = instances[selectedIdx] || null;

  const fortinetInsts = instances.filter((i) => i.vendor === "fortinet");
  const paloAltoInsts = instances.filter((i) => i.vendor === "paloalto");

  const filteredPolicies = useMemo(() => {
    if (!inst) return [];
    const allPolicies = inst._policies || [];
    return allPolicies.filter((p) => {
      const matchSearch = !policySearch || (p.name || "").toLowerCase().includes(policySearch.toLowerCase()) || (p.srcaddr || "").toLowerCase().includes(policySearch.toLowerCase()) || (p.dstaddr || "").toLowerCase().includes(policySearch.toLowerCase());
      const action = (p.action || "").toLowerCase();
      const matchFilter = policyFilter === "All" || (policyFilter === "Allow" && (action === "accept" || action === "allow")) || (policyFilter === "Deny" && action === "deny") || (policyFilter === "Disabled" && (p.status === "disable" || p.enabled === false));
      return matchSearch && matchFilter;
    });
  }, [inst, policySearch, policyFilter]);

  if (!hasData) {
    return (
      <EmptyState icon="🔥" title="No Firewall Data" sub="Connect Fortinet FortiGate or Palo Alto Networks devices to monitor firewall policies, bandwidth, and security posture.">
        <div style={{ display: "flex", gap: 12, justifyContent: "center", flexWrap: "wrap" }}>
          <CollectBtn tool="fortinet" label="Fortinet" collecting={collecting} onCollect={onCollect} />
          <CollectBtn tool="paloalto" label="Palo Alto" collecting={collecting} onCollect={onCollect} />
        </div>
        <CollectMsg msg={collectMsg} />
      </EmptyState>
    );
  }

  const bwTop    = (inst ? inst.bandwidth || [] : []).slice(0, 12);
  const appsTop  = (inst ? inst.topApps || [] : []).slice(0, 12);
  const webTop   = (inst ? inst.topWebCategories || [] : []).slice(0, 12);
  const cis      = inst ? inst.cisBenchmark || [] : [];
  const cisPass  = cis.filter((c) => c.pass === true).length;
  const cisFail  = cis.filter((c) => c.pass === false).length;
  const cisUnk   = cis.filter((c) => c.pass == null).length;
  const cisPct   = cis.length ? Math.round((cisPass / cis.length) * 100) : 0;

  return (
    <div className="page-fade" style={{ display: "flex", gap: 20, minHeight: 0 }}>
      {/* Left device panel */}
      <div style={{
        width: 210, flexShrink: 0, background: C.bgCard,
        borderRadius: 12, border: `1px solid ${C.border}`,
        boxShadow: "0 1px 3px rgba(0,0,0,0.06)",
        overflow: "hidden", alignSelf: "flex-start",
      }}>
        <div style={{ padding: "14px 16px", borderBottom: `1px solid ${C.border}`, background: C.bgMuted }}>
          <div style={{ fontSize: 12, fontWeight: 700, color: C.textSm, textTransform: "uppercase", letterSpacing: 0.6 }}>Devices</div>
          <div style={{ fontSize: 11, color: C.muted, marginTop: 3 }}>{instances.length} total</div>
        </div>
        {fortinetInsts.length > 0 && (
          <div>
            <div style={{ padding: "8px 16px 4px", display: "flex", alignItems: "center", gap: 6 }}>
              <span style={{ fontSize: 14 }}>🔥</span>
              <span style={{ fontSize: 11, fontWeight: 700, color: C.muted, textTransform: "uppercase", letterSpacing: 0.5 }}>Fortinet</span>
              <span style={{ marginLeft: "auto", fontSize: 10, background: C.primaryLt, color: C.primary, padding: "1px 7px", borderRadius: 99, fontWeight: 700 }}>{fortinetInsts.length}</span>
            </div>
            {fortinetInsts.map((inst2) => {
              const realIdx = instances.indexOf(inst2);
              return (
                <button key={realIdx} onClick={() => { setSelectedIdx(realIdx); setTab("Overview"); }} style={{
                  width: "100%", padding: "9px 16px 9px 24px", border: "none", textAlign: "left",
                  background: selectedIdx === realIdx ? C.primaryLt : "transparent",
                  color: selectedIdx === realIdx ? C.primary : C.textMd,
                  fontSize: 13, fontWeight: selectedIdx === realIdx ? 700 : 500,
                  cursor: "pointer", transition: "background 0.12s",
                  borderLeft: selectedIdx === realIdx ? `3px solid ${C.primary}` : "3px solid transparent",
                }}>
                  {inst2.hostname || inst2.host}
                </button>
              );
            })}
          </div>
        )}
        {paloAltoInsts.length > 0 && (
          <div>
            <div style={{ padding: "8px 16px 4px", display: "flex", alignItems: "center", gap: 6, borderTop: fortinetInsts.length > 0 ? `1px solid ${C.border}` : "none" }}>
              <span style={{ fontSize: 14 }}>🛡️</span>
              <span style={{ fontSize: 11, fontWeight: 700, color: C.muted, textTransform: "uppercase", letterSpacing: 0.5 }}>Palo Alto</span>
              <span style={{ marginLeft: "auto", fontSize: 10, background: C.purpleBg, color: C.purple, padding: "1px 7px", borderRadius: 99, fontWeight: 700 }}>{paloAltoInsts.length}</span>
            </div>
            {paloAltoInsts.map((inst2) => {
              const realIdx = instances.indexOf(inst2);
              return (
                <button key={realIdx} onClick={() => { setSelectedIdx(realIdx); setTab("Overview"); }} style={{
                  width: "100%", padding: "9px 16px 9px 24px", border: "none", textAlign: "left",
                  background: selectedIdx === realIdx ? C.primaryLt : "transparent",
                  color: selectedIdx === realIdx ? C.primary : C.textMd,
                  fontSize: 13, fontWeight: selectedIdx === realIdx ? 700 : 500,
                  cursor: "pointer", transition: "background 0.12s",
                  borderLeft: selectedIdx === realIdx ? `3px solid ${C.primary}` : "3px solid transparent",
                }}>
                  {inst2.hostname || inst2.host}
                </button>
              );
            })}
          </div>
        )}
      </div>

      {/* Main content */}
      {inst && (
        <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 16, minWidth: 0 }}>
          {/* Device info header */}
          <div style={{
            padding: "14px 20px", background: C.bgCard, borderRadius: 12, border: `1px solid ${C.border}`,
            display: "flex", alignItems: "center", gap: 20, flexWrap: "wrap",
          }}>
            <span style={{ fontSize: 24 }}>{inst.vendor === "fortinet" ? "🔥" : "🛡️"}</span>
            <div>
              <div style={{ fontSize: 15, fontWeight: 700, color: C.text }}>{inst.hostname}</div>
              <div style={{ fontSize: 12, color: C.muted }}>{inst.host} {inst.version ? `· v${inst.version}` : ""}</div>
            </div>
            <div style={{ marginLeft: "auto", fontSize: 11, color: C.muted }}>
              {inst.collectedAt ? `Collected ${new Date(inst.collectedAt).toLocaleString()}` : ""}
            </div>
          </div>

          <Tabs
            tabs={["Overview","Policies","Bandwidth","Top Applications","Web Categories","CIS Benchmark"]}
            active={tab} onChange={setTab}
          />

          {tab === "Overview" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              <div style={{ display: "flex", gap: 14, flexWrap: "wrap" }}>
                <StatCard icon="📋" label="Total Policies" value={inst.policyCount} color={C.primary} accent={C.primary} />
                <StatCard icon="✅" label="Allow Rules"   value={inst.allowCount}  color={C.ok}       accent={C.ok} />
                <StatCard icon="🚫" label="Deny Rules"    value={inst.denyCount}   color={C.critical} accent={C.critical} />
                <StatCard icon="🟢" label="Enabled Rules" value={inst.enabledCount} color={C.info}    accent={C.info} />
              </div>
              <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
                <Card style={{ flex: "1 1 42%", minWidth: 240 }}>
                  <SectionHeader title="Policy Action Distribution" />
                  {(inst.allowCount + inst.denyCount) > 0 ? (
                    <ResponsiveContainer width="100%" height={200}>
                      <PieChart>
                        <Pie
                          data={[
                            { name: "Allow", value: inst.allowCount, fill: C.ok },
                            { name: "Deny",  value: inst.denyCount,  fill: C.critical },
                          ].filter((d) => d.value > 0)}
                          dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80} innerRadius={40}
                        >
                          {[C.ok, C.critical].map((fill, i) => <Cell key={i} fill={fill} />)}
                        </Pie>
                        <Tooltip />
                        <Legend />
                      </PieChart>
                    </ResponsiveContainer>
                  ) : <div style={{ textAlign: "center", color: C.muted, padding: 40 }}>No policy data</div>}
                </Card>
                <Card style={{ flex: "1 1 52%", minWidth: 260 }}>
                  <SectionHeader title="Device Information" />
                  <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                    {[
                      { label: "Vendor",    value: inst.vendor === "fortinet" ? "Fortinet FortiGate" : "Palo Alto Networks" },
                      { label: "Hostname",  value: inst.hostname },
                      { label: "Host/IP",   value: inst.host || "—" },
                      { label: "Version",   value: inst.version || "—" },
                      { label: "Total Policies", value: inst.policyCount },
                      { label: "Last Collected", value: inst.collectedAt ? new Date(inst.collectedAt).toLocaleString() : "—" },
                    ].map((row) => (
                      <div key={row.label} style={{ display: "flex", justifyContent: "space-between", padding: "8px 0", borderBottom: `1px solid ${C.border}` }}>
                        <span style={{ fontSize: 13, color: C.muted }}>{row.label}</span>
                        <span style={{ fontSize: 13, fontWeight: 600, color: C.text }}>{row.value}</span>
                      </div>
                    ))}
                  </div>
                </Card>
              </div>
            </div>
          )}

          {tab === "Policies" && (
            <Card style={{ padding: "20px 24px 0" }}>
              <div style={{ display: "flex", gap: 10, marginBottom: 16, flexWrap: "wrap" }}>
                <input
                  value={policySearch} onChange={(e) => setPolicySearch(e.target.value)}
                  placeholder="Search by name, source, destination…"
                  style={{ padding: "8px 12px", borderRadius: 8, border: `1px solid ${C.border}`, fontSize: 13, flex: 1, minWidth: 200 }}
                />
                {["All","Allow","Deny","Disabled"].map((f) => (
                  <button key={f} onClick={() => setPolicyFilter(f)} style={{
                    padding: "6px 14px", borderRadius: 99, border: `1px solid ${f === policyFilter ? C.primary : C.border}`,
                    background: f === policyFilter ? C.primary : "transparent", color: f === policyFilter ? "#fff" : C.textSm,
                    cursor: "pointer", fontSize: 12, fontWeight: 600,
                  }}>{f}</button>
                ))}
              </div>
              {filteredPolicies.length === 0 ? (
                <div style={{ textAlign: "center", color: C.muted, padding: "32px 0" }}>
                  {inst.policyCount > 0 ? "No matching policies." : "No policy detail in snapshot — raw policy data not included."}
                </div>
              ) : (
                <DataTable
                  columns={[
                    { key: "name",    label: "Policy Name" },
                    { key: "action",  label: "Action", render: (v) => <ActionBadge action={v} /> },
                    { key: "srcaddr", label: "Source" },
                    { key: "dstaddr", label: "Destination" },
                    { key: "service", label: "Service" },
                    { key: "status",  label: "Status", render: (v) => (
                      <span style={{ fontSize: 11, fontWeight: 600, color: (v === "enable" || v === "enabled") ? C.ok : C.muted }}>
                        {v === "enable" || v === "enabled" ? "● Enabled" : "○ Disabled"}
                      </span>
                    )},
                  ]}
                  rows={filteredPolicies}
                  maxHeight={500}
                />
              )}
            </Card>
          )}

          {tab === "Bandwidth" && (
            <Card>
              <SectionHeader title="Interface Bandwidth" sub="Top interfaces by throughput" />
              {bwTop.length === 0 ? (
                <div style={{ textAlign: "center", color: C.muted, padding: 40 }}>No bandwidth data available.</div>
              ) : (
                <>
                  <ResponsiveContainer width="100%" height={300}>
                    <BarChart data={bwTop} margin={{ bottom: 20 }}>
                      <XAxis dataKey="name" tick={{ fontSize: 11, fill: C.muted }} axisLine={false} angle={-30} textAnchor="end" />
                      <YAxis tick={{ fontSize: 11, fill: C.muted }} axisLine={false} tickLine={false} />
                      <Tooltip contentStyle={{ borderRadius: 9, border: `1px solid ${C.border}`, fontSize: 13 }} />
                      <Legend />
                      <Bar dataKey="in_bps"  name="Inbound bps"  fill={C.primary} radius={[3,3,0,0]} />
                      <Bar dataKey="out_bps" name="Outbound bps" fill={C.accent}  radius={[3,3,0,0]} />
                    </BarChart>
                  </ResponsiveContainer>
                  <div style={{ marginTop: 16 }}>
                    <DataTable
                      columns={[
                        { key: "name",     label: "Interface" },
                        { key: "in_bps",   label: "In (bps)",   render: (v) => (v || 0).toLocaleString() },
                        { key: "out_bps",  label: "Out (bps)",  render: (v) => (v || 0).toLocaleString() },
                        { key: "rx_bytes", label: "Rx Total",   render: (v) => (v || 0).toLocaleString() },
                        { key: "tx_bytes", label: "Tx Total",   render: (v) => (v || 0).toLocaleString() },
                      ]}
                      rows={bwTop}
                    />
                  </div>
                </>
              )}
            </Card>
          )}

          {tab === "Top Applications" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              <Card>
                <SectionHeader title="Top Applications by Sessions" />
                {appsTop.length === 0 ? (
                  <div style={{ textAlign: "center", color: C.muted, padding: 40 }}>No application data available for this device.</div>
                ) : (
                  <ResponsiveContainer width="100%" height={280}>
                    <BarChart data={appsTop} margin={{ bottom: 20 }}>
                      <XAxis dataKey="name" tick={{ fontSize: 11, fill: C.muted }} axisLine={false} angle={-30} textAnchor="end" />
                      <YAxis tick={{ fontSize: 11, fill: C.muted }} axisLine={false} tickLine={false} />
                      <Tooltip contentStyle={{ borderRadius: 9, border: `1px solid ${C.border}`, fontSize: 13 }} />
                      <Bar dataKey="sessions" fill={C.primary} radius={[3,3,0,0]} />
                    </BarChart>
                  </ResponsiveContainer>
                )}
              </Card>
              {appsTop.length > 0 && (
                <Card style={{ padding: "20px 24px 0" }}>
                  <DataTable
                    columns={[
                      { key: "name",     label: "Application" },
                      { key: "sessions", label: "Sessions", render: (v) => (v || 0).toLocaleString() },
                      { key: "bytes",    label: "Bytes",    render: (v) => (v || 0).toLocaleString() },
                      { key: "risk",     label: "Risk", render: (v) => v ? <SeverityBadge level={v.charAt(0).toUpperCase() + v.slice(1)} /> : "—" },
                    ]}
                    rows={appsTop}
                  />
                </Card>
              )}
            </div>
          )}

          {tab === "Web Categories" && (
            <Card>
              <SectionHeader title="Top Web Categories" sub="Traffic by web category" />
              {webTop.length === 0 ? (
                <div style={{ textAlign: "center", color: C.muted, padding: 40 }}>No web category data available for this device.</div>
              ) : (
                <>
                  <ResponsiveContainer width="100%" height={300}>
                    <BarChart data={webTop} layout="vertical" margin={{ left: 0, right: 20 }}>
                      <XAxis type="number" tick={{ fontSize: 11, fill: C.muted }} axisLine={false} tickLine={false} />
                      <YAxis type="category" dataKey="name" width={150} tick={{ fontSize: 11, fill: C.textSm }} axisLine={false} tickLine={false} />
                      <Tooltip contentStyle={{ borderRadius: 9, border: `1px solid ${C.border}`, fontSize: 13 }} />
                      <Bar dataKey="sessions" fill={C.purple} radius={[0,4,4,0]} />
                    </BarChart>
                  </ResponsiveContainer>
                  <div style={{ marginTop: 16 }}>
                    <DataTable
                      columns={[
                        { key: "name",     label: "Category" },
                        { key: "sessions", label: "Sessions", render: (v) => (v || 0).toLocaleString() },
                        { key: "bytes",    label: "Bytes",    render: (v) => (v || 0).toLocaleString() },
                      ]}
                      rows={webTop}
                    />
                  </div>
                </>
              )}
            </Card>
          )}

          {tab === "CIS Benchmark" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              <div style={{ display: "flex", gap: 16, flexWrap: "wrap", alignItems: "flex-start" }}>
                <Card style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 10, minWidth: 200 }}>
                  <ScoreRing score={cisPct} size={140} label="% pass" />
                  <div style={{ display: "flex", gap: 16, fontSize: 13 }}>
                    <span style={{ color: C.ok, fontWeight: 700 }}>✅ {cisPass} Pass</span>
                    <span style={{ color: C.critical, fontWeight: 700 }}>❌ {cisFail} Fail</span>
                    <span style={{ color: C.muted, fontWeight: 700 }}>❓ {cisUnk} Unknown</span>
                  </div>
                </Card>
                {cis.length > 0 && (
                  <div style={{ flex: 1, minWidth: 240 }}>
                    <div style={{ marginBottom: 16 }}>
                      <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, color: C.muted, marginBottom: 6 }}>
                        <span>Compliance rate</span>
                        <span style={{ fontWeight: 700, color: cisPct >= 80 ? C.ok : cisPct >= 60 ? C.warn : C.critical }}>{cisPct}%</span>
                      </div>
                      <div style={{ height: 10, background: C.bgMuted, borderRadius: 5, overflow: "hidden" }}>
                        <div style={{
                          height: "100%", borderRadius: 5,
                          width: `${cisPct}%`,
                          background: cisPct >= 80 ? C.ok : cisPct >= 60 ? C.warn : C.critical,
                          transition: "width 0.8s ease",
                        }} />
                      </div>
                    </div>
                  </div>
                )}
              </div>
              {cis.length > 0 ? (
                <Card style={{ padding: "20px 24px 0" }}>
                  <SectionHeader title="CIS Benchmark Checks" sub={`${cis.length} checks performed`} />
                  <DataTable
                    columns={[
                      { key: "id",    label: "Check ID" },
                      { key: "title", label: "Description" },
                      { key: "pass",  label: "Result", render: (v) => (
                        v === true ? <span style={{ color: C.ok, fontWeight: 700, fontSize: 15 }}>✅ Pass</span> :
                        v === false ? <span style={{ color: C.critical, fontWeight: 700, fontSize: 15 }}>❌ Fail</span> :
                        <span style={{ color: C.muted, fontWeight: 700, fontSize: 15 }}>❓ Unknown</span>
                      )},
                    ]}
                    rows={cis}
                    maxHeight={460}
                  />
                </Card>
              ) : (
                <Card><div style={{ textAlign: "center", color: C.muted, padding: 32 }}>No CIS benchmark data available for this device.</div></Card>
              )}
            </div>
          )}
        </div>
      )}
      {collectMsg && <CollectMsg msg={collectMsg} />}
    </div>
  );
}


/* ═══════════════════════════════════════════════════════════════════════════
   ASSETS & PATCHES PAGE (ManageEngine)
   ═════════════════════════════════════════════════════════════════════════ */
function AssetPage({ data, collecting, onCollect, collectMsg }) {
  const assets  = data.assets || {};
  const hasData = (data._integrationStatus || {}).manageengine === "connected";

  const compliancePie = [
    { name: "Compliant",     value: assets.patchCompliant    || 0, fill: C.ok },
    { name: "Non-Compliant", value: assets.patchNonCompliant || 0, fill: C.critical },
  ].filter((d) => d.value > 0);

  const osCounts = useMemo(() => {
    const counts = {};
    (assets.list || []).forEach((a) => { const os = a.os || a.operatingSystem || "Unknown"; counts[os] = (counts[os] || 0) + 1; });
    return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([name, value]) => ({ name, value }));
  }, [assets.list]);

  if (!hasData) {
    return (
      <EmptyState icon="📦" title="No Asset Data" sub="Connect ManageEngine to track assets, patch compliance, and software inventory across your environment.">
        <CollectBtn tool="manageengine" label="ManageEngine" collecting={collecting} onCollect={onCollect} />
        <CollectMsg msg={collectMsg} />
      </EmptyState>
    );
  }

  return (
    <div className="page-fade" style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      {/* KPI strip */}
      <div style={{ display: "flex", gap: 14, flexWrap: "wrap" }}>
        <StatCard icon="📦" label="Total Assets"      value={assets.total || 0}              color={C.primary}  accent={C.primary} />
        <StatCard icon="🟢" label="Online"            value={assets.online || 0}             color={C.ok}       accent={C.ok} />
        <StatCard icon="⚫" label="Offline"           value={assets.offline || 0}            color={C.muted}    accent={C.muted} />
        <StatCard icon="✅" label="Patch Compliance"  value={`${assets.patchCompliancePct || 0}%`} color={assets.patchCompliancePct >= 80 ? C.ok : C.warn} accent={C.ok} />
        <StatCard icon="❌" label="Non-Compliant"     value={assets.patchNonCompliant || 0}  color={C.critical} accent={C.critical} />
      </div>

      {/* Charts row */}
      <div style={{ display: "flex", gap: 20, flexWrap: "wrap" }}>
        <Card style={{ flex: "1 1 40%", minWidth: 260 }}>
          <SectionHeader title="Patch Compliance" sub={`${assets.patchCompliant || 0} compliant of ${assets.total || 0} total`} />
          {compliancePie.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie
                  data={compliancePie} dataKey="value" nameKey="name"
                  cx="50%" cy="50%" outerRadius={88} innerRadius={50} paddingAngle={4}
                  label={({ name, percent }) => `${name} ${Math.round(percent * 100)}%`}
                >
                  {compliancePie.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
                </Pie>
                <Tooltip contentStyle={{ borderRadius: 9, border: `1px solid ${C.border}`, fontSize: 13 }} />
              </PieChart>
            </ResponsiveContainer>
          ) : <div style={{ textAlign: "center", color: C.muted, padding: 40 }}>No compliance data</div>}
        </Card>

        {osCounts.length > 0 && (
          <Card style={{ flex: "1 1 52%", minWidth: 280 }}>
            <SectionHeader title="OS Distribution" sub="Assets by operating system" />
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={osCounts} layout="vertical" margin={{ left: 0, right: 10 }}>
                <XAxis type="number" tick={{ fontSize: 11, fill: C.muted }} axisLine={false} tickLine={false} />
                <YAxis type="category" dataKey="name" width={140} tick={{ fontSize: 11, fill: C.textSm }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={{ borderRadius: 9, border: `1px solid ${C.border}`, fontSize: 13 }} />
                <Bar dataKey="value" fill={C.primary} radius={[0,4,4,0]} />
              </BarChart>
            </ResponsiveContainer>
          </Card>
        )}
      </div>

      {/* Asset table */}
      <Card style={{ padding: "20px 24px 0" }}>
        <SectionHeader title="Asset Inventory" sub={`${(assets.list || []).length} assets`} />
        {(assets.list || []).length === 0 ? (
          <div style={{ textAlign: "center", color: C.muted, padding: 32 }}>No asset details available in snapshot.</div>
        ) : (
          <DataTable
            searchable
            columns={[
              { key: "name",           label: "Asset Name" },
              { key: "ip",             label: "IP Address" },
              { key: "os",             label: "Operating System" },
              { key: "status",         label: "Status", render: (v) => (
                <span style={{ fontSize: 11, fontWeight: 600, color: (v === "online" || v === "Active") ? C.ok : C.muted }}>
                  {(v === "online" || v === "Active") ? "● Online" : "○ Offline"}
                </span>
              )},
              { key: "patchCompliant", label: "Patch Status", render: (v) => (
                <span style={{ fontSize: 11, fontWeight: 600, color: v ? C.ok : C.critical }}>
                  {v ? "✅ Compliant" : "❌ Non-Compliant"}
                </span>
              )},
            ]}
            rows={assets.list}
            maxHeight={480}
          />
        )}
      </Card>

      {/* Patches table */}
      {(assets.patches || []).length > 0 && (
        <Card style={{ padding: "20px 24px 0" }}>
          <SectionHeader title="Patch Details" sub={`${(assets.patches || []).length} patches`} />
          <DataTable
            columns={[
              { key: "name",     label: "Patch Name" },
              { key: "severity", label: "Severity", render: (v) => v ? <SeverityBadge level={v} /> : "—" },
              { key: "status",   label: "Status" },
              { key: "released", label: "Released", render: (v) => v ? new Date(v).toLocaleDateString() : "—" },
            ]}
            rows={assets.patches}
            maxHeight={360}
          />
        </Card>
      )}
      {collectMsg && <CollectMsg msg={collectMsg} />}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════
   CLOUD SECURITY PAGE (Azure)
   ═════════════════════════════════════════════════════════════════════════ */
function CloudPage({ data, collecting, onCollect, collectMsg }) {
  const azure   = data.azure || {};
  const hasData = (data._integrationStatus || {}).azure === "connected";
  const [sevFilter, setSevFilter] = useState("All");
  const [expanded, setExpanded]   = useState(null);

  const sum = azure.alertSummary || {};

  const filteredAlerts = useMemo(() => {
    const alerts = azure.alerts || [];
    if (sevFilter === "All") return alerts;
    return alerts.filter((a) => a.severity === sevFilter);
  }, [azure.alerts, sevFilter]);

  if (!hasData) {
    return (
      <EmptyState icon="☁️" title="No Cloud Security Data" sub="Connect Azure Security Center to monitor cloud security posture, alerts, and compliance recommendations.">
        <CollectBtn tool="azure" label="Azure" collecting={collecting} onCollect={onCollect} />
        <CollectMsg msg={collectMsg} />
      </EmptyState>
    );
  }

  return (
    <div className="page-fade" style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      {/* Hero strip */}
      <div style={{
        background: `linear-gradient(135deg, #0f172a, #1e3a5f)`,
        borderRadius: 14, padding: "24px 32px",
        display: "flex", gap: 32, flexWrap: "wrap", alignItems: "center",
      }}>
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 8 }}>
          <ScoreRing score={azure.secureScore || 0} size={150} strokeWidth={14} />
          <span style={{ fontSize: 13, color: "rgba(255,255,255,0.5)", fontWeight: 600 }}>Azure Secure Score</span>
          <span style={{ fontSize: 12, color: "rgba(255,255,255,0.4)" }}>{azure.currentScore} / {azure.maxScore} pts</span>
        </div>
        <div style={{ flex: 1, display: "flex", gap: 16, flexWrap: "wrap" }}>
          {[
            { label: "High Alerts",   value: sum.high   || 0, color: C.critical, icon: "🔴" },
            { label: "Medium Alerts", value: sum.medium || 0, color: C.warn,     icon: "🟡" },
            { label: "Low Alerts",    value: sum.low    || 0, color: C.ok,       icon: "🟢" },
            { label: "Total Alerts",  value: (azure.alerts || []).length, color: C.info, icon: "🔔" },
          ].map((c) => (
            <div key={c.label} style={{
              padding: "16px 20px", borderRadius: 10,
              background: "rgba(255,255,255,0.08)",
              border: "1px solid rgba(255,255,255,0.12)", minWidth: 110,
            }}>
              <div style={{ fontSize: 22, marginBottom: 4 }}>{c.icon}</div>
              <div style={{ fontSize: 26, fontWeight: 800, color: "#fff" }}>{c.value}</div>
              <div style={{ fontSize: 11, color: "rgba(255,255,255,0.5)", fontWeight: 600 }}>{c.label}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Alerts table */}
      <Card style={{ padding: "20px 24px 0" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16, flexWrap: "wrap" }}>
          <SectionHeader title="Security Alerts" sub={`${filteredAlerts.length} alerts`} />
          <div style={{ display: "flex", gap: 6, marginLeft: "auto" }}>
            {["All","High","Medium","Low"].map((s) => (
              <button key={s} onClick={() => setSevFilter(s)} style={{
                padding: "5px 14px", borderRadius: 99, border: `1px solid ${s === sevFilter ? C.primary : C.border}`,
                background: s === sevFilter ? C.primary : "transparent", color: s === sevFilter ? "#fff" : C.textSm,
                cursor: "pointer", fontSize: 12, fontWeight: 600,
              }}>{s}</button>
            ))}
          </div>
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 0 }}>
          {filteredAlerts.length === 0 ? (
            <div style={{ textAlign: "center", color: C.muted, padding: 40 }}>
              {sevFilter === "All" ? "No security alerts — cloud posture is healthy 🎉" : `No ${sevFilter} severity alerts.`}
            </div>
          ) : filteredAlerts.map((alert, i) => (
            <div key={i}>
              <div
                onClick={() => setExpanded(expanded === i ? null : i)}
                style={{
                  display: "flex", alignItems: "center", gap: 14,
                  padding: "14px 0", borderBottom: `1px solid ${C.border}`,
                  cursor: "pointer", transition: "background 0.12s",
                }}
                onMouseEnter={(e) => { e.currentTarget.style.background = C.bgMuted; }}
                onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
              >
                <span style={{
                  display: "inline-block", width: 8, height: 8, borderRadius: "50%", flexShrink: 0,
                  background: alert.severity === "High" ? C.critical : alert.severity === "Medium" ? C.warn : C.ok,
                }} />
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 13, fontWeight: 600, color: C.text }}>{alert.displayName}</div>
                  <div style={{ fontSize: 12, color: C.muted, marginTop: 2 }}>{alert.entity || "—"}</div>
                </div>
                <SeverityBadge level={alert.severity || "Low"} />
                <span style={{ fontSize: 11, color: C.muted, marginLeft: 8 }}>
                  {alert.status === "Resolved" ? (
                    <span style={{ color: C.ok, fontWeight: 600 }}>✓ Resolved</span>
                  ) : (
                    <span style={{ color: C.warn, fontWeight: 600 }}>⚠ Active</span>
                  )}
                </span>
                <span style={{ fontSize: 14, color: C.muted }}>{expanded === i ? "▲" : "▼"}</span>
              </div>
              {expanded === i && alert.description && (
                <div style={{
                  padding: "14px 24px", background: C.bgMuted, borderBottom: `1px solid ${C.border}`,
                  fontSize: 13, color: C.textMd, lineHeight: 1.6,
                }}>
                  <div style={{ fontWeight: 600, color: C.text, marginBottom: 8 }}>Description</div>
                  <p style={{ margin: 0 }}>{alert.description}</p>
                </div>
              )}
            </div>
          ))}
        </div>
      </Card>
      {collectMsg && <CollectMsg msg={collectMsg} />}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════
   TOOLS CONFIG
   ═════════════════════════════════════════════════════════════════════════ */
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

/* ═══════════════════════════════════════════════════════════════════════════
   SETTINGS PAGE
   ═════════════════════════════════════════════════════════════════════════ */
function SettingsToolCard({ tool, existing, collecting, onCollect, onSaved, onRefresh }) {
  const [expanded,   setExpanded]   = useState(false);
  const [formValues, setFormValues] = useState({});
  const [instances,  setInstances]  = useState([{ name: "", host: "", apikey: "" }]);
  const [testResult, setTestResult] = useState(null);
  const [saving,     setSaving]     = useState(false);

  const status      = existing?.status      || "no-data";
  const lastError   = existing?.last_error  || null;
  const collectedAt = existing?.collectedAt || existing?.last_tested || null;

  function handleExpand() {
    if (!expanded && existing) {
      if (tool.multiInstance) {
        const insts = existing.instances;
        if (insts && insts.length > 0) {
          setInstances(insts.map((i) => ({ name: i.name || "", host: i.host || "", apikey: "" })));
        }
      } else {
        const safe = existing.safe_credentials || {};
        const prefill = {};
        (tool.fields || []).forEach((f) => {
          prefill[f.key] = f.type === "password" ? "" : (safe[f.key] || "");
        });
        setFormValues(prefill);
      }
    }
    setExpanded(!expanded);
    setTestResult(null);
  }

  function setField(key, val) {
    setFormValues((prev) => ({ ...prev, [key]: val }));
  }

  async function handleSave() {
    setSaving(true); setTestResult(null);
    try {
      const credentials = tool.multiInstance ? { instances } : formValues;
      const res = await apiFetch(`${API}/api/integrations/${tool.key}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ credentials }),
      });
      const j = await res.json().catch(() => ({}));
      if (res.ok) {
        setTestResult({ ok: true, msg: "✅ Settings saved successfully." });
        setExpanded(false);
        if (onSaved) onSaved();
      } else {
        setTestResult({ ok: false, msg: "❌ " + (j.error || `Server error ${res.status}`) });
      }
    } catch (err) {
      setTestResult({ ok: false, msg: "❌ " + (err.message || "Network error") });
    }
    setSaving(false);
  }

  async function handleTest() {
    setTestResult({ ok: null, msg: "⏳ Testing connection…" });
    try {
      const res = await apiFetch(`${API}/api/integrations/${tool.key}/test`, { method: "POST" });
      const j = await res.json().catch(() => ({}));
      if (j.ok || j.success) {
        setTestResult({ ok: true, msg: "✅ " + (j.message || "Connection successful.") });
        if (onRefresh) setTimeout(onRefresh, 1000);
      } else {
        setTestResult({ ok: false, msg: "❌ " + (j.error || "Connection test failed.") });
      }
    } catch (err) {
      setTestResult({ ok: false, msg: "❌ " + (err.message || "Network error.") });
    }
  }

  const inputStyle = {
    width: "100%", padding: "9px 12px", borderRadius: 8,
    border: `1.5px solid ${C.border}`, fontSize: 13, color: C.text,
    background: C.bgMuted, boxSizing: "border-box",
    transition: "border-color 0.15s", outline: "none",
  };
  const labelStyle = {
    fontSize: 11, fontWeight: 700, color: C.textSm,
    textTransform: "uppercase", letterSpacing: 0.6,
    display: "block", marginBottom: 5,
  };

  return (
    <div style={{
      background: C.bgCard, borderRadius: 12, border: `1px solid ${C.border}`,
      boxShadow: "0 1px 3px rgba(0,0,0,0.06)", overflow: "hidden",
    }}>
      {/* Card header */}
      <div style={{ padding: "20px 24px" }}>
        <div style={{ display: "flex", alignItems: "flex-start", gap: 14, marginBottom: 14 }}>
          <div style={{
            width: 48, height: 48, borderRadius: 12, background: C.bgMuted,
            display: "flex", alignItems: "center", justifyContent: "center", fontSize: 24, flexShrink: 0,
          }}>{tool.icon}</div>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 16, fontWeight: 700, color: C.text, marginBottom: 3 }}>{tool.name}</div>
            <div style={{ fontSize: 12, color: C.muted }}>{tool.description}</div>
          </div>
          <StatusBadge status={status} />
        </div>

        {lastError && status === "error" && (
          <div style={{
            padding: "8px 12px", borderRadius: 8, background: C.criticalBg,
            border: `1px solid ${C.critical}25`, fontSize: 12, color: C.critical, marginBottom: 12,
          }}>⚠️ {lastError}</div>
        )}

        {collectedAt && (
          <div style={{ fontSize: 11, color: C.muted, marginBottom: 12 }}>
            Last collected: {new Date(collectedAt).toLocaleString()}
          </div>
        )}

        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <button
            onClick={handleExpand}
            style={{
              padding: "7px 16px", borderRadius: 8,
              border: `1.5px solid ${C.primary}`, background: expanded ? C.primary : "transparent",
              color: expanded ? "#fff" : C.primary, cursor: "pointer", fontSize: 13, fontWeight: 600,
              transition: "all 0.15s",
            }}
          >{expanded ? "Close" : (existing ? "Edit Config" : "Configure")}</button>
          <button
            onClick={handleTest}
            style={{
              padding: "7px 16px", borderRadius: 8,
              border: `1.5px solid ${C.info}`, background: "transparent",
              color: C.info, cursor: "pointer", fontSize: 13, fontWeight: 600,
            }}
          >Test Connection</button>
          <CollectBtn
            tool={tool.key} label={tool.name}
            collecting={collecting} onCollect={onCollect}
            style={{ padding: "7px 14px", fontSize: 13 }}
          />
        </div>

        {testResult && (
          <div style={{
            marginTop: 10, padding: "8px 12px", borderRadius: 8, fontSize: 13, fontWeight: 600,
            background: testResult.ok === true ? C.okBg : testResult.ok === false ? C.criticalBg : C.warnBg,
            color: testResult.ok === true ? C.ok : testResult.ok === false ? C.critical : C.warn,
            border: `1px solid ${testResult.ok === true ? C.ok : testResult.ok === false ? C.critical : C.warn}30`,
          }}>{testResult.msg}</div>
        )}
      </div>

      {/* Expandable config form */}
      {expanded && (
        <div style={{
          borderTop: `1px solid ${C.border}`,
          padding: "20px 24px",
          background: C.bgMuted,
          display: "flex", flexDirection: "column", gap: 14,
        }}>
          <div style={{ fontSize: 13, fontWeight: 700, color: C.text }}>Configuration</div>
          {tool.multiInstance ? (
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              {instances.map((inst, i) => (
                <div key={i} style={{
                  background: C.bgCard, borderRadius: 10, padding: "14px 16px",
                  border: `1px solid ${C.border}`,
                }}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10 }}>
                    <span style={{ fontSize: 12, fontWeight: 700, color: C.textSm }}>Instance {i + 1}</span>
                    <button
                      onClick={() => setInstances(instances.filter((_, j) => j !== i))}
                      style={{ border: "none", background: C.criticalBg, color: C.critical, borderRadius: 6, padding: "3px 8px", cursor: "pointer", fontSize: 12, fontWeight: 600 }}
                    >Remove</button>
                  </div>
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(180px, 1fr))", gap: 10 }}>
                    {tool.instanceFields.map((f) => (
                      <div key={f.key}>
                        <label style={labelStyle}>{f.label}</label>
                        <input
                          type={f.type} value={inst[f.key] || ""}
                          onChange={(e) => { const next = [...instances]; next[i] = { ...next[i], [f.key]: e.target.value }; setInstances(next); }}
                          style={inputStyle}
                          onFocus={(e) => { e.target.style.borderColor = C.primary; }}
                          onBlur={(e) => { e.target.style.borderColor = C.border; }}
                        />
                      </div>
                    ))}
                  </div>
                </div>
              ))}
              <button
                onClick={() => setInstances([...instances, { name: "", host: "", apikey: "" }])}
                style={{
                  alignSelf: "flex-start", padding: "7px 16px", borderRadius: 8,
                  border: `1.5px solid ${C.ok}`, background: "transparent",
                  color: C.ok, cursor: "pointer", fontSize: 13, fontWeight: 600,
                }}
              >+ Add Instance</button>
            </div>
          ) : (
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))", gap: 14 }}>
              {(tool.fields || []).map((f) => (
                <div key={f.key}>
                  <label style={labelStyle}>{f.label}</label>
                  <input
                    type={f.type} value={formValues[f.key] || ""}
                    onChange={(e) => setField(f.key, e.target.value)}
                    style={inputStyle}
                    onFocus={(e) => { e.target.style.borderColor = C.primary; }}
                    onBlur={(e) => { e.target.style.borderColor = C.border; }}
                  />
                </div>
              ))}
            </div>
          )}
          <div style={{ display: "flex", gap: 8 }}>
            <button
              onClick={handleSave} disabled={saving}
              style={{
                padding: "9px 24px", borderRadius: 8, border: "none",
                background: saving ? C.muted : C.primary, color: "#fff",
                fontSize: 13, fontWeight: 700, cursor: saving ? "default" : "pointer",
                display: "inline-flex", alignItems: "center", gap: 6,
              }}
            >
              {saving && <span style={{ width: 12, height: 12, border: "2px solid rgba(255,255,255,0.3)", borderTop: "2px solid #fff", borderRadius: "50%", animation: "spin 0.7s linear infinite" }} />}
              {saving ? "Saving…" : "Save Settings"}
            </button>
            <button
              onClick={() => { setExpanded(false); setTestResult(null); }}
              style={{ padding: "9px 16px", borderRadius: 8, border: `1px solid ${C.border}`, background: "transparent", color: C.textSm, cursor: "pointer", fontSize: 13 }}
            >Cancel</button>
          </div>
        </div>
      )}
    </div>
  );
}

function SettingsPage({ data, collecting, onCollect, collectMsg, onRefresh }) {
  const [integrations, setIntegrations] = useState({});
  const [loadingInteg, setLoadingInteg] = useState(true);

  const fetchIntegrations = useCallback(async () => {
    setLoadingInteg(true);
    try {
      const res = await apiFetch(`${API}/api/integrations`);
      if (res.ok) {
        const list = await res.json().catch(() => []);
        const map = {};
        (Array.isArray(list) ? list : []).forEach((i) => { map[i.tool_name] = i; });
        const snappedAt = data._collectedAt || {};
        Object.keys(snappedAt).forEach((k) => { if (map[k]) map[k].collectedAt = snappedAt[k]; });
        setIntegrations(map);
      }
    } catch {}
    setLoadingInteg(false);
  }, [data._collectedAt]);

  useEffect(() => { fetchIntegrations(); }, [fetchIntegrations]);

  return (
    <div className="page-fade" style={{ display: "flex", flexDirection: "column", gap: 24 }}>
      <div>
        <h2 style={{ fontSize: 22, fontWeight: 800, color: C.text, margin: "0 0 4px" }}>Integrations & Settings</h2>
        <p style={{ fontSize: 14, color: C.muted, margin: 0 }}>Configure integrations, test connections, and trigger data collection.</p>
      </div>
      {collectMsg && <CollectMsg msg={collectMsg} />}
      {loadingInteg ? (
        <div style={{ display: "flex", alignItems: "center", gap: 10, color: C.muted, fontSize: 14 }}>
          <span style={{ width: 16, height: 16, border: `2px solid ${C.border}`, borderTop: `2px solid ${C.primary}`, borderRadius: "50%", animation: "spin 0.75s linear infinite" }} />
          Loading integration status…
        </div>
      ) : (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(420px, 1fr))", gap: 16 }}>
          {TOOLS_CONFIG.map((tool) => (
            <SettingsToolCard
              key={tool.key}
              tool={tool}
              existing={integrations[tool.key] || null}
              collecting={collecting}
              onCollect={onCollect}
              onSaved={() => { fetchIntegrations(); if (onRefresh) onRefresh(); }}
              onRefresh={onRefresh}
            />
          ))}
        </div>
      )}
    </div>
  );
}


/* ═══════════════════════════════════════════════════════════════════════════
   APP ROOT
   ═════════════════════════════════════════════════════════════════════════ */
export default function App() {
  const [session,     setSession]     = useState(null);
  const [page,        setPage]        = useState("dashboard");
  const [data,        setData]        = useState({});
  const [loading,     setLoading]     = useState(true);
  const [collecting,  setCollecting]  = useState(null);
  const [collectMsg,  setCollectMsg]  = useState("");
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [refreshTick, setRefreshTick] = useState(300);

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
    } catch {
      // server unreachable — keep current state
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    loadAll();
    const timer = setInterval(loadAll, 5 * 60 * 1000);
    return () => clearInterval(timer);
  }, [loadAll]);

  /* Refresh countdown */
  useEffect(() => {
    const tick = setInterval(() => setRefreshTick((t) => t <= 1 ? 300 : t - 1), 1000);
    return () => clearInterval(tick);
  }, []);

  /* collectNow */
  const collectNow = useCallback(async (tool, label) => {
    setCollecting(tool); setCollectMsg("");
    try {
      const res = await apiFetch(`${API}/api/collect/${tool}`, { method: "POST" });
      const j = await res.json().catch(() => ({}));
      if (j.ok || j.success) {
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

  /* Nav items by role */
  const navItems = useMemo(() => {
    if (role === "executive") {
      return [{ id: "dashboard", icon: "🏛️", label: "Executive Dashboard" }];
    }
    return [
      { id: "dashboard", icon: "🏛️", label: "Dashboard" },
      { id: "surface",   icon: "🌐", label: "Threat Surface" },
      { id: "vulns",     icon: "🔍", label: "Vulnerabilities" },
      { id: "firewall",  icon: "🔥", label: "Firewalls" },
      { id: "assets",    icon: "📦", label: "Assets & Patches" },
      { id: "cloud",     icon: "☁️", label: "Cloud Security" },
      { id: "settings",  icon: "⚙️", label: "Settings" },
    ];
  }, [role]);

  async function handleLogout() {
    await apiFetch(`${API}/api/auth/logout`, { method: "POST" }).catch(() => {});
    setSession(null);
    setPage("dashboard");
    setData({});
  }

  /* Loading screen */
  if (loading) {
    return (
      <div style={{
        minHeight: "100vh", background: C.bg,
        display: "flex", alignItems: "center", justifyContent: "center",
        fontFamily: "'Inter','Segoe UI',system-ui,sans-serif",
      }}>
        <style>{GLOBAL_STYLES}</style>
        <div style={{ textAlign: "center" }}>
          <div style={{ fontSize: 48, marginBottom: 20 }}>🛡️</div>
          <Spinner />
          <div style={{ fontSize: 14, color: C.muted, marginTop: 16 }}>Loading SecOps Command Center…</div>
        </div>
      </div>
    );
  }

  /* Login screen */
  if (!session) {
    return <LoginPage onLogin={(u) => { setSession(u); setLoading(true); loadAll(); }} />;
  }

  /* Page renderer */
  const pageProps = { data, collecting, onCollect: collectNow, collectMsg, onRefresh: loadAll };

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

  const currentNav = navItems.find((n) => n.id === page) || navItems[0];
  const SIDEBAR_W = sidebarOpen ? 230 : 64;
  const initials = ((session.display_name || session.username || "U")[0]).toUpperCase();

  /* Status counts for header */
  const critCount = (data.vulnSummary || {}).critical || 0;

  return (
    <div style={{ display: "flex", minHeight: "100vh", background: C.bg, fontFamily: "'Inter','Segoe UI',system-ui,-apple-system,sans-serif", color: C.text }}>
      <style>{GLOBAL_STYLES}</style>

      {/* ── Sidebar ─────────────────────────────────────────────────── */}
      <aside style={{
        width: SIDEBAR_W, minHeight: "100vh",
        background: C.sidebar,
        display: "flex", flexDirection: "column",
        position: "sticky", top: 0, height: "100vh",
        transition: "width 0.22s cubic-bezier(0.4,0,0.2,1)",
        overflow: "hidden", flexShrink: 0,
        zIndex: 200,
      }}>
        {/* Logo area */}
        <div style={{
          padding: sidebarOpen ? "18px 16px 16px" : "18px 14px 16px",
          display: "flex", alignItems: "center", gap: 10,
          borderBottom: `1px solid ${C.sidebarBdr}`, flexShrink: 0,
        }}>
          <div style={{
            width: 32, height: 32, borderRadius: 8, background: C.primary,
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: 18, flexShrink: 0,
          }}>🛡️</div>
          {sidebarOpen && (
            <div style={{ flex: 1, overflow: "hidden" }}>
              <div style={{ fontSize: 14, fontWeight: 800, color: "#fff", lineHeight: 1.2, whiteSpace: "nowrap" }}>SecOps</div>
              <div style={{ fontSize: 10, color: "rgba(255,255,255,0.4)", fontWeight: 500, whiteSpace: "nowrap" }}>Command Center</div>
            </div>
          )}
          <button
            onClick={() => setSidebarOpen(!sidebarOpen)}
            style={{
              background: "rgba(255,255,255,0.07)", border: "none", borderRadius: 6,
              width: 26, height: 26, cursor: "pointer", color: "rgba(255,255,255,0.45)",
              fontSize: 12, display: "flex", alignItems: "center", justifyContent: "center",
              flexShrink: 0, transition: "background 0.15s",
            }}
            onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(255,255,255,0.12)"; }}
            onMouseLeave={(e) => { e.currentTarget.style.background = "rgba(255,255,255,0.07)"; }}
          >{sidebarOpen ? "◀" : "▶"}</button>
        </div>

        {/* Navigation */}
        <nav style={{ flex: 1, padding: "10px 8px", display: "flex", flexDirection: "column", gap: 2, overflowY: "auto" }}>
          {navItems.map((item) => {
            const isActive = page === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setPage(item.id)}
                title={!sidebarOpen ? item.label : undefined}
                style={{
                  display: "flex", alignItems: "center", gap: 10,
                  padding: sidebarOpen ? "10px 12px" : "10px",
                  borderRadius: 8, border: "none", cursor: "pointer", textAlign: "left",
                  background: isActive ? C.sidebarAct : "transparent",
                  color: isActive ? "#fff" : "rgba(255,255,255,0.6)",
                  fontSize: 13, fontWeight: isActive ? 700 : 500,
                  transition: "background 0.12s, color 0.12s",
                  borderLeft: isActive ? `3px solid ${C.accent}` : "3px solid transparent",
                  justifyContent: sidebarOpen ? "flex-start" : "center",
                  position: "relative",
                  overflow: "hidden",
                  whiteSpace: "nowrap",
                }}
                onMouseEnter={(e) => { if (!isActive) e.currentTarget.style.background = C.sidebarHov; }}
                onMouseLeave={(e) => { if (!isActive) e.currentTarget.style.background = "transparent"; }}
              >
                <span style={{ fontSize: 17, flexShrink: 0 }}>{item.icon}</span>
                {sidebarOpen && <span style={{ overflow: "hidden", textOverflow: "ellipsis" }}>{item.label}</span>}
              </button>
            );
          })}
        </nav>

        {/* User area */}
        <div style={{
          padding: "12px 10px", borderTop: `1px solid ${C.sidebarBdr}`,
          display: "flex", alignItems: "center", gap: 8, flexShrink: 0,
        }}>
          <div style={{
            width: 34, height: 34, borderRadius: "50%",
            background: `linear-gradient(135deg, ${C.primary}, ${C.accent})`,
            display: "flex", alignItems: "center", justifyContent: "center",
            color: "#fff", fontSize: 14, fontWeight: 800, flexShrink: 0,
          }}>{initials}</div>
          {sidebarOpen && (
            <>
              <div style={{ flex: 1, overflow: "hidden" }}>
                <div style={{ fontSize: 12, fontWeight: 700, color: "#fff", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {session.display_name || session.username}
                </div>
                <div style={{ fontSize: 10, color: "rgba(255,255,255,0.4)", textTransform: "capitalize" }}>{session.role}</div>
              </div>
              <button
                onClick={handleLogout}
                title="Logout"
                style={{
                  background: "rgba(255,255,255,0.07)", border: "none", borderRadius: 6,
                  width: 28, height: 28, cursor: "pointer", color: "rgba(255,255,255,0.45)",
                  fontSize: 14, display: "flex", alignItems: "center", justifyContent: "center",
                  transition: "background 0.15s",
                }}
                onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(220,38,38,0.2)"; e.currentTarget.style.color = C.critical; }}
                onMouseLeave={(e) => { e.currentTarget.style.background = "rgba(255,255,255,0.07)"; e.currentTarget.style.color = "rgba(255,255,255,0.45)"; }}
              >⏻</button>
            </>
          )}
        </div>
      </aside>

      {/* ── Main content ─────────────────────────────────────────────── */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0, overflow: "hidden" }}>

        {/* Header */}
        <header style={{
          height: 56, background: C.bgDark, flexShrink: 0,
          display: "flex", alignItems: "center", padding: "0 24px", gap: 16,
          position: "sticky", top: 0, zIndex: 100,
          borderBottom: `1px solid ${C.sidebarBdr}`,
        }}>
          <h1 style={{ flex: 1, fontSize: 15, fontWeight: 700, color: "#fff", margin: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
            {currentNav.label}
          </h1>

          {/* Critical count badge */}
          {critCount > 0 && (
            <div style={{
              display: "flex", alignItems: "center", gap: 5, padding: "4px 10px",
              borderRadius: 99, background: `${C.critical}20`, border: `1px solid ${C.critical}40`,
            }}>
              <span style={{ width: 6, height: 6, borderRadius: "50%", background: C.critical }} />
              <span style={{ fontSize: 11, color: C.critical, fontWeight: 700 }}>{critCount} Critical</span>
            </div>
          )}

          {/* Collecting indicator */}
          {collecting && (
            <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, color: "rgba(255,255,255,0.55)" }}>
              <span style={{ width: 8, height: 8, borderRadius: "50%", background: C.warn, animation: "pulse 1.2s ease-in-out infinite" }} />
              Collecting data…
            </div>
          )}

          {/* Refresh button */}
          <button onClick={loadAll} title="Refresh data now" style={{
            background: "rgba(255,255,255,0.08)", border: "1px solid rgba(255,255,255,0.15)",
            color: "rgba(255,255,255,0.75)", borderRadius: 6, padding: "4px 12px",
            cursor: "pointer", fontSize: 12, fontWeight: 600, whiteSpace: "nowrap",
          }}>⟳ Refresh</button>
          {/* Auto-refresh countdown */}
          <div style={{ fontSize: 11, color: "rgba(255,255,255,0.35)", display: "flex", alignItems: "center", gap: 5 }}>
            <span>Auto-refresh in {refreshTick}s</span>
          </div>

          {/* Date */}
          <div style={{ fontSize: 12, color: "rgba(255,255,255,0.4)", whiteSpace: "nowrap" }}>
            {new Date().toLocaleDateString("en-AU", { day: "2-digit", month: "short", year: "numeric" })}
          </div>
        </header>

        {/* Page content */}
        <main style={{ flex: 1, padding: 24, overflowY: "auto", overflowX: "hidden" }}>
          {renderPage()}
        </main>
      </div>
    </div>
  );
}
