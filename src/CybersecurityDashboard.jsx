import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, AreaChart, Area, LineChart, Line, Legend } from 'recharts';

const API = `http://${window.location.hostname}:4000`;

const C = {
  bg:       "#070d1a",
  bgCard:   "#0d1526",
  bgCardHov:"#111d33",
  bgMuted:  "#0a1020",
  sidebar:  "#050c17",
  border:   "rgba(30,80,180,0.25)",
  borderAct:"rgba(56,189,248,0.5)",
  primary:  "#1e40af",
  accent:   "#38bdf8",
  success:  "#22d3ee",
  ok:       "#10b981",
  warn:     "#f59e0b",
  high:     "#f97316",
  critical: "#ef4444",
  text:     "#e2e8f0",
  textMd:   "#94a3b8",
  textSm:   "#64748b",
  glow:     "rgba(56,189,248,0.12)",
};

const GLOBAL_STYLES = `
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background-color: #070d1a;
    background-image:
      radial-gradient(ellipse 70% 50% at 50% -10%, rgba(30,64,175,0.25) 0%, transparent 60%),
      linear-gradient(90deg, rgba(56,189,248,0.03) 1px, transparent 1px),
      linear-gradient(0deg, rgba(56,189,248,0.03) 1px, transparent 1px);
    background-size: 100% 100%, 40px 40px, 40px 40px;
    color: #e2e8f0;
    overflow: hidden;
  }
  ::-webkit-scrollbar { width: 6px; height: 6px; }
  ::-webkit-scrollbar-track { background: #070d1a; }
  ::-webkit-scrollbar-thumb { background: rgba(56,189,248,0.2); border-radius: 3px; }
  ::-webkit-scrollbar-thumb:hover { background: rgba(56,189,248,0.4); }
  @keyframes fadeIn { from { opacity:0; transform:translateY(8px); } to { opacity:1; transform:translateY(0); } }
  @keyframes pulse { 0%,100% { box-shadow: 0 0 0 0 rgba(56,189,248,0.4); } 50% { box-shadow: 0 0 0 12px rgba(56,189,248,0); } }
  @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
  @keyframes glow { 0%,100% { opacity:0.6; } 50% { opacity:1; } }
  @keyframes shimmer { 0% { background-position: -200% 0; } 100% { background-position: 200% 0; } }
  input, select, textarea { outline: none; }
  button { cursor: pointer; }
  a { color: inherit; text-decoration: none; }
`;

const cardStyle = {
  background: C.bgCard,
  border: `1px solid ${C.border}`,
  borderRadius: 12,
  padding: "20px 24px",
  boxShadow: "0 4px 24px rgba(0,0,0,0.4)",
};

// ─── Shared Components ────────────────────────────────────────────────────────

function Spinner({ size = 20, color = C.accent }) {
  return (
    <div style={{
      width: size, height: size,
      border: `2px solid rgba(56,189,248,0.2)`,
      borderTop: `2px solid ${color}`,
      borderRadius: "50%",
      animation: "spin 0.8s linear infinite",
      display: "inline-block",
      flexShrink: 0,
    }} />
  );
}

function ScoreRing({ score, max = 100, size = 120, strokeWidth = 10, label }) {
  const r = (size - strokeWidth) / 2;
  const circ = 2 * Math.PI * r;
  const pct = Math.min(Math.max((score || 0) / max, 0), 1);
  const dash = pct * circ;
  const color = score < 40 ? C.critical : score < 70 ? C.warn : C.ok;
  return (
    <div style={{ position: "relative", width: size, height: size, display: "inline-flex", alignItems: "center", justifyContent: "center" }}>
      <svg width={size} height={size} style={{ transform: "rotate(-90deg)", position: "absolute" }}>
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth={strokeWidth} />
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={color} strokeWidth={strokeWidth}
          strokeDasharray={`${dash} ${circ}`} strokeLinecap="round"
          style={{ filter: `drop-shadow(0 0 6px ${color})`, transition: "stroke-dasharray 0.8s ease" }} />
      </svg>
      <div style={{ textAlign: "center", zIndex: 1 }}>
        <div style={{ fontSize: size * 0.22, fontWeight: 700, color, lineHeight: 1 }}>{score ?? "--"}</div>
        {label && <div style={{ fontSize: size * 0.1, color: C.textSm, marginTop: 2 }}>{label}</div>}
      </div>
    </div>
  );
}

function SeverityBadge({ level }) {
  const map = {
    critical: { bg: "rgba(239,68,68,0.15)", color: "#ef4444", border: "rgba(239,68,68,0.3)" },
    high:     { bg: "rgba(249,115,22,0.15)", color: "#f97316", border: "rgba(249,115,22,0.3)" },
    medium:   { bg: "rgba(245,158,11,0.15)", color: "#f59e0b", border: "rgba(245,158,11,0.3)" },
    low:      { bg: "rgba(16,185,129,0.15)", color: "#10b981", border: "rgba(16,185,129,0.3)" },
    info:     { bg: "rgba(56,189,248,0.15)", color: "#38bdf8", border: "rgba(56,189,248,0.3)" },
    informational: { bg: "rgba(56,189,248,0.15)", color: "#38bdf8", border: "rgba(56,189,248,0.3)" },
  };
  const k = (level || "info").toLowerCase();
  const s = map[k] || map.info;
  return (
    <span style={{
      background: s.bg, color: s.color, border: `1px solid ${s.border}`,
      borderRadius: 20, padding: "2px 10px", fontSize: 11, fontWeight: 600,
      textTransform: "uppercase", letterSpacing: "0.05em", whiteSpace: "nowrap",
    }}>{level || "Info"}</span>
  );
}

function StatCard({ icon, label, value, sub, color = C.accent, trend }) {
  const [hov, setHov] = useState(false);
  return (
    <div onMouseEnter={() => setHov(true)} onMouseLeave={() => setHov(false)}
      style={{
        ...cardStyle,
        borderLeft: `3px solid ${color}`,
        transition: "background 0.2s, transform 0.2s",
        background: hov ? C.bgCardHov : C.bgCard,
        transform: hov ? "translateY(-2px)" : "none",
        animation: "fadeIn 0.4s ease",
      }}>
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between" }}>
        <div>
          <div style={{ fontSize: 24, marginBottom: 4 }}>{icon}</div>
          <div style={{ fontSize: 28, fontWeight: 700, color, lineHeight: 1, textShadow: `0 0 12px ${color}40` }}>{value ?? "--"}</div>
          <div style={{ fontSize: 13, color: C.textMd, marginTop: 4 }}>{label}</div>
          {sub && <div style={{ fontSize: 11, color: C.textSm, marginTop: 2 }}>{sub}</div>}
        </div>
        {trend !== undefined && (
          <div style={{ fontSize: 12, color: trend >= 0 ? C.ok : C.critical, fontWeight: 600 }}>
            {trend >= 0 ? "▲" : "▼"} {Math.abs(trend)}%
          </div>
        )}
      </div>
    </div>
  );
}

function EmptyState({ icon, title, sub, children }) {
  return (
    <div style={{ ...cardStyle, textAlign: "center", padding: "60px 40px", animation: "fadeIn 0.4s ease" }}>
      <div style={{ fontSize: 48, marginBottom: 16, opacity: 0.5 }}>{icon || "📭"}</div>
      <div style={{ fontSize: 18, fontWeight: 600, color: C.textMd, marginBottom: 8 }}>{title || "No Data"}</div>
      {sub && <div style={{ fontSize: 13, color: C.textSm, marginBottom: 24, maxWidth: 400, margin: "0 auto 24px" }}>{sub}</div>}
      {children && <div style={{ marginTop: 20 }}>{children}</div>}
    </div>
  );
}

function CollectBtn({ tool, label, onCollect }) {
  const [status, setStatus] = useState("idle");
  const [msg, setMsg] = useState("");
  const collect = async () => {
    setStatus("loading"); setMsg("");
    try {
      const r = await fetch(`${API}/api/collect/${tool}`, { method: "POST", credentials: "include" });
      const j = await r.json().catch(() => ({}));
      if (r.ok) {
        setStatus("success"); setMsg("Collected!");
        if (onCollect) onCollect();
        setTimeout(() => setStatus("idle"), 3000);
      } else {
        setStatus("error"); setMsg(j.error || j.message || "Collection failed");
        setTimeout(() => setStatus("idle"), 4000);
      }
    } catch (e) {
      setStatus("error"); setMsg("Network error");
      setTimeout(() => setStatus("idle"), 4000);
    }
  };
  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 8 }}>
      <button onClick={collect} disabled={status === "loading"}
        style={{
          background: status === "loading" ? "rgba(56,189,248,0.1)" : `linear-gradient(135deg, ${C.primary}, ${C.accent}20)`,
          border: `1px solid ${C.borderAct}`,
          color: C.accent, borderRadius: 8, padding: "10px 24px",
          fontSize: 14, fontWeight: 600, display: "flex", alignItems: "center", gap: 8,
          opacity: status === "loading" ? 0.7 : 1, transition: "all 0.2s",
        }}>
        {status === "loading" && <Spinner size={14} />}
        {status === "loading" ? "Collecting..." : label || `Collect ${tool}`}
      </button>
      {msg && (
        <div style={{ fontSize: 12, color: status === "success" ? C.ok : C.critical, fontWeight: 500 }}>
          {status === "success" ? "✅" : "❌"} {msg}
        </div>
      )}
    </div>
  );
}

function Modal({ open, onClose, title, children, width = 640 }) {
  useEffect(() => {
    const handler = (e) => { if (e.key === "Escape") onClose(); };
    if (open) document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div onClick={onClose} style={{
      position: "fixed", inset: 0, background: "rgba(0,0,0,0.7)", backdropFilter: "blur(4px)",
      zIndex: 1000, display: "flex", alignItems: "center", justifyContent: "center", padding: 24,
    }}>
      <div onClick={e => e.stopPropagation()} style={{
        background: C.bgCard, border: `1px solid ${C.borderAct}`, borderRadius: 16,
        width: "100%", maxWidth: width, maxHeight: "85vh", overflow: "auto",
        boxShadow: "0 20px 60px rgba(0,0,0,0.6)", animation: "fadeIn 0.2s ease",
      }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "20px 24px", borderBottom: `1px solid ${C.border}` }}>
          <div style={{ fontSize: 16, fontWeight: 700, color: C.text }}>{title}</div>
          <button onClick={onClose} style={{ background: "none", border: "none", color: C.textSm, fontSize: 20, lineHeight: 1, padding: 4, borderRadius: 4 }}>✕</button>
        </div>
        <div style={{ padding: "20px 24px" }}>{children}</div>
      </div>
    </div>
  );
}

function SectionHeader({ title, sub, action }) {
  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
      <div>
        <div style={{ fontSize: 18, fontWeight: 700, color: C.text }}>{title}</div>
        {sub && <div style={{ fontSize: 13, color: C.textSm, marginTop: 2 }}>{sub}</div>}
      </div>
      {action && <div>{action}</div>}
    </div>
  );
}

function LoadingScreen() {
  return (
    <div style={{ height: "100vh", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", background: C.bg, gap: 20 }}>
      <div style={{ fontSize: 48 }}>🛡️</div>
      <div style={{ fontSize: 22, fontWeight: 700, color: C.accent, letterSpacing: "0.05em" }}>SecOps Command Center</div>
      <Spinner size={32} />
      <div style={{ fontSize: 13, color: C.textSm }}>Initializing secure session...</div>
    </div>
  );
}

// ─── Data Hook ───────────────────────────────────────────────────────────────

function useFreshData() {
  const [snap, setSnap] = useState(null);
  const [loading, setLoading] = useState(true);
  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch(`${API}/api/snapshot`, { credentials: "include" });
      if (r.ok) { const j = await r.json(); setSnap(j.data || {}); }
    } catch {} finally { setLoading(false); }
  }, []);
  useEffect(() => { refresh(); }, [refresh]);
  return { snap, loading, refresh };
}

// ─── Transform Snapshot ───────────────────────────────────────────────────────

function transformSnapshot(raw) {
  if (!raw) return {};
  const fw = { devices: [], policies: [], apps: [], interfaces: [], cis: [] };
  if (raw.fortinet) {
    const ft = Array.isArray(raw.fortinet) ? raw.fortinet : [raw.fortinet];
    ft.forEach(d => {
      if (!d) return;
      const host = d.hostname || d.host || "Fortinet";
      fw.devices.push({ vendor: "Fortinet", host, status: d.status || "online", policyCount: (d.policies || []).length });
      (d.policies || []).forEach(p => fw.policies.push({ ...p, device: host, vendor: "Fortinet" }));
      (d.top_apps || d.apps || []).forEach(a => fw.apps.push({ ...a, device: host }));
      (d.interfaces || []).forEach(i => fw.interfaces.push({ ...i, device: host }));
      (d.cis_checks || d.cis || []).forEach(c => fw.cis.push({ ...c, device: host }));
    });
  }
  if (raw.paloalto) {
    const pa = Array.isArray(raw.paloalto) ? raw.paloalto : [raw.paloalto];
    pa.forEach(d => {
      if (!d) return;
      const host = d.hostname || d.host || "Palo Alto";
      fw.devices.push({ vendor: "PaloAlto", host, status: d.status || "online", policyCount: (d.policies || d.rules || []).length });
      (d.policies || d.rules || []).forEach(p => fw.policies.push({ ...p, device: host, vendor: "PaloAlto" }));
      (d.top_apps || d.apps || []).forEach(a => fw.apps.push({ ...a, device: host }));
      (d.interfaces || []).forEach(i => fw.interfaces.push({ ...i, device: host }));
      (d.cis_checks || d.cis || []).forEach(c => fw.cis.push({ ...c, device: host }));
    });
  }

  const ug = raw.upguard || {};
  const surface = {
    score: ug.score ?? ug.security_score ?? null,
    domains: ug.domains || [],
    ips: ug.ip_addresses || ug.ips || [],
    risks: ug.risks || ug.vulnerabilities || [],
    domainCount: (ug.domains || []).length,
    ipCount: (ug.ip_addresses || ug.ips || []).length,
  };

  const q = raw.qualys || {};
  const vulnList = q.vulnerabilities || q.vulns || [];
  const vulnSummary = { critical: 0, high: 0, medium: 0, low: 0 };
  vulnList.forEach(v => {
    const sev = (v.severity || "").toLowerCase();
    if (sev === "critical") vulnSummary.critical++;
    else if (sev === "high") vulnSummary.high++;
    else if (sev === "medium") vulnSummary.medium++;
    else if (sev === "low") vulnSummary.low++;
  });

  const me = raw.manageengine || {};
  const assetList = me.assets || me.devices || [];
  const online = assetList.filter(a => (a.status || "").toLowerCase() === "online").length;
  const compliant = assetList.filter(a => a.patch_compliant || a.compliant).length;
  const assets = {
    list: assetList,
    total: assetList.length,
    online,
    offline: assetList.length - online,
    patchCompliance: assetList.length ? Math.round(compliant / assetList.length * 100) : 0,
  };

  const az = raw.azure || {};
  const azAlerts = az.alerts || [];
  const azBySev = { high: 0, medium: 0, low: 0, informational: 0 };
  azAlerts.forEach(a => {
    const sev = (a.severity || "").toLowerCase();
    if (azBySev[sev] !== undefined) azBySev[sev]++;
  });
  const azure = {
    score: az.secure_score ?? az.score ?? null,
    alerts: azAlerts,
    alertsBySev: azBySev,
    recommendations: az.recommendations || [],
  };

  const securityScore = ug.score ?? az.secure_score ?? null;
  const securityGrade = securityScore == null ? "N/A"
    : securityScore >= 90 ? "A" : securityScore >= 75 ? "B"
    : securityScore >= 60 ? "C" : securityScore >= 45 ? "D" : "F";

  const _integrationStatus = {
    upguard:       ug.score != null ? "connected" : (raw.upguard ? "error" : "unconfigured"),
    qualys:        vulnList.length ? "connected" : (raw.qualys ? "error" : "unconfigured"),
    fortinet:      fw.devices.filter(d => d.vendor === "Fortinet").length ? "connected" : (raw.fortinet ? "error" : "unconfigured"),
    paloalto:      fw.devices.filter(d => d.vendor === "PaloAlto").length ? "connected" : (raw.paloalto ? "error" : "unconfigured"),
    manageengine:  assetList.length ? "connected" : (raw.manageengine ? "error" : "unconfigured"),
    azure:         az.score != null ? "connected" : (raw.azure ? "error" : "unconfigured"),
  };

  return {
    firewall: fw, surface, vulnerabilities: vulnList, vulnSummary,
    assets, azure, securityScore, securityGrade,
    _hasData: !!(vulnList.length || assetList.length || fw.devices.length || ug.score != null || az.score != null),
    _integrationStatus,
  };
}

// ─── Login Page ───────────────────────────────────────────────────────────────

function LoginPage({ onLogin }) {
  const [user, setUser] = useState("");
  const [pass, setPass] = useState("");
  const [showPass, setShowPass] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const submit = async (e) => {
    e.preventDefault();
    if (!user || !pass) { setError("Please enter username and password."); return; }
    setLoading(true); setError("");
    try {
      const r = await fetch(`${API}/api/auth/login`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: user, password: pass }),
      });
      const j = await r.json().catch(() => ({}));
      if (r.ok && j.username) { onLogin(j); }
      else { setError(j.error || j.message || "Invalid credentials. Please try again."); }
    } catch { setError("Cannot connect to server. Please check your network."); }
    setLoading(false);
  };

  return (
    <div style={{ height: "100vh", display: "flex", overflow: "hidden" }}>
      {/* Left panel */}
      <div style={{
        flex: 1, background: "linear-gradient(145deg, #050c17 0%, #0f1f40 60%, #1e3a8a 100%)",
        display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center",
        padding: 60, position: "relative", overflow: "hidden",
      }}>
        <div style={{
          position: "absolute", top: "50%", left: "50%", transform: "translate(-50%,-50%)",
          width: 600, height: 600, borderRadius: "50%",
          background: "radial-gradient(circle, rgba(56,189,248,0.08) 0%, transparent 70%)",
          pointerEvents: "none",
        }} />
        <div style={{
          width: 100, height: 100, display: "flex", alignItems: "center", justifyContent: "center",
          background: "rgba(56,189,248,0.1)", border: `2px solid ${C.borderAct}`,
          borderRadius: "50%", marginBottom: 32, animation: "pulse 2.5s infinite",
          boxShadow: "0 0 40px rgba(56,189,248,0.2)",
        }}>
          <svg width="52" height="52" viewBox="0 0 24 24" fill="none">
            <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z" fill="rgba(56,189,248,0.2)" stroke="#38bdf8" strokeWidth="1.5" strokeLinejoin="round"/>
            <path d="M9 12l2 2 4-4" stroke="#38bdf8" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
          </svg>
        </div>
        <div style={{ fontSize: 32, fontWeight: 800, color: C.text, marginBottom: 12, letterSpacing: "-0.02em", textAlign: "center" }}>
          SecOps Command Center
        </div>
        <div style={{ fontSize: 15, color: C.textMd, textAlign: "center", maxWidth: 320, lineHeight: 1.6 }}>
          Unified cybersecurity operations dashboard for enterprise threat intelligence and compliance monitoring.
        </div>
        <div style={{ display: "flex", gap: 24, marginTop: 48 }}>
          {["UpGuard", "Qualys", "Fortinet", "Azure"].map(t => (
            <div key={t} style={{ fontSize: 11, color: C.textSm, background: "rgba(255,255,255,0.05)", borderRadius: 6, padding: "4px 10px", border: "1px solid rgba(255,255,255,0.08)" }}>{t}</div>
          ))}
        </div>
      </div>
      {/* Right panel */}
      <div style={{
        width: 440, background: C.bg, display: "flex", alignItems: "center", justifyContent: "center", padding: 48,
        borderLeft: `1px solid ${C.border}`,
      }}>
        <div style={{ width: "100%", maxWidth: 360 }}>
          <div style={{ marginBottom: 32 }}>
            <div style={{ fontSize: 24, fontWeight: 700, color: C.text, marginBottom: 6 }}>Sign In</div>
            <div style={{ fontSize: 14, color: C.textSm }}>Access your security operations dashboard</div>
          </div>
          <form onSubmit={submit}>
            <div style={{ marginBottom: 16 }}>
              <label style={{ display: "block", fontSize: 12, fontWeight: 600, color: C.textMd, marginBottom: 6, letterSpacing: "0.05em", textTransform: "uppercase" }}>Username</label>
              <input value={user} onChange={e => setUser(e.target.value)}
                style={{
                  width: "100%", background: C.bgCard, border: `1px solid ${C.border}`,
                  borderRadius: 8, padding: "12px 14px", fontSize: 14, color: C.text,
                  transition: "border 0.2s",
                }}
                onFocus={e => e.target.style.border = `1px solid ${C.borderAct}`}
                onBlur={e => e.target.style.border = `1px solid ${C.border}`}
                placeholder="Enter username" autoComplete="username" />
            </div>
            <div style={{ marginBottom: 24 }}>
              <label style={{ display: "block", fontSize: 12, fontWeight: 600, color: C.textMd, marginBottom: 6, letterSpacing: "0.05em", textTransform: "uppercase" }}>Password</label>
              <div style={{ position: "relative" }}>
                <input value={pass} onChange={e => setPass(e.target.value)} type={showPass ? "text" : "password"}
                  style={{
                    width: "100%", background: C.bgCard, border: `1px solid ${C.border}`,
                    borderRadius: 8, padding: "12px 44px 12px 14px", fontSize: 14, color: C.text,
                    transition: "border 0.2s",
                  }}
                  onFocus={e => e.target.style.border = `1px solid ${C.borderAct}`}
                  onBlur={e => e.target.style.border = `1px solid ${C.border}`}
                  placeholder="Enter password" autoComplete="current-password" />
                <button type="button" onClick={() => setShowPass(v => !v)}
                  style={{ position: "absolute", right: 12, top: "50%", transform: "translateY(-50%)", background: "none", border: "none", color: C.textSm, fontSize: 16, padding: 4 }}>
                  {showPass ? "🙈" : "👁️"}
                </button>
              </div>
            </div>
            {error && (
              <div style={{ background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.3)", borderRadius: 8, padding: "10px 14px", marginBottom: 16, fontSize: 13, color: C.critical }}>
                {error}
              </div>
            )}
            <button type="submit" disabled={loading}
              style={{
                width: "100%", background: loading ? "rgba(30,64,175,0.5)" : `linear-gradient(135deg, ${C.primary}, #2563eb)`,
                border: "none", borderRadius: 8, padding: "13px", fontSize: 15, fontWeight: 700,
                color: "#fff", display: "flex", alignItems: "center", justifyContent: "center", gap: 8,
                transition: "all 0.2s", boxShadow: loading ? "none" : "0 4px 16px rgba(30,64,175,0.4)",
              }}>
              {loading && <Spinner size={16} color="#fff" />}
              {loading ? "Signing in..." : "Sign In"}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}

// ─── Layout ────────────────────────────────────────────────────────────────────

const NAV_ITEMS = [
  { key: "dashboard", icon: "🏠", label: "Dashboard" },
  { key: "surface",   icon: "🌐", label: "Attack Surface" },
  { key: "vulns",     icon: "🔍", label: "Vulnerabilities" },
  { key: "firewall",  icon: "🔥", label: "Firewalls" },
  { key: "assets",    icon: "📦", label: "Assets" },
  { key: "cloud",     icon: "☁️",  label: "Cloud Security" },
  { key: "settings",  icon: "⚙️",  label: "Settings" },
];

function Layout({ page, setPage, session, sidebarOpen, setSidebarOpen, children }) {
  const pageMeta = NAV_ITEMS.find(n => n.key === page) || NAV_ITEMS[0];
  return (
    <div style={{ display: "flex", height: "100vh", overflow: "hidden", background: C.bg }}>
      {/* Sidebar */}
      <div style={{
        width: sidebarOpen ? 240 : 60, background: C.sidebar,
        borderRight: `1px solid ${C.border}`, display: "flex", flexDirection: "column",
        transition: "width 0.25s ease", flexShrink: 0, overflow: "hidden",
      }}>
        {/* Logo */}
        <div style={{ padding: sidebarOpen ? "20px 20px 16px" : "20px 0 16px", display: "flex", alignItems: "center", gap: 12, justifyContent: sidebarOpen ? "flex-start" : "center", borderBottom: `1px solid ${C.border}` }}>
          <div style={{ width: 36, height: 36, flexShrink: 0, display: "flex", alignItems: "center", justifyContent: "center", background: "rgba(56,189,248,0.1)", borderRadius: 10, border: `1px solid ${C.borderAct}` }}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
              <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z" fill="rgba(56,189,248,0.2)" stroke="#38bdf8" strokeWidth="1.5"/>
            </svg>
          </div>
          {sidebarOpen && <div style={{ fontSize: 14, fontWeight: 700, color: C.text, whiteSpace: "nowrap" }}>SecOps Center</div>}
        </div>
        {/* Nav */}
        <nav style={{ flex: 1, padding: "12px 0", overflowY: "auto" }}>
          {NAV_ITEMS.filter(n => session?.role === "executive" ? n.key === "dashboard" : true).map(item => {
            const active = page === item.key;
            return (
              <button key={item.key} onClick={() => setPage(item.key)}
                style={{
                  width: "100%", display: "flex", alignItems: "center", gap: 12,
                  padding: sidebarOpen ? "11px 20px" : "11px 0", justifyContent: sidebarOpen ? "flex-start" : "center",
                  background: active ? `linear-gradient(90deg, rgba(56,189,248,0.12), transparent)` : "none",
                  border: "none", borderLeft: active ? `2px solid ${C.accent}` : "2px solid transparent",
                  color: active ? C.accent : C.textSm, fontSize: 14, fontWeight: active ? 600 : 400,
                  cursor: "pointer", transition: "all 0.15s", borderRadius: "0 8px 8px 0",
                  whiteSpace: "nowrap",
                }}>
                <span style={{ fontSize: 18, flexShrink: 0 }}>{item.icon}</span>
                {sidebarOpen && item.label}
              </button>
            );
          })}
        </nav>
        {/* User info */}
        <div style={{ padding: sidebarOpen ? "16px 20px" : "16px 0", borderTop: `1px solid ${C.border}`, display: "flex", flexDirection: "column", alignItems: sidebarOpen ? "flex-start" : "center", gap: 6 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, justifyContent: sidebarOpen ? "flex-start" : "center" }}>
            <div style={{ width: 30, height: 30, borderRadius: "50%", background: `linear-gradient(135deg, ${C.primary}, ${C.accent})`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 13, fontWeight: 700, color: "#fff", flexShrink: 0 }}>
              {(session?.username || "U")[0].toUpperCase()}
            </div>
            {sidebarOpen && <div style={{ fontSize: 13, fontWeight: 600, color: C.textMd, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{session?.username}</div>}
          </div>
          {sidebarOpen && (
            <span style={{ fontSize: 10, background: "rgba(56,189,248,0.15)", color: C.accent, border: `1px solid ${C.borderAct}`, borderRadius: 20, padding: "2px 10px", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.08em" }}>
              {session?.role || "Analyst"}
            </span>
          )}
        </div>
      </div>
      {/* Main */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden", minWidth: 0 }}>
        {/* Header */}
        <div style={{ height: 60, borderBottom: `1px solid ${C.border}`, display: "flex", alignItems: "center", justifyContent: "space-between", padding: "0 24px", background: "rgba(5,12,23,0.6)", backdropFilter: "blur(10px)", flexShrink: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
            <button onClick={() => setSidebarOpen(v => !v)} style={{ background: "none", border: "none", color: C.textSm, fontSize: 18, padding: 4, borderRadius: 6 }}>☰</button>
            <div>
              <div style={{ fontSize: 16, fontWeight: 700, color: C.text }}>{pageMeta.icon} {pageMeta.label}</div>
            </div>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <div style={{ fontSize: 12, color: C.textSm }}>{new Date().toLocaleDateString("en-AU", { weekday: "short", month: "short", day: "numeric", year: "numeric" })}</div>
            <div style={{ width: 8, height: 8, borderRadius: "50%", background: C.ok, boxShadow: `0 0 6px ${C.ok}` }} />
            <span style={{ fontSize: 12, color: C.ok, fontWeight: 500 }}>Live</span>
          </div>
        </div>
        {/* Content */}
        <div style={{ flex: 1, overflowY: "auto", padding: 24 }}>
          {children}
        </div>
      </div>
    </div>
  );
}

// ─── Executive Dashboard ───────────────────────────────────────────────────────

function ExecDashboard({ data }) {
  const integ = data?._integrationStatus || {};
  const score = data?.securityScore;
  const grade = data?.securityGrade || "N/A";
  const vs = data?.vulnSummary || {};
  const fwCount = data?.firewall?.devices?.length || 0;
  const azScore = data?.azure?.score;

  const vulnChartData = [
    { name: "Critical", value: vs.critical || 0, fill: C.critical },
    { name: "High", value: vs.high || 0, fill: C.high },
    { name: "Medium", value: vs.medium || 0, fill: C.warn },
    { name: "Low", value: vs.low || 0, fill: C.ok },
  ];

  const trendData = useMemo(() => Array.from({ length: 14 }, (_, i) => ({
    day: `Day ${i + 1}`,
    alerts: Math.floor(Math.random() * 30 + 10),
    resolved: Math.floor(Math.random() * 25 + 5),
  })), []);

  const statusColor = (s) => s === "connected" ? C.ok : s === "error" ? C.critical : s === "collecting" ? C.warn : C.textSm;
  const statusLabel = (s) => s === "connected" ? "🟢 Connected" : s === "error" ? "🔴 Error" : s === "collecting" ? "🟡 Collecting" : "⚫ Unconfigured";

  return (
    <div style={{ animation: "fadeIn 0.4s ease" }}>
      {/* Score + Grade */}
      <div style={{ display: "flex", gap: 24, marginBottom: 24, flexWrap: "wrap" }}>
        <div style={{ ...cardStyle, display: "flex", alignItems: "center", gap: 32, flex: "0 0 auto" }}>
          <ScoreRing score={score ?? 0} size={140} strokeWidth={12} label="Security" />
          <div>
            <div style={{ fontSize: 12, color: C.textSm, textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 4 }}>Security Grade</div>
            <div style={{ fontSize: 72, fontWeight: 900, lineHeight: 1, color: score >= 75 ? C.ok : score >= 50 ? C.warn : C.critical }}>{grade}</div>
            <div style={{ fontSize: 13, color: C.textMd, marginTop: 4 }}>Overall security posture</div>
          </div>
        </div>
        <div style={{ flex: 1, display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 16, minWidth: 0 }}>
          <StatCard icon="🛡️" label="Security Score" value={score ?? "N/A"} sub="/100 points" color={C.accent} />
          <StatCard icon="🚨" label="Critical Vulns" value={vs.critical || 0} sub="Requires immediate action" color={C.critical} />
          <StatCard icon="🔥" label="Firewall Devices" value={fwCount} sub="Active protection" color={C.warn} />
          <StatCard icon="☁️" label="Azure Score" value={azScore != null ? `${azScore}%` : "N/A"} sub="Cloud security" color={C.success} />
        </div>
      </div>

      {/* Charts */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1.5fr", gap: 24, marginBottom: 24 }}>
        <div style={cardStyle}>
          <SectionHeader title="Vulnerability Distribution" />
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={vulnChartData} margin={{ top: 0, right: 0, bottom: 0, left: -20 }}>
              <XAxis dataKey="name" tick={{ fill: C.textSm, fontSize: 12 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: C.textSm, fontSize: 11 }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={{ background: C.bgCard, border: `1px solid ${C.border}`, borderRadius: 8, color: C.text }} />
              <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                {vulnChartData.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
        <div style={cardStyle}>
          <SectionHeader title="Alert Trend (14 Days)" />
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={trendData} margin={{ top: 0, right: 12, bottom: 0, left: -20 }}>
              <XAxis dataKey="day" tick={{ fill: C.textSm, fontSize: 11 }} axisLine={false} tickLine={false} interval={2} />
              <YAxis tick={{ fill: C.textSm, fontSize: 11 }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={{ background: C.bgCard, border: `1px solid ${C.border}`, borderRadius: 8, color: C.text }} />
              <Legend wrapperStyle={{ color: C.textMd, fontSize: 12 }} />
              <Line type="monotone" dataKey="alerts" stroke={C.critical} strokeWidth={2} dot={false} name="New Alerts" />
              <Line type="monotone" dataKey="resolved" stroke={C.ok} strokeWidth={2} dot={false} name="Resolved" />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Integration Status */}
      <div style={cardStyle}>
        <SectionHeader title="Integration Status" sub="Connected security tools" />
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 14 }}>
          <thead>
            <tr style={{ borderBottom: `1px solid ${C.border}` }}>
              {["Tool", "Status", "Category"].map(h => (
                <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontSize: 11, color: C.textSm, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em" }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {[
              { tool: "UpGuard", key: "upguard", cat: "Attack Surface" },
              { tool: "Qualys", key: "qualys", cat: "Vulnerability Management" },
              { tool: "Fortinet", key: "fortinet", cat: "Network Security" },
              { tool: "Palo Alto", key: "paloalto", cat: "Network Security" },
              { tool: "ManageEngine", key: "manageengine", cat: "Asset Management" },
              { tool: "Azure", key: "azure", cat: "Cloud Security" },
            ].map((row, i) => (
              <tr key={row.key} style={{ background: i % 2 === 0 ? "transparent" : C.bgMuted, borderBottom: `1px solid ${C.border}` }}>
                <td style={{ padding: "12px 12px", fontWeight: 500, color: C.text }}>{row.tool}</td>
                <td style={{ padding: "12px 12px" }}>
                  <span style={{ fontSize: 13, color: statusColor(integ[row.key]) }}>{statusLabel(integ[row.key])}</span>
                </td>
                <td style={{ padding: "12px 12px", color: C.textSm, fontSize: 13 }}>{row.cat}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ─── Threat Surface Page ──────────────────────────────────────────────────────

function ThreatSurfacePage({ onRefresh }) {
  const { snap, loading, refresh } = useFreshData();
  const [tab, setTab] = useState("risks");
  const [search, setSearch] = useState("");

  const ug = snap?.upguard || {};
  const hasData = snap && (ug.score != null || (ug.risks || []).length > 0);

  const risks = (ug.risks || []).filter(r => !search || (r.name || r.title || "").toLowerCase().includes(search.toLowerCase()));
  const domains = (ug.domains || []).filter(d => !search || (d.hostname || d.domain || "").toLowerCase().includes(search.toLowerCase()));
  const ips = (ug.ip_addresses || ug.ips || []).filter(ip => !search || (ip.ip || ip.address || "").includes(search));

  const riskBySev = useMemo(() => {
    const m = { critical: 0, high: 0, medium: 0, low: 0 };
    (ug.risks || []).forEach(r => { const k = (r.severity || "low").toLowerCase(); if (m[k] !== undefined) m[k]++; });
    return m;
  }, [snap]);

  const tabStyle = (k) => ({
    background: tab === k ? `rgba(56,189,248,0.12)` : "none",
    border: tab === k ? `1px solid ${C.borderAct}` : `1px solid ${C.border}`,
    color: tab === k ? C.accent : C.textMd,
    borderRadius: 8, padding: "8px 18px", fontSize: 13, fontWeight: 600, cursor: "pointer",
    transition: "all 0.15s",
  });

  if (loading) return <div style={{ display: "flex", justifyContent: "center", marginTop: 80 }}><Spinner size={40} /></div>;

  if (!hasData) return (
    <div style={{ animation: "fadeIn 0.4s ease" }}>
      <SectionHeader title="Attack Surface" sub="UpGuard external threat intelligence" />
      <EmptyState icon="🌐" title="No UpGuard Data" sub="Connect UpGuard to see your external attack surface, domain risks, and IP exposure.">
        <CollectBtn tool="upguard" label="Collect UpGuard Data" onCollect={refresh} />
      </EmptyState>
    </div>
  );

  return (
    <div style={{ animation: "fadeIn 0.4s ease" }}>
      <SectionHeader title="Attack Surface" sub="UpGuard external threat intelligence"
        action={<CollectBtn tool="upguard" label="Refresh" onCollect={refresh} />} />

      <div style={{ display: "grid", gridTemplateColumns: "auto 1fr 1fr 1fr 1fr 1fr", gap: 16, marginBottom: 24, alignItems: "start" }}>
        <div style={{ ...cardStyle, display: "flex", alignItems: "center", justifyContent: "center" }}>
          <ScoreRing score={ug.score ?? 0} size={120} strokeWidth={10} label="Score" />
        </div>
        <StatCard icon="🌐" label="Domains" value={(ug.domains || []).length} color={C.accent} />
        <StatCard icon="🖧" label="IP Addresses" value={(ug.ip_addresses || ug.ips || []).length} color={C.success} />
        <StatCard icon="🚨" label="Critical Risks" value={riskBySev.critical} color={C.critical} />
        <StatCard icon="⚠️" label="High Risks" value={riskBySev.high} color={C.high} />
        <StatCard icon="⚡" label="Medium Risks" value={riskBySev.medium} color={C.warn} />
      </div>

      <div style={cardStyle}>
        <div style={{ display: "flex", gap: 8, marginBottom: 20, alignItems: "center", justifyContent: "space-between", flexWrap: "wrap" }}>
          <div style={{ display: "flex", gap: 8 }}>
            {["risks", "domains", "ips"].map(k => (
              <button key={k} style={tabStyle(k)} onClick={() => { setTab(k); setSearch(""); }}>
                {k === "risks" ? "Risks" : k === "domains" ? "Domains" : "IP Addresses"}
              </button>
            ))}
          </div>
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder={`Search ${tab}...`}
            style={{ background: C.bgMuted, border: `1px solid ${C.border}`, borderRadius: 8, padding: "8px 14px", fontSize: 13, color: C.text, width: 220 }} />
        </div>

        {tab === "risks" && (
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
            <thead>
              <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                {["Risk Name", "Severity", "Category", "Score"].map(h => (
                  <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontSize: 11, color: C.textSm, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {risks.length === 0 ? (
                <tr><td colSpan={4} style={{ textAlign: "center", padding: 32, color: C.textSm }}>No risks found</td></tr>
              ) : risks.map((r, i) => (
                <tr key={i} style={{ background: i % 2 === 0 ? "transparent" : C.bgMuted, borderBottom: `1px solid ${C.border}` }}>
                  <td style={{ padding: "10px 12px", color: C.text, fontWeight: 500 }}>{r.name || r.title || "Unknown Risk"}</td>
                  <td style={{ padding: "10px 12px" }}><SeverityBadge level={r.severity} /></td>
                  <td style={{ padding: "10px 12px", color: C.textMd }}>{r.category || r.type || "—"}</td>
                  <td style={{ padding: "10px 12px", color: C.textSm }}>{r.score ?? r.risk_score ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {tab === "domains" && (
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
            <thead>
              <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                {["Domain", "Status", "Risk", "Last Seen"].map(h => (
                  <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontSize: 11, color: C.textSm, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {domains.length === 0 ? (
                <tr><td colSpan={4} style={{ textAlign: "center", padding: 32, color: C.textSm }}>No domains found</td></tr>
              ) : domains.map((d, i) => (
                <tr key={i} style={{ background: i % 2 === 0 ? "transparent" : C.bgMuted, borderBottom: `1px solid ${C.border}` }}>
                  <td style={{ padding: "10px 12px", color: C.accent, fontFamily: "monospace" }}>{d.hostname || d.domain || d}</td>
                  <td style={{ padding: "10px 12px" }}><span style={{ color: d.active !== false ? C.ok : C.textSm, fontSize: 12 }}>{d.active !== false ? "● Active" : "○ Inactive"}</span></td>
                  <td style={{ padding: "10px 12px" }}>{d.risk ? <SeverityBadge level={d.risk} /> : <span style={{ color: C.textSm }}>—</span>}</td>
                  <td style={{ padding: "10px 12px", color: C.textSm, fontSize: 12 }}>{d.last_seen ? new Date(d.last_seen).toLocaleDateString() : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {tab === "ips" && (
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
            <thead>
              <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                {["IP Address", "Country", "Open Ports", "Exposure"].map(h => (
                  <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontSize: 11, color: C.textSm, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {ips.length === 0 ? (
                <tr><td colSpan={4} style={{ textAlign: "center", padding: 32, color: C.textSm }}>No IPs found</td></tr>
              ) : ips.map((ip, i) => (
                <tr key={i} style={{ background: i % 2 === 0 ? "transparent" : C.bgMuted, borderBottom: `1px solid ${C.border}` }}>
                  <td style={{ padding: "10px 12px", color: C.accent, fontFamily: "monospace" }}>{ip.ip || ip.address || ip}</td>
                  <td style={{ padding: "10px 12px", color: C.textMd }}>{ip.country || "—"}</td>
                  <td style={{ padding: "10px 12px", color: C.textSm }}>{ip.open_ports ? ip.open_ports.join(", ") : "—"}</td>
                  <td style={{ padding: "10px 12px" }}>{ip.exposure ? <SeverityBadge level={ip.exposure} /> : <span style={{ color: C.textSm }}>—</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

// ─── Vulnerability Page ───────────────────────────────────────────────────────

function VulnerabilityPage({ onRefresh }) {
  const { snap, loading, refresh } = useFreshData();
  const [sortBy, setSortBy] = useState("severity");
  const [sortDir, setSortDir] = useState("desc");
  const [selected, setSelected] = useState(null);
  const [search, setSearch] = useState("");

  const q = snap?.qualys || {};
  const rawVulns = q.vulnerabilities || q.vulns || [];
  const hasData = snap && rawVulns.length > 0;

  const sevOrder = { critical: 4, high: 3, medium: 2, low: 1 };
  const vulns = useMemo(() => {
    let v = [...rawVulns];
    if (search) v = v.filter(x => (x.title || x.name || x.cve || "").toLowerCase().includes(search.toLowerCase()) || (x.host || "").toLowerCase().includes(search.toLowerCase()));
    v.sort((a, b) => {
      let cmp = 0;
      if (sortBy === "severity") cmp = (sevOrder[b.severity?.toLowerCase()] || 0) - (sevOrder[a.severity?.toLowerCase()] || 0);
      else if (sortBy === "host") cmp = (a.host || "").localeCompare(b.host || "");
      else if (sortBy === "cve") cmp = (a.cve || "").localeCompare(b.cve || "");
      return sortDir === "asc" ? -cmp : cmp;
    });
    return v;
  }, [rawVulns, sortBy, sortDir, search]);

  const summary = useMemo(() => {
    const m = { critical: 0, high: 0, medium: 0, low: 0 };
    rawVulns.forEach(v => { const k = (v.severity || "low").toLowerCase(); if (m[k] !== undefined) m[k]++; });
    return m;
  }, [snap]);

  const pieData = [
    { name: "Critical", value: summary.critical, fill: C.critical },
    { name: "High", value: summary.high, fill: C.high },
    { name: "Medium", value: summary.medium, fill: C.warn },
    { name: "Low", value: summary.low, fill: C.ok },
  ].filter(d => d.value > 0);

  const hostCounts = useMemo(() => {
    const m = {};
    rawVulns.forEach(v => { if (v.host) m[v.host] = (m[v.host] || 0) + 1; });
    return Object.entries(m).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([host, count]) => ({ host, count }));
  }, [snap]);

  const doSort = (col) => {
    if (sortBy === col) setSortDir(d => d === "asc" ? "desc" : "asc");
    else { setSortBy(col); setSortDir("desc"); }
  };

  const thStyle = (col) => ({
    padding: "8px 12px", textAlign: "left", fontSize: 11, color: sortBy === col ? C.accent : C.textSm,
    fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", cursor: "pointer", userSelect: "none",
  });

  if (loading) return <div style={{ display: "flex", justifyContent: "center", marginTop: 80 }}><Spinner size={40} /></div>;

  if (!hasData) return (
    <div style={{ animation: "fadeIn 0.4s ease" }}>
      <SectionHeader title="Vulnerabilities" sub="Qualys vulnerability management" />
      <EmptyState icon="🔍" title="No Qualys Data" sub="Connect Qualys to see vulnerabilities, CVEs, and affected hosts across your environment.">
        <CollectBtn tool="qualys" label="Collect Qualys Data" onCollect={refresh} />
      </EmptyState>
    </div>
  );

  return (
    <div style={{ animation: "fadeIn 0.4s ease" }}>
      <SectionHeader title="Vulnerabilities" sub={`${rawVulns.length} total vulnerabilities found`}
        action={<CollectBtn tool="qualys" label="Refresh" onCollect={refresh} />} />

      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16, marginBottom: 24 }}>
        <StatCard icon="💀" label="Critical" value={summary.critical} color={C.critical} />
        <StatCard icon="🔴" label="High" value={summary.high} color={C.high} />
        <StatCard icon="🟡" label="Medium" value={summary.medium} color={C.warn} />
        <StatCard icon="🟢" label="Low" value={summary.low} color={C.ok} />
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1.5fr", gap: 24, marginBottom: 24 }}>
        <div style={cardStyle}>
          <SectionHeader title="Severity Distribution" />
          <div style={{ display: "flex", justifyContent: "center" }}>
            <PieChart width={260} height={200}>
              <Pie data={pieData} cx={130} cy={100} innerRadius={55} outerRadius={85} dataKey="value" paddingAngle={3}>
                {pieData.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
              </Pie>
              <Tooltip contentStyle={{ background: C.bgCard, border: `1px solid ${C.border}`, borderRadius: 8, color: C.text }} />
              <Legend wrapperStyle={{ fontSize: 12, color: C.textMd }} />
            </PieChart>
          </div>
        </div>
        <div style={cardStyle}>
          <SectionHeader title="Top Vulnerable Hosts" />
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={hostCounts} layout="vertical" margin={{ top: 0, right: 12, bottom: 0, left: 0 }}>
              <XAxis type="number" tick={{ fill: C.textSm, fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis type="category" dataKey="host" tick={{ fill: C.textMd, fontSize: 11 }} axisLine={false} tickLine={false} width={100} />
              <Tooltip contentStyle={{ background: C.bgCard, border: `1px solid ${C.border}`, borderRadius: 8, color: C.text }} />
              <Bar dataKey="count" fill={C.accent} radius={[0, 4, 4, 0]} name="Vulns" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div style={cardStyle}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
          <div style={{ fontSize: 16, fontWeight: 700, color: C.text }}>Vulnerability List</div>
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search CVE, title, host..."
            style={{ background: C.bgMuted, border: `1px solid ${C.border}`, borderRadius: 8, padding: "8px 14px", fontSize: 13, color: C.text, width: 260 }} />
        </div>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
          <thead>
            <tr style={{ borderBottom: `1px solid ${C.border}` }}>
              <th style={thStyle("cve")} onClick={() => doSort("cve")}>CVE {sortBy === "cve" ? (sortDir === "asc" ? "↑" : "↓") : ""}</th>
              <th style={thStyle("severity")} onClick={() => doSort("severity")}>Severity {sortBy === "severity" ? (sortDir === "asc" ? "↑" : "↓") : ""}</th>
              <th style={thStyle("host")} onClick={() => doSort("host")}>Host {sortBy === "host" ? (sortDir === "asc" ? "↑" : "↓") : ""}</th>
              <th style={{ padding: "8px 12px", textAlign: "left", fontSize: 11, color: C.textSm, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em" }}>Title</th>
              <th style={{ padding: "8px 12px" }}></th>
            </tr>
          </thead>
          <tbody>
            {vulns.slice(0, 100).map((v, i) => (
              <tr key={i} style={{ background: i % 2 === 0 ? "transparent" : C.bgMuted, borderBottom: `1px solid ${C.border}`, cursor: "pointer" }}
                onClick={() => setSelected(v)}>
                <td style={{ padding: "10px 12px", color: C.accent, fontFamily: "monospace", fontSize: 12 }}>{v.cve || v.id || "—"}</td>
                <td style={{ padding: "10px 12px" }}><SeverityBadge level={v.severity} /></td>
                <td style={{ padding: "10px 12px", color: C.textMd, fontFamily: "monospace", fontSize: 12 }}>{v.host || "—"}</td>
                <td style={{ padding: "10px 12px", color: C.text }}>{(v.title || v.name || "Unknown").substring(0, 60)}{(v.title || v.name || "").length > 60 ? "..." : ""}</td>
                <td style={{ padding: "10px 12px", color: C.textSm, fontSize: 12 }}>›</td>
              </tr>
            ))}
          </tbody>
        </table>
        {vulns.length > 100 && <div style={{ padding: "12px 12px", color: C.textSm, fontSize: 12, textAlign: "center" }}>Showing 100 of {vulns.length} vulnerabilities. Use search to filter.</div>}
      </div>

      <Modal open={!!selected} onClose={() => setSelected(null)} title={selected?.cve || selected?.id || "Vulnerability Detail"} width={700}>
        {selected && (
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
              <SeverityBadge level={selected.severity} />
              {selected.cvss && <span style={{ fontSize: 13, color: C.textMd }}>CVSS: <strong style={{ color: C.text }}>{selected.cvss}</strong></span>}
              {selected.host && <span style={{ fontSize: 13, color: C.textMd }}>Host: <span style={{ color: C.accent, fontFamily: "monospace" }}>{selected.host}</span></span>}
            </div>
            <div>
              <div style={{ fontSize: 16, fontWeight: 600, color: C.text, marginBottom: 8 }}>{selected.title || selected.name || "Unknown Vulnerability"}</div>
              {selected.description && <div style={{ fontSize: 13, color: C.textMd, lineHeight: 1.7 }}>{selected.description}</div>}
            </div>
            {selected.solution && (
              <div style={{ background: "rgba(16,185,129,0.08)", border: "1px solid rgba(16,185,129,0.2)", borderRadius: 8, padding: "12px 16px" }}>
                <div style={{ fontSize: 12, fontWeight: 600, color: C.ok, marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.06em" }}>Remediation</div>
                <div style={{ fontSize: 13, color: C.textMd, lineHeight: 1.6 }}>{selected.solution}</div>
              </div>
            )}
            {selected.references && (
              <div>
                <div style={{ fontSize: 12, fontWeight: 600, color: C.textSm, marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.06em" }}>References</div>
                {(Array.isArray(selected.references) ? selected.references : [selected.references]).map((r, i) => (
                  <div key={i} style={{ fontSize: 12, color: C.accent, fontFamily: "monospace", wordBreak: "break-all" }}>{r}</div>
                ))}
              </div>
            )}
          </div>
        )}
      </Modal>
    </div>
  );
}

// ─── Firewall Page ────────────────────────────────────────────────────────────

function FirewallPage({ onRefresh }) {
  const { snap, loading, refresh } = useFreshData();
  const [tab, setTab] = useState("overview");

  const fw = useMemo(() => {
    if (!snap) return { devices: [], policies: [], apps: [], interfaces: [], cis: [] };
    const devices = [], policies = [], apps = [], interfaces = [], cis = [];
    const addDevice = (d, vendor) => {
      if (!d) return;
      const host = d.hostname || d.host || vendor;
      devices.push({ vendor, host, status: d.status || "online", policyCount: (d.policies || d.rules || []).length });
      (d.policies || d.rules || []).forEach(p => policies.push({ ...p, device: host, vendor }));
      (d.top_apps || d.apps || []).forEach(a => apps.push({ ...a, device: host }));
      (d.interfaces || []).forEach(i => interfaces.push({ ...i, device: host }));
      (d.cis_checks || d.cis || []).forEach(c => cis.push({ ...c, device: host }));
    };
    if (snap.fortinet) { const ft = Array.isArray(snap.fortinet) ? snap.fortinet : [snap.fortinet]; ft.forEach(d => addDevice(d, "Fortinet")); }
    if (snap.paloalto) { const pa = Array.isArray(snap.paloalto) ? snap.paloalto : [snap.paloalto]; pa.forEach(d => addDevice(d, "PaloAlto")); }
    return { devices, policies, apps, interfaces, cis };
  }, [snap]);

  const hasData = snap && fw.devices.length > 0;

  const tabStyle = (k) => ({
    background: tab === k ? `rgba(56,189,248,0.12)` : "none",
    border: tab === k ? `1px solid ${C.borderAct}` : `1px solid ${C.border}`,
    color: tab === k ? C.accent : C.textMd,
    borderRadius: 8, padding: "8px 18px", fontSize: 13, fontWeight: 600, cursor: "pointer", transition: "all 0.15s",
  });

  const appChart = fw.apps.slice(0, 10).map(a => ({ name: a.name || a.app || "Unknown", sessions: a.sessions || a.count || 0 }));
  const bwChart = fw.interfaces.slice(0, 10).map(i => ({ name: i.name || i.interface || "Unknown", rx: Math.round((i.rx_bytes || 0) / 1e6), tx: Math.round((i.tx_bytes || 0) / 1e6) }));

  const policyStats = fw.devices.map(d => {
    const devPolicies = fw.policies.filter(p => p.device === d.host);
    return {
      host: d.host, vendor: d.vendor,
      allow: devPolicies.filter(p => (p.action || "").toLowerCase() === "allow").length,
      deny: devPolicies.filter(p => (p.action || "").toLowerCase() === "deny" || (p.action || "").toLowerCase() === "drop").length,
      total: devPolicies.length,
    };
  });

  if (loading) return <div style={{ display: "flex", justifyContent: "center", marginTop: 80 }}><Spinner size={40} /></div>;

  if (!hasData) return (
    <div style={{ animation: "fadeIn 0.4s ease" }}>
      <SectionHeader title="Firewalls" sub="Fortinet & Palo Alto network security" />
      <EmptyState icon="🔥" title="No Firewall Data" sub="Connect Fortinet or Palo Alto to see device status, policies, top apps, and CIS benchmarks.">
        <div style={{ display: "flex", gap: 12 }}>
          <CollectBtn tool="fortinet" label="Collect Fortinet" onCollect={refresh} />
          <CollectBtn tool="paloalto" label="Collect Palo Alto" onCollect={refresh} />
        </div>
      </EmptyState>
    </div>
  );

  return (
    <div style={{ animation: "fadeIn 0.4s ease" }}>
      <SectionHeader title="Firewalls" sub={`${fw.devices.length} device(s) monitored`}
        action={<div style={{ display: "flex", gap: 8 }}><CollectBtn tool="fortinet" label="Fortinet" onCollect={refresh} /><CollectBtn tool="paloalto" label="Palo Alto" onCollect={refresh} /></div>} />

      {/* Device Cards */}
      <div style={{ display: "flex", gap: 16, marginBottom: 24, flexWrap: "wrap" }}>
        {fw.devices.map((d, i) => (
          <div key={i} style={{ ...cardStyle, flex: "0 0 auto", minWidth: 200, borderTop: `3px solid ${d.vendor === "Fortinet" ? C.high : C.critical}` }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12 }}>
              <div style={{ fontSize: 22 }}>{d.vendor === "Fortinet" ? "🟠" : "🔴"}</div>
              <div>
                <div style={{ fontSize: 14, fontWeight: 700, color: C.text }}>{d.host}</div>
                <span style={{ fontSize: 11, background: d.vendor === "Fortinet" ? "rgba(249,115,22,0.15)" : "rgba(239,68,68,0.15)", color: d.vendor === "Fortinet" ? C.high : C.critical, borderRadius: 20, padding: "2px 8px", fontWeight: 600 }}>{d.vendor}</span>
              </div>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12 }}>
              <span style={{ color: C.textSm }}>Policies</span>
              <span style={{ color: C.text, fontWeight: 600 }}>{d.policyCount}</span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, marginTop: 4 }}>
              <span style={{ color: C.textSm }}>Status</span>
              <span style={{ color: d.status === "online" ? C.ok : C.critical, fontWeight: 600 }}>{d.status || "online"}</span>
            </div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div style={cardStyle}>
        <div style={{ display: "flex", gap: 8, marginBottom: 20 }}>
          {["overview", "apps", "bandwidth", "cis"].map(k => (
            <button key={k} style={tabStyle(k)} onClick={() => setTab(k)}>
              {k === "overview" ? "Overview" : k === "apps" ? "Top Apps" : k === "bandwidth" ? "Bandwidth" : "CIS Benchmark"}
            </button>
          ))}
        </div>

        {tab === "overview" && (
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
            <thead>
              <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                {["Device", "Vendor", "Total Policies", "Allow", "Deny"].map(h => (
                  <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontSize: 11, color: C.textSm, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {policyStats.map((d, i) => (
                <tr key={i} style={{ background: i % 2 === 0 ? "transparent" : C.bgMuted, borderBottom: `1px solid ${C.border}` }}>
                  <td style={{ padding: "12px 12px", color: C.text, fontWeight: 500, fontFamily: "monospace" }}>{d.host}</td>
                  <td style={{ padding: "12px 12px" }}><span style={{ fontSize: 12, color: d.vendor === "Fortinet" ? C.high : C.critical, fontWeight: 600 }}>{d.vendor}</span></td>
                  <td style={{ padding: "12px 12px", color: C.text }}>{d.total}</td>
                  <td style={{ padding: "12px 12px", color: C.ok }}>{d.allow}</td>
                  <td style={{ padding: "12px 12px", color: C.critical }}>{d.deny}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {tab === "apps" && (
          appChart.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={appChart} margin={{ top: 0, right: 12, bottom: 40, left: -20 }}>
                <XAxis dataKey="name" tick={{ fill: C.textSm, fontSize: 11 }} axisLine={false} tickLine={false} angle={-30} textAnchor="end" />
                <YAxis tick={{ fill: C.textSm, fontSize: 11 }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={{ background: C.bgCard, border: `1px solid ${C.border}`, borderRadius: 8, color: C.text }} />
                <Bar dataKey="sessions" fill={C.accent} radius={[4, 4, 0, 0]} name="Sessions" />
              </BarChart>
            </ResponsiveContainer>
          ) : <div style={{ textAlign: "center", padding: 40, color: C.textSm }}>No app data available</div>
        )}

        {tab === "bandwidth" && (
          bwChart.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={bwChart} margin={{ top: 0, right: 12, bottom: 40, left: -20 }}>
                <XAxis dataKey="name" tick={{ fill: C.textSm, fontSize: 11 }} axisLine={false} tickLine={false} angle={-30} textAnchor="end" />
                <YAxis tick={{ fill: C.textSm, fontSize: 11 }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={{ background: C.bgCard, border: `1px solid ${C.border}`, borderRadius: 8, color: C.text }} formatter={(v) => [`${v} MB`, ""]} />
                <Legend wrapperStyle={{ color: C.textMd, fontSize: 12 }} />
                <Bar dataKey="rx" fill={C.success} radius={[4, 4, 0, 0]} name="RX (MB)" />
                <Bar dataKey="tx" fill={C.accent} radius={[4, 4, 0, 0]} name="TX (MB)" />
              </BarChart>
            </ResponsiveContainer>
          ) : <div style={{ textAlign: "center", padding: 40, color: C.textSm }}>No bandwidth data available</div>
        )}

        {tab === "cis" && (
          fw.cis.length > 0 ? (
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
              <thead>
                <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                  {["Check", "Device", "Status", "Details"].map(h => (
                    <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontSize: 11, color: C.textSm, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em" }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {fw.cis.map((c, i) => (
                  <tr key={i} style={{ background: i % 2 === 0 ? "transparent" : C.bgMuted, borderBottom: `1px solid ${C.border}` }}>
                    <td style={{ padding: "10px 12px", color: C.text, fontWeight: 500 }}>{c.name || c.check || "—"}</td>
                    <td style={{ padding: "10px 12px", color: C.textMd, fontFamily: "monospace", fontSize: 12 }}>{c.device || "—"}</td>
                    <td style={{ padding: "10px 12px" }}>
                      <span style={{ fontSize: 12, fontWeight: 600, color: c.passed || c.status === "pass" ? C.ok : C.critical }}>
                        {c.passed || c.status === "pass" ? "✅ Pass" : "❌ Fail"}
                      </span>
                    </td>
                    <td style={{ padding: "10px 12px", color: C.textSm, fontSize: 12 }}>{c.details || c.description || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : <div style={{ textAlign: "center", padding: 40, color: C.textSm }}>No CIS benchmark data available</div>
        )}
      </div>
    </div>
  );
}

// ─── Asset Page ────────────────────────────────────────────────────────────────

function AssetPage({ onRefresh }) {
  const { snap, loading, refresh } = useFreshData();
  const [search, setSearch] = useState("");

  const me = snap?.manageengine || {};
  const rawAssets = me.assets || me.devices || [];
  const hasData = snap && rawAssets.length > 0;

  const assets = useMemo(() => {
    if (!search) return rawAssets;
    return rawAssets.filter(a => (a.name || a.hostname || "").toLowerCase().includes(search.toLowerCase()) || (a.os || "").toLowerCase().includes(search.toLowerCase()));
  }, [rawAssets, search]);

  const online = rawAssets.filter(a => (a.status || "").toLowerCase() === "online").length;
  const compliant = rawAssets.filter(a => a.patch_compliant || a.compliant).length;
  const patchPct = rawAssets.length ? Math.round(compliant / rawAssets.length * 100) : 0;

  const pieData = [
    { name: "Compliant", value: compliant, fill: C.ok },
    { name: "Non-Compliant", value: rawAssets.length - compliant, fill: C.critical },
  ].filter(d => d.value > 0);

  const osMap = useMemo(() => {
    const m = {};
    rawAssets.forEach(a => { const os = a.os || a.operating_system || "Unknown"; m[os] = (m[os] || 0) + 1; });
    return Object.entries(m).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([os, count]) => ({ os: os.substring(0, 20), count }));
  }, [snap]);

  if (loading) return <div style={{ display: "flex", justifyContent: "center", marginTop: 80 }}><Spinner size={40} /></div>;

  if (!hasData) return (
    <div style={{ animation: "fadeIn 0.4s ease" }}>
      <SectionHeader title="Assets" sub="ManageEngine endpoint management" />
      <EmptyState icon="📦" title="No Asset Data" sub="Connect ManageEngine to see all endpoints, patch compliance, and OS distribution.">
        <CollectBtn tool="manageengine" label="Collect Asset Data" onCollect={refresh} />
      </EmptyState>
    </div>
  );

  return (
    <div style={{ animation: "fadeIn 0.4s ease" }}>
      <SectionHeader title="Assets" sub={`${rawAssets.length} endpoints managed`}
        action={<CollectBtn tool="manageengine" label="Refresh" onCollect={refresh} />} />

      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16, marginBottom: 24 }}>
        <StatCard icon="📦" label="Total Assets" value={rawAssets.length} color={C.accent} />
        <StatCard icon="🟢" label="Online" value={online} color={C.ok} />
        <StatCard icon="🔴" label="Offline" value={rawAssets.length - online} color={C.critical} />
        <StatCard icon="🛠️" label="Patch Compliance" value={`${patchPct}%`} color={patchPct > 80 ? C.ok : patchPct > 50 ? C.warn : C.critical} />
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1.5fr", gap: 24, marginBottom: 24 }}>
        <div style={cardStyle}>
          <SectionHeader title="Patch Compliance" />
          <div style={{ display: "flex", justifyContent: "center" }}>
            <PieChart width={240} height={200}>
              <Pie data={pieData} cx={120} cy={100} innerRadius={55} outerRadius={85} dataKey="value" paddingAngle={3}>
                {pieData.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
              </Pie>
              <Tooltip contentStyle={{ background: C.bgCard, border: `1px solid ${C.border}`, borderRadius: 8, color: C.text }} />
              <Legend wrapperStyle={{ fontSize: 12, color: C.textMd }} />
            </PieChart>
          </div>
        </div>
        <div style={cardStyle}>
          <SectionHeader title="OS Distribution" />
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={osMap} layout="vertical" margin={{ top: 0, right: 12, bottom: 0, left: 0 }}>
              <XAxis type="number" tick={{ fill: C.textSm, fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis type="category" dataKey="os" tick={{ fill: C.textMd, fontSize: 11 }} axisLine={false} tickLine={false} width={120} />
              <Tooltip contentStyle={{ background: C.bgCard, border: `1px solid ${C.border}`, borderRadius: 8, color: C.text }} />
              <Bar dataKey="count" fill={C.accent} radius={[0, 4, 4, 0]} name="Count" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div style={cardStyle}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
          <div style={{ fontSize: 16, fontWeight: 700, color: C.text }}>Asset Inventory</div>
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search assets..."
            style={{ background: C.bgMuted, border: `1px solid ${C.border}`, borderRadius: 8, padding: "8px 14px", fontSize: 13, color: C.text, width: 240 }} />
        </div>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
          <thead>
            <tr style={{ borderBottom: `1px solid ${C.border}` }}>
              {["Name", "OS", "Status", "Last Seen", "Patch Status"].map(h => (
                <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontSize: 11, color: C.textSm, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em" }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {assets.slice(0, 100).map((a, i) => {
              const isOnline = (a.status || "").toLowerCase() === "online";
              const isCompliant = a.patch_compliant || a.compliant;
              return (
                <tr key={i} style={{ background: i % 2 === 0 ? "transparent" : C.bgMuted, borderBottom: `1px solid ${C.border}` }}>
                  <td style={{ padding: "10px 12px", color: C.text, fontWeight: 500 }}>{a.name || a.hostname || "—"}</td>
                  <td style={{ padding: "10px 12px", color: C.textMd, fontSize: 12 }}>{a.os || a.operating_system || "—"}</td>
                  <td style={{ padding: "10px 12px" }}>
                    <span style={{ fontSize: 12, fontWeight: 600, color: isOnline ? C.ok : C.critical }}>
                      {isOnline ? "● Online" : "○ Offline"}
                    </span>
                  </td>
                  <td style={{ padding: "10px 12px", color: C.textSm, fontSize: 12 }}>{a.last_seen ? new Date(a.last_seen).toLocaleDateString() : "—"}</td>
                  <td style={{ padding: "10px 12px" }}>
                    <span style={{ fontSize: 12, fontWeight: 600, color: isCompliant ? C.ok : C.critical }}>
                      {isCompliant ? "✅ Compliant" : "❌ Non-Compliant"}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {assets.length > 100 && <div style={{ padding: 12, color: C.textSm, fontSize: 12, textAlign: "center" }}>Showing 100 of {assets.length} assets</div>}
      </div>
    </div>
  );
}

// ─── Cloud Page ────────────────────────────────────────────────────────────────

function CloudPage({ onRefresh }) {
  const { snap, loading, refresh } = useFreshData();
  const [sevFilter, setSevFilter] = useState("all");
  const [search, setSearch] = useState("");
  const [expandedRec, setExpandedRec] = useState(null);

  const az = snap?.azure || {};
  const hasData = snap && (az.score != null || (az.alerts || []).length > 0);

  const alerts = useMemo(() => {
    let a = az.alerts || [];
    if (sevFilter !== "all") a = a.filter(x => (x.severity || "").toLowerCase() === sevFilter);
    if (search) a = a.filter(x => (x.name || x.alertDisplayName || "").toLowerCase().includes(search.toLowerCase()) || (x.resource || "").toLowerCase().includes(search.toLowerCase()));
    return a;
  }, [snap, sevFilter, search]);

  const alertsBySev = useMemo(() => {
    const m = { high: 0, medium: 0, low: 0, informational: 0 };
    (az.alerts || []).forEach(a => { const k = (a.severity || "").toLowerCase(); if (m[k] !== undefined) m[k]++; });
    return m;
  }, [snap]);

  if (loading) return <div style={{ display: "flex", justifyContent: "center", marginTop: 80 }}><Spinner size={40} /></div>;

  if (!hasData) return (
    <div style={{ animation: "fadeIn 0.4s ease" }}>
      <SectionHeader title="Cloud Security" sub="Microsoft Azure Defender" />
      <EmptyState icon="☁️" title="No Azure Data" sub="Connect Azure to see your Secure Score, security alerts, and recommendations.">
        <CollectBtn tool="azure" label="Collect Azure Data" onCollect={refresh} />
      </EmptyState>
    </div>
  );

  return (
    <div style={{ animation: "fadeIn 0.4s ease" }}>
      <SectionHeader title="Cloud Security" sub="Microsoft Azure Defender for Cloud"
        action={<CollectBtn tool="azure" label="Refresh" onCollect={refresh} />} />

      <div style={{ display: "flex", gap: 24, marginBottom: 24, flexWrap: "wrap" }}>
        <div style={{ ...cardStyle, display: "flex", alignItems: "center", gap: 24, flex: "0 0 auto" }}>
          <ScoreRing score={az.score ?? 0} size={130} strokeWidth={12} label="Secure Score" />
          <div>
            <div style={{ fontSize: 12, color: C.textSm, textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 4 }}>Azure Secure Score</div>
            <div style={{ fontSize: 36, fontWeight: 800, color: az.score >= 70 ? C.ok : az.score >= 40 ? C.warn : C.critical }}>{az.score ?? "N/A"}%</div>
            <div style={{ fontSize: 13, color: C.textMd }}>Microsoft Defender for Cloud</div>
          </div>
        </div>
        <div style={{ flex: 1, display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))", gap: 16, minWidth: 0 }}>
          <StatCard icon="🚨" label="High Alerts" value={alertsBySev.high} color={C.critical} />
          <StatCard icon="⚠️" label="Medium Alerts" value={alertsBySev.medium} color={C.warn} />
          <StatCard icon="ℹ️" label="Low Alerts" value={alertsBySev.low} color={C.ok} />
          <StatCard icon="💬" label="Informational" value={alertsBySev.informational} color={C.textMd} />
        </div>
      </div>

      {/* Alerts */}
      <div style={{ ...cardStyle, marginBottom: 24 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16, flexWrap: "wrap", gap: 10 }}>
          <div style={{ fontSize: 16, fontWeight: 700, color: C.text }}>Security Alerts</div>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            {["all", "high", "medium", "low", "informational"].map(s => (
              <button key={s} onClick={() => setSevFilter(s)}
                style={{ background: sevFilter === s ? "rgba(56,189,248,0.12)" : "none", border: `1px solid ${sevFilter === s ? C.borderAct : C.border}`, color: sevFilter === s ? C.accent : C.textSm, borderRadius: 8, padding: "6px 14px", fontSize: 12, fontWeight: 600, cursor: "pointer", transition: "all 0.15s", textTransform: "capitalize" }}>
                {s}
              </button>
            ))}
            <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search..."
              style={{ background: C.bgMuted, border: `1px solid ${C.border}`, borderRadius: 8, padding: "6px 12px", fontSize: 12, color: C.text, width: 180 }} />
          </div>
        </div>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
          <thead>
            <tr style={{ borderBottom: `1px solid ${C.border}` }}>
              {["Alert Name", "Severity", "Status", "Resource"].map(h => (
                <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontSize: 11, color: C.textSm, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em" }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {alerts.length === 0 ? (
              <tr><td colSpan={4} style={{ textAlign: "center", padding: 32, color: C.textSm }}>No alerts match filter</td></tr>
            ) : alerts.slice(0, 50).map((a, i) => (
              <tr key={i} style={{ background: i % 2 === 0 ? "transparent" : C.bgMuted, borderBottom: `1px solid ${C.border}` }}>
                <td style={{ padding: "10px 12px", color: C.text, fontWeight: 500 }}>{a.name || a.alertDisplayName || "Unknown"}</td>
                <td style={{ padding: "10px 12px" }}><SeverityBadge level={a.severity} /></td>
                <td style={{ padding: "10px 12px", color: C.textMd, fontSize: 12 }}>{a.status || a.intent || "Active"}</td>
                <td style={{ padding: "10px 12px", color: C.textSm, fontFamily: "monospace", fontSize: 11 }}>{(a.resource || a.resourceIdentifiers?.[0]?.resourceName || "—").substring(0, 40)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Recommendations */}
      {(az.recommendations || []).length > 0 && (
        <div style={cardStyle}>
          <SectionHeader title="Recommendations" sub={`${(az.recommendations || []).length} active recommendations`} />
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {(az.recommendations || []).slice(0, 20).map((rec, i) => (
              <div key={i} style={{ background: C.bgMuted, border: `1px solid ${C.border}`, borderRadius: 8, overflow: "hidden" }}>
                <div onClick={() => setExpandedRec(expandedRec === i ? null : i)}
                  style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "12px 16px", cursor: "pointer" }}>
                  <div style={{ flex: 1, display: "flex", gap: 12, alignItems: "center" }}>
                    <SeverityBadge level={rec.severity} />
                    <span style={{ fontSize: 13, fontWeight: 500, color: C.text }}>{rec.name || rec.displayName || "Recommendation"}</span>
                  </div>
                  <span style={{ color: C.textSm, fontSize: 14 }}>{expandedRec === i ? "▲" : "▼"}</span>
                </div>
                {expandedRec === i && (
                  <div style={{ padding: "0 16px 16px", borderTop: `1px solid ${C.border}` }}>
                    {rec.description && <div style={{ fontSize: 13, color: C.textMd, lineHeight: 1.6, paddingTop: 12 }}>{rec.description}</div>}
                    {rec.remediation_description && (
                      <div style={{ marginTop: 10, fontSize: 12, color: C.ok, background: "rgba(16,185,129,0.08)", border: "1px solid rgba(16,185,129,0.2)", borderRadius: 6, padding: "8px 12px" }}>
                        <strong>Fix: </strong>{rec.remediation_description}
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Settings Page ────────────────────────────────────────────────────────────

function SettingsPage() {
  const [integrations, setIntegrations] = useState({});
  const [loadingInteg, setLoadingInteg] = useState(true);
  const [saving, setSaving] = useState({});
  const [testing, setTesting] = useState({});
  const [testResults, setTestResults] = useState({});
  const [creds, setCreds] = useState({});

  useEffect(() => {
    fetch(`${API}/api/integrations`, { credentials: "include" })
      .then(r => r.json()).then(j => { setIntegrations(j || {}); }).catch(() => {})
      .finally(() => setLoadingInteg(false));
  }, []);

  const updateCred = (tool, key, val) => setCreds(prev => ({ ...prev, [tool]: { ...(prev[tool] || {}), [key]: val } }));

  const saveTool = async (tool) => {
    setSaving(s => ({ ...s, [tool]: true }));
    try {
      const r = await fetch(`${API}/api/integrations/${tool}`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ credentials: creds[tool] || {} }),
      });
      const j = await r.json().catch(() => ({}));
      setTestResults(prev => ({ ...prev, [tool]: { ok: r.ok, msg: r.ok ? "Saved successfully" : (j.error || "Save failed") } }));
      if (r.ok) setTimeout(() => setTestResults(prev => ({ ...prev, [tool]: null })), 3000);
    } catch { setTestResults(prev => ({ ...prev, [tool]: { ok: false, msg: "Network error" } })); }
    setSaving(s => ({ ...s, [tool]: false }));
  };

  const testTool = async (tool) => {
    setTesting(t => ({ ...t, [tool]: true }));
    try {
      const r = await fetch(`${API}/api/integrations/${tool}/test`, { method: "POST", credentials: "include" });
      const j = await r.json().catch(() => ({}));
      setTestResults(prev => ({ ...prev, [tool]: { ok: r.ok, msg: r.ok ? (j.message || "Connection successful!") : (j.error || "Test failed") } }));
    } catch { setTestResults(prev => ({ ...prev, [tool]: { ok: false, msg: "Cannot connect" } })); }
    setTesting(t => ({ ...t, [tool]: false }));
  };

  const TOOLS = [
    { key: "upguard", name: "UpGuard", icon: "🌐", cat: "Attack Surface Management", fields: [{ k: "api_key", l: "API Key" }, { k: "api_secret", l: "API Secret" }] },
    { key: "qualys", name: "Qualys", icon: "🔍", cat: "Vulnerability Management", fields: [{ k: "username", l: "Username" }, { k: "password", l: "Password" }, { k: "platform_url", l: "Platform URL", type: "text" }] },
    { key: "fortinet", name: "Fortinet", icon: "🔥", cat: "Network Security", fields: [{ k: "host", l: "Hostname/IP", type: "text" }, { k: "username", l: "Username", type: "text" }, { k: "password", l: "Password" }, { k: "api_key", l: "API Key" }] },
    { key: "paloalto", name: "Palo Alto", icon: "🔴", cat: "Network Security", fields: [{ k: "host", l: "Hostname/IP", type: "text" }, { k: "username", l: "Username", type: "text" }, { k: "password", l: "Password" }, { k: "api_key", l: "API Key" }] },
    { key: "manageengine", name: "ManageEngine", icon: "📦", cat: "Asset Management", fields: [{ k: "server_url", l: "Server URL", type: "text" }, { k: "api_key", l: "API Key" }, { k: "client_id", l: "Client ID", type: "text" }, { k: "client_secret", l: "Client Secret" }] },
    { key: "azure", name: "Azure", icon: "☁️", cat: "Cloud Security", fields: [{ k: "tenant_id", l: "Tenant ID", type: "text" }, { k: "client_id", l: "Client ID", type: "text" }, { k: "client_secret", l: "Client Secret" }, { k: "subscription_id", l: "Subscription ID", type: "text" }] },
  ];

  const statusColor = (s) => s === "connected" ? C.ok : s === "error" ? C.critical : s === "collecting" ? C.warn : C.textSm;
  const statusLabel = (s) => s === "connected" ? "🟢 Connected" : s === "error" ? "🔴 Error" : s === "collecting" ? "🟡 Collecting" : "⚫ Unconfigured";

  if (loadingInteg) return <div style={{ display: "flex", justifyContent: "center", marginTop: 80 }}><Spinner size={40} /></div>;

  return (
    <div style={{ animation: "fadeIn 0.4s ease" }}>
      <SectionHeader title="Integration Settings" sub="Configure credentials for connected security tools" />
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(360px, 1fr))", gap: 20 }}>
        {TOOLS.map(tool => {
          const status = integrations[tool.key]?.status || "unconfigured";
          const result = testResults[tool.key];
          return (
            <div key={tool.key} style={{ ...cardStyle, display: "flex", flexDirection: "column", gap: 16 }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <div style={{ fontSize: 26 }}>{tool.icon}</div>
                  <div>
                    <div style={{ fontSize: 15, fontWeight: 700, color: C.text }}>{tool.name}</div>
                    <div style={{ fontSize: 11, color: C.textSm }}>{tool.cat}</div>
                  </div>
                </div>
                <span style={{ fontSize: 12, fontWeight: 500, color: statusColor(status) }}>{statusLabel(status)}</span>
              </div>

              <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                {tool.fields.map(f => (
                  <div key={f.k}>
                    <label style={{ display: "block", fontSize: 11, fontWeight: 600, color: C.textSm, marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.05em" }}>{f.l}</label>
                    <input
                      type={f.type || "password"}
                      value={(creds[tool.key] || {})[f.k] || ""}
                      onChange={e => updateCred(tool.key, f.k, e.target.value)}
                      placeholder={f.type === "text" ? `Enter ${f.l}` : "••••••••"}
                      style={{ width: "100%", background: C.bgMuted, border: `1px solid ${C.border}`, borderRadius: 7, padding: "9px 12px", fontSize: 13, color: C.text, transition: "border 0.2s" }}
                      onFocus={e => e.target.style.border = `1px solid ${C.borderAct}`}
                      onBlur={e => e.target.style.border = `1px solid ${C.border}`}
                    />
                  </div>
                ))}
              </div>

              {result && (
                <div style={{ background: result.ok ? "rgba(16,185,129,0.1)" : "rgba(239,68,68,0.1)", border: `1px solid ${result.ok ? "rgba(16,185,129,0.3)" : "rgba(239,68,68,0.3)"}`, borderRadius: 7, padding: "8px 12px", fontSize: 12, color: result.ok ? C.ok : C.critical }}>
                  {result.ok ? "✅" : "❌"} {result.msg}
                </div>
              )}

              <div style={{ display: "flex", gap: 8, marginTop: 4 }}>
                <button onClick={() => saveTool(tool.key)} disabled={saving[tool.key]}
                  style={{ flex: 1, background: saving[tool.key] ? "rgba(30,64,175,0.3)" : `linear-gradient(135deg, ${C.primary}, #2563eb)`, border: "none", borderRadius: 8, padding: "9px", fontSize: 13, fontWeight: 600, color: "#fff", display: "flex", alignItems: "center", justifyContent: "center", gap: 6, transition: "all 0.2s" }}>
                  {saving[tool.key] && <Spinner size={12} color="#fff" />}
                  {saving[tool.key] ? "Saving..." : "Save"}
                </button>
                <button onClick={() => testTool(tool.key)} disabled={testing[tool.key]}
                  style={{ flex: 1, background: "none", border: `1px solid ${C.borderAct}`, borderRadius: 8, padding: "9px", fontSize: 13, fontWeight: 600, color: C.accent, display: "flex", alignItems: "center", justifyContent: "center", gap: 6, transition: "all 0.2s" }}>
                  {testing[tool.key] && <Spinner size={12} />}
                  {testing[tool.key] ? "Testing..." : "Test Connection"}
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─── App Root ─────────────────────────────────────────────────────────────────

export default function App() {
  const [session, setSession] = useState(null);
  const [page, setPage] = useState("dashboard");
  const [data, setData] = useState({});
  const [loading, setLoading] = useState(true);
  const [sidebarOpen, setSidebarOpen] = useState(true);

  useEffect(() => {
    const style = document.createElement("style");
    style.textContent = GLOBAL_STYLES;
    document.head.appendChild(style);
    return () => document.head.removeChild(style);
  }, []);

  const loadAll = useCallback(async () => {
    try {
      const meRes = await fetch(`${API}/api/auth/me`, { credentials: "include" });
      if (!meRes.ok) { setSession(null); setLoading(false); return; }
      const me = await meRes.json();
      if (!me?.username) { setSession(null); setLoading(false); return; }
      setSession(me);
      const snapRes = await fetch(`${API}/api/snapshot`, { credentials: "include" });
      if (snapRes.ok) {
        const raw = await snapRes.json();
        setData(transformSnapshot(raw.data || raw));
      }
    } catch {}
    setLoading(false);
  }, []);

  useEffect(() => {
    loadAll();
    const t = setInterval(loadAll, 5 * 60 * 1000);
    return () => clearInterval(t);
  }, [loadAll]);

  if (loading) return <LoadingScreen />;
  if (!session) return <LoginPage onLogin={(u) => { setSession(u); loadAll(); }} />;

  const pageProps = { data, onRefresh: loadAll };

  if (session.role === "executive") {
    return (
      <Layout page="dashboard" setPage={() => {}} session={session} sidebarOpen={sidebarOpen} setSidebarOpen={setSidebarOpen}>
        <ExecDashboard {...pageProps} />
      </Layout>
    );
  }

  return (
    <Layout page={page} setPage={setPage} session={session} sidebarOpen={sidebarOpen} setSidebarOpen={setSidebarOpen}>
      {page === "dashboard"  && <ExecDashboard {...pageProps} />}
      {page === "surface"    && <ThreatSurfacePage {...pageProps} />}
      {page === "vulns"      && <VulnerabilityPage {...pageProps} />}
      {page === "firewall"   && <FirewallPage {...pageProps} />}
      {page === "assets"     && <AssetPage {...pageProps} />}
      {page === "cloud"      && <CloudPage {...pageProps} />}
      {page === "settings"   && <SettingsPage />}
    </Layout>
  );
}
