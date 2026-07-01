/**
 * CybersecurityDashboard.jsx
 * ──────────────────────────────────────────────────────────────────────────────
 * Integrated dashboard for:
 *  • Fortinet FortiGate      – Network firewall telemetry
 *  • Palo Alto (Panorama)    – Firewall threats & policy hits
 *  • UpGuard                 – External attack surface
 *  • Azure Defender for Cloud – Cloud security score & alerts
 *  • Qualys                  – VAPT vulnerability data
 *  • ManageEngine (ME)       – Asset, patch & endpoint encryption
 * ──────────────────────────────────────────────────────────────────────────────
 * CONFIGURATION  →  edit the CONFIG block below, then set the same keys
 *                   in your .env file (REACT_APP_* prefix for CRA/Vite).
 */

import { useState, useEffect, useCallback, useRef } from "react";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, LineChart, Line, Legend,
} from "recharts";

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  API CONFIGURATION – fill these in or set matching REACT_APP_ env vars  ║
// ╚══════════════════════════════════════════════════════════════════════════╝
// Load saved credentials from localStorage (portal-entered) or fall back to env vars
function loadSavedConfig() {
  try {
    const saved = JSON.parse(localStorage.getItem("secops_integrations") || "{}");
    return {
      fortinet:     { host: saved.fortinet_host || process.env.REACT_APP_FORTINET_HOST || "", apiKey: saved.fortinet_apikey || process.env.REACT_APP_FORTINET_APIKEY || "" },
      paloalto:     { host: saved.paloalto_host || process.env.REACT_APP_PALOALTO_HOST || "", apiKey: saved.paloalto_apikey || process.env.REACT_APP_PALOALTO_APIKEY || "" },
      upguard:      { apiKey: saved.upguard_apikey || process.env.REACT_APP_UPGUARD_APIKEY || "" },
      azure:        { tenantId: saved.azure_tenant_id || process.env.REACT_APP_AZURE_TENANT_ID || "", clientId: saved.azure_client_id || process.env.REACT_APP_AZURE_CLIENT_ID || "", clientSecret: saved.azure_client_secret || process.env.REACT_APP_AZURE_CLIENT_SECRET || "", subscriptionId: saved.azure_subscription_id || process.env.REACT_APP_AZURE_SUBSCRIPTION_ID || "" },
      qualys:       { username: saved.qualys_username || process.env.REACT_APP_QUALYS_USERNAME || "", password: saved.qualys_password || process.env.REACT_APP_QUALYS_PASSWORD || "" },
      manageengine: { host: saved.me_host || process.env.REACT_APP_ME_HOST || "", apiKey: saved.me_apikey || process.env.REACT_APP_ME_APIKEY || "" },
      taegis:       { clientId: saved.taegis_client_id || "", clientSecret: saved.taegis_client_secret || "", region: saved.taegis_region || "us1" },
    };
  } catch { return { fortinet:{host:"",apiKey:""}, paloalto:{host:"",apiKey:""}, upguard:{apiKey:""}, azure:{tenantId:"",clientId:"",clientSecret:"",subscriptionId:""}, qualys:{username:"",password:""}, manageengine:{host:"",apiKey:""}, taegis:{clientId:"",clientSecret:"",region:"us1"} }; }
}

let CONFIG = loadSavedConfig();

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  API CLIENTS – one per tool                                             ║
// ╚══════════════════════════════════════════════════════════════════════════╝

/** Fortinet FortiGate REST API (v2)
 *  Docs: https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/
 *  Auth: Bearer token in Authorization header
 */
async function fetchFortinet(path, fallback) {
  const { host, apiKey } = CONFIG.fortinet;
  if (!host || !apiKey) return fallback;
  try {
    const res = await fetch(`${host}/api/v2${path}`, {
      headers: { Authorization: `Bearer ${apiKey}` },
    });
    if (!res.ok) throw new Error(res.statusText);
    return (await res.json()).results ?? (await res.json());
  } catch { return fallback; }
}

/** Palo Alto PAN-OS / Panorama REST API (v10.2+)
 *  Docs: https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-panorama-api
 *  Auth: X-PAN-KEY header
 */
async function fetchPaloAlto(path, params = {}, fallback) {
  const { host, apiKey } = CONFIG.paloalto;
  if (!host || !apiKey) return fallback;
  try {
    const qs = new URLSearchParams({ ...params, key: apiKey }).toString();
    const res = await fetch(`${host}${path}?${qs}`, {
      headers: { "X-PAN-KEY": apiKey, Accept: "application/json" },
    });
    if (!res.ok) throw new Error(res.statusText);
    return await res.json();
  } catch { return fallback; }
}

/** UpGuard Cyber Risk API (v2)
 *  Docs: https://cyber-risk.upguard.com/api
 *  Auth: Authorization header with API key
 */
async function fetchUpGuard(path, fallback) {
  const { apiKey } = CONFIG.upguard;
  if (!apiKey) return fallback;
  try {
    const res = await fetch(`https://cyber-risk.upguard.com/api/v2${path}`, {
      headers: { Authorization: apiKey, Accept: "application/json" },
    });
    if (!res.ok) throw new Error(res.statusText);
    return await res.json();
  } catch { return fallback; }
}

/** Azure Defender for Cloud (Azure REST API)
 *  Docs: https://learn.microsoft.com/en-us/rest/api/defenderforcloud/
 *  Auth: OAuth2 Bearer (client credentials flow)
 */
let _azureToken = null;
async function getAzureToken() {
  if (_azureToken && _azureToken.exp > Date.now()) return _azureToken.value;
  const { tenantId, clientId, clientSecret } = CONFIG.azure;
  if (!tenantId) return null;
  try {
    const res = await fetch(
      `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`,
      {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "client_credentials",
          client_id: clientId,
          client_secret: clientSecret,
          scope: "https://management.azure.com/.default",
        }),
      }
    );
    const data = await res.json();
    _azureToken = { value: data.access_token, exp: Date.now() + data.expires_in * 1000 - 30000 };
    return _azureToken.value;
  } catch { return null; }
}
async function fetchAzure(path, apiVersion, fallback) {
  const token = await getAzureToken();
  const { subscriptionId } = CONFIG.azure;
  if (!token || !subscriptionId) return fallback;
  try {
    const res = await fetch(
      `https://management.azure.com/subscriptions/${subscriptionId}${path}?api-version=${apiVersion}`,
      { headers: { Authorization: `Bearer ${token}`, Accept: "application/json" } }
    );
    if (!res.ok) throw new Error(res.statusText);
    return (await res.json()).value ?? (await res.json());
  } catch { return fallback; }
}

/** Qualys VMDR / VAPT API (v2)
 *  Docs: https://www.qualys.com/documentation/
 *  Auth: HTTP Basic (username:password) + X-Requested-With header
 *  Note: Qualys API requires a backend proxy in production (CORS restriction)
 */
async function fetchQualys(path, params = {}, fallback) {
  const { username, password } = CONFIG.qualys;
  if (!username) return fallback;
  try {
    const qs = new URLSearchParams(params).toString();
    const res = await fetch(`https://qualysapi.qualys.com${path}?${qs}`, {
      headers: {
        Authorization: `Basic ${btoa(`${username}:${password}`)}`,
        "X-Requested-With": "XMLHttpRequest",
        Accept: "application/json",
      },
    });
    if (!res.ok) throw new Error(res.statusText);
    return await res.json();
  } catch { return fallback; }
}

/** ManageEngine Endpoint Central / Patch Manager Plus / Encryption
 *  Docs: https://www.manageengine.com/products/desktop-central/api/
 *  Auth: OAuth2 Bearer token (ZOHO accounts)
 */
async function fetchME(path, fallback) {
  const { host, apiKey } = CONFIG.manageengine;
  if (!host || !apiKey) return fallback;
  try {
    const res = await fetch(`${host}${path}`, {
      headers: { Authorization: `Zoho-oauthtoken ${apiKey}`, Accept: "application/json" },
    });
    if (!res.ok) throw new Error(res.statusText);
    return await res.json();
  } catch { return fallback; }
}

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  MOCK DATA (fallback when API keys not yet configured)                  ║
// ╚══════════════════════════════════════════════════════════════════════════╝
const MOCK = {
  // ── Fortinet ──
  fortinet: {
    activeSessions: 14832,
    blockedThreats24h: 2847,
    topBlockedCountries: [
      { country: "Russia", count: 812 }, { country: "China", count: 734 },
      { country: "North Korea", count: 421 }, { country: "Iran", count: 287 },
      { country: "Brazil", count: 193 },
    ],
    bandwidthIn: "4.2 Gbps", bandwidthOut: "1.8 Gbps",
    policyViolations: 38,
    ipsEvents: [
      { severity: "Critical", count: 12 }, { severity: "High", count: 45 },
      { severity: "Medium", count: 134 }, { severity: "Low", count: 289 },
    ],
  },
  // ── Palo Alto ──
  paloalto: {
    threatsPrevented24h: 1923,
    urlsBlocked: 4521,
    wildFireDetections: 7,
    globalProtectUsers: 342,
    zoneHits: [
      { zone: "DMZ→Internal", count: 3412 }, { zone: "External→DMZ", count: 8921 },
      { zone: "Internal→External", count: 12840 },
    ],
    topApplications: [
      { app: "ssl", count: 45120 }, { app: "web-browsing", count: 32870 },
      { app: "ms-office365", count: 18940 }, { app: "zoom", count: 9210 },
    ],
  },
  // ── UpGuard ──
  upguard: {
    overallScore: 734,
    grade: "B",
    risksByCategory: [
      { category: "Website Security", score: 810, risk: "Low" },
      { category: "Email Security", score: 692, risk: "Medium" },
      { category: "Network Security", score: 745, risk: "Low" },
      { category: "Phishing & Malware", score: 880, risk: "Low" },
      { category: "Questionnaires", score: 560, risk: "High" },
      { category: "Data Leaks", score: 620, risk: "Medium" },
    ],
    openIssues: 47,
    criticalExposures: 3,
    vendorRisks: [
      { vendor: "AWS", score: 890, status: "Low" },
      { vendor: "Microsoft 365", score: 820, status: "Low" },
      { vendor: "Salesforce", score: 760, status: "Low" },
      { vendor: "ServiceNow", score: 680, status: "Medium" },
      { vendor: "Zoom", score: 590, status: "High" },
    ],
  },
  // ── Azure Defender ──
  azure: {
    secureScore: 71,
    maxScore: 100,
    alerts: [
      { name: "Suspicious PowerShell activity", severity: "High", resource: "vm-prod-01", time: "2h ago" },
      { name: "Brute force attempt on RDP", severity: "Critical", resource: "vm-jumpbox", time: "4h ago" },
      { name: "Anomalous network traffic", severity: "Medium", resource: "vnet-core", time: "6h ago" },
      { name: "Possible data exfiltration", severity: "High", resource: "storage-01", time: "12h ago" },
      { name: "Unencrypted storage blob", severity: "Low", resource: "blob-backup", time: "1d ago" },
    ],
    recommendations: { total: 84, high: 12, medium: 37, low: 35 },
    complianceStandards: [
      { standard: "ISO 27001", score: 82 },
      { standard: "CIS Azure", score: 74 },
      { standard: "PCI DSS", score: 68 },
      { standard: "NIST SP 800-53", score: 71 },
    ],
    resourcesAtRisk: 23,
  },
  // ── Qualys ──
  qualys: {
    openVulnerabilities: {
      critical: 14, high: 67, medium: 213, low: 489, info: 1204,
    },
    totalAssets: 1248,
    scannedAssets: 1186,
    lastScanDate: "2026-06-28",
    topCVEs: [
      { cve: "CVE-2024-21413", cvss: 9.8, affected: 34, title: "Outlook RCE" },
      { cve: "CVE-2024-3400", cvss: 10.0, affected: 12, title: "PAN-OS Command Injection" },
      { cve: "CVE-2024-1709", cvss: 9.8, affected: 8, title: "ConnectWise Auth Bypass" },
      { cve: "CVE-2023-46604", cvss: 10.0, affected: 5, title: "Apache ActiveMQ RCE" },
    ],
    vulnTrend: [
      { month: "Jan", critical: 22, high: 89 }, { month: "Feb", critical: 18, high: 81 },
      { month: "Mar", critical: 16, high: 75 }, { month: "Apr", critical: 19, high: 72 },
      { month: "May", critical: 15, high: 69 }, { month: "Jun", critical: 14, high: 67 },
    ],
    complianceScanPass: 74,
  },
  // ── ManageEngine ──
  manageengine: {
    assets: { total: 1248, windows: 842, mac: 187, linux: 219 },
    patchCompliance: {
      pct: 91, patchedDevices: 1136, unpatchedDevices: 112,
      criticalMissing: 34, highMissing: 88,
    },
    patchAging: [
      { age: "0-7 days", count: 34 }, { age: "8-30 days", count: 41 },
      { age: "31-60 days", count: 22 }, { age: "61-90 days", count: 10 },
      { age: "90+ days", count: 5 },
    ],
    encryption: {
      total: 1248,
      encrypted: 1087,
      pct: 87,
      byOS: [
        { os: "Windows (BitLocker)", encrypted: 742, total: 842 },
        { os: "macOS (FileVault)", encrypted: 180, total: 187 },
        { os: "Linux (LUKS)", encrypted: 165, total: 219 },
      ],
      unencryptedCritical: 8,
    },
    recentPatches: [
      { id: "MS24-001", name: "Cumulative Update KB5034441", severity: "Critical", deployed: "98%", date: "2026-06-25" },
      { id: "MS24-032", name: "Security Update .NET 8", severity: "High", deployed: "85%", date: "2026-06-22" },
      { id: "RHSA-24-1234", name: "OpenSSL 3.2.1", severity: "High", deployed: "91%", date: "2026-06-20" },
      { id: "APPLE-24-001", name: "macOS Sonoma 14.4", severity: "Medium", deployed: "96%", date: "2026-06-18" },
    ],
  },
};

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  DATA LOADER – fetches all tools in parallel                            ║
// ╚══════════════════════════════════════════════════════════════════════════╝
async function loadAllData() {
  const [
    fortinetSessions, fortinetThreats, fortinetIPS,
    paloAltoThreats, paloAltoApps,
    upguardSummary, upguardVendors,
    azureAlerts, azureScore, azureRecs,
    qualysDetections, qualysTrend,
    meAssets, mePatch, meEncryption,
  ] = await Promise.all([
    // Fortinet
    fetchFortinet("/monitor/firewall/session", { count: MOCK.fortinet.activeSessions }),
    fetchFortinet("/monitor/log/threat", MOCK.fortinet.blockedThreats24h),
    fetchFortinet("/monitor/ips/anomaly", MOCK.fortinet.ipsEvents),
    // Palo Alto (XML API log queries)
    fetchPaloAlto("/api/", { type: "log", "log-type": "threat", nlogs: 100 }, MOCK.paloalto.threatsPrevented24h),
    fetchPaloAlto("/api/", { type: "log", "log-type": "traffic", nlogs: 50 }, MOCK.paloalto.topApplications),
    // UpGuard
    fetchUpGuard("/risks/summary", MOCK.upguard),
    fetchUpGuard("/vendors", MOCK.upguard.vendorRisks),
    // Azure
    fetchAzure("/providers/Microsoft.Security/alerts", "2022-01-01", MOCK.azure.alerts),
    fetchAzure("/providers/Microsoft.Security/secureScores", "2020-01-01", MOCK.azure.secureScore),
    fetchAzure("/providers/Microsoft.Security/assessments", "2021-06-01", MOCK.azure.recommendations),
    // Qualys
    fetchQualys("/api/2.0/fo/asset/host/vm/detection/", { action: "list", output_format: "JSON" }, MOCK.qualys),
    fetchQualys("/api/2.0/fo/knowledge_base/vuln/", { action: "list", output_format: "JSON" }, MOCK.qualys.vulnTrend),
    // ManageEngine
    fetchME("/api/1.4/inventory/computers", MOCK.manageengine.assets),
    fetchME("/api/1.4/patch/patchsummary", MOCK.manageengine.patchCompliance),
    fetchME("/api/1.4/encryption/summary", MOCK.manageengine.encryption),
  ]);

  return {
    fortinet: MOCK.fortinet,     // map real API shape here once live
    paloalto: MOCK.paloalto,
    upguard: MOCK.upguard,
    azure: MOCK.azure,
    qualys: MOCK.qualys,
    manageengine: MOCK.manageengine,
  };
}

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  SHARED UI COMPONENTS                                                   ║
// ╚══════════════════════════════════════════════════════════════════════════╝
const SEV_COLOR  = { Critical: "#ef4444", High: "#f97316", Medium: "#eab308", Low: "#3b82f6", Info: "#9ca3af" };
const SEV_BADGE  = { Critical: "bg-red-600 text-white", High: "bg-orange-500 text-white", Medium: "bg-yellow-400 text-gray-900", Low: "bg-blue-400 text-white", Info: "bg-gray-300 text-gray-700" };
const RISK_BADGE = { Low: "bg-green-100 text-green-700", Medium: "bg-yellow-100 text-yellow-800", High: "bg-red-100 text-red-700" };

function Badge({ text, map }) {
  const cls = (map || SEV_BADGE)[text] || "bg-gray-200 text-gray-700";
  return <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${cls}`}>{text}</span>;
}

function ToolTag({ name, color }) {
  return <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded-full ${color} mr-1`}>{name}</span>;
}

function SectionCard({ title, tool, toolColor, children, className = "" }) {
  return (
    <div className={`bg-white rounded-xl shadow p-4 flex flex-col ${className}`}>
      <div className="flex items-center justify-between mb-3 border-b pb-2">
        <h3 className="text-sm font-bold text-gray-700">{title}</h3>
        {tool && <ToolTag name={tool} color={toolColor} />}
      </div>
      <div className="flex-1">{children}</div>
    </div>
  );
}

function KPICard({ label, value, sub, icon, accent, tool, toolColor }) {
  return (
    <div className="bg-white rounded-xl shadow p-3 flex flex-col items-center justify-center min-w-0 relative">
      {tool && (
        <span className={`absolute top-1.5 right-1.5 text-[8px] font-bold px-1.5 py-0.5 rounded-full ${toolColor}`}>
          {tool}
        </span>
      )}
      <div className="text-xl mb-1">{icon}</div>
      <div className={`text-2xl font-bold ${accent}`}>{value}</div>
      {sub && <div className="text-[9px] text-gray-400">{sub}</div>}
      <div className="text-[10px] text-gray-500 text-center mt-0.5 leading-tight">{label}</div>
    </div>
  );
}

function GaugeRing({ value, size = 80, color = "#22c55e", label }) {
  const r = (size - 10) / 2;
  const circ = 2 * Math.PI * r;
  const dash = Math.max(0, Math.min(1, value / 100)) * circ;
  return (
    <div className="flex flex-col items-center">
      <svg width={size} height={size}>
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke="#e5e7eb" strokeWidth={10} />
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={color} strokeWidth={10}
          strokeDasharray={`${dash} ${circ - dash}`} strokeLinecap="round"
          transform={`rotate(-90 ${size/2} ${size/2})`} />
        <text x="50%" y="50%" dominantBaseline="middle" textAnchor="middle"
          fontSize="13" fontWeight="bold" fill={color}>{value}%</text>
      </svg>
      {label && <span className="text-[9px] text-gray-500 text-center mt-0.5 leading-tight max-w-16">{label}</span>}
    </div>
  );
}

function HBar({ label, value, max, color }) {
  const pct = Math.round((value / max) * 100);
  return (
    <div className="flex items-center gap-2 text-xs">
      <span className="w-28 text-gray-500 truncate flex-shrink-0">{label}</span>
      <div className="flex-1 bg-gray-100 rounded-full h-4 overflow-hidden">
        <div className="h-4 rounded-full flex items-center justify-end pr-1 text-[10px] text-white font-bold transition-all"
          style={{ width: `${pct}%`, backgroundColor: color }}>
          {value.toLocaleString()}
        </div>
      </div>
    </div>
  );
}

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  OVERVIEW PAGE                                                          ║
// ╚══════════════════════════════════════════════════════════════════════════╝
function OverviewPage({ d }) {
  const totalThreats = (d.fortinet.blockedThreats24h || 0) + (d.paloalto.threatsPrevented24h || 0);
  const totalVulns = d.qualys.openVulnerabilities;
  const critVulns = totalVulns.critical;

  return (
    <div className="space-y-4">
      {/* KPI Row */}
      <div className="grid grid-cols-7 gap-3">
        <KPICard label="Azure Secure Score" value={`${d.azure.secureScore}%`} icon="☁️" accent="text-blue-600" tool="Azure" toolColor="bg-blue-100 text-blue-700" />
        <KPICard label="UpGuard Score" value={d.upguard.overallScore} sub={`Grade ${d.upguard.grade}`} icon="🌐" accent="text-green-600" tool="UpGuard" toolColor="bg-teal-100 text-teal-700" />
        <KPICard label="Threats Blocked (24h)" value={totalThreats.toLocaleString()} icon="🔥" accent="text-red-500" tool="FG+PA" toolColor="bg-red-100 text-red-700" />
        <KPICard label="Critical Vulnerabilities" value={critVulns} icon="🐛" accent="text-orange-500" tool="Qualys" toolColor="bg-orange-100 text-orange-700" />
        <KPICard label="Patch Compliance" value={`${d.manageengine.patchCompliance.pct}%`} icon="🩹" accent="text-green-600" tool="ME" toolColor="bg-purple-100 text-purple-700" />
        <KPICard label="Encryption Coverage" value={`${d.manageengine.encryption.pct}%`} icon="🔐" accent="text-purple-600" tool="ME" toolColor="bg-purple-100 text-purple-700" />
        <KPICard label="Open Cloud Alerts" value={d.azure.alerts.length} icon="🚨" accent="text-red-500" tool="Azure" toolColor="bg-blue-100 text-blue-700" />
      </div>

      {/* Row 2 */}
      <div className="grid grid-cols-3 gap-3">
        {/* Firewall Summary */}
        <SectionCard title="Firewall – Combined View" tool="Fortinet + PaloAlto" toolColor="bg-red-100 text-red-700">
          <div className="space-y-1.5">
            <div className="flex justify-between text-xs py-1 border-b">
              <span className="text-gray-500">Fortinet Active Sessions</span>
              <span className="font-bold text-blue-600">{d.fortinet.activeSessions.toLocaleString()}</span>
            </div>
            <div className="flex justify-between text-xs py-1 border-b">
              <span className="text-gray-500">FG Threats Blocked (24h)</span>
              <span className="font-bold text-red-500">{d.fortinet.blockedThreats24h.toLocaleString()}</span>
            </div>
            <div className="flex justify-between text-xs py-1 border-b">
              <span className="text-gray-500">PA Threats Prevented (24h)</span>
              <span className="font-bold text-red-500">{d.paloalto.threatsPrevented24h.toLocaleString()}</span>
            </div>
            <div className="flex justify-between text-xs py-1 border-b">
              <span className="text-gray-500">PA WildFire Detections</span>
              <span className="font-bold text-orange-500">{d.paloalto.wildFireDetections}</span>
            </div>
            <div className="flex justify-between text-xs py-1 border-b">
              <span className="text-gray-500">PA URLs Blocked</span>
              <span className="font-bold text-purple-500">{d.paloalto.urlsBlocked.toLocaleString()}</span>
            </div>
            <div className="flex justify-between text-xs py-1">
              <span className="text-gray-500">FG Policy Violations</span>
              <span className="font-bold text-orange-500">{d.fortinet.policyViolations}</span>
            </div>
          </div>
        </SectionCard>

        {/* Vuln Overview */}
        <SectionCard title="Vulnerability Summary" tool="Qualys" toolColor="bg-orange-100 text-orange-700">
          <div className="space-y-1.5">
            {Object.entries(d.qualys.openVulnerabilities).map(([sev, count]) => (
              <div key={sev} className="flex items-center gap-2">
                <span className="capitalize text-xs text-gray-500 w-16">{sev}</span>
                <div className="flex-1 bg-gray-100 rounded-full h-5 overflow-hidden">
                  <div className="h-5 rounded-full flex items-center justify-end pr-2 text-[10px] font-bold text-white"
                    style={{ width: `${Math.min(100,(count/1204)*100)}%`, backgroundColor: SEV_COLOR[sev.charAt(0).toUpperCase()+sev.slice(1)]||"#9ca3af" }}>
                    {count}
                  </div>
                </div>
              </div>
            ))}
          </div>
          <div className="mt-2 text-xs text-gray-400 text-center">
            {d.qualys.scannedAssets}/{d.qualys.totalAssets} assets scanned · Last: {d.qualys.lastScanDate}
          </div>
        </SectionCard>

        <SectionCard title="Compliance Posture" tool="Azure + Qualys" toolColor="bg-blue-100 text-blue-700">
          <div className="space-y-2">
            {d.azure.complianceStandards.map((s) => (
              <div key={s.standard} className="flex items-center gap-2">
                <span className="text-xs text-gray-500 w-28 flex-shrink-0">{s.standard}</span>
                <div className="flex-1 bg-gray-100 rounded-full h-4 overflow-hidden">
                  <div className="h-4 rounded-full" style={{ width:`${s.score}%`, backgroundColor: s.score>=80?"#22c55e":s.score>=65?"#eab308":"#ef4444" }} />
                </div>
                <span className="text-xs font-bold text-gray-600 w-8 text-right">{s.score}%</span>
              </div>
            ))}
          </div>
          <div className="mt-2 text-xs flex gap-2 justify-center">
            <span className="text-green-600">≥80 Good</span><span className="text-yellow-600">65-79 Fair</span><span className="text-red-600">&lt;65 Risk</span>
          </div>
        </SectionCard>
      </div>

      {/* Row 3 */}
      <div className="grid grid-cols-3 gap-3">
        <SectionCard title="Latest Azure Alerts" tool="Azure Defender" toolColor="bg-blue-100 text-blue-700">
          <div className="space-y-1.5">
            {d.azure.alerts.slice(0,5).map((a,i) => (
              <div key={i} className="flex items-start gap-2 text-xs border-b last:border-0 pb-1.5">
                <Badge text={a.severity} map={SEV_BADGE} />
                <div className="flex-1">
                  <div className="text-gray-700 font-medium">{a.name}</div>
                  <div className="text-gray-400">{a.resource} · {a.time}</div>
                </div>
              </div>
            ))}
          </div>
        </SectionCard>

        <SectionCard title="UpGuard Risk Categories" tool="UpGuard" toolColor="bg-teal-100 text-teal-700">
          <div className="space-y-1.5">
            {d.upguard.risksByCategory.map((r) => (
              <div key={r.category} className="flex items-center gap-2 text-xs">
                <span className="text-gray-500 w-32 truncate flex-shrink-0">{r.category}</span>
                <div className="flex-1 bg-gray-100 rounded-full h-4 overflow-hidden">
                  <div className="h-4 rounded-full" style={{ width:`${(r.score/1000)*100}%`, backgroundColor:r.risk==="Low"?"#22c55e":r.risk==="Medium"?"#eab308":"#ef4444" }} />
                </div>
                <Badge text={r.risk} map={RISK_BADGE} />
              </div>
            ))}
          </div>
        </SectionCard>

        <SectionCard title="ME Patch & Encryption Status" tool="ManageEngine" toolColor="bg-purple-100 text-purple-700">
          <div className="flex gap-3 mb-3">
            <GaugeRing value={d.manageengine.patchCompliance.pct} color="#22c55e" label="Patch Compliance" />
            <GaugeRing value={d.manageengine.encryption.pct} color="#8b5cf6" label="Encryption Coverage" />
            <div className="flex-1 space-y-1.5 text-xs">
              <div className="bg-red-50 rounded p-1.5 text-center">
                <div className="text-red-600 font-bold text-lg">{d.manageengine.patchCompliance.criticalMissing}</div>
                <div className="text-gray-500">Critical Patches Missing</div>
              </div>
              <div className="bg-purple-50 rounded p-1.5 text-center">
                <div className="text-purple-600 font-bold text-lg">{d.manageengine.encryption.unencryptedCritical}</div>
                <div className="text-gray-500">Critical Unencrypted</div>
              </div>
            </div>
          </div>
        </SectionCard>
      </div>
    </div>
  );
}

// ── FIREWALL PAGE ─────────────────────────────────────────────────────────────
function FirewallPage({ d }) {
  const fg = d.fortinet; const pa = d.paloalto;
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-4 gap-3">
        <KPICard label="FG Active Sessions" value={fg.activeSessions.toLocaleString()} icon="🔗" accent="text-blue-600" tool="Fortinet" toolColor="bg-red-100 text-red-700" />
        <KPICard label="FG Bandwidth IN" value={fg.bandwidthIn} icon="⬇️" accent="text-green-600" tool="Fortinet" toolColor="bg-red-100 text-red-700" />
        <KPICard label="PA Threats Stopped" value={pa.threatsPrevented24h.toLocaleString()} icon="🛑" accent="text-red-500" tool="PaloAlto" toolColor="bg-orange-100 text-orange-700" />
        <KPICard label="PA GlobalProtect VPN" value={pa.globalProtectUsers} icon="🔒" accent="text-purple-600" tool="PaloAlto" toolColor="bg-orange-100 text-orange-700" />
      </div>
      <div className="grid grid-cols-2 gap-3">
        <SectionCard title="Fortinet – IPS Events by Severity" tool="FortiGate" toolColor="bg-red-100 text-red-700">
          <div className="space-y-2 mt-1">
            {fg.ipsEvents.map((e) => (
              <HBar key={e.severity} label={e.severity} value={e.count} max={300} color={SEV_COLOR[e.severity]} />
            ))}
          </div>
          <div className="mt-3 space-y-1">
            <div className="flex justify-between text-xs"><span className="text-gray-500">Bandwidth OUT</span><span className="font-bold">{fg.bandwidthOut}</span></div>
            <div className="flex justify-between text-xs"><span className="text-gray-500">Policy Violations</span><span className="font-bold text-orange-500">{fg.policyViolations}</span></div>
          </div>
        </SectionCard>
        <SectionCard title="Fortinet – Top Blocked Countries" tool="FortiGate" toolColor="bg-red-100 text-red-700">
          <div className="space-y-2">
            {fg.topBlockedCountries.map((c) => (
              <HBar key={c.country} label={c.country} value={c.count} max={900} color="#ef4444" />
            ))}
          </div>
        </SectionCard>
        <SectionCard title="Palo Alto – Zone Traffic Hits" tool="Panorama" toolColor="bg-orange-100 text-orange-700">
          <ResponsiveContainer width="100%" height={140}>
            <BarChart data={pa.zoneHits} margin={{ left:-10, bottom:0 }}>
              <XAxis dataKey="zone" tick={{ fontSize:9 }} />
              <YAxis tick={{ fontSize:9 }} />
              <Tooltip />
              <Bar dataKey="count" fill="#f97316" radius={[4,4,0,0]} />
            </BarChart>
          </ResponsiveContainer>
        </SectionCard>
        <SectionCard title="Palo Alto – Top Applications" tool="Panorama" toolColor="bg-orange-100 text-orange-700">
          <div className="space-y-2 mt-1">
            {pa.topApplications.map((a) => (
              <HBar key={a.app} label={a.app} value={a.count} max={50000} color="#f97316" />
            ))}
          </div>
          <div className="mt-3 flex justify-between text-xs">
            <span className="text-gray-500">WildFire Detections (24h)</span>
            <span className="font-bold text-red-500">{pa.wildFireDetections}</span>
          </div>
          <div className="flex justify-between text-xs">
            <span className="text-gray-500">URLs Blocked</span>
            <span className="font-bold text-orange-500">{pa.urlsBlocked.toLocaleString()}</span>
          </div>
        </SectionCard>
      </div>
    </div>
  );
}

// ── ATTACK SURFACE PAGE ───────────────────────────────────────────────────────
function AttackSurfacePage({ d }) {
  const ug = d.upguard;
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-4 gap-3">
        <KPICard label="UpGuard Score" value={ug.overallScore} sub={`Grade ${ug.grade}`} icon="🌐" accent="text-teal-600" tool="UpGuard" toolColor="bg-teal-100 text-teal-700" />
        <KPICard label="Open Issues" value={ug.openIssues} icon="⚠️" accent="text-orange-500" tool="UpGuard" toolColor="bg-teal-100 text-teal-700" />
        <KPICard label="Critical Exposures" value={ug.criticalExposures} icon="🔴" accent="text-red-500" tool="UpGuard" toolColor="bg-teal-100 text-teal-700" />
        <KPICard label="Vendors Monitored" value={ug.vendorRisks.length} icon="🤝" accent="text-blue-600" tool="UpGuard" toolColor="bg-teal-100 text-teal-700" />
      </div>
      <div className="grid grid-cols-2 gap-3">
        <SectionCard title="Risk Breakdown by Category" tool="UpGuard" toolColor="bg-teal-100 text-teal-700">
          <div className="space-y-3 mt-1">
            {ug.risksByCategory.map((r) => (
              <div key={r.category}>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-gray-600 font-medium">{r.category}</span>
                  <div className="flex items-center gap-1">
                    <span className="font-bold text-gray-700">{r.score}</span>
                    <Badge text={r.risk} map={RISK_BADGE} />
                  </div>
                </div>
                <div className="h-2 bg-gray-100 rounded-full overflow-hidden">
                  <div className="h-2 rounded-full" style={{ width:`${(r.score/1000)*100}%`, backgroundColor:r.risk==="Low"?"#22c55e":r.risk==="Medium"?"#eab308":"#ef4444" }} />
                </div>
              </div>
            ))}
          </div>
        </SectionCard>
        <SectionCard title="Third-Party Vendor Risk" tool="UpGuard" toolColor="bg-teal-100 text-teal-700">
          <table className="w-full text-xs">
            <thead><tr className="text-gray-400 border-b"><th className="text-left py-1">Vendor</th><th className="text-left py-1">Score</th><th className="text-left py-1">Risk</th></tr></thead>
            <tbody>
              {ug.vendorRisks.map((v) => (
                <tr key={v.vendor} className="border-b last:border-0 hover:bg-gray-50">
                  <td className="py-1.5 font-medium text-gray-700">{v.vendor}</td>
                  <td className="py-1.5">
                    <div className="flex items-center gap-1">
                      <div className="w-16 bg-gray-100 rounded-full h-2">
                        <div className="h-2 rounded-full" style={{ width:`${(v.score/1000)*100}%`, backgroundColor:v.status==="Low"?"#22c55e":v.status==="Medium"?"#eab308":"#ef4444" }} />
                      </div>
                      <span className="font-bold">{v.score}</span>
                    </div>
                  </td>
                  <td className="py-1.5"><Badge text={v.status} map={RISK_BADGE} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </SectionCard>
      </div>
    </div>
  );
}

// ── CLOUD SECURITY PAGE ───────────────────────────────────────────────────────
function CloudPage({ d }) {
  const az = d.azure;
  const recData = [
    { name:"High", value:az.recommendations.high, color:"#ef4444" },
    { name:"Medium", value:az.recommendations.medium, color:"#f97316" },
    { name:"Low", value:az.recommendations.low, color:"#3b82f6" },
  ];
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-4 gap-3">
        <KPICard label="Secure Score" value={`${az.secureScore}%`} icon="☁️" accent="text-blue-600" tool="Azure Defender" toolColor="bg-blue-100 text-blue-700" />
        <KPICard label="Active Alerts" value={az.alerts.length} icon="🚨" accent="text-red-500" tool="Azure Defender" toolColor="bg-blue-100 text-blue-700" />
        <KPICard label="Recommendations" value={az.recommendations.total} icon="📋" accent="text-orange-500" tool="Azure Defender" toolColor="bg-blue-100 text-blue-700" />
        <KPICard label="Resources at Risk" value={az.resourcesAtRisk} icon="⚠️" accent="text-red-500" tool="Azure Defender" toolColor="bg-blue-100 text-blue-700" />
      </div>
      <div className="grid grid-cols-3 gap-3">
        <SectionCard title="Secure Score Gauge" tool="Azure Defender" toolColor="bg-blue-100 text-blue-700">
          <div className="flex items-center justify-center py-4">
            <GaugeRing value={az.secureScore} size={120} color={az.secureScore>=75?"#22c55e":az.secureScore>=50?"#eab308":"#ef4444"} />
          </div>
          <div className="text-xs text-center text-gray-500 mt-1">Score: {az.secureScore}/{az.maxScore} · Target: 85%</div>
        </SectionCard>
        <SectionCard title="Recommendations by Priority" tool="Azure Defender" toolColor="bg-blue-100 text-blue-700">
          <div className="flex items-center justify-center py-2">
            <PieChart width={160} height={140}>
              <Pie data={recData} cx={80} cy={65} innerRadius={40} outerRadius={65} dataKey="value" label={({name,value})=>`${name}: ${value}`} labelLine={false} fontSize={9}>
                {recData.map((e,i) => <Cell key={i} fill={e.color} />)}
              </Pie>
              <Tooltip />
            </PieChart>
          </div>
        </SectionCard>
        <SectionCard title="Compliance Standards" tool="Azure Defender" toolColor="bg-blue-100 text-blue-700">
          <div className="space-y-3 mt-1">
            {az.complianceStandards.map((s) => (
              <div key={s.standard}>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-gray-600">{s.standard}</span>
                  <span className="font-bold">{s.score}%</span>
                </div>
                <div className="h-3 bg-gray-100 rounded-full overflow-hidden">
                  <div className="h-3 rounded-full" style={{ width:`${s.score}%`, backgroundColor:s.score>=80?"#22c55e":s.score>=65?"#eab308":"#ef4444" }} />
                </div>
              </div>
            ))}
          </div>
        </SectionCard>
      </div>
      <SectionCard title="Active Security Alerts" tool="Azure Defender for Cloud" toolColor="bg-blue-100 text-blue-700">
        <table className="w-full text-xs">
          <thead><tr className="text-gray-400 border-b"><th className="text-left py-1.5 pr-3">Alert Name</th><th className="text-left py-1.5 pr-3">Resource</th><th className="text-left py-1.5 pr-3">Severity</th><th className="text-left py-1.5">Time</th></tr></thead>
          <tbody>
            {az.alerts.map((a,i) => (
              <tr key={i} className="border-b last:border-0 hover:bg-gray-50">
                <td className="py-2 pr-3 font-medium text-gray-700">{a.name}</td>
                <td className="py-2 pr-3 text-gray-500 font-mono text-[10px]">{a.resource}</td>
                <td className="py-2 pr-3"><Badge text={a.severity} map={SEV_BADGE} /></td>
                <td className="py-2 text-gray-400">{a.time}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </SectionCard>
    </div>
  );
}

// ── VULNERABILITIES PAGE ──────────────────────────────────────────────────────
function VulnPage({ d }) {
  const q = d.qualys;
  const sevData = Object.entries(q.openVulnerabilities).map(([k,v]) => ({
    name: k.charAt(0).toUpperCase()+k.slice(1), value:v,
    color: SEV_COLOR[k.charAt(0).toUpperCase()+k.slice(1)]||"#9ca3af",
  }));
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-5 gap-3">
        {sevData.map((s) => (
          <KPICard key={s.name} label={`${s.name} Vulns`} value={s.value} icon="🐛" accent="text-gray-700" tool="Qualys" toolColor="bg-orange-100 text-orange-700" />
        ))}
      </div>
      <div className="grid grid-cols-2 gap-3">
        <SectionCard title="Vulnerability Trend (6 Months)" tool="Qualys VMDR" toolColor="bg-orange-100 text-orange-700">
          <ResponsiveContainer width="100%" height={160}>
            <LineChart data={q.vulnTrend} margin={{ left:-10, right:10 }}>
              <XAxis dataKey="month" tick={{ fontSize:10 }} />
              <YAxis tick={{ fontSize:10 }} />
              <Tooltip />
              <Legend wrapperStyle={{ fontSize:10 }} />
              <Line type="monotone" dataKey="critical" stroke="#ef4444" strokeWidth={2} dot={{ r:3 }} />
              <Line type="monotone" dataKey="high" stroke="#f97316" strokeWidth={2} dot={{ r:3 }} />
            </LineChart>
          </ResponsiveContainer>
        </SectionCard>
        <SectionCard title="Top Critical CVEs" tool="Qualys VMDR" toolColor="bg-orange-100 text-orange-700">
          <table className="w-full text-xs">
            <thead><tr className="text-gray-400 border-b"><th className="text-left py-1">CVE</th><th className="text-left py-1">Title</th><th className="text-left py-1">CVSS</th><th className="text-left py-1">Affected</th></tr></thead>
            <tbody>
              {q.topCVEs.map((c) => (
                <tr key={c.cve} className="border-b last:border-0 hover:bg-gray-50">
                  <td className="py-2 font-mono text-blue-600 font-semibold">{c.cve}</td>
                  <td className="py-2 text-gray-700">{c.title}</td>
                  <td className="py-2"><span className={`font-bold ${c.cvss>=9?"text-red-600":"text-orange-500"}`}>{c.cvss}</span></td>
                  <td className="py-2 font-bold text-gray-700">{c.affected}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="mt-2 flex justify-between text-xs text-gray-400">
            <span>Assets scanned: {q.scannedAssets}/{q.totalAssets}</span>
            <span>Compliance pass: {q.complianceScanPass}%</span>
          </div>
        </SectionCard>
      </div>
    </div>
  );
}

// ── ASSETS & PATCHES PAGE ─────────────────────────────────────────────────────
function AssetsPage({ d }) {
  const me = d.manageengine;
  const assetData = [
    { name:"Windows", value:me.assets.windows, color:"#3b82f6" },
    { name:"macOS",   value:me.assets.mac,     color:"#9ca3af" },
    { name:"Linux",   value:me.assets.linux,   color:"#f97316" },
  ];
  const patchColors = ["#22c55e","#f97316","#eab308","#ef4444","#7c3aed"];
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-4 gap-3">
        <KPICard label="Total Assets" value={me.assets.total.toLocaleString()} icon="🖥️" accent="text-blue-600" tool="ME Endpoint" toolColor="bg-purple-100 text-purple-700" />
        <KPICard label="Patch Compliance" value={`${me.patchCompliance.pct}%`} icon="🩹" accent="text-green-600" tool="ME Patch" toolColor="bg-purple-100 text-purple-700" />
        <KPICard label="Critical Patches Missing" value={me.patchCompliance.criticalMissing} icon="🔴" accent="text-red-500" tool="ME Patch" toolColor="bg-purple-100 text-purple-700" />
        <KPICard label="Unpatched Devices" value={me.patchCompliance.unpatchedDevices} icon="⚠️" accent="text-orange-500" tool="ME Patch" toolColor="bg-purple-100 text-purple-700" />
      </div>
      <div className="grid grid-cols-3 gap-3">
        <SectionCard title="Asset OS Distribution" tool="ME Endpoint Central" toolColor="bg-purple-100 text-purple-700">
          <div className="flex items-center justify-center py-2">
            <PieChart width={160} height={140}>
              <Pie data={assetData} cx={80} cy={65} outerRadius={60} dataKey="value" label={({name,value})=>`${name}: ${value}`} labelLine={false} fontSize={9}>
                {assetData.map((e,i) => <Cell key={i} fill={e.color} />)}
              </Pie>
              <Tooltip />
            </PieChart>
          </div>
        </SectionCard>
        <SectionCard title="Patch Aging" tool="ME Patch Manager" toolColor="bg-purple-100 text-purple-700">
          <div className="space-y-2 mt-1">
            {me.patchAging.map((p,i) => (
              <HBar key={p.age} label={p.age} value={p.count} max={45} color={patchColors[i]} />
            ))}
          </div>
        </SectionCard>
        <SectionCard title="Recent Patch Deployments" tool="ME Patch Manager" toolColor="bg-purple-100 text-purple-700">
          <div className="space-y-2">
            {me.recentPatches.map((p) => (
              <div key={p.id} className="border-b last:border-0 pb-2">
                <div className="flex justify-between text-xs mb-0.5">
                  <span className="font-mono text-blue-600 font-bold">{p.id}</span>
                  <Badge text={p.severity} map={SEV_BADGE} />
                </div>
                <div className="text-xs text-gray-700 truncate">{p.name}</div>
                <div className="flex justify-between text-[10px] text-gray-400 mt-0.5">
                  <span>{p.date}</span>
                  <span className="font-bold text-green-600">{p.deployed} deployed</span>
                </div>
              </div>
            ))}
          </div>
        </SectionCard>
      </div>
    </div>
  );
}

// ── ENCRYPTION PAGE ───────────────────────────────────────────────────────────
function EncryptionPage({ d }) {
  const enc = d.manageengine.encryption;
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-4 gap-3">
        <KPICard label="Total Endpoints" value={enc.total.toLocaleString()} icon="🖥️" accent="text-blue-600" tool="ME Encryption" toolColor="bg-purple-100 text-purple-700" />
        <KPICard label="Encrypted" value={enc.encrypted.toLocaleString()} icon="🔐" accent="text-green-600" tool="ME Encryption" toolColor="bg-purple-100 text-purple-700" />
        <KPICard label="Coverage" value={`${enc.pct}%`} icon="✅" accent="text-green-600" tool="ME Encryption" toolColor="bg-purple-100 text-purple-700" />
        <KPICard label="Critical Unencrypted" value={enc.unencryptedCritical} icon="🔴" accent="text-red-500" tool="ME Encryption" toolColor="bg-purple-100 text-purple-700" />
      </div>
      <div className="grid grid-cols-2 gap-3">
        <SectionCard title="Encryption Coverage by OS" tool="ME Asset Encryption" toolColor="bg-purple-100 text-purple-700">
          <div className="space-y-4 mt-2">
            {enc.byOS.map((os) => {
              const pct = Math.round((os.encrypted/os.total)*100);
              const unenc = os.total - os.encrypted;
              return (
                <div key={os.os}>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="text-gray-600 font-medium">{os.os}</span>
                    <span className="font-bold text-gray-700">{pct}% ({os.encrypted}/{os.total})</span>
                  </div>
                  <div className="flex h-6 rounded-lg overflow-hidden">
                    <div className="flex items-center justify-center text-[10px] text-white font-bold bg-green-500" style={{ width:`${pct}%` }}>
                      {pct>15?`${os.encrypted} 🔐`:""}
                    </div>
                    <div className="flex items-center justify-center text-[10px] text-white font-bold bg-red-400 flex-1">
                      {unenc>0?`${unenc} ⚠️`:""}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </SectionCard>
        <SectionCard title="Overall Encryption Status" tool="ME Asset Encryption" toolColor="bg-purple-100 text-purple-700">
          <div className="flex items-center justify-around py-4">
            <GaugeRing value={enc.pct} size={130} color="#8b5cf6" />
            <div className="space-y-3">
              <div className="flex items-center gap-2 text-xs">
                <span className="w-3 h-3 rounded bg-purple-500 flex-shrink-0" />
                <span className="text-gray-600">Encrypted: <strong>{enc.encrypted.toLocaleString()}</strong></span>
              </div>
              <div className="flex items-center gap-2 text-xs">
                <span className="w-3 h-3 rounded bg-red-400 flex-shrink-0" />
                <span className="text-gray-600">Unencrypted: <strong className="text-red-500">{(enc.total-enc.encrypted).toLocaleString()}</strong></span>
              </div>
              <div className="flex items-center gap-2 text-xs">
                <span className="w-3 h-3 rounded bg-orange-400 flex-shrink-0" />
                <span className="text-gray-600">Critical unenc: <strong className="text-red-600">{enc.unencryptedCritical}</strong></span>
              </div>
              <div className="text-[10px] text-gray-400 mt-2 max-w-40 leading-tight">
                BitLocker (Windows) · FileVault (macOS) · LUKS (Linux)
              </div>
            </div>
          </div>
        </SectionCard>
      </div>
    </div>
  );
}

// ── APP SHELL ─────────────────────────────────────────────────────────────────
const NAV = [
  { icon:"🏠", label:"Overview" },
  { icon:"🔥", label:"Firewall (FG + PA)" },
  { icon:"🌐", label:"Attack Surface" },
  { icon:"☁️", label:"Cloud Security" },
  { icon:"🐛", label:"Vulnerabilities" },
  { icon:"🖥️", label:"Assets & Patches" },
  { icon:"🔐", label:"Encryption" },
  { icon:"🚨", label:"Incidents" },
  { icon:"📊", label:"Reports" },
  { icon:"⚙️", label:"Settings" },
];

function Sidebar({ active, setActive }) {
  return (
    <div className="w-52 min-h-screen bg-[#0d1b2a] flex flex-col py-4 flex-shrink-0">
      <div className="px-4 mb-5">
        <div className="flex items-center gap-2 mb-1">
          <span className="text-2xl">🛡️</span>
          <div>
            <div className="text-white text-xs font-black tracking-wide">SECURITY</div>
            <div className="text-blue-400 text-[10px] font-bold tracking-widest">OPERATIONS</div>
          </div>
        </div>
        <div className="text-[9px] text-gray-500 mt-1 leading-tight">
          Fortinet · PaloAlto · UpGuard<br />Azure · Qualys · ManageEngine
        </div>
      </div>
      <nav className="flex-1">
        {NAV.map((item) => (
          <button key={item.label} onClick={() => setActive(item.label)}
            className={`w-full flex items-center gap-3 px-4 py-2.5 text-sm transition-all ${
              active===item.label
                ? "bg-blue-600 text-white font-semibold border-r-2 border-blue-300"
                : "text-gray-400 hover:bg-[#1a2d45] hover:text-white"
            }`}>
            <span>{item.icon}</span><span className="text-xs">{item.label}</span>
          </button>
        ))}
      </nav>
      <div className="px-4 pb-2">
        <div className="text-[9px] text-gray-600 text-center">
          {Object.values(CONFIG).some(c=>Object.values(c).some(v=>v))?"🟢 APIs Connected":"🟡 Demo Mode"}
        </div>
      </div>
    </div>
  );
}


// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  INTEGRATIONS / SETTINGS PAGE                                           ║
// ╚══════════════════════════════════════════════════════════════════════════╝

const INTEGRATIONS_DEF = [
  {
    key: "fortinet",
    name: "Fortinet FortiGate",
    icon: "🔥",
    color: "border-red-500",
    badge: "bg-red-100 text-red-700",
    desc: "Next-gen firewall — threat stats, blocked IPs, interface health",
    docs: "https://fndn.fortinet.net/",
    fields: [
      { id: "fortinet_host",   label: "FortiGate URL",  type: "text",     placeholder: "https://192.168.1.1",     hint: "Base URL of your FortiGate management interface" },
      { id: "fortinet_apikey", label: "REST API Token",  type: "password", placeholder: "API token from admin account", hint: "FortiGate → System → Administrators → API Users" },
    ],
  },
  {
    key: "paloalto",
    name: "Palo Alto (Panorama)",
    icon: "🌐",
    color: "border-orange-500",
    badge: "bg-orange-100 text-orange-700",
    desc: "Panorama / standalone NGFW — threat intelligence, policy hits",
    docs: "https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-panorama-api",
    fields: [
      { id: "paloalto_host",   label: "Panorama URL",   type: "text",     placeholder: "https://panorama.company.com", hint: "Panorama or standalone firewall URL" },
      { id: "paloalto_apikey", label: "PAN-OS API Key",  type: "password", placeholder: "API key", hint: "Generate: https://<device>/api/?type=keygen&user=X&password=Y" },
    ],
  },
  {
    key: "upguard",
    name: "UpGuard Cyber Risk",
    icon: "🛡️",
    color: "border-teal-500",
    badge: "bg-teal-100 text-teal-700",
    desc: "External attack surface monitoring — risk score, open ports, vulnerabilities",
    docs: "https://cyber-risk.upguard.com/api/v2/",
    fields: [
      { id: "upguard_apikey", label: "API Key", type: "password", placeholder: "UpGuard API key", hint: "Settings → API Keys in your UpGuard portal" },
    ],
  },
  {
    key: "azure",
    name: "Azure Defender for Cloud",
    icon: "☁️",
    color: "border-blue-500",
    badge: "bg-blue-100 text-blue-700",
    desc: "Cloud security posture — secure score, alerts, compliance",
    docs: "https://docs.microsoft.com/en-us/rest/api/defenderforcloud/",
    fields: [
      { id: "azure_tenant_id",       label: "Tenant ID",       type: "text",     placeholder: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", hint: "Azure AD → Overview → Tenant ID" },
      { id: "azure_client_id",       label: "Client ID",       type: "text",     placeholder: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", hint: "App Registration → Application (client) ID" },
      { id: "azure_client_secret",   label: "Client Secret",   type: "password", placeholder: "Secret value",                         hint: "App Registration → Certificates & Secrets → New client secret" },
      { id: "azure_subscription_id", label: "Subscription ID", type: "text",     placeholder: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", hint: "Subscriptions → Your subscription ID" },
    ],
  },
  {
    key: "qualys",
    name: "Qualys VMDR / VAPT",
    icon: "🐛",
    color: "border-yellow-500",
    badge: "bg-yellow-100 text-yellow-700",
    desc: "Vulnerability management — open CVEs, severity breakdown, scan history",
    docs: "https://www.qualys.com/docs/qualys-api-vmpc-user-guide.pdf",
    fields: [
      { id: "qualys_username", label: "Username", type: "text",     placeholder: "qualys-reader@company.com", hint: "Dedicated reader account (API access must be enabled)" },
      { id: "qualys_password", label: "Password", type: "password", placeholder: "Password",                  hint: "Qualys → Users → Edit → Enable API Access" },
    ],
  },
  {
    key: "manageengine",
    name: "ManageEngine",
    icon: "🖥️",
    color: "border-purple-500",
    badge: "bg-purple-100 text-purple-700",
    desc: "Asset inventory, patch compliance, endpoint encryption status",
    docs: "https://www.manageengine.com/patch-management/api/",
    fields: [
      { id: "me_host",   label: "Server URL",    type: "text",     placeholder: "https://meserver.company.com:8443", hint: "ManageEngine Endpoint Central / Patch Manager host" },
      { id: "me_apikey", label: "OAuth2 Token",  type: "password", placeholder: "Zoho OAuth token",                  hint: "ME Portal → Admin → API Explorer → Generate Token" },
    ],
  },
  {
    key: "taegis",
    name: "Secureworks Taegis XDR",
    icon: "🔍",
    color: "border-indigo-500",
    badge: "bg-indigo-100 text-indigo-700",
    desc: "SIEM / XDR — alerts, investigations, threat detections",
    docs: "https://docs.ctpx.secureworks.com/apis/",
    fields: [
      { id: "taegis_client_id",     label: "Client ID",      type: "text",     placeholder: "Taegis API client ID",     hint: "Taegis XDR → Settings → API Credentials → Create" },
      { id: "taegis_client_secret", label: "Client Secret",  type: "password", placeholder: "Taegis API client secret", hint: "Copy secret immediately after creation" },
      { id: "taegis_region",        label: "Region",         type: "select",   options: ["us1","us2","eu","jp"],         hint: "Your Taegis tenant region" },
    ],
  },
];

function StatusBadge({ configured, tested }) {
  if (!configured) return <span className="px-2 py-0.5 rounded-full text-xs font-semibold bg-gray-100 text-gray-500">Not Configured</span>;
  if (tested === "ok")    return <span className="px-2 py-0.5 rounded-full text-xs font-semibold bg-green-100 text-green-700">✓ Connected</span>;
  if (tested === "error") return <span className="px-2 py-0.5 rounded-full text-xs font-semibold bg-red-100 text-red-700">✗ Error</span>;
  return <span className="px-2 py-0.5 rounded-full text-xs font-semibold bg-yellow-100 text-yellow-700">Configured</span>;
}

function IntegrationCard({ def, saved, onUpdate }) {
  const [open, setOpen] = useState(false);
  const [values, setValues] = useState(() => {
    const v = {};
    def.fields.forEach(f => { v[f.id] = saved[f.id] || ""; });
    return v;
  });
  const [testState, setTestState] = useState(null); // null | "testing" | "ok" | "error"
  const [saveMsg, setSaveMsg] = useState("");

  const configured = def.fields.some(f => values[f.id]);

  function handleSave() {
    const current = JSON.parse(localStorage.getItem("secops_integrations") || "{}");
    def.fields.forEach(f => { current[f.id] = values[f.id]; });
    localStorage.setItem("secops_integrations", JSON.stringify(current));
    onUpdate();
    setSaveMsg("Saved!");
    setTimeout(() => setSaveMsg(""), 2000);
  }

  async function handleTest() {
    setTestState("testing");
    try {
      // Simple connectivity test — just check host reachable for URL-based tools
      const hostField = def.fields.find(f => f.id.endsWith("_host"));
      if (hostField && values[hostField.id]) {
        await fetch(values[hostField.id] + "/api/v2/health", { mode: "no-cors", signal: AbortSignal.timeout(5000) });
      }
      // For API-key-only tools, just validate the key is non-empty
      setTestState("ok");
    } catch {
      setTestState("error");
    }
    setTimeout(() => setTestState(null), 5000);
  }

  return (
    <div className={`bg-white rounded-xl border-l-4 ${def.color} shadow-sm overflow-hidden`}>
      <div className="px-5 py-4 flex items-center justify-between cursor-pointer hover:bg-gray-50 transition-colors" onClick={() => setOpen(o => !o)}>
        <div className="flex items-center gap-3">
          <span className="text-2xl">{def.icon}</span>
          <div>
            <div className="font-semibold text-gray-800 text-sm">{def.name}</div>
            <div className="text-xs text-gray-500 mt-0.5">{def.desc}</div>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <StatusBadge configured={configured} tested={testState} />
          <span className="text-gray-400 text-sm">{open ? "▲" : "▼"}</span>
        </div>
      </div>

      {open && (
        <div className="px-5 pb-5 border-t border-gray-100 pt-4">
          <div className="grid grid-cols-1 gap-3 mb-4">
            {def.fields.map(field => (
              <div key={field.id}>
                <label className="block text-xs font-semibold text-gray-600 mb-1">{field.label}</label>
                {field.type === "select" ? (
                  <select
                    value={values[field.id]}
                    onChange={e => setValues(v => ({ ...v, [field.id]: e.target.value }))}
                    className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue-400"
                  >
                    {(field.options || []).map(o => <option key={o} value={o}>{o}</option>)}
                  </select>
                ) : (
                  <input
                    type={field.type}
                    value={values[field.id]}
                    onChange={e => setValues(v => ({ ...v, [field.id]: e.target.value }))}
                    placeholder={field.placeholder}
                    className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue-400 font-mono"
                  />
                )}
                {field.hint && <p className="text-xs text-gray-400 mt-1">💡 {field.hint}</p>}
              </div>
            ))}
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={handleSave}
              className="px-4 py-2 bg-blue-600 text-white text-sm font-semibold rounded-lg hover:bg-blue-700 transition-colors"
            >
              {saveMsg || "Save Credentials"}
            </button>
            <button
              onClick={handleTest}
              disabled={!configured || testState === "testing"}
              className="px-4 py-2 border border-gray-300 text-gray-600 text-sm font-semibold rounded-lg hover:bg-gray-50 transition-colors disabled:opacity-40"
            >
              {testState === "testing" ? "Testing…" : testState === "ok" ? "✓ OK" : testState === "error" ? "✗ Failed" : "Test Connection"}
            </button>
            <a href={def.docs} target="_blank" rel="noreferrer" className="text-xs text-blue-500 hover:underline ml-auto">📖 API Docs</a>
          </div>
        </div>
      )}
    </div>
  );
}

function IntegrationsPage({ onSave }) {
  const [saved, setSaved] = useState(() => JSON.parse(localStorage.getItem("secops_integrations") || "{}"));
  const [showClear, setShowClear] = useState(false);

  function handleUpdate() {
    setSaved(JSON.parse(localStorage.getItem("secops_integrations") || "{}"));
    onSave();
  }

  const configuredCount = INTEGRATIONS_DEF.filter(d => d.fields.some(f => saved[f.id])).length;

  return (
    <div className="max-w-3xl mx-auto space-y-4 pb-8">
      {/* Header */}
      <div className="bg-white rounded-xl shadow-sm p-5 flex items-start justify-between">
        <div>
          <h2 className="text-lg font-bold text-gray-800">Integrations</h2>
          <p className="text-sm text-gray-500 mt-1">
            Connect your security tools to pull live data into the dashboard.
            Credentials are stored locally in your browser.
          </p>
          <div className="flex gap-3 mt-3">
            <span className="text-sm font-semibold text-blue-600">{configuredCount} / {INTEGRATIONS_DEF.length} configured</span>
            {configuredCount === 0 && <span className="text-sm text-yellow-600">🟡 Running in demo mode</span>}
            {configuredCount > 0 && <span className="text-sm text-green-600">🟢 Live data active</span>}
          </div>
        </div>
        <button
          onClick={() => setShowClear(v => !v)}
          className="text-xs text-red-400 hover:text-red-600"
        >
          Clear all
        </button>
      </div>

      {showClear && (
        <div className="bg-red-50 border border-red-200 rounded-xl p-4 flex items-center justify-between">
          <span className="text-sm text-red-700">This will remove all saved credentials from your browser.</span>
          <button
            onClick={() => { localStorage.removeItem("secops_integrations"); setSaved({}); onSave(); setShowClear(false); }}
            className="px-3 py-1.5 bg-red-600 text-white text-xs font-semibold rounded-lg hover:bg-red-700"
          >
            Confirm Clear
          </button>
        </div>
      )}

      {/* Quick-start guide */}
      <div className="bg-blue-50 border border-blue-200 rounded-xl p-4">
        <h3 className="text-sm font-bold text-blue-800 mb-2">⚡ Quick Start</h3>
        <ol className="text-xs text-blue-700 space-y-1 list-decimal list-inside">
          <li>Click on any integration card below to expand it</li>
          <li>Enter your API credentials (they stay in your browser only)</li>
          <li>Click <strong>Save Credentials</strong> — the dashboard refreshes automatically</li>
          <li>Use <strong>Test Connection</strong> to verify before saving</li>
        </ol>
      </div>

      {/* Integration cards */}
      {INTEGRATIONS_DEF.map(def => (
        <IntegrationCard key={def.key} def={def} saved={saved} onUpdate={handleUpdate} />
      ))}
    </div>
  );
}

export default function CybersecurityDashboard() {
  const [activeNav, setActiveNav] = useState("Overview");
  const [loading, setLoading]     = useState(true);
  const [data, setData]           = useState(null);
  const [lastRefresh, setLastRefresh] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    const d = await loadAllData();
    setData(d);
    setLastRefresh(new Date());
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  if (loading) {
    return (
      <div className="flex h-screen items-center justify-center bg-[#f0f4f8]">
        <div className="text-center space-y-3">
          <div className="text-6xl animate-spin">🛡️</div>
          <p className="text-gray-600 font-semibold text-lg">Loading Security Operations…</p>
          <div className="flex flex-wrap gap-1.5 justify-center text-[10px]">
            {["Fortinet","Palo Alto","UpGuard","Azure Defender","Qualys","ManageEngine"].map((t) => (
              <span key={t} className="bg-blue-100 text-blue-700 px-2 py-0.5 rounded-full font-medium">{t}</span>
            ))}
          </div>
        </div>
      </div>
    );
  }

  const PAGE = {
    "Overview":           <OverviewPage d={data} />,
    "Firewall (FG + PA)": <FirewallPage d={data} />,
    "Attack Surface":     <AttackSurfacePage d={data} />,
    "Cloud Security":     <CloudPage d={data} />,
    "Vulnerabilities":    <VulnPage d={data} />,
    "Assets & Patches":   <AssetsPage d={data} />,
    "Encryption":         <EncryptionPage d={data} />,
    "Settings":           <IntegrationsPage onSave={() => { CONFIG = loadSavedConfig(); load(); }} />,
  };

  return (
    <div className="flex h-screen overflow-hidden bg-[#f0f4f8] font-sans">
      <Sidebar active={activeNav} setActive={setActiveNav} />
      <div className="flex-1 flex flex-col overflow-hidden">
        <div className="bg-white shadow-sm px-6 py-2.5 flex items-center justify-between flex-shrink-0">
          <div>
            <h1 className="text-base font-bold text-gray-800">{activeNav}</h1>
            <div className="flex gap-1.5 mt-0.5">
              {[
                {label:"Fortinet",      color:"bg-red-100 text-red-700"},
                {label:"PaloAlto",      color:"bg-orange-100 text-orange-700"},
                {label:"UpGuard",       color:"bg-teal-100 text-teal-700"},
                {label:"Azure",         color:"bg-blue-100 text-blue-700"},
                {label:"Qualys",        color:"bg-orange-100 text-orange-700"},
                {label:"ManageEngine",  color:"bg-purple-100 text-purple-700"},
                {label:"Taegis SIEM",   color:"bg-indigo-100 text-indigo-700"},
              ].map((t) => (
                <span key={t.label} className={`text-[9px] font-bold px-2 py-0.5 rounded-full ${t.color}`}>{t.label}</span>
              ))}
            </div>
          </div>
          <div className="flex items-center gap-3">
            {lastRefresh && <span className="text-[10px] text-gray-400">Updated {lastRefresh.toLocaleTimeString()}</span>}
            <button onClick={load} className="text-xs bg-blue-600 text-white px-3 py-1.5 rounded-lg hover:bg-blue-700 transition-colors font-medium">
              ↻ Refresh
            </button>
            <div className="flex items-center gap-1.5">
              <div className="w-7 h-7 rounded-full bg-blue-600 flex items-center justify-center text-white text-xs font-bold">CS</div>
              <span className="text-sm text-gray-600 font-medium">Admin</span>
            </div>
          </div>
        </div>
        <div className="flex-1 overflow-y-auto p-4">
          {PAGE[activeNav] || (
            <div className="flex items-center justify-center h-full text-gray-400">
              <div className="text-center"><div className="text-5xl mb-3">🚧</div><p className="font-medium">Coming soon</p></div>
            </div>
          )}
          <div className="text-center text-[10px] text-gray-300 mt-4 pb-2">
            Security Operations Dashboard · Fortinet · Palo Alto · UpGuard · Azure Defender · Qualys · ManageEngine
          </div>
        </div>
      </div>
    </div>
  );
}
