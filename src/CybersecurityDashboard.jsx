import { useState, useEffect, useCallback, useRef } from "react";
import {
  BarChart, Bar, LineChart, Line, AreaChart, Area,
  PieChart, Pie, Cell, RadarChart, Radar, PolarGrid,
  PolarAngleAxis, XAxis, YAxis, CartesianGrid, Tooltip,
  Legend, ResponsiveContainer
} from "recharts";

/* ─────────────────────────────────────────────────────────────────────────
   transformSnapshot: maps per-tool snapshot data (from /api/snapshot) into
   the flat structure pages expect.  Returns {} when no data is available.
──────────────────────────────────────────────────────────────────────────── */
function transformSnapshot(snap) {
  if (!snap || Object.keys(snap).length === 0) return {};

  const ft = snap.fortinet || {};
  const pa = snap.paloalto  || {};
  const az = snap.azure     || {};
  const ug = snap.upguard   || {};
  const ql = snap.qualys    || {};
  const me = snap.manageengine || {};
  const tx = snap.taegis    || {};

  // ── Alerts (merge Taegis + Azure Defender) ──────────────────────────────
  const SEV = s => {
    const l = (s||"").toLowerCase();
    if (l.includes("critical")) return "Critical";
    if (l.includes("high"))     return "High";
    if (l.includes("medium"))   return "Medium";
    return "Low";
  };

  const alerts = [
    ...(Array.isArray(tx.alerts) ? tx.alerts.map((a,i) => ({
      id: a.id || `tx-${i}`,
      tool: "Taegis XDR",
      type: a.rule_name || a.type || "Alert",
      severity: SEV(a.severity),
      desc: a.message || a.description || "Alert detected",
      time: a.metadata?.created_at ? new Date(a.metadata.created_at).toLocaleString() : "Recent",
      status: a.status === "OPEN" ? "Active" : (a.status || "Active"),
      src: a.metadata?.device_ip || "N/A",
    })) : []),
    ...(Array.isArray(az.alerts) ? az.alerts.map((a,i) => ({
      id: a.id || a.name || `az-${i}`,
      tool: "Azure Defender",
      type: a.properties?.alertType || "Azure Alert",
      severity: SEV(a.properties?.severity || a.severity),
      desc: a.properties?.alertDisplayName || a.displayName || "Azure security alert",
      time: a.properties?.startTimeUtc ? new Date(a.properties.startTimeUtc).toLocaleString() : "Recent",
      status: a.properties?.status || "Active",
      src: a.properties?.resourceIdentifiers?.[0]?.resourceId?.split("/").pop() || "Azure",
    })) : []),
  ].sort((a,b) => {
    const ord = { Critical:0, High:1, Medium:2, Low:3 };
    return (ord[a.severity]||3) - (ord[b.severity]||3);
  });

  // ── Secure score ────────────────────────────────────────────────────────
  let score = 0;
  if (az.secureScore?.score !== undefined) score = Math.round(az.secureScore.score * 100);
  else if (ug.risks?.score)                 score = ug.risks.score;
  else if (ug.score)                        score = ug.score;

  // ── Vulnerabilities ─────────────────────────────────────────────────────
  const rawDetections = ql.detections;
  const vulns = Array.isArray(rawDetections) ? rawDetections.map((d,i) => ({
    id: d.QID || `qid-${i}`,
    host: d.IP || d.DNS_HOST_NAME || "Unknown",
    severity: SEV(String(d.SEVERITY || "")),
    title: d.TITLE || d.VULN_NAME || "Vulnerability",
    cve: d.CVE_LIST?.CVE?.[0]?.ID || "",
    status: d.STATUS || "Active",
    lastFound: d.LAST_FOUND_DATETIME || "",
  })) : [];

  // ── Firewall ────────────────────────────────────────────────────────────
  const firewall = {
    instance: ft.instance || pa.instance || "",
    policies: Array.isArray(ft.policies) ? ft.policies : [],
    stats:     Array.isArray(ft.stats)    ? ft.stats    : [],
    interfaces: Array.isArray(ft.interfaces) ? ft.interfaces : [],
    rules:     Array.isArray(pa.rules)    ? pa.rules    : [],
  };

  // ── SIEM ────────────────────────────────────────────────────────────────
  const siem = {
    eventsToday:    (tx.alerts?.length || 0) + (az.alerts?.length || 0),
    activeIncidents: alerts.filter(a => a.status === "Active" || a.status === "OPEN").length,
    meanDetect: "N/A",
    events: alerts.slice(0, 20),
  };

  // ── Assets (ManageEngine) ───────────────────────────────────────────────
  const meRaw = me.assets || {};
  const assets = {
    endpoints: meRaw.total_count || meRaw.total || 0,
    patches:   (me.patches?.SystemDetails || []),
    raw:       meRaw,
  };

  // ── UpGuard risks ───────────────────────────────────────────────────────
  const risks = ug.risks || ug.domain_risks || {};

  // ── Azure (flatten secureScore to a number) ──────────────────────────────
  const azFull = {
    ...az,
    secureScore: az.secureScore?.score !== undefined
      ? Math.round(az.secureScore.score * 100)
      : (typeof az.secureScore === "number" ? az.secureScore : 0),
    secureScoreMax: 100,
  };

  return {
    _hasData:  true,
    _sources:  Object.keys(snap).filter(k => !k.startsWith("_")),
    score,
    trendDays: [],          // requires historical API — use /api/snapshots/:tool
    alerts,
    risks,
    firewall,
    assets,
    siem,
    vulns,
    azure:        azFull,
    upguard:      ug,
    qualys:       ql,
    manageengine: me,
  };
}


/* ═══════════════════════════════════════════════════════════════════════════
   CONFIG
═══════════════════════════════════════════════════════════════════════════ */
const API = window.location.hostname === "localhost" ? "http://localhost:4000" : "";
const VER = "2.0";

const C = {
  critical:"#dc2626", high:"#ea580c", medium:"#d97706", low:"#16a34a",
  info:"#2563eb", ok:"#16a34a", warn:"#d97706",
  primary:"#1d4ed8", primaryLight:"#3b82f6",
  bg:"#f1f5f9", card:"#ffffff", sidebar:"#0f172a", header:"#1e293b",
  text:"#0f172a", muted:"#64748b", border:"#e2e8f0",
};

const SEVERITY_COLORS = { Critical:C.critical, High:C.high, Medium:C.medium, Low:C.low, Info:C.info };

const TOOLS = [
  { key:"fortinet",     name:"Fortinet",       icon:"🔥", cat:"Network Security",  color:"#f97316" },
  { key:"paloalto",     name:"Palo Alto",       icon:"🛡️", cat:"Network Security",  color:"#3b82f6" },
  { key:"upguard",      name:"UpGuard",         icon:"🌐", cat:"Attack Surface",    color:"#8b5cf6" },
  { key:"azure",        name:"Azure Defender",  icon:"☁️", cat:"Cloud Security",    color:"#0ea5e9" },
  { key:"qualys",       name:"Qualys VMDR",     icon:"🔍", cat:"Vulnerability Mgmt",color:"#ec4899" },
  { key:"manageengine", name:"ManageEngine",    icon:"💻", cat:"Asset Management",  color:"#14b8a6" },
  { key:"taegis",       name:"Taegis XDR",      icon:"🎯", cat:"SIEM / XDR",        color:"#f59e0b" },
];

const INTERVALS = [
  { label:"1 min",  value:60   },
  { label:"5 min",  value:300  },
  { label:"15 min", value:900  },
  { label:"30 min", value:1800 },
  { label:"1 hour", value:3600 },
];

/* ═══════════════════════════════════════════════════════════════════════════
   MOCK DATA  (displayed when no integrations are configured)
═══════════════════════════════════════════════════════════════════════════ */
function buildMock() {
  const days = Array.from({length:30},(_,i)=>{
    const d = new Date(); d.setDate(d.getDate()-29+i);
    const base = 68+Math.round(Math.sin(i/5)*4+i*0.13);
    return { date:d.toLocaleDateString("en-GB",{day:"2-digit",month:"short"}), score:Math.min(100,base),
      alerts:Math.max(0,12-Math.floor(i/4)+Math.round(Math.random()*3)),
      vulns:Math.max(30,55-Math.floor(i/3)+Math.round(Math.random()*5)) };
  });
  return {
    score:74,
    trend:days,
    alerts:[
      {id:1,severity:"Critical",title:"Lateral movement detected – Taegis XDR",tool:"taegis",resource:"SRV-DC01",time:"10 min ago",status:"Open"},
      {id:2,severity:"Critical",title:"Ransomware signature matched on endpoint",tool:"taegis",resource:"WKS-FIN-007",time:"22 min ago",status:"Open"},
      {id:3,severity:"High",title:"Critical CVE-2024-1234 unpatched on 14 hosts",tool:"qualys",resource:"Multiple",time:"1 hr ago",status:"Open"},
      {id:4,severity:"High",title:"Exposed RDP port detected – external scan",tool:"upguard",resource:"192.168.10.45",time:"2 hr ago",status:"Investigating"},
      {id:5,severity:"High",title:"Azure Security Score dropped below threshold",tool:"azure",resource:"Subscription",time:"3 hr ago",status:"Open"},
      {id:6,severity:"Medium",title:"SSL certificate expires in 14 days",tool:"upguard",resource:"api.company.com",time:"4 hr ago",status:"Open"},
      {id:7,severity:"Medium",title:"Fortinet IPS blocked exploit attempt",tool:"fortinet",resource:"DMZ-FW-01",time:"5 hr ago",status:"Resolved"},
      {id:8,severity:"Medium",title:"Palo Alto PAN-OS update available",tool:"paloalto",resource:"PA-5250",time:"6 hr ago",status:"Scheduled"},
      {id:9,severity:"Low",title:"Failed login attempts exceeded threshold",tool:"azure",resource:"admin@company.com",time:"8 hr ago",status:"Investigating"},
      {id:10,severity:"Low",title:"23 endpoints missing latest patch",tool:"manageengine",resource:"Various",time:"12 hr ago",status:"Open"},
    ],
    vulnerabilities:[
      {id:1,cve:"CVE-2024-1234",severity:"Critical",cvss:9.8,title:"Remote Code Execution in Apache Log4j",affected:14,status:"Unpatched",tool:"qualys",age:5},
      {id:2,cve:"CVE-2024-2345",severity:"Critical",cvss:9.1,title:"Privilege Escalation – Windows Print Spooler",affected:8,status:"Unpatched",tool:"qualys",age:3},
      {id:3,cve:"CVE-2024-3456",severity:"High",cvss:8.5,title:"SQL Injection in Web Application",affected:2,status:"In Progress",tool:"qualys",age:12},
      {id:4,cve:"CVE-2024-4567",severity:"High",cvss:7.8,title:"Authentication Bypass – OpenSSH",affected:31,status:"Unpatched",tool:"qualys",age:8},
      {id:5,cve:"CVE-2024-5678",severity:"High",cvss:7.5,title:"Buffer Overflow – Cisco IOS",affected:5,status:"Scheduled",tool:"qualys",age:21},
      {id:6,cve:"CVE-2023-9999",severity:"Medium",cvss:6.5,title:"Cross-Site Scripting in CMS Portal",affected:1,status:"In Progress",tool:"qualys",age:45},
      {id:7,cve:"CVE-2023-8888",severity:"Medium",cvss:5.8,title:"Information Disclosure – HTTP Headers",affected:18,status:"Unpatched",tool:"qualys",age:67},
    ],
    riskByDomain:[
      {domain:"Network Security",  score:82, maxScore:100, controls:24, gaps:4},
      {domain:"Cloud Security",    score:71, maxScore:100, controls:18, gaps:7},
      {domain:"Endpoint Security", score:78, maxScore:100, controls:15, gaps:3},
      {domain:"Identity & Access", score:69, maxScore:100, controls:20, gaps:8},
      {domain:"Attack Surface",    score:68, maxScore:100, controls:12, gaps:5},
      {domain:"Vulnerability Mgmt",score:65, maxScore:100, controls:16, gaps:9},
      {domain:"Data Protection",   score:80, maxScore:100, controls:10, gaps:2},
    ],
    compliance:[
      {framework:"SOC 2 Type II",     score:87, controls:112, passing:97,  color:"#3b82f6"},
      {framework:"ISO 27001",         score:82, controls:93,  passing:76,  color:"#8b5cf6"},
      {framework:"PCI-DSS v4",        score:91, controls:251, passing:228, color:"#10b981"},
      {framework:"NIST CSF",          score:75, controls:108, passing:81,  color:"#f59e0b"},
      {framework:"Essential Eight",   score:70, controls:40,  passing:28,  color:"#ec4899"},
    ],
    firewall:{
      blockedToday:12847, allowedToday:184293, topThreatCountries:[
        {country:"RU",count:3241},{country:"CN",count:2189},{country:"KP",count:987},
        {country:"IR",count:654},{country:"BR",count:432},
      ],
      trafficByHour: Array.from({length:24},(_,h)=>({
        hour:`${h.toString().padStart(2,"0")}:00`,
        blocked:Math.round(300+Math.random()*800+(h>=9&&h<=17?400:0)),
        allowed:Math.round(3000+Math.random()*8000+(h>=9&&h<=17?4000:0)),
      })),
      topPolicies:[
        {name:"Block Malicious IP",hits:5421,action:"Deny"},
        {name:"Allow Corporate VPN",hits:3218,action:"Allow"},
        {name:"Block Tor Exit Nodes",hits:1876,action:"Deny"},
        {name:"IPS – Exploit Prevention",hits:892,action:"Drop"},
        {name:"URL Filtering – Gambling",hits:674,action:"Deny"},
      ],
    },
    assets:{
      total:342, online:298, offline:44,
      patchedPct:72, encryptedPct:85,
      byType:[
        {type:"Workstation",count:198,patched:148,encrypted:178},
        {type:"Server",count:87,patched:62,encrypted:85},
        {type:"Network Device",count:34,patched:24,encrypted:0},
        {type:"Mobile",count:23,patched:18,encrypted:21},
      ],
      recentPatches:[
        {date:"2024-06-28",name:"Windows KB5039894",devices:42,status:"Success"},
        {date:"2024-06-25",name:"Chrome 126.0",devices:187,status:"Success"},
        {date:"2024-06-20",name:"Office 365 June Update",devices:198,status:"Partial"},
        {date:"2024-06-15",name:"Adobe Reader 24.002",devices:134,status:"Success"},
      ],
    },
    surface:{
      score:68, grade:"C+",
      findings:[
        {severity:"Critical",title:"Open RDP to internet (port 3389)",asset:"192.168.10.45",first:"2024-06-20"},
        {severity:"High",title:"SSL certificate expires in 14 days",asset:"api.company.com",first:"2024-06-25"},
        {severity:"High",title:"Subdomain takeover risk detected",asset:"legacy.company.com",first:"2024-06-22"},
        {severity:"Medium",title:"HTTP security headers missing (CSP)",asset:"www.company.com",first:"2024-06-01"},
        {severity:"Medium",title:"SSH accessible from 0.0.0.0/0",asset:"backup.company.com",first:"2024-05-15"},
        {severity:"Low",title:"DMARC policy not enforced",asset:"company.com",first:"2024-04-10"},
      ],
      ipRanges:5, domains:12, subdomains:34, openPorts:18,
    },
    siem:{
      eventsToday:284710, meanDetect:"4.2 min", activeIncidents:3,
      events:[
        {time:"10:42",type:"Malware",severity:"Critical",desc:"Ransomware file activity on FIN-WKS007",src:"10.1.5.7",status:"Active"},
        {time:"10:28",type:"Lateral Movement",severity:"Critical",desc:"Pass-the-hash to Domain Controller",src:"10.1.5.7",status:"Active"},
        {time:"09:15",type:"Brute Force",severity:"High",desc:"5000+ auth failures – admin account",src:"185.220.101.42",status:"Active"},
        {time:"08:33",type:"C2 Beacon",severity:"High",desc:"Outbound connection to known C2 IP",src:"10.2.1.44",status:"Contained"},
        {time:"07:21",type:"Privilege Escalation",severity:"High",desc:"Mimikatz usage detected",src:"10.1.3.22",status:"Contained"},
        {time:"06:45",type:"Anomaly",severity:"Medium",desc:"Unusual data exfiltration volume",src:"10.3.2.11",status:"Investigating"},
      ],
    },
    azure:{
      secureScore:71, secureScoreMax:100,
      subscriptions:[
        {name:"Production",id:"sub-001",score:73,resources:142},
        {name:"Development",id:"sub-002",score:64,resources:58},
        {name:"DR / Backup",id:"sub-003",score:78,resources:22},
      ],
      byCategory:[
        {cat:"Identity & Access",score:68,resources:24,issues:5,icon:"🔐"},
        {cat:"Compute",score:72,resources:18,issues:4,icon:"💻"},
        {cat:"Data & Storage",score:85,resources:12,issues:1,icon:"💾"},
        {cat:"Network",score:74,resources:31,issues:3,icon:"🌐"},
        {cat:"App Services",score:60,resources:6,issues:4,icon:"🌍"},
        {cat:"Logging & Monitor",score:88,resources:8,issues:1,icon:"📊"},
        {cat:"Key Vault",score:95,resources:2,issues:0,icon:"🔑"},
      ],
      virtualMachines:[
        {name:"vm-prod-web-01",rg:"rg-production",os:"Windows Server 2022",size:"D4s_v3",status:"Running",patches:"Current",defender:"On",compliance:"Compliant",ip:"10.0.1.4"},
        {name:"vm-prod-app-01",rg:"rg-production",os:"Ubuntu 22.04 LTS",size:"D8s_v3",status:"Running",patches:"Critical",defender:"On",compliance:"Non-Compliant",ip:"10.0.1.5"},
        {name:"vm-prod-db-01",rg:"rg-production",os:"Windows Server 2019",size:"E8s_v3",status:"Running",patches:"Current",defender:"On",compliance:"Compliant",ip:"10.0.2.4"},
        {name:"vm-prod-dc-01",rg:"rg-production",os:"Windows Server 2022",size:"D4s_v3",status:"Running",patches:"Current",defender:"On",compliance:"Compliant",ip:"10.0.0.4"},
        {name:"vm-prod-backup",rg:"rg-backup",os:"Windows Server 2019",size:"D2s_v3",status:"Running",patches:"Warning",defender:"On",compliance:"Warning",ip:"10.0.3.4"},
        {name:"vm-dev-build-01",rg:"rg-development",os:"Ubuntu 20.04 LTS",size:"B4ms",status:"Running",patches:"Warning",defender:"Off",compliance:"Non-Compliant",ip:"10.1.0.4"},
        {name:"vm-dev-test-01",rg:"rg-development",os:"Windows Server 2019",size:"B2s",status:"Stopped",patches:"Critical",defender:"Off",compliance:"Non-Compliant",ip:"10.1.0.5"},
        {name:"vm-dr-01",rg:"rg-dr",os:"Windows Server 2022",size:"D4s_v3",status:"Stopped (deallocated)",patches:"Current",defender:"On",compliance:"Compliant",ip:"10.2.0.4"},
      ],
      storageAccounts:[
        {name:"stproddata001",rg:"rg-production",kind:"StorageV2",replication:"GRS",encryption:"Enabled",publicAccess:"Disabled",https:"Enforced",compliance:"Compliant"},
        {name:"stprodlogs001",rg:"rg-production",kind:"StorageV2",replication:"LRS",encryption:"Enabled",publicAccess:"Disabled",https:"Enforced",compliance:"Compliant"},
        {name:"stdevartifacts",rg:"rg-development",kind:"StorageV2",replication:"LRS",encryption:"Enabled",publicAccess:"Enabled",https:"Enforced",compliance:"Non-Compliant"},
        {name:"stdrbackups001",rg:"rg-dr",kind:"StorageV2",replication:"GRS",encryption:"Enabled",publicAccess:"Disabled",https:"Enforced",compliance:"Compliant"},
      ],
      databases:[
        {name:"sql-prod-main",type:"Azure SQL",rg:"rg-production",tde:"Enabled",audit:"Enabled",threat:"Enabled",firewall:"Configured",compliance:"Compliant"},
        {name:"cosmos-prod-api",type:"Cosmos DB",rg:"rg-production",tde:"Enabled",audit:"Disabled",threat:"Enabled",firewall:"Open",compliance:"Warning"},
        {name:"psql-dev-db",type:"PostgreSQL",rg:"rg-development",tde:"Enabled",audit:"Disabled",threat:"Disabled",firewall:"Open",compliance:"Non-Compliant"},
      ],
      webApps:[
        {name:"app-portal-prod",rg:"rg-production",runtime:"Node 18",https:"Enforced",auth:"Azure AD",tls:"1.2+",compliance:"Compliant"},
        {name:"app-api-prod",rg:"rg-production",runtime:"Python 3.11",https:"Enforced",auth:"None",tls:"1.0",compliance:"Non-Compliant"},
        {name:"app-admin-prod",rg:"rg-production",runtime:".NET 8",https:"Enforced",auth:"Azure AD",tls:"1.2+",compliance:"Compliant"},
        {name:"app-dev-portal",rg:"rg-development",runtime:"Node 18",https:"Not Enforced",auth:"None",tls:"1.0",compliance:"Non-Compliant"},
        {name:"func-prod-proc",rg:"rg-production",runtime:"Python 3.11",https:"Enforced",auth:"MSI",tls:"1.2+",compliance:"Compliant"},
      ],
      keyVaults:[
        {name:"kv-prod-secrets",rg:"rg-production",purge:"Enabled",soft:"90 days",rbac:"Enabled",compliance:"Compliant"},
        {name:"kv-prod-certs",rg:"rg-production",purge:"Enabled",soft:"90 days",rbac:"Enabled",compliance:"Compliant"},
      ],
      recommendations:[
        {severity:"High",title:"Enable MFA for all Azure AD administrator accounts",category:"Identity",affected:5,effort:"Low"},
        {severity:"High",title:"Remediate JIT VM access on production VMs",category:"Compute",affected:4,effort:"Medium"},
        {severity:"High",title:"Apply system updates on vm-prod-app-01 (critical patches missing)",category:"Compute",affected:1,effort:"Low"},
        {severity:"High",title:"Restrict public network access to PostgreSQL server",category:"Data",affected:1,effort:"Low"},
        {severity:"Medium",title:"Enable Azure Defender for open-source databases",category:"Data",affected:2,effort:"Low"},
        {severity:"Medium",title:"Enable TLS 1.2+ on app-api-prod",category:"Network",affected:1,effort:"Low"},
        {severity:"Medium",title:"Enable auditing on Cosmos DB and PostgreSQL",category:"Logging",affected:2,effort:"Medium"},
        {severity:"Low",title:"Disable public blob access on stdevartifacts",category:"Storage",affected:1,effort:"Low"},
        {severity:"Low",title:"Enable diagnostic logs on all App Services",category:"Logging",affected:4,effort:"Medium"},
      ],
      azureAlerts:[
        {severity:"High",title:"Suspicious authentication from anonymous IP address",resource:"app-api-prod",time:"2 hr ago",status:"Active"},
        {severity:"High",title:"Potential SQL injection attempt detected",resource:"sql-prod-main",time:"5 hr ago",status:"Investigating"},
        {severity:"Medium",title:"Unusual outbound data transfer volume",resource:"stproddata001",time:"8 hr ago",status:"Active"},
        {severity:"Medium",title:"VM without disk encryption detected",resource:"vm-dev-build-01",time:"1 day ago",status:"Open"},
        {severity:"Low",title:"Storage account allows public blob access",resource:"stdevartifacts",time:"2 days ago",status:"Open"},
      ],
    },
  };
}

/* ═══════════════════════════════════════════════════════════════════════════
   SHARED COMPONENTS
═══════════════════════════════════════════════════════════════════════════ */
function Card({ children, style={}, className="" }) {
  return (
    <div style={{ background:C.card, borderRadius:12, boxShadow:"0 1px 3px rgba(0,0,0,0.08),0 1px 2px rgba(0,0,0,0.06)", border:`1px solid ${C.border}`, ...style }}>
      {children}
    </div>
  );
}

function SectionTitle({ title, subtitle, action }) {
  return (
    <div style={{ display:"flex", alignItems:"flex-start", justifyContent:"space-between", marginBottom:20 }}>
      <div>
        <h2 style={{ fontSize:18, fontWeight:700, color:C.text, margin:0 }}>{title}</h2>
        {subtitle && <p style={{ fontSize:13, color:C.muted, margin:"4px 0 0" }}>{subtitle}</p>}
      </div>
      {action}
    </div>
  );
}

function MetricCard({ icon, label, value, sub, trend, trendUp, color=C.primary, onClick }) {
  const isPositive = trendUp === undefined ? true : trendUp;
  return (
    <Card style={{ padding:20, cursor:onClick?"pointer":"default" }} onClick={onClick}>
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start" }}>
        <div>
          <div style={{ fontSize:12, fontWeight:600, color:C.muted, textTransform:"uppercase", letterSpacing:0.8, marginBottom:8 }}>{label}</div>
          <div style={{ fontSize:32, fontWeight:800, color:C.text, lineHeight:1 }}>{value}</div>
          {sub && <div style={{ fontSize:12, color:C.muted, marginTop:6 }}>{sub}</div>}
          {trend && (
            <div style={{ fontSize:12, color:isPositive ? C.ok : C.critical, marginTop:6, fontWeight:600 }}>
              {isPositive ? "▲" : "▼"} {trend}
            </div>
          )}
        </div>
        <div style={{ width:44, height:44, borderRadius:10, background:`${color}18`, display:"flex", alignItems:"center", justifyContent:"center", fontSize:22 }}>
          {icon}
        </div>
      </div>
    </Card>
  );
}

function SeverityBadge({ level }) {
  const colors = { Critical:["#fef2f2","#dc2626"], High:["#fff7ed","#ea580c"], Medium:["#fffbeb","#d97706"], Low:["#f0fdf4","#16a34a"], Info:["#eff6ff","#2563eb"] };
  const [bg, text] = colors[level] || ["#f8fafc","#64748b"];
  return (
    <span style={{ display:"inline-flex", alignItems:"center", padding:"2px 10px", borderRadius:20, background:bg, color:text, fontSize:11, fontWeight:700, letterSpacing:0.3 }}>
      {level === "Critical" && "⬤ "}{level}
    </span>
  );
}

function ScoreGauge({ score, size=180 }) {
  const color = score >= 80 ? C.ok : score >= 65 ? C.warn : C.critical;
  const label = score >= 80 ? "STRONG" : score >= 65 ? "MODERATE" : "AT RISK";
  const pct = score / 100;
  const r = size * 0.38;
  const cx = size / 2;
  const cy = size * 0.56;
  const startAngle = Math.PI;
  const endAngle = 0;
  const arcLen = endAngle - startAngle;
  const sweep = startAngle + arcLen * pct;
  const x1 = cx + r * Math.cos(startAngle);
  const y1 = cy + r * Math.sin(startAngle);
  const x2 = cx + r * Math.cos(endAngle);
  const y2 = cy + r * Math.sin(endAngle);
  const sx = cx + r * Math.cos(startAngle);
  const sy = cy + r * Math.sin(startAngle);
  const ex = cx + r * Math.cos(sweep);
  const ey = cy + r * Math.sin(sweep);
  return (
    <div style={{ display:"flex", flexDirection:"column", alignItems:"center" }}>
      <svg width={size} height={size * 0.62}>
        {/* Track */}
        <path d={`M ${cx-r} ${cy} A ${r} ${r} 0 0 1 ${cx+r} ${cy}`}
          fill="none" stroke="#e2e8f0" strokeWidth={size*0.08} strokeLinecap="round"/>
        {/* Progress */}
        <path d={`M ${sx} ${sy} A ${r} ${r} 0 ${pct > 0.5 ? 1 : 0} 1 ${ex} ${ey}`}
          fill="none" stroke={color} strokeWidth={size*0.08} strokeLinecap="round"
          style={{filter:`drop-shadow(0 0 6px ${color}60)`}}/>
        {/* Score text */}
        <text x={cx} y={cy-2} textAnchor="middle" fontSize={size*0.22} fontWeight="800" fill={C.text}>{score}</text>
        <text x={cx} y={cy+size*0.08} textAnchor="middle" fontSize={size*0.07} fontWeight="600" fill={color} letterSpacing="1">{label}</text>
      </svg>
      <div style={{ fontSize:12, color:C.muted, marginTop:4 }}>Security Health Score</div>
    </div>
  );
}

function RiskBar({ label, score }) {
  const color = score >= 80 ? C.ok : score >= 65 ? C.warn : C.critical;
  return (
    <div style={{ marginBottom:12 }}>
      <div style={{ display:"flex", justifyContent:"space-between", marginBottom:4 }}>
        <span style={{ fontSize:13, color:C.text, fontWeight:500 }}>{label}</span>
        <span style={{ fontSize:13, fontWeight:700, color }}>{score}/100</span>
      </div>
      <div style={{ height:8, background:"#f1f5f9", borderRadius:4, overflow:"hidden" }}>
        <div style={{ height:"100%", width:`${score}%`, background:`linear-gradient(90deg,${color}bb,${color})`, borderRadius:4, transition:"width 1s ease" }} />
      </div>
    </div>
  );
}

function StatRow({ label, value, sub, color }) {
  return (
    <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", padding:"10px 0", borderBottom:`1px solid ${C.border}` }}>
      <span style={{ fontSize:13, color:C.text }}>{label}</span>
      <div style={{ textAlign:"right" }}>
        <span style={{ fontSize:14, fontWeight:700, color:color||C.text }}>{value}</span>
        {sub && <div style={{ fontSize:11, color:C.muted }}>{sub}</div>}
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════
   EXECUTIVE PAGES
═══════════════════════════════════════════════════════════════════════════ */

/* ── NoData helper ──────────────────────────────────────────────────────── */
function NoData({ icon="📭", title="No live data yet", message }) {
  return (
    <div style={{ textAlign:"center", padding:"64px 24px", color:C.muted }}>
      <div style={{ fontSize:52, marginBottom:14, opacity:0.6 }}>{icon}</div>
      <div style={{ fontSize:17, fontWeight:700, color:C.text, marginBottom:8 }}>{title}</div>
      <div style={{ fontSize:13, maxWidth:420, margin:"0 auto", lineHeight:1.6 }}>
        {message || "Configure this integration in ⚙️ Settings to start collecting live data."}
      </div>
    </div>
  );
}

// ── Security Posture (Executive Home) ────────────────────────────────────────
function OverviewPage({ data }) {
  const d = data || {};
  if (!d._hasData) return <NoData icon="🛡️" title="No security data yet"
    message="Connect your security integrations in ⚙️ Settings to populate this dashboard with live data." />;
  const alerts = d.alerts || [];
  const critAlerts = alerts.filter(a=>a.severity==="Critical").length;
  const highAlerts = alerts.filter(a=>a.severity==="High").length;
  const critVulns = (d.vulns||[]).filter(v=>v.severity==="Critical").length;
  const openVulns = (d.vulns||[]).length;
  const avgCompliance = d.compliance ? Math.round(d.compliance.reduce((s,c)=>s+c.score,0)/d.compliance.length) : 0;

  return (
    <div>
      <SectionTitle title="Security Posture Overview"
        subtitle={`Organisation-wide security health as of ${new Date().toLocaleDateString("en-AU",{weekday:"long",year:"numeric",month:"long",day:"numeric"})}`} />

      {/* Top KPI row */}
      <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:16, marginBottom:24 }}>
        <MetricCard icon="🛡️" label="Security Score" value={`${d.score}/100`}
          trend="↑ 3 pts this month" trendUp={true} color={C.primaryLight} />
        <MetricCard icon="🚨" label="Critical Alerts" value={critAlerts}
          sub={`${highAlerts} High, ${alerts.filter(a=>a.severity==="Medium").length} Medium`}
          trend={critAlerts > 0 ? `${critAlerts} require immediate action` : "None active"}
          trendUp={critAlerts === 0} color={critAlerts > 0 ? C.critical : C.ok} />
        <MetricCard icon="🔍" label="Open Vulnerabilities" value={openVulns}
          sub={`${critVulns} Critical severity`}
          trend={critVulns > 0 ? `${critVulns} critical unpatched` : "No critical vulns"}
          trendUp={critVulns === 0} color={critVulns > 0 ? C.critical : C.ok} />
        <MetricCard icon="✅" label="Compliance" value={`${avgCompliance}%`}
          sub={`Across ${d.compliance?.length || 5} frameworks`}
          trend="↑ 2% since last audit" trendUp={true} color={C.ok} />
      </div>

      {/* Main content grid */}
      <div style={{ display:"grid", gridTemplateColumns:"300px 1fr 280px", gap:16, marginBottom:24 }}>
        {/* Score gauge */}
        <Card style={{ padding:24, display:"flex", flexDirection:"column", alignItems:"center", justifyContent:"center" }}>
          <ScoreGauge score={d.score} size={200} />
          <div style={{ marginTop:16, width:"100%" }}>
            <div style={{ display:"flex", justifyContent:"space-between", fontSize:11, color:C.muted, marginBottom:4 }}>
              <span>At Risk</span><span>Moderate</span><span>Strong</span>
            </div>
            <div style={{ height:6, borderRadius:3, background:"linear-gradient(90deg,#dc2626,#d97706,#16a34a)" }} />
          </div>
        </Card>

        {/* 30-day trend */}
        <Card style={{ padding:20 }}>
          <div style={{ fontSize:14, fontWeight:700, color:C.text, marginBottom:16 }}>30-Day Security Trend</div>
          <ResponsiveContainer width="100%" height={180}>
            <AreaChart data={d.trendDays||[]} margin={{top:5,right:10,left:-20,bottom:0}}>
              <defs>
                <linearGradient id="scoreGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={C.primaryLight} stopOpacity={0.3}/>
                  <stop offset="95%" stopColor={C.primaryLight} stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke={C.border} />
              <XAxis dataKey="date" tick={{fontSize:10,fill:C.muted}} tickLine={false} axisLine={false}
                interval={4} />
              <YAxis domain={[50,100]} tick={{fontSize:10,fill:C.muted}} tickLine={false} axisLine={false}/>
              <Tooltip contentStyle={{background:C.card,border:`1px solid ${C.border}`,borderRadius:8,fontSize:12}} />
              <Area type="monotone" dataKey="score" stroke={C.primaryLight} strokeWidth={2.5}
                fill="url(#scoreGrad)" name="Security Score" />
            </AreaChart>
          </ResponsiveContainer>
          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:8, marginTop:12 }}>
            <div style={{ background:"#f8fafc", borderRadius:8, padding:"8px 12px" }}>
              <div style={{ fontSize:11, color:C.muted }}>30-day avg alerts</div>
              <div style={{ fontSize:18, fontWeight:700, color:C.text }}>{(d.trendDays||[]).length ? Math.round((d.trendDays||[]).reduce((s,t)=>s+t.alerts,0)/(d.trendDays||[]).length) : "N/A"}</div>
            </div>
            <div style={{ background:"#f8fafc", borderRadius:8, padding:"8px 12px" }}>
              <div style={{ fontSize:11, color:C.muted }}>Avg open vulns</div>
              <div style={{ fontSize:18, fontWeight:700, color:C.text }}>{(d.trendDays||[]).length ? Math.round((d.trendDays||[]).reduce((s,t)=>s+t.vulns,0)/(d.trendDays||[]).length) : "N/A"}</div>
            </div>
          </div>
        </Card>

        {/* Risk summary */}
        <Card style={{ padding:20 }}>
          <div style={{ fontSize:14, fontWeight:700, color:C.text, marginBottom:16 }}>Risk by Domain</div>
          {(d.riskByDomain||[]).map(r=>(
            <RiskBar key={r.domain} label={r.domain} score={r.score} />
          ))}
        </Card>
      </div>

      {/* Bottom row */}
      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:16 }}>
        {/* Critical alerts */}
        <Card style={{ padding:20 }}>
          <div style={{ fontSize:14, fontWeight:700, color:C.text, marginBottom:16 }}>Active Critical & High Alerts</div>
          <div>
            {alerts.filter(a=>["Critical","High"].includes(a.severity)).slice(0,5).map(a=>(
              <div key={a.id} style={{ display:"flex", alignItems:"flex-start", gap:12, padding:"10px 0", borderBottom:`1px solid ${C.border}` }}>
                <div style={{ width:8, height:8, borderRadius:"50%", background:SEVERITY_COLORS[a.severity], marginTop:5, flexShrink:0 }} />
                <div style={{ flex:1, minWidth:0 }}>
                  <div style={{ fontSize:13, color:C.text, fontWeight:500, whiteSpace:"nowrap", overflow:"hidden", textOverflow:"ellipsis" }}>{a.title}</div>
                  <div style={{ fontSize:11, color:C.muted, marginTop:2 }}>{TOOLS.find(t=>t.key===a.tool)?.name} • {a.resource} • {a.time}</div>
                </div>
                <SeverityBadge level={a.severity} />
              </div>
            ))}
          </div>
        </Card>

        {/* Compliance */}
        <Card style={{ padding:20 }}>
          <div style={{ fontSize:14, fontWeight:700, color:C.text, marginBottom:16 }}>Compliance Posture</div>
          {(d.compliance||[]).map(c=>(
            <div key={c.framework} style={{ marginBottom:14 }}>
              <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:5 }}>
                <span style={{ fontSize:13, color:C.text, fontWeight:500 }}>{c.framework}</span>
                <div style={{ display:"flex", alignItems:"center", gap:8 }}>
                  <span style={{ fontSize:12, color:C.muted }}>{c.passing}/{c.controls} controls</span>
                  <span style={{ fontSize:14, fontWeight:700, color:c.score>=80?C.ok:c.score>=70?C.warn:C.critical }}>{c.score}%</span>
                </div>
              </div>
              <div style={{ height:6, background:"#f1f5f9", borderRadius:3, overflow:"hidden" }}>
                <div style={{ height:"100%", width:`${c.score}%`, background:c.color, borderRadius:3 }} />
              </div>
            </div>
          ))}
        </Card>
      </div>
    </div>
  );
}

// ── Risk & Compliance ────────────────────────────────────────────────────────
function RiskCompliancePage({ data }) {
  const d = data || {};
  if (!d._hasData) return <NoData icon="⚖️" title="No risk data yet" message="Connect UpGuard and your SIEM/XDR integrations to see risk and compliance data." />;
  return (
    <div>
      <SectionTitle title="Risk & Compliance" subtitle="Detailed risk assessment and regulatory compliance status" />
      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:16, marginBottom:16 }}>
        {/* Compliance frameworks */}
        <Card style={{ padding:24 }}>
          <div style={{ fontSize:14, fontWeight:700, color:C.text, marginBottom:20 }}>Framework Compliance Scores</div>
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={d.compliance} layout="vertical" margin={{left:100,right:20}}>
              <CartesianGrid strokeDasharray="3 3" stroke={C.border} horizontal={false}/>
              <XAxis type="number" domain={[0,100]} tick={{fontSize:11,fill:C.muted}} tickLine={false} axisLine={false}/>
              <YAxis type="category" dataKey="framework" tick={{fontSize:11,fill:C.muted}} tickLine={false} axisLine={false} width={100}/>
              <Tooltip contentStyle={{background:C.card,border:`1px solid ${C.border}`,borderRadius:8,fontSize:12}}
                formatter={(v)=>[`${v}%`,"Score"]}/>
              <Bar dataKey="score" radius={[0,4,4,0]}>
                {(d.compliance||[]).map((c,i)=><Cell key={i} fill={c.color}/>)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </Card>

        {/* Risk matrix */}
        <Card style={{ padding:24 }}>
          <div style={{ fontSize:14, fontWeight:700, color:C.text, marginBottom:20 }}>Risk Register Summary</div>
          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:12, marginBottom:16 }}>
            {[
              {label:"Critical Risks",count:2,color:C.critical},
              {label:"High Risks",count:5,color:C.high},
              {label:"Medium Risks",count:11,color:C.medium},
              {label:"Low Risks",count:18,color:C.low},
            ].map(r=>(
              <div key={r.label} style={{ background:`${r.color}10`, border:`1px solid ${r.color}30`, borderRadius:10, padding:16, textAlign:"center" }}>
                <div style={{ fontSize:32, fontWeight:800, color:r.color }}>{r.count}</div>
                <div style={{ fontSize:12, color:C.muted, marginTop:4 }}>{r.label}</div>
              </div>
            ))}
          </div>
          <div style={{ borderTop:`1px solid ${C.border}`, paddingTop:16 }}>
            {(d.riskByDomain||[]).map(r=>(
              <div key={r.domain} style={{ display:"flex", justifyContent:"space-between", alignItems:"center", padding:"6px 0" }}>
                <span style={{ fontSize:12, color:C.text }}>{r.domain}</span>
                <div style={{ display:"flex", alignItems:"center", gap:8 }}>
                  <span style={{ fontSize:11, color:C.muted }}>{r.gaps} gaps</span>
                  <span style={{ fontSize:12, fontWeight:700, color:r.score>=80?C.ok:r.score>=65?C.warn:C.critical }}>{r.score}/100</span>
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* Action items */}
      <Card style={{ padding:24 }}>
        <div style={{ fontSize:14, fontWeight:700, color:C.text, marginBottom:16 }}>Priority Action Items for Board</div>
        <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:12 }}>
          {[
            { priority:1, title:"Patch Critical CVEs", desc:"14 hosts running vulnerable Log4j. Patch within 48 hours to prevent remote code execution.", effort:"48hr", owner:"IT Security", status:"Urgent" },
            { priority:2, title:"Close Open RDP Exposure", desc:"External RDP access detected on production server. Requires firewall rule change.", effort:"4hr", owner:"Network Ops", status:"Urgent" },
            { priority:3, title:"MFA Enforcement", desc:"37% of privileged accounts lack MFA. Essential Eight requires 100% coverage.", effort:"1 week", owner:"IAM Team", status:"High" },
            { priority:4, title:"Patch Cycle Improvement", desc:"28% of endpoints missing patches. Target: <5% within 30 days.", effort:"30 days", owner:"IT Ops", status:"High" },
            { priority:5, title:"Azure Security Posture", desc:"7 security recommendations outstanding in Defender for Cloud.", effort:"2 weeks", owner:"Cloud Team", status:"Medium" },
            { priority:6, title:"Incident Response Plan", desc:"IR playbooks need updating for ransomware scenario per current threat landscape.", effort:"3 weeks", owner:"CISO Office", status:"Medium" },
          ].map(a=>(
            <div key={a.priority} style={{ background:"#f8fafc", borderRadius:10, padding:16, border:`1px solid ${C.border}` }}>
              <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:8 }}>
                <span style={{ background:a.status==="Urgent"?C.critical:a.status==="High"?C.high:C.medium, color:"white", borderRadius:4, padding:"2px 8px", fontSize:10, fontWeight:700 }}>{a.status}</span>
                <span style={{ fontSize:11, color:C.muted }}>#{a.priority}</span>
              </div>
              <div style={{ fontSize:13, fontWeight:700, color:C.text, marginBottom:6 }}>{a.title}</div>
              <div style={{ fontSize:12, color:C.muted, marginBottom:8, lineHeight:1.5 }}>{a.desc}</div>
              <div style={{ display:"flex", justifyContent:"space-between", fontSize:11, color:C.muted }}>
                <span>⏱ {a.effort}</span><span>👤 {a.owner}</span>
              </div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}

// ── Threat Intelligence ──────────────────────────────────────────────────────
function ThreatPage({ data }) {
  const d = data || {};
  if (!d._hasData) return <NoData icon="🎯" title="No threat data yet" message="Connect Taegis XDR or Azure Defender in ⚙️ Settings to see live threat intelligence." />;
  const threatData = [
    {name:"Jan",incidents:3},{name:"Feb",incidents:5},{name:"Mar",incidents:2},{name:"Apr",incidents:8},
    {name:"May",incidents:6},{name:"Jun",incidents:4},
  ];
  return (
    <div>
      <SectionTitle title="Threat Intelligence" subtitle="Active threats, incident timeline, and attack surface overview" />
      <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:16, marginBottom:24 }}>
        <MetricCard icon="⚡" label="Events Today" value={d.siem?.eventsToday?.toLocaleString()||"284,710"} sub="From all security tools" color={C.primaryLight}/>
        <MetricCard icon="🎯" label="Active Incidents" value={d.siem?.activeIncidents||3} sub="Requiring response" trendUp={false} color={C.critical}/>
        <MetricCard icon="⏱" label="Mean Time to Detect" value={d.siem?.meanDetect||"4.2 min"} sub="Target: <5 min" trendUp={true} color={C.ok}/>
        <MetricCard icon="🌍" label="Blocked Today" value={(d.firewall?.blockedToday||12847).toLocaleString()} sub="Malicious connections" color={C.high}/>
      </div>
      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:16, marginBottom:16 }}>
        <Card style={{ padding:20 }}>
          <div style={{ fontSize:14, fontWeight:700, color:C.text, marginBottom:16 }}>Security Incidents – 2024</div>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={threatData}>
              <CartesianGrid strokeDasharray="3 3" stroke={C.border}/>
              <XAxis dataKey="name" tick={{fontSize:11,fill:C.muted}} tickLine={false} axisLine={false}/>
              <YAxis tick={{fontSize:11,fill:C.muted}} tickLine={false} axisLine={false}/>
              <Tooltip contentStyle={{background:C.card,border:`1px solid ${C.border}`,borderRadius:8,fontSize:12}}/>
              <Bar dataKey="incidents" fill={C.primaryLight} radius={[4,4,0,0]} name="Incidents"/>
            </BarChart>
          </ResponsiveContainer>
        </Card>
        <Card style={{ padding:20 }}>
          <div style={{ fontSize:14, fontWeight:700, color:C.text, marginBottom:16 }}>Top Threat Source Countries</div>
          {d.firewall?.topThreatCountries?.map((c,i)=>(
            <div key={c.country} style={{ display:"flex", alignItems:"center", gap:12, marginBottom:12 }}>
              <span style={{ fontSize:11, color:C.muted, width:20, textAlign:"right" }}>#{i+1}</span>
              <div style={{ flex:1 }}>
                <div style={{ display:"flex", justifyContent:"space-between", marginBottom:3 }}>
                  <span style={{ fontSize:12, fontWeight:600, color:C.text }}>{c.country}</span>
                  <span style={{ fontSize:12, color:C.muted }}>{c.count.toLocaleString()} attempts</span>
                </div>
                <div style={{ height:6, background:"#f1f5f9", borderRadius:3 }}>
                  <div style={{ height:"100%", width:`${(c.count/d.firewall.topThreatCountries[0].count)*100}%`, background:C.critical, borderRadius:3 }}/>
                </div>
              </div>
            </div>
          ))}
        </Card>
      </div>
      <Card style={{ padding:20 }}>
        <div style={{ fontSize:14, fontWeight:700, color:C.text, marginBottom:16 }}>Active SIEM Events – Past 12 Hours</div>
        <table style={{ width:"100%", borderCollapse:"collapse" }}>
          <thead>
            <tr style={{ background:"#f8fafc" }}>
              {["Time","Type","Severity","Description","Source","Status"].map(h=>(
                <th key={h} style={{ padding:"8px 12px", textAlign:"left", fontSize:11, fontWeight:700, color:C.muted, textTransform:"uppercase", letterSpacing:0.5, borderBottom:`2px solid ${C.border}` }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {d.siem?.events?.map((e,i)=>(
              <tr key={i} style={{ borderBottom:`1px solid ${C.border}` }}>
                <td style={{ padding:"10px 12px", fontSize:12, color:C.muted, fontFamily:"monospace" }}>{e.time}</td>
                <td style={{ padding:"10px 12px", fontSize:12, fontWeight:600, color:C.text }}>{e.type}</td>
                <td style={{ padding:"10px 12px" }}><SeverityBadge level={e.severity}/></td>
                <td style={{ padding:"10px 12px", fontSize:12, color:C.text }}>{e.desc}</td>
                <td style={{ padding:"10px 12px", fontSize:12, fontFamily:"monospace", color:C.muted }}>{e.src}</td>
                <td style={{ padding:"10px 12px" }}>
                  <span style={{ fontSize:11, fontWeight:600, color:e.status==="Active"?C.critical:e.status==="Contained"?C.ok:C.warn }}>{e.status}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  );
}

// ── Cloud Security – Executive View ─────────────────────────────────────────
function ComplianceDot({ status }) {
  const cfg = {
    Compliant:     ["#f0fdf4","#16a34a","✅"],
    "Non-Compliant":["#fef2f2","#dc2626","❌"],
    Warning:       ["#fffbeb","#d97706","⚠️"],
    Enabled:       ["#f0fdf4","#16a34a","✓"],
    Disabled:      ["#fef2f2","#dc2626","✗"],
    On:            ["#f0fdf4","#16a34a","✓"],
    Off:           ["#fef2f2","#dc2626","✗"],
    Enforced:      ["#f0fdf4","#16a34a","✓"],
    "Not Enforced":["#fef2f2","#dc2626","✗"],
    Current:       ["#f0fdf4","#16a34a","✓"],
    Critical:      ["#fef2f2","#dc2626","!"],
  }[status] || ["#f1f5f9","#64748b","–"];
  return (
    <span style={{ display:"inline-flex", alignItems:"center", justifyContent:"center", padding:"2px 8px",
      borderRadius:12, background:cfg[0], color:cfg[1], fontSize:11, fontWeight:700 }}>
      {cfg[2]} {status}
    </span>
  );
}

function CloudPage({ data }) {
  const d   = data || {};
  const az  = d.azure || {};
  if (!d._hasData || !az.subscriptions) return <NoData icon="☁️" title="No Azure cloud data yet" message="Configure Azure Defender credentials in ⚙️ Settings to see cloud security posture and asset inventory." />;
  const score = az.secureScore || 71;
  const totalResources = az.subscriptions?.reduce((s,x)=>s+x.resources,0) || 222;
  const highRecs = az.recommendations?.filter(r=>r.severity==="High").length || 3;

  const vmCompliant = az.virtualMachines?.filter(v=>v.compliance==="Compliant").length || 0;
  const vmTotal     = az.virtualMachines?.length || 0;

  return (
    <div>
      <SectionTitle title="Cloud Security – Microsoft Azure"
        subtitle="Security posture, deployed assets and Defender for Cloud recommendations" />

      {/* KPI row */}
      <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:16, marginBottom:24 }}>
        <MetricCard icon="☁️" label="Secure Score" value={`${score}%`}
          sub="Target: ≥85%" trendUp={false} color={score>=80?C.ok:C.warn}/>
        <MetricCard icon="🖥️" label="Total Resources" value={totalResources}
          sub={`Across ${az.subscriptions?.length||3} subscriptions`} color={C.primaryLight}/>
        <MetricCard icon="⚠️" label="High Recommendations" value={highRecs}
          sub="Require immediate attention" trendUp={false} color={C.high}/>
        <MetricCard icon="✅" label="VM Compliance" value={`${vmTotal>0?Math.round(vmCompliant/vmTotal*100):0}%`}
          sub={`${vmCompliant} of ${vmTotal} compliant`} trendUp={vmCompliant===vmTotal} color={C.ok}/>
      </div>

      {/* Subscriptions + score by category */}
      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:16, marginBottom:16 }}>
        <Card style={{ padding:20 }}>
          <div style={{ fontSize:14, fontWeight:700, color:C.text, marginBottom:16 }}>Subscriptions Overview</div>
          {az.subscriptions?.map(sub=>(
            <div key={sub.id} style={{ marginBottom:16 }}>
              <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:5 }}>
                <div>
                  <div style={{ fontSize:13, fontWeight:600, color:C.text }}>{sub.name}</div>
                  <div style={{ fontSize:11, color:C.muted }}>{sub.resources} resources</div>
                </div>
                <span style={{ fontSize:18, fontWeight:800, color:sub.score>=80?C.ok:sub.score>=65?C.warn:C.critical }}>{sub.score}%</span>
              </div>
              <div style={{ height:8, background:"#f1f5f9", borderRadius:4 }}>
                <div style={{ height:"100%", width:`${sub.score}%`, borderRadius:4,
                  background:`linear-gradient(90deg,${sub.score>=80?C.ok:sub.score>=65?C.warn:C.critical}99,${sub.score>=80?C.ok:sub.score>=65?C.warn:C.critical})` }}/>
              </div>
            </div>
          ))}
        </Card>
        <Card style={{ padding:20 }}>
          <div style={{ fontSize:14, fontWeight:700, color:C.text, marginBottom:16 }}>Security Score by Category</div>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={az.byCategory} layout="vertical" margin={{left:130,right:30,top:0,bottom:0}}>
              <CartesianGrid strokeDasharray="3 3" stroke={C.border} horizontal={false}/>
              <XAxis type="number" domain={[0,100]} tick={{fontSize:10,fill:C.muted}} tickLine={false} axisLine={false}/>
              <YAxis type="category" dataKey="cat" tick={{fontSize:11,fill:C.muted}} tickLine={false} axisLine={false} width={130}/>
              <Tooltip contentStyle={{background:C.card,border:`1px solid ${C.border}`,borderRadius:8,fontSize:12}}
                formatter={(v)=>[`${v}%`,"Score"]}/>
              <Bar dataKey="score" radius={[0,4,4,0]}>
                {az.byCategory?.map((c,i)=><Cell key={i} fill={c.score>=80?C.ok:c.score>=65?C.warn:C.critical}/>)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </Card>
      </div>

      {/* Asset inventory summary */}
      <Card style={{ padding:20, marginBottom:16 }}>
        <div style={{ fontSize:14, fontWeight:700, color:C.text, marginBottom:16 }}>Deployed Asset Inventory – Summary</div>
        <div style={{ display:"grid", gridTemplateColumns:"repeat(5,1fr)", gap:12 }}>
          {[
            {icon:"🖥️",label:"Virtual Machines",count:az.virtualMachines?.length||0,
              ok:az.virtualMachines?.filter(v=>v.compliance==="Compliant").length||0,color:"#3b82f6"},
            {icon:"💾",label:"Storage Accounts",count:az.storageAccounts?.length||0,
              ok:az.storageAccounts?.filter(v=>v.compliance==="Compliant").length||0,color:"#8b5cf6"},
            {icon:"🗄️",label:"Databases",count:az.databases?.length||0,
              ok:az.databases?.filter(v=>v.compliance==="Compliant").length||0,color:"#14b8a6"},
            {icon:"🌍",label:"Web / Functions",count:az.webApps?.length||0,
              ok:az.webApps?.filter(v=>v.compliance==="Compliant").length||0,color:"#f59e0b"},
            {icon:"🔑",label:"Key Vaults",count:az.keyVaults?.length||0,
              ok:az.keyVaults?.filter(v=>v.compliance==="Compliant").length||0,color:"#10b981"},
          ].map(a=>(
            <div key={a.label} style={{ background:"#f8fafc", borderRadius:10, padding:16, textAlign:"center", border:`1px solid ${C.border}` }}>
              <div style={{ fontSize:28 }}>{a.icon}</div>
              <div style={{ fontSize:26, fontWeight:800, color:C.text, lineHeight:1.2, marginTop:4 }}>{a.count}</div>
              <div style={{ fontSize:11, color:C.muted, marginTop:2 }}>{a.label}</div>
              <div style={{ fontSize:11, fontWeight:700, color:a.ok===a.count?C.ok:C.warn, marginTop:4 }}>
                {a.ok}/{a.count} Compliant
              </div>
            </div>
          ))}
        </div>
      </Card>

      {/* Recommendations + Alerts */}
      <div style={{ display:"grid", gridTemplateColumns:"3fr 2fr", gap:16 }}>
        <Card style={{ padding:20 }}>
          <div style={{ fontSize:14, fontWeight:700, color:C.text, marginBottom:16 }}>Top Security Recommendations</div>
          {az.recommendations?.filter(r=>r.severity!=="Low").slice(0,6).map((r,i)=>(
            <div key={i} style={{ display:"flex", gap:12, padding:"10px 0", borderBottom:`1px solid ${C.border}` }}>
              <SeverityBadge level={r.severity}/>
              <div style={{ flex:1 }}>
                <div style={{ fontSize:13, color:C.text, fontWeight:500 }}>{r.title}</div>
                <div style={{ fontSize:11, color:C.muted, marginTop:2 }}>{r.category} • {r.affected} resource{r.affected!==1?"s":""} • Effort: {r.effort}</div>
              </div>
            </div>
          ))}
        </Card>
        <Card style={{ padding:20 }}>
          <div style={{ fontSize:14, fontWeight:700, color:C.text, marginBottom:16 }}>Azure Defender Alerts</div>
          {az.azureAlerts?.map((a,i)=>(
            <div key={i} style={{ padding:"10px 0", borderBottom:`1px solid ${C.border}` }}>
              <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:3 }}>
                <SeverityBadge level={a.severity}/>
                <span style={{ fontSize:11, color:C.muted }}>{a.time}</span>
              </div>
              <div style={{ fontSize:12, color:C.text, fontWeight:500, marginTop:4 }}>{a.title}</div>
              <div style={{ fontSize:11, color:C.muted }}>{a.resource}</div>
            </div>
          ))}
        </Card>
      </div>
    </div>
  );
}

// ── Cloud Security – Analyst View ─────────────────────────────────────────────
function CloudAnalystPage({ data }) {
  const d  = data || {};
  const az = d.azure || {};
  if (!d._hasData || !az.subscriptions) return <NoData icon="☁️" title="No Azure cloud data yet" message="Configure Azure Defender credentials in ⚙️ Settings to populate the cloud security inventory." />;
  const [tab,    setTab]    = useState("vms");
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("All");

  const tabs = [
    {id:"vms",    label:"Virtual Machines",  count:az.virtualMachines?.length},
    {id:"storage",label:"Storage Accounts",  count:az.storageAccounts?.length},
    {id:"db",     label:"Databases",         count:az.databases?.length},
    {id:"apps",   label:"Web & Functions",   count:az.webApps?.length},
    {id:"kv",     label:"Key Vaults",        count:az.keyVaults?.length},
    {id:"recs",   label:"Recommendations",   count:az.recommendations?.length},
  ];

  function TableWrap({ headers, children }) {
    return (
      <table style={{ width:"100%", borderCollapse:"collapse" }}>
        <thead><tr style={{ background:"#f8fafc" }}>
          {headers.map(h=>(
            <th key={h} style={{ padding:"10px 12px", textAlign:"left", fontSize:11, fontWeight:700,
              color:C.muted, textTransform:"uppercase", letterSpacing:0.5, borderBottom:`2px solid ${C.border}` }}>{h}</th>
          ))}
        </tr></thead>
        <tbody>{children}</tbody>
      </table>
    );
  }

  const filterBar = (placeholder, filterOptions) => (
    <div style={{ display:"flex", gap:10, marginBottom:16, alignItems:"center" }}>
      <input value={search} onChange={e=>setSearch(e.target.value)} placeholder={placeholder}
        style={{ flex:1, padding:"7px 12px", borderRadius:8, border:`1px solid ${C.border}`, fontSize:13, outline:"none" }}/>
      {filterOptions && (
        <select value={filter} onChange={e=>setFilter(e.target.value)}
          style={{ padding:"7px 12px", borderRadius:8, border:`1px solid ${C.border}`, fontSize:13, background:"white" }}>
          {filterOptions.map(o=><option key={o}>{o}</option>)}
        </select>
      )}
    </div>
  );

  function renderTab() {
    const q = search.toLowerCase();

    if (tab === "vms") {
      const rows = (az.virtualMachines||[]).filter(v=>
        (filter==="All"||v.compliance===filter) &&
        (!q||v.name.toLowerCase().includes(q)||v.rg.toLowerCase().includes(q)||v.os.toLowerCase().includes(q))
      );
      return (
        <div>
          {filterBar("Search by name, resource group, OS…", ["All","Compliant","Non-Compliant","Warning"])}
          <div style={{ fontSize:12, color:C.muted, marginBottom:12 }}>{rows.length} of {az.virtualMachines?.length} VMs shown</div>
          <TableWrap headers={["VM Name","Resource Group","OS","Size","Status","Patches","Defender","Compliance"]}>
            {rows.map((v,i)=>(
              <tr key={i} style={{ borderBottom:`1px solid ${C.border}`, background:v.compliance==="Non-Compliant"?"#fef2f208":"transparent" }}>
                <td style={{ padding:"10px 12px", fontSize:13, fontWeight:600, color:C.primary }}>{v.name}</td>
                <td style={{ padding:"10px 12px", fontSize:12, color:C.muted }}>{v.rg}</td>
                <td style={{ padding:"10px 12px", fontSize:12, color:C.text }}>{v.os}</td>
                <td style={{ padding:"10px 12px", fontSize:11, fontFamily:"monospace", color:C.muted }}>{v.size}</td>
                <td style={{ padding:"10px 12px" }}>
                  <span style={{ fontSize:11, fontWeight:600, color:v.status==="Running"?C.ok:C.muted }}>{v.status}</span>
                </td>
                <td style={{ padding:"10px 12px" }}><ComplianceDot status={v.patches}/></td>
                <td style={{ padding:"10px 12px" }}><ComplianceDot status={v.defender}/></td>
                <td style={{ padding:"10px 12px" }}><ComplianceDot status={v.compliance}/></td>
              </tr>
            ))}
          </TableWrap>
        </div>
      );
    }

    if (tab === "storage") {
      const rows = (az.storageAccounts||[]).filter(v=>!q||v.name.toLowerCase().includes(q)||v.rg.toLowerCase().includes(q));
      return (
        <div>
          {filterBar("Search storage accounts…")}
          <TableWrap headers={["Account Name","Resource Group","Kind","Replication","Encryption","Public Access","HTTPS Only","Compliance"]}>
            {rows.map((v,i)=>(
              <tr key={i} style={{ borderBottom:`1px solid ${C.border}` }}>
                <td style={{ padding:"10px 12px", fontSize:13, fontWeight:600, color:C.primary }}>{v.name}</td>
                <td style={{ padding:"10px 12px", fontSize:12, color:C.muted }}>{v.rg}</td>
                <td style={{ padding:"10px 12px", fontSize:11, color:C.text }}>{v.kind}</td>
                <td style={{ padding:"10px 12px", fontSize:11, color:C.text }}>{v.replication}</td>
                <td style={{ padding:"10px 12px" }}><ComplianceDot status={v.encryption}/></td>
                <td style={{ padding:"10px 12px" }}>
                  <span style={{ fontSize:11,fontWeight:700,color:v.publicAccess==="Disabled"?C.ok:C.critical }}>{v.publicAccess}</span>
                </td>
                <td style={{ padding:"10px 12px" }}><ComplianceDot status={v.https}/></td>
                <td style={{ padding:"10px 12px" }}><ComplianceDot status={v.compliance}/></td>
              </tr>
            ))}
          </TableWrap>
        </div>
      );
    }

    if (tab === "db") {
      const rows = (az.databases||[]).filter(v=>!q||v.name.toLowerCase().includes(q));
      return (
        <div>
          {filterBar("Search databases…")}
          <TableWrap headers={["Database","Type","Resource Group","Encryption (TDE)","Auditing","Threat Detect","Firewall","Compliance"]}>
            {rows.map((v,i)=>(
              <tr key={i} style={{ borderBottom:`1px solid ${C.border}` }}>
                <td style={{ padding:"10px 12px", fontSize:13, fontWeight:600, color:C.primary }}>{v.name}</td>
                <td style={{ padding:"10px 12px", fontSize:12, color:C.text }}>{v.type}</td>
                <td style={{ padding:"10px 12px", fontSize:12, color:C.muted }}>{v.rg}</td>
                <td style={{ padding:"10px 12px" }}><ComplianceDot status={v.tde}/></td>
                <td style={{ padding:"10px 12px" }}><ComplianceDot status={v.audit}/></td>
                <td style={{ padding:"10px 12px" }}><ComplianceDot status={v.threat}/></td>
                <td style={{ padding:"10px 12px" }}>
                  <span style={{ fontSize:11, fontWeight:700, color:v.firewall==="Configured"?C.ok:C.critical }}>{v.firewall}</span>
                </td>
                <td style={{ padding:"10px 12px" }}><ComplianceDot status={v.compliance}/></td>
              </tr>
            ))}
          </TableWrap>
        </div>
      );
    }

    if (tab === "apps") {
      const rows = (az.webApps||[]).filter(v=>!q||v.name.toLowerCase().includes(q)||v.rg.toLowerCase().includes(q));
      return (
        <div>
          {filterBar("Search web apps & functions…")}
          <TableWrap headers={["App Name","Resource Group","Runtime","HTTPS","Authentication","Min TLS","Compliance"]}>
            {rows.map((v,i)=>(
              <tr key={i} style={{ borderBottom:`1px solid ${C.border}` }}>
                <td style={{ padding:"10px 12px", fontSize:13, fontWeight:600, color:C.primary }}>{v.name}</td>
                <td style={{ padding:"10px 12px", fontSize:12, color:C.muted }}>{v.rg}</td>
                <td style={{ padding:"10px 12px", fontSize:11, color:C.text }}>{v.runtime}</td>
                <td style={{ padding:"10px 12px" }}><ComplianceDot status={v.https}/></td>
                <td style={{ padding:"10px 12px" }}>
                  <span style={{ fontSize:12, color:v.auth==="None"?C.critical:C.ok, fontWeight:600 }}>{v.auth}</span>
                </td>
                <td style={{ padding:"10px 12px" }}>
                  <span style={{ fontSize:11, fontWeight:700, color:v.tls==="1.0"?C.critical:C.ok }}>{v.tls}</span>
                </td>
                <td style={{ padding:"10px 12px" }}><ComplianceDot status={v.compliance}/></td>
              </tr>
            ))}
          </TableWrap>
        </div>
      );
    }

    if (tab === "kv") {
      const rows = (az.keyVaults||[]).filter(v=>!q||v.name.toLowerCase().includes(q));
      return (
        <div>
          {filterBar("Search key vaults…")}
          <TableWrap headers={["Key Vault","Resource Group","Purge Protection","Soft Delete","RBAC","Compliance"]}>
            {rows.map((v,i)=>(
              <tr key={i} style={{ borderBottom:`1px solid ${C.border}` }}>
                <td style={{ padding:"10px 12px", fontSize:13, fontWeight:600, color:C.primary }}>{v.name}</td>
                <td style={{ padding:"10px 12px", fontSize:12, color:C.muted }}>{v.rg}</td>
                <td style={{ padding:"10px 12px" }}><ComplianceDot status={v.purge}/></td>
                <td style={{ padding:"10px 12px", fontSize:12, color:C.text }}>{v.soft}</td>
                <td style={{ padding:"10px 12px" }}><ComplianceDot status={v.rbac}/></td>
                <td style={{ padding:"10px 12px" }}><ComplianceDot status={v.compliance}/></td>
              </tr>
            ))}
          </TableWrap>
        </div>
      );
    }

    if (tab === "recs") {
      const rows = (az.recommendations||[]).filter(r=>
        (filter==="All"||r.severity===filter) &&
        (!q||r.title.toLowerCase().includes(q)||r.category.toLowerCase().includes(q))
      );
      return (
        <div>
          {filterBar("Search recommendations…", ["All","High","Medium","Low"])}
          <TableWrap headers={["Severity","Recommendation","Category","Affected Resources","Effort"]}>
            {rows.map((r,i)=>(
              <tr key={i} style={{ borderBottom:`1px solid ${C.border}` }}>
                <td style={{ padding:"10px 12px" }}><SeverityBadge level={r.severity}/></td>
                <td style={{ padding:"10px 12px", fontSize:13, color:C.text }}>{r.title}</td>
                <td style={{ padding:"10px 12px", fontSize:12, color:C.muted }}>{r.category}</td>
                <td style={{ padding:"10px 12px", fontSize:13, fontWeight:700, color:C.text, textAlign:"center" }}>{r.affected}</td>
                <td style={{ padding:"10px 12px" }}>
                  <span style={{ fontSize:11, fontWeight:600, padding:"3px 10px", borderRadius:20,
                    background:r.effort==="Low"?"#f0fdf4":r.effort==="Medium"?"#fffbeb":"#fef2f2",
                    color:r.effort==="Low"?C.ok:r.effort==="Medium"?C.warn:C.critical }}>{r.effort}</span>
                </td>
              </tr>
            ))}
          </TableWrap>
        </div>
      );
    }
  }

  return (
    <div>
      <SectionTitle title="Cloud Security – Azure Asset Inventory"
        subtitle="Complete inventory of all Azure deployed resources with security posture and compliance status" />

      {/* Score + subscription tiles */}
      <div style={{ display:"grid", gridTemplateColumns:"160px 1fr", gap:16, marginBottom:24 }}>
        <Card style={{ padding:20, display:"flex", flexDirection:"column", alignItems:"center", justifyContent:"center" }}>
          <div style={{ fontSize:14, color:C.muted, marginBottom:4 }}>Secure Score</div>
          <div style={{ fontSize:56, fontWeight:900, color:az.secureScore>=80?C.ok:az.secureScore>=65?C.warn:C.critical, lineHeight:1 }}>
            {az.secureScore||71}
          </div>
          <div style={{ fontSize:13, color:C.muted }}>/ 100</div>
        </Card>
        <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:12 }}>
          {az.subscriptions?.map(sub=>(
            <Card key={sub.id} style={{ padding:16 }}>
              <div style={{ fontSize:12, fontWeight:700, color:C.text }}>{sub.name}</div>
              <div style={{ fontSize:11, color:C.muted, marginBottom:8 }}>{sub.resources} resources</div>
              <div style={{ fontSize:24, fontWeight:800, color:sub.score>=80?C.ok:sub.score>=65?C.warn:C.critical }}>{sub.score}%</div>
              <div style={{ height:5, background:"#f1f5f9", borderRadius:3, marginTop:6 }}>
                <div style={{ height:"100%", width:`${sub.score}%`, background:sub.score>=80?C.ok:sub.score>=65?C.warn:C.critical, borderRadius:3 }}/>
              </div>
            </Card>
          ))}
        </div>
      </div>

      {/* Tab navigation + content */}
      <Card style={{ padding:0, overflow:"hidden" }}>
        {/* Tabs */}
        <div style={{ display:"flex", borderBottom:`2px solid ${C.border}`, background:"#f8fafc", overflowX:"auto" }}>
          {tabs.map(t=>(
            <button key={t.id} onClick={()=>{ setTab(t.id); setSearch(""); setFilter("All"); }}
              style={{ padding:"12px 20px", border:"none", borderBottom:`2px solid ${tab===t.id?C.primary:"transparent"}`,
                marginBottom:-2, background:"transparent", cursor:"pointer", whiteSpace:"nowrap",
                color:tab===t.id?C.primary:C.muted, fontWeight:tab===t.id?700:400, fontSize:13,
                display:"flex", alignItems:"center", gap:6 }}>
              {t.label}
              <span style={{ background:tab===t.id?C.primary:C.border, color:tab===t.id?"white":C.muted,
                borderRadius:10, padding:"1px 7px", fontSize:10, fontWeight:700 }}>{t.count}</span>
            </button>
          ))}
        </div>
        <div style={{ padding:20 }}>{renderTab()}</div>
      </Card>
    </div>
  );
}

// ── Executive Report ─────────────────────────────────────────────────────────
function ReportPage({ data }) {
  const d = data || {};
  if (!d._hasData) return <NoData icon="📊" title="No data for report yet" message="Connect your integrations in ⚙️ Settings. Reports generate automatically once data is collected." />;
  const avgCompliance = (d.compliance||[]).length ? Math.round((d.compliance||[]).reduce((s,c)=>s+c.score,0)/(d.compliance||[]).length) : 0;
  const critAlerts = (d.alerts||[]).filter(a=>a.severity==="Critical").length;
  const openVulns = d.vulnerabilities?.filter(v=>v.status!=="Resolved").length || 0;
  return (
    <div>
      <SectionTitle title="Executive Security Report"
        subtitle={`Prepared for Board Review – ${new Date().toLocaleDateString("en-AU",{year:"numeric",month:"long"})}`}
        action={<button onClick={()=>window.print()} style={{ background:C.primary, color:"white", border:"none", borderRadius:8, padding:"8px 18px", fontSize:13, fontWeight:600, cursor:"pointer" }}>🖨️ Print / Export PDF</button>}/>
      <Card style={{ padding:36, maxWidth:800, margin:"0 auto" }}>
        {/* Letterhead */}
        <div style={{ borderBottom:`3px solid ${C.primary}`, paddingBottom:20, marginBottom:24, display:"flex", justifyContent:"space-between", alignItems:"flex-end" }}>
          <div>
            <div style={{ fontSize:22, fontWeight:800, color:C.text }}>Security Operations Report</div>
            <div style={{ fontSize:14, color:C.muted, marginTop:4 }}>{new Date().toLocaleDateString("en-AU",{weekday:"long",year:"numeric",month:"long",day:"numeric"})}</div>
          </div>
          <div style={{ fontSize:32 }}>🛡️</div>
        </div>

        {/* Executive Summary */}
        <div style={{ background:"#eff6ff", borderRadius:10, padding:20, marginBottom:24, borderLeft:`4px solid ${C.primary}` }}>
          <div style={{ fontSize:14, fontWeight:700, color:C.primary, marginBottom:8 }}>Executive Summary</div>
          <div style={{ fontSize:13, color:C.text, lineHeight:1.8 }}>
            The organisation's overall security posture is rated <strong>MODERATE</strong> with a health score of <strong>{d.score}/100</strong>.
            {" "}The security programme has improved by 3 points over the past month. There are currently <strong>{critAlerts} critical</strong> and{" "}
            <strong>{(d.alerts||[]).filter(a=>a.severity==="High").length} high</strong> severity alerts requiring attention, and <strong>{openVulns} open vulnerabilities</strong>{" "}
            across the environment. Average compliance posture across all frameworks stands at <strong>{avgCompliance}%</strong>.
          </div>
        </div>

        {/* Metrics table */}
        <div style={{ fontSize:14, fontWeight:700, color:C.text, marginBottom:12 }}>Key Performance Indicators</div>
        <table style={{ width:"100%", borderCollapse:"collapse", marginBottom:24 }}>
          <thead><tr style={{ background:"#f8fafc" }}>
            {["Metric","Current","Target","Status"].map(h=>(
              <th key={h} style={{ padding:"10px 16px", textAlign:"left", fontSize:12, fontWeight:700, color:C.muted, textTransform:"uppercase", letterSpacing:0.5, borderBottom:`2px solid ${C.border}` }}>{h}</th>
            ))}
          </tr></thead>
          <tbody>
            {[
              {metric:"Security Health Score", current:`${d.score}/100`, target:"≥80/100", ok:d.score>=80},
              {metric:"Critical Alerts (Open)", current:critAlerts, target:"0", ok:critAlerts===0},
              {metric:"Mean Time to Detect", current:"4.2 min", target:"<5 min", ok:true},
              {metric:"Patch Compliance", current:`${d.assets?.patchedPct||72}%`, target:"≥95%", ok:(d.assets?.patchedPct||72)>=95},
              {metric:"Avg Compliance Score", current:`${avgCompliance}%`, target:"≥85%", ok:avgCompliance>=85},
              {metric:"Endpoint Encryption", current:`${d.assets?.encryptedPct||85}%`, target:"100%", ok:(d.assets?.encryptedPct||85)>=100},
            ].map(r=>(
              <tr key={r.metric} style={{ borderBottom:`1px solid ${C.border}` }}>
                <td style={{ padding:"10px 16px", fontSize:13, color:C.text, fontWeight:500 }}>{r.metric}</td>
                <td style={{ padding:"10px 16px", fontSize:13, fontWeight:700, color:C.text }}>{r.current}</td>
                <td style={{ padding:"10px 16px", fontSize:13, color:C.muted }}>{r.target}</td>
                <td style={{ padding:"10px 16px" }}>
                  <span style={{ fontSize:12, fontWeight:600, color:r.ok?C.ok:C.critical }}>{r.ok?"✅ On Target":"⚠️ Below Target"}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {/* Recommendations */}
        <div style={{ fontSize:14, fontWeight:700, color:C.text, marginBottom:12 }}>Board Recommendations</div>
        {[
          { n:1, text:"Approve emergency patching window for critical CVEs on 14 affected hosts. Risk of ransomware exploitation is HIGH without immediate action." },
          { n:2, text:"Mandate MFA enforcement across all privileged accounts within 30 days. Current coverage of 63% fails Essential Eight compliance." },
          { n:3, text:"Fund dedicated Vulnerability Management programme to close patch cycle gap and reach <5% non-compliant endpoints." },
          { n:4, text:"Review and approve updated Incident Response Plan incorporating ransomware-specific playbooks." },
        ].map(r=>(
          <div key={r.n} style={{ display:"flex", gap:12, marginBottom:12, padding:14, background:"#f8fafc", borderRadius:8 }}>
            <div style={{ width:24, height:24, background:C.primary, borderRadius:"50%", color:"white", fontSize:11, fontWeight:700, display:"flex", alignItems:"center", justifyContent:"center", flexShrink:0 }}>{r.n}</div>
            <div style={{ fontSize:13, color:C.text, lineHeight:1.6 }}>{r.text}</div>
          </div>
        ))}
      </Card>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════
   ANALYST PAGES
═══════════════════════════════════════════════════════════════════════════ */

// ── Alert Queue ──────────────────────────────────────────────────────────────
function AlertsPage({ data }) {
  const d = data || {};
  if (!d._hasData) return <NoData icon="🚨" title="No alerts yet" message="Connect Taegis XDR or Azure Defender in ⚙️ Settings to see live alerts." />;
  const alertList = d.alerts || [];
  const [filter, setFilter] = useState("All");
  const [search, setSearch] = useState("");
  const [toolFilter, setToolFilter] = useState("All");
  const severities = ["All","Critical","High","Medium","Low"];
  const filtered = (d.alerts||[]).filter(a=>
    (filter==="All"||a.severity===filter) &&
    (toolFilter==="All"||a.tool===toolFilter) &&
    (search===""||a.title.toLowerCase().includes(search.toLowerCase())||a.resource.toLowerCase().includes(search.toLowerCase()))
  );
  const counts = {};
  d.alerts.forEach(a=>{ counts[a.severity]=(counts[a.severity]||0)+1; });
  return (
    <div>
      <SectionTitle title="Alert Queue" subtitle="Real-time alerts from all connected security tools" />
      <div style={{ display:"grid", gridTemplateColumns:"repeat(5,1fr)", gap:12, marginBottom:20 }}>
        {severities.map(s=>(
          <button key={s} onClick={()=>setFilter(s)}
            style={{ padding:"10px 6px", borderRadius:8, border:`2px solid ${filter===s?(SEVERITY_COLORS[s]||C.primary):C.border}`,
              background:filter===s?`${SEVERITY_COLORS[s]||C.primary}12`:"white", cursor:"pointer", textAlign:"center" }}>
            <div style={{ fontSize:18, fontWeight:800, color:SEVERITY_COLORS[s]||C.text }}>{s==="All"?(d.alerts||[]).length:counts[s]||0}</div>
            <div style={{ fontSize:10, fontWeight:600, color:C.muted, textTransform:"uppercase", letterSpacing:0.5 }}>{s}</div>
          </button>
        ))}
      </div>
      <Card style={{ padding:20 }}>
        <div style={{ display:"flex", gap:12, marginBottom:16 }}>
          <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search alerts..."
            style={{ flex:1, padding:"8px 14px", borderRadius:8, border:`1px solid ${C.border}`, fontSize:13, outline:"none" }}/>
          <select value={toolFilter} onChange={e=>setToolFilter(e.target.value)}
            style={{ padding:"8px 14px", borderRadius:8, border:`1px solid ${C.border}`, fontSize:13, outline:"none", background:"white" }}>
            <option value="All">All Tools</option>
            {TOOLS.map(t=><option key={t.key} value={t.key}>{t.name}</option>)}
          </select>
        </div>
        <table style={{ width:"100%", borderCollapse:"collapse" }}>
          <thead><tr style={{ background:"#f8fafc" }}>
            {["Severity","Title","Tool","Resource","Time","Status"].map(h=>(
              <th key={h} style={{ padding:"10px 12px", textAlign:"left", fontSize:11, fontWeight:700, color:C.muted, textTransform:"uppercase", letterSpacing:0.5, borderBottom:`2px solid ${C.border}` }}>{h}</th>
            ))}
          </tr></thead>
          <tbody>
            {filtered.map(a=>(
              <tr key={a.id} style={{ borderBottom:`1px solid ${C.border}`, background:a.severity==="Critical"?"#fef2f220":"transparent" }}>
                <td style={{ padding:"12px 12px" }}><SeverityBadge level={a.severity}/></td>
                <td style={{ padding:"12px 12px", fontSize:13, color:C.text, fontWeight:500 }}>{a.title}</td>
                <td style={{ padding:"12px 12px" }}>
                  <span style={{ display:"flex", alignItems:"center", gap:4, fontSize:12 }}>
                    <span>{TOOLS.find(t=>t.key===a.tool)?.icon}</span>
                    <span style={{ color:C.muted }}>{TOOLS.find(t=>t.key===a.tool)?.name}</span>
                  </span>
                </td>
                <td style={{ padding:"12px 12px", fontSize:12, fontFamily:"monospace", color:C.muted }}>{a.resource}</td>
                <td style={{ padding:"12px 12px", fontSize:12, color:C.muted }}>{a.time}</td>
                <td style={{ padding:"12px 12px" }}>
                  <span style={{ fontSize:11, fontWeight:600, padding:"3px 10px", borderRadius:20,
                    background:a.status==="Open"?"#fef2f2":a.status==="Resolved"?"#f0fdf4":"#fffbeb",
                    color:a.status==="Open"?C.critical:a.status==="Resolved"?C.ok:C.warn }}>{a.status}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {filtered.length===0&&<div style={{ textAlign:"center", padding:32, color:C.muted, fontSize:13 }}>No alerts match current filters</div>}
      </Card>
    </div>
  );
}

// ── Vulnerability Deep Dive ──────────────────────────────────────────────────
function VulnerabilitiesPage({ data }) {
  const d = data || {};
  if (!d._hasData) return <NoData icon="🔍" title="No vulnerability data yet" message="Connect Qualys VMDR in ⚙️ Settings to see live vulnerability scan results." />;
  const [sort, setSort] = useState("cvss");
  const vulns = [...(d.vulnerabilities||[])].sort((a,b)=> sort==="cvss"?b.cvss-a.cvss:sort==="age"?b.age-a.age:b.affected-a.affected);
  const bySev = {};
  (d.vulnerabilities||[]).forEach(v=>{ bySev[v.severity]=(bySev[v.severity]||0)+1; });
  const pieData = Object.entries(bySev).map(([k,v])=>({name:k,value:v,color:SEVERITY_COLORS[k]}));
  return (
    <div>
      <SectionTitle title="Vulnerability Management – Qualys VMDR" subtitle="Detailed vulnerability findings, CVE analysis and remediation tracking" />
      <div style={{ display:"grid", gridTemplateColumns:"1fr 240px", gap:16, marginBottom:24 }}>
        <Card style={{ padding:20 }}>
          <div style={{ fontSize:14, fontWeight:700, color:C.text, marginBottom:12 }}>Vulnerability Distribution</div>
          <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:12 }}>
            {["Critical","High","Medium","Low"].map(s=>(
              <div key={s} style={{ textAlign:"center", padding:16, borderRadius:10, background:`${SEVERITY_COLORS[s]}10`, border:`1px solid ${SEVERITY_COLORS[s]}30` }}>
                <div style={{ fontSize:28, fontWeight:800, color:SEVERITY_COLORS[s] }}>{bySev[s]||0}</div>
                <div style={{ fontSize:11, color:C.muted, marginTop:4 }}>{s}</div>
              </div>
            ))}
          </div>
        </Card>
        <Card style={{ padding:20 }}>
          <div style={{ fontSize:13, fontWeight:700, color:C.text, marginBottom:8 }}>By Severity</div>
          <ResponsiveContainer width="100%" height={160}>
            <PieChart><Pie data={pieData} cx="50%" cy="50%" outerRadius={65} dataKey="value">
              {pieData.map((e,i)=><Cell key={i} fill={e.color}/>)}
            </Pie>
            <Tooltip contentStyle={{borderRadius:8,fontSize:12}}/></PieChart>
          </ResponsiveContainer>
        </Card>
      </div>
      <Card style={{ padding:20 }}>
        <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:16 }}>
          <div style={{ fontSize:14, fontWeight:700, color:C.text }}>CVE Detail – Prioritised Remediation List</div>
          <div style={{ display:"flex", gap:8 }}>
            {[["cvss","By CVSS"],["affected","By Hosts Affected"],["age","By Age"]].map(([v,l])=>(
              <button key={v} onClick={()=>setSort(v)}
                style={{ padding:"6px 14px", borderRadius:6, border:`1px solid ${sort===v?C.primary:C.border}`,
                  background:sort===v?`${C.primary}12`:"white", color:sort===v?C.primary:C.muted, fontSize:12, cursor:"pointer", fontWeight:600 }}>{l}</button>
            ))}
          </div>
        </div>
        <table style={{ width:"100%", borderCollapse:"collapse" }}>
          <thead><tr style={{ background:"#f8fafc" }}>
            {["CVE","Severity","CVSS","Title","Affected Hosts","Age (days)","Status"].map(h=>(
              <th key={h} style={{ padding:"10px 12px", textAlign:"left", fontSize:11, fontWeight:700, color:C.muted, textTransform:"uppercase", letterSpacing:0.5, borderBottom:`2px solid ${C.border}` }}>{h}</th>
            ))}
          </tr></thead>
          <tbody>
            {vulns.map(v=>(
              <tr key={v.id} style={{ borderBottom:`1px solid ${C.border}` }}>
                <td style={{ padding:"12px 12px", fontFamily:"monospace", fontSize:12, fontWeight:700, color:C.primary }}>{v.cve}</td>
                <td style={{ padding:"12px 12px" }}><SeverityBadge level={v.severity}/></td>
                <td style={{ padding:"12px 12px" }}>
                  <span style={{ fontSize:14, fontWeight:800, color:v.cvss>=9?C.critical:v.cvss>=7?C.high:C.medium }}>{v.cvss}</span>
                </td>
                <td style={{ padding:"12px 12px", fontSize:12, color:C.text }}>{v.title}</td>
                <td style={{ padding:"12px 12px", fontSize:13, fontWeight:700, color:C.text, textAlign:"center" }}>{v.affected}</td>
                <td style={{ padding:"12px 12px", fontSize:12, color:v.age>30?C.critical:v.age>14?C.warn:C.muted, fontWeight:v.age>14?700:400 }}>{v.age}d</td>
                <td style={{ padding:"12px 12px" }}>
                  <span style={{ fontSize:11, fontWeight:600, padding:"3px 10px", borderRadius:20,
                    background:v.status==="Unpatched"?"#fef2f2":v.status==="In Progress"?"#fffbeb":"#f0fdf4",
                    color:v.status==="Unpatched"?C.critical:v.status==="In Progress"?C.warn:C.ok }}>{v.status}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  );
}

// ── Firewall Analytics ───────────────────────────────────────────────────────
function FirewallPage({ data }) {
  const d = data || {};
  if (!d._hasData) return <NoData icon="🔥" title="No firewall data yet" message="Connect Fortinet or Palo Alto in ⚙️ Settings to see live firewall analytics." />;
  return (
    <div>
      <SectionTitle title="Firewall Analytics – Fortinet & Palo Alto" subtitle="Traffic analysis, policy hits and threat blocking statistics" />
      <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:16, marginBottom:24 }}>
        <MetricCard icon="🚫" label="Blocked Today" value={(d.firewall?.blockedToday||12847).toLocaleString()} sub="Malicious connections" color={C.critical}/>
        <MetricCard icon="✅" label="Allowed Today" value={(d.firewall?.allowedToday||184293).toLocaleString()} sub="Legitimate traffic" color={C.ok}/>
        <MetricCard icon="📊" label="Block Rate" value={`${Math.round(d.firewall?.blockedToday/(d.firewall?.blockedToday+d.firewall?.allowedToday)*100)||6.5}%`} sub="Of total traffic" color={C.primaryLight}/>
        <MetricCard icon="⚡" label="IPS Signatures" value="47,231" sub="Active threat signatures" color={C.primary}/>
      </div>
      <Card style={{ padding:20, marginBottom:16 }}>
        <div style={{ fontSize:14, fontWeight:700, color:C.text, marginBottom:16 }}>Traffic Volume – Last 24 Hours</div>
        <ResponsiveContainer width="100%" height={220}>
          <AreaChart data={d.firewall?.trafficByHour||[]} margin={{top:5,right:10,left:-10,bottom:0}}>
            <defs>
              <linearGradient id="blockGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={C.critical} stopOpacity={0.3}/><stop offset="95%" stopColor={C.critical} stopOpacity={0}/>
              </linearGradient>
              <linearGradient id="allowGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={C.ok} stopOpacity={0.3}/><stop offset="95%" stopColor={C.ok} stopOpacity={0}/>
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke={C.border}/>
            <XAxis dataKey="hour" tick={{fontSize:10,fill:C.muted}} tickLine={false} axisLine={false} interval={3}/>
            <YAxis tick={{fontSize:10,fill:C.muted}} tickLine={false} axisLine={false}/>
            <Tooltip contentStyle={{background:C.card,border:`1px solid ${C.border}`,borderRadius:8,fontSize:12}}/>
            <Legend iconType="circle" wrapperStyle={{fontSize:12}}/>
            <Area type="monotone" dataKey="allowed" name="Allowed" stroke={C.ok} fill="url(#allowGrad)" strokeWidth={2}/>
            <Area type="monotone" dataKey="blocked" name="Blocked" stroke={C.critical} fill="url(#blockGrad)" strokeWidth={2}/>
          </AreaChart>
        </ResponsiveContainer>
      </Card>
      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:16 }}>
        <Card style={{ padding:20 }}>
          <div style={{ fontSize:14, fontWeight:700, color:C.text, marginBottom:16 }}>Top Firewall Policy Hits</div>
          <table style={{ width:"100%", borderCollapse:"collapse" }}>
            <thead><tr><th style={{ padding:"8px 10px", textAlign:"left", fontSize:11, fontWeight:700, color:C.muted, textTransform:"uppercase", borderBottom:`2px solid ${C.border}` }}>Policy</th>
              <th style={{ padding:"8px 10px", textAlign:"right", fontSize:11, fontWeight:700, color:C.muted, textTransform:"uppercase", borderBottom:`2px solid ${C.border}` }}>Hits</th>
              <th style={{ padding:"8px 10px", textAlign:"center", fontSize:11, fontWeight:700, color:C.muted, textTransform:"uppercase", borderBottom:`2px solid ${C.border}` }}>Action</th>
            </tr></thead>
            <tbody>{d.firewall?.topPolicies?.map((p,i)=>(
              <tr key={i} style={{ borderBottom:`1px solid ${C.border}` }}>
                <td style={{ padding:"10px 10px", fontSize:12, color:C.text }}>{p.name}</td>
                <td style={{ padding:"10px 10px", fontSize:13, fontWeight:700, color:C.text, textAlign:"right" }}>{p.hits.toLocaleString()}</td>
                <td style={{ padding:"10px 10px", textAlign:"center" }}>
                  <span style={{ fontSize:11, fontWeight:600, padding:"2px 8px", borderRadius:10,
                    background:p.action==="Allow"?"#f0fdf4":"#fef2f2", color:p.action==="Allow"?C.ok:C.critical }}>{p.action}</span>
                </td>
              </tr>
            ))}</tbody>
          </table>
        </Card>
        <Card style={{ padding:20 }}>
          <div style={{ fontSize:14, fontWeight:700, color:C.text, marginBottom:16 }}>Top Threat Source Countries</div>
          {d.firewall?.topThreatCountries?.map((c,i)=>(
            <div key={c.country} style={{ display:"flex", alignItems:"center", gap:12, marginBottom:14 }}>
              <div style={{ width:28, height:28, background:`${C.critical}15`, borderRadius:6, display:"flex", alignItems:"center", justifyContent:"center", fontSize:11, fontWeight:800, color:C.critical }}>{i+1}</div>
              <div style={{ flex:1 }}>
                <div style={{ display:"flex", justifyContent:"space-between", marginBottom:4 }}>
                  <span style={{ fontSize:12, fontWeight:600, color:C.text }}>{c.country}</span>
                  <span style={{ fontSize:12, color:C.muted }}>{c.count.toLocaleString()}</span>
                </div>
                <div style={{ height:6, background:"#f1f5f9", borderRadius:3 }}>
                  <div style={{ height:"100%", width:`${(c.count/d.firewall.topThreatCountries[0].count)*100}%`, background:`linear-gradient(90deg,${C.critical}aa,${C.critical})`, borderRadius:3 }}/>
                </div>
              </div>
            </div>
          ))}
        </Card>
      </div>
    </div>
  );
}

// ── Attack Surface ───────────────────────────────────────────────────────────
function AttackSurfacePage({ data }) {
  const d = data || {};
  if (!d._hasData) return <NoData icon="🌐" title="No attack surface data yet" message="Connect UpGuard in ⚙️ Settings to see your external attack surface data." />;
  const s = d.surface;
  const gradeColor = s?.grade?.startsWith("A")?C.ok:s?.grade?.startsWith("B")?C.ok:s?.grade?.startsWith("C")?C.warn:C.critical;
  return (
    <div>
      <SectionTitle title="Attack Surface – UpGuard" subtitle="External exposure monitoring, risk findings and brand protection" />
      <div style={{ display:"grid", gridTemplateColumns:"200px 1fr", gap:16, marginBottom:24 }}>
        <Card style={{ padding:24, display:"flex", flexDirection:"column", alignItems:"center", justifyContent:"center" }}>
          <div style={{ fontSize:72, fontWeight:900, color:gradeColor, lineHeight:1 }}>{s?.grade||"C+"}</div>
          <div style={{ fontSize:14, color:C.muted, marginTop:8 }}>Surface Score</div>
          <div style={{ fontSize:28, fontWeight:800, color:C.text, marginTop:4 }}>{s?.score||68}/100</div>
        </Card>
        <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:12 }}>
          {[
            {icon:"🌐",label:"Domains",value:s?.domains||12},{icon:"🔗",label:"Subdomains",value:s?.subdomains||34},
            {icon:"🔌",label:"Open Ports",value:s?.openPorts||18},{icon:"📡",label:"IP Ranges",value:s?.ipRanges||5},
          ].map(m=>(
            <Card key={m.label} style={{ padding:16, textAlign:"center" }}>
              <div style={{ fontSize:24 }}>{m.icon}</div>
              <div style={{ fontSize:24, fontWeight:800, color:C.text, marginTop:4 }}>{m.value}</div>
              <div style={{ fontSize:11, color:C.muted }}>{m.label}</div>
            </Card>
          ))}
        </div>
      </div>
      <Card style={{ padding:20 }}>
        <div style={{ fontSize:14, fontWeight:700, color:C.text, marginBottom:16 }}>External Risk Findings</div>
        <table style={{ width:"100%", borderCollapse:"collapse" }}>
          <thead><tr style={{ background:"#f8fafc" }}>
            {["Severity","Finding","Asset / Domain","First Detected"].map(h=>(
              <th key={h} style={{ padding:"10px 12px", textAlign:"left", fontSize:11, fontWeight:700, color:C.muted, textTransform:"uppercase", borderBottom:`2px solid ${C.border}` }}>{h}</th>
            ))}
          </tr></thead>
          <tbody>{s?.findings?.map((f,i)=>(
            <tr key={i} style={{ borderBottom:`1px solid ${C.border}` }}>
              <td style={{ padding:"12px 12px" }}><SeverityBadge level={f.severity}/></td>
              <td style={{ padding:"12px 12px", fontSize:13, color:C.text }}>{f.title}</td>
              <td style={{ padding:"12px 12px", fontFamily:"monospace", fontSize:12, color:C.muted }}>{f.asset}</td>
              <td style={{ padding:"12px 12px", fontSize:12, color:C.muted }}>{f.first}</td>
            </tr>
          ))}</tbody>
        </table>
      </Card>
    </div>
  );
}

// ── Assets & Patches ─────────────────────────────────────────────────────────
function AssetsPage({ data }) {
  const d = data || {};
  if (!d._hasData) return <NoData icon="💻" title="No asset data yet" message="Connect ManageEngine in ⚙️ Settings to see live asset and patch management data." />;
  const a = d.assets;
  return (
    <div>
      <SectionTitle title="Assets & Patch Management – ManageEngine" subtitle="Asset inventory, patch compliance and disk encryption status" />
      <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:16, marginBottom:24 }}>
        <MetricCard icon="💻" label="Total Assets" value={a?.total||342} sub={`${a?.online||298} online, ${a?.offline||44} offline`} color={C.primaryLight}/>
        <MetricCard icon="🔄" label="Patch Compliance" value={`${a?.patchedPct||72}%`} sub="Target: 95%" trendUp={false} color={a?.patchedPct>=95?C.ok:C.warn}/>
        <MetricCard icon="🔒" label="Disk Encryption" value={`${a?.encryptedPct||85}%`} sub="BitLocker / FileVault" trendUp={false} color={a?.encryptedPct>=95?C.ok:C.warn}/>
        <MetricCard icon="⚠️" label="Non-compliant" value={Math.round((a?.total||342)*(1-(a?.patchedPct||72)/100))} sub="Missing critical patches" trendUp={false} color={C.high}/>
      </div>
      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:16, marginBottom:16 }}>
        <Card style={{ padding:20 }}>
          <div style={{ fontSize:14, fontWeight:700, color:C.text, marginBottom:16 }}>Asset Types – Patch & Encryption Status</div>
          <table style={{ width:"100%", borderCollapse:"collapse" }}>
            <thead><tr style={{ background:"#f8fafc" }}>
              {["Type","Total","Patched","Encrypted"].map(h=>(
                <th key={h} style={{ padding:"8px 12px", textAlign:h==="Type"?"left":"center", fontSize:11, fontWeight:700, color:C.muted, textTransform:"uppercase", borderBottom:`2px solid ${C.border}` }}>{h}</th>
              ))}
            </tr></thead>
            <tbody>{a?.byType?.map(t=>(
              <tr key={t.type} style={{ borderBottom:`1px solid ${C.border}` }}>
                <td style={{ padding:"10px 12px", fontSize:13, fontWeight:500, color:C.text }}>{t.type}</td>
                <td style={{ padding:"10px 12px", fontSize:13, fontWeight:700, color:C.text, textAlign:"center" }}>{t.count}</td>
                <td style={{ padding:"10px 12px", textAlign:"center" }}>
                  <span style={{ fontSize:13, fontWeight:700, color:t.patched/t.count>=0.9?C.ok:C.warn }}>{t.patched}</span>
                  <span style={{ fontSize:11, color:C.muted }}> / {t.count}</span>
                </td>
                <td style={{ padding:"10px 12px", textAlign:"center" }}>
                  {t.encrypted > 0 ? (
                    <><span style={{ fontSize:13, fontWeight:700, color:t.encrypted/t.count>=0.9?C.ok:C.warn }}>{t.encrypted}</span>
                    <span style={{ fontSize:11, color:C.muted }}> / {t.count}</span></>
                  ):<span style={{ fontSize:12, color:C.muted }}>N/A</span>}
                </td>
              </tr>
            ))}</tbody>
          </table>
        </Card>
        <Card style={{ padding:20 }}>
          <div style={{ fontSize:14, fontWeight:700, color:C.text, marginBottom:16 }}>Recent Patch Deployments</div>
          {a?.recentPatches?.map((p,i)=>(
            <div key={i} style={{ display:"flex", alignItems:"center", gap:12, padding:"10px 0", borderBottom:`1px solid ${C.border}` }}>
              <div style={{ width:36, height:36, borderRadius:8, background:p.status==="Success"?"#f0fdf4":p.status==="Partial"?"#fffbeb":"#fef2f2", display:"flex", alignItems:"center", justifyContent:"center", fontSize:18, flexShrink:0 }}>
                {p.status==="Success"?"✅":p.status==="Partial"?"⚠️":"❌"}
              </div>
              <div style={{ flex:1 }}>
                <div style={{ fontSize:13, fontWeight:500, color:C.text }}>{p.name}</div>
                <div style={{ fontSize:11, color:C.muted, marginTop:2 }}>{p.date} • {p.devices} devices</div>
              </div>
              <span style={{ fontSize:11, fontWeight:600, color:p.status==="Success"?C.ok:p.status==="Partial"?C.warn:C.critical }}>{p.status}</span>
            </div>
          ))}
        </Card>
      </div>
    </div>
  );
}

// ── SIEM / XDR ───────────────────────────────────────────────────────────────
function SIEMPage({ data }) {
  const d = data || {};
  if (!d._hasData) return <NoData icon="📡" title="No SIEM / XDR data yet" message="Connect Taegis XDR in ⚙️ Settings to see live SIEM event data." />;
  const [invOpen, setInvOpen] = useState(null);
  return (
    <div>
      <SectionTitle title="SIEM / XDR – Taegis" subtitle="Security events, correlation alerts and active investigation queue" />
      <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:16, marginBottom:24 }}>
        <MetricCard icon="📡" label="Events Today" value={(d.siem?.eventsToday||284710).toLocaleString()} color={C.primaryLight}/>
        <MetricCard icon="🚨" label="Active Incidents" value={d.siem?.activeIncidents||3} trendUp={false} color={C.critical}/>
        <MetricCard icon="⏱" label="MTTD" value={d.siem?.meanDetect||"4.2 min"} sub="Mean Time to Detect" trendUp={true} color={C.ok}/>
        <MetricCard icon="🔬" label="Correlation Rules" value="1,247" sub="Active detection rules" color={C.primary}/>
      </div>
      <Card style={{ padding:20 }}>
        <div style={{ fontSize:14, fontWeight:700, color:C.text, marginBottom:16 }}>Investigation Queue</div>
        {d.siem?.events?.map((e,i)=>(
          <div key={i} onClick={()=>setInvOpen(invOpen===i?null:i)}
            style={{ borderBottom:`1px solid ${C.border}`, cursor:"pointer" }}>
            <div style={{ display:"flex", alignItems:"center", gap:12, padding:"14px 0" }}>
              <div style={{ width:10, height:10, borderRadius:"50%", background:SEVERITY_COLORS[e.severity], flexShrink:0 }}/>
              <div style={{ flex:1 }}>
                <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:3 }}>
                  <span style={{ fontSize:11, fontFamily:"monospace", color:C.muted }}>{e.time}</span>
                  <SeverityBadge level={e.severity}/>
                  <span style={{ fontSize:12, fontWeight:600, color:C.text }}>{e.type}</span>
                </div>
                <div style={{ fontSize:13, color:C.text }}>{e.desc}</div>
                <div style={{ fontSize:11, color:C.muted, marginTop:2 }}>Source: {e.src}</div>
              </div>
              <span style={{ fontSize:11, fontWeight:600, padding:"4px 12px", borderRadius:20,
                background:e.status==="Active"?"#fef2f2":e.status==="Contained"?"#f0fdf4":"#fffbeb",
                color:e.status==="Active"?C.critical:e.status==="Contained"?C.ok:C.warn }}>{e.status}</span>
              <span style={{ color:C.muted, fontSize:14 }}>{invOpen===i?"▲":"▼"}</span>
            </div>
            {invOpen===i&&(
              <div style={{ background:"#f8fafc", borderRadius:8, padding:16, marginBottom:12 }}>
                <div style={{ fontSize:12, fontWeight:700, color:C.text, marginBottom:8 }}>Investigation Details</div>
                <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:12, fontSize:12, color:C.text }}>
                  <div><span style={{ color:C.muted }}>Event Type:</span><br/><strong>{e.type}</strong></div>
                  <div><span style={{ color:C.muted }}>Source IP:</span><br/><strong style={{ fontFamily:"monospace" }}>{e.src}</strong></div>
                  <div><span style={{ color:C.muted }}>Status:</span><br/><strong style={{ color:e.status==="Active"?C.critical:C.ok }}>{e.status}</strong></div>
                </div>
                <div style={{ marginTop:12, display:"flex", gap:8 }}>
                  <button style={{ padding:"6px 14px", borderRadius:6, border:`1px solid ${C.primary}`, background:"white", color:C.primary, fontSize:12, cursor:"pointer", fontWeight:600 }}>Assign to Me</button>
                  <button style={{ padding:"6px 14px", borderRadius:6, border:`1px solid ${C.ok}`, background:"white", color:C.ok, fontSize:12, cursor:"pointer", fontWeight:600 }}>Mark Contained</button>
                  <button style={{ padding:"6px 14px", borderRadius:6, border:`1px solid ${C.border}`, background:"white", color:C.muted, fontSize:12, cursor:"pointer" }}>Add Note</button>
                </div>
              </div>
            )}
          </div>
        ))}
      </Card>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════
   SETTINGS – INTEGRATIONS
═══════════════════════════════════════════════════════════════════════════ */

// Tools that support multiple instances
const MULTI_INSTANCE_TOOLS = ["fortinet", "azure"];

const FIELDS = {
  fortinet:     [["name","Instance Name","e.g. HQ Firewall"],["host","Host URL","https://192.168.1.1"],["apikey","API Key","FortiGate REST API token"]],
  paloalto:     [["host","Host / Panorama URL","https://panorama.company.com"],["apikey","API Key","PAN-OS API key"]],
  upguard:      [["apikey","API Key","UpGuard API key"],["subdomain","Subdomain (optional)","company"]],
  azure:        [["name","Account Name","e.g. Production"],["tenantId","Tenant ID","xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"],["clientId","Client ID",""],["clientSecret","Client Secret",""],["subscriptionId","Subscription ID",""]],
  qualys:       [["username","Username","qualys-reader@company.com"],["password","Password",""],["platform","Platform URL","https://qualysapi.qualys.com"]],
  manageengine: [["host","Server URL","https://meserver:8443"],["apikey","API Key","Zoho OAuth token"]],
  taegis:       [["clientId","Client ID",""],["clientSecret","Client Secret",""],["region","Region","us1"]],
};

// ── Admin – Integration Status ────────────────────────────────────────────────
function AdminPage() {
  const [statuses,    setStatuses]    = useState({});
  const [testing,     setTesting]     = useState(null);
  const [collecting,  setCollecting]  = useState(false);
  const [testResults, setTestResults] = useState({});
  const [toast,       setToast]       = useState(null);
  const [collectLog,  setCollectLog]  = useState(null);
  const [lastRefresh, setLastRefresh] = useState(null);

  useEffect(() => {
    fetchStatuses();
    const t = setInterval(fetchStatuses, 30_000);
    return () => clearInterval(t);
  }, []);

  async function fetchStatuses() {
    try {
      const r = await fetch(`${API}/api/integrations`);
      if (r.ok) {
        const arr = await r.json();
        const m = {};
        arr.forEach(x => { m[x.tool_name] = x; });
        setStatuses(m);
        setLastRefresh(new Date());
      }
    } catch(e) { console.error("Admin fetch failed:", e); }
  }

  function showToast(msg, ok=true) {
    setToast({ msg, ok });
    setTimeout(() => setToast(null), 4000);
  }

  async function testTool(toolKey, instanceIdx=null) {
    const key = instanceIdx !== null ? `${toolKey}__${instanceIdx}` : toolKey;
    setTesting(key);
    try {
      const url = instanceIdx !== null
        ? `${API}/api/integrations/${toolKey}/test?instance=${instanceIdx}`
        : `${API}/api/integrations/${toolKey}/test`;
      const r = await fetch(url, { method: "POST" });
      const d = await r.json();
      setTestResults(prev => ({ ...prev, [key]: d }));
      showToast(d.success ? `${toolKey} — connected ✅` : `${toolKey} — ${d.error}`, d.success);
      fetchStatuses();
    } catch(e) {
      setTestResults(prev => ({ ...prev, [key]: { success: false, error: e.message } }));
      showToast(`Test failed: ${e.message}`, false);
    }
    setTesting(null);
  }

  async function collectNow() {
    setCollecting(true);
    setCollectLog("Triggering collection for all configured integrations…");
    try {
      const r = await fetch(`${API}/api/collect`, { method: "POST" });
      const d = await r.json();
      setCollectLog(d.message || "Collection triggered. Data will update in ~30 seconds.");
      showToast("Collection triggered ✅");
      setTimeout(fetchStatuses, 5000);
    } catch(e) {
      setCollectLog(`Error: ${e.message}`);
      showToast("Collection trigger failed", false);
    }
    setCollecting(false);
  }

  const STATUS_CFG = {
    connected:    { color: C.ok,       bg: "#f0fdf4", dot: "#16a34a", label: "Connected"    },
    configured:   { color: C.warn,     bg: "#fffbeb", dot: "#d97706", label: "Configured"   },
    error:        { color: C.critical, bg: "#fef2f2", dot: "#dc2626", label: "Error"        },
    unconfigured: { color: C.muted,    bg: "#f8fafc", dot: "#cbd5e1", label: "Not Set Up"   },
  };

  const totalTools  = TOOLS.length;
  const connected   = Object.values(statuses).filter(s => s.status === "connected").length;
  const errored     = Object.values(statuses).filter(s => s.status === "error").length;
  const unconfigured = Object.values(statuses).filter(s => s.status === "unconfigured" || !s.status).length;

  return (
    <div>
      <SectionTitle
        title="Admin — Integration Status"
        subtitle="Live status of all connected security devices and services. Auto-refreshes every 30 seconds."
        action={
          <div style={{ display:"flex", gap:8, alignItems:"center" }}>
            {lastRefresh && <span style={{ fontSize:11, color:C.muted }}>Last refresh: {lastRefresh.toLocaleTimeString()}</span>}
            <button onClick={fetchStatuses}
              style={{ padding:"6px 14px", borderRadius:8, border:`1px solid ${C.border}`, background:"white",
                color:C.text, fontSize:12, fontWeight:600, cursor:"pointer" }}>
              🔄 Refresh
            </button>
            <button onClick={collectNow} disabled={collecting}
              style={{ padding:"6px 14px", borderRadius:8, border:"none", background:C.primary,
                color:"white", fontSize:12, fontWeight:700, cursor:"pointer" }}>
              {collecting ? "Collecting…" : "⚡ Collect All Now"}
            </button>
          </div>
        }
      />

      {toast && (
        <div style={{ position:"fixed", bottom:24, right:24, zIndex:1000,
          background: toast.ok ? C.ok : C.critical, color:"white",
          padding:"12px 20px", borderRadius:10, fontSize:13, fontWeight:600,
          boxShadow:"0 4px 20px rgba(0,0,0,0.25)", maxWidth:340 }}>
          {toast.msg}
        </div>
      )}

      {/* Summary KPI row */}
      <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:16, marginBottom:24 }}>
        {[
          { icon:"🔌", label:"Total Integrations", value:totalTools,   color:C.primaryLight },
          { icon:"✅", label:"Connected",           value:connected,    color:C.ok           },
          { icon:"⚠️", label:"Errors",              value:errored,      color:C.critical     },
          { icon:"⚙️", label:"Not Configured",      value:unconfigured, color:C.muted        },
        ].map(k => (
          <Card key={k.label} style={{ padding:20, display:"flex", alignItems:"center", gap:16 }}>
            <div style={{ width:44, height:44, borderRadius:10, background:`${k.color}18`,
              display:"flex", alignItems:"center", justifyContent:"center", fontSize:22, flexShrink:0 }}>
              {k.icon}
            </div>
            <div>
              <div style={{ fontSize:28, fontWeight:800, color:C.text, lineHeight:1 }}>{k.value}</div>
              <div style={{ fontSize:11, color:C.muted, marginTop:3 }}>{k.label}</div>
            </div>
          </Card>
        ))}
      </div>

      {/* Collect log */}
      {collectLog && (
        <div style={{ background:"#f0fdf4", border:`1px solid #bbf7d0`, borderRadius:10,
          padding:"12px 16px", marginBottom:16, fontSize:13, color:"#166534" }}>
          ⚡ {collectLog}
        </div>
      )}

      {/* Device status table */}
      <Card style={{ padding:0, overflow:"hidden" }}>
        <div style={{ padding:"16px 20px", borderBottom:`1px solid ${C.border}`,
          display:"flex", alignItems:"center", justifyContent:"space-between" }}>
          <div style={{ fontSize:14, fontWeight:700, color:C.text }}>Integrated Devices & Services</div>
          <div style={{ fontSize:11, color:C.muted }}>Click Test to verify live connectivity</div>
        </div>

        <table style={{ width:"100%", borderCollapse:"collapse" }}>
          <thead>
            <tr style={{ background:"#f8fafc" }}>
              {["Tool / Device","Category","Status","Instances","Last Tested","Refresh Interval","Last Error","Actions"].map(h => (
                <th key={h} style={{ padding:"10px 16px", textAlign:"left", fontSize:11,
                  fontWeight:700, color:C.muted, textTransform:"uppercase", letterSpacing:0.5,
                  borderBottom:`2px solid ${C.border}`, whiteSpace:"nowrap" }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {TOOLS.map(tool => {
              const st       = statuses[tool.key] || {};
              const cfg      = STATUS_CFG[st.status] || STATUS_CFG.unconfigured;
              const isMulti  = MULTI_INSTANCE_TOOLS.includes(tool.key);
              const instances= st.credentials?.instances || [];
              const interval = st.refresh_interval || 300;
              const mins     = Math.round(interval / 60);

              return (
                <React.Fragment key={tool.key}>
                  {/* Main tool row */}
                  <tr style={{ borderBottom:`1px solid ${C.border}`,
                    background: st.status === "error" ? "#fff5f5" : "transparent" }}>

                    {/* Tool name */}
                    <td style={{ padding:"14px 16px" }}>
                      <div style={{ display:"flex", alignItems:"center", gap:10 }}>
                        <div style={{ width:36, height:36, borderRadius:8, background:`${tool.color}18`,
                          display:"flex", alignItems:"center", justifyContent:"center", fontSize:20, flexShrink:0 }}>
                          {tool.icon}
                        </div>
                        <div>
                          <div style={{ fontSize:13, fontWeight:700, color:C.text }}>{tool.name}</div>
                          {isMulti && <div style={{ fontSize:10, color:tool.color, fontWeight:700 }}>MULTI-INSTANCE</div>}
                        </div>
                      </div>
                    </td>

                    {/* Category */}
                    <td style={{ padding:"14px 16px", fontSize:12, color:C.muted }}>{tool.cat}</td>

                    {/* Status badge */}
                    <td style={{ padding:"14px 16px" }}>
                      <div style={{ display:"inline-flex", alignItems:"center", gap:6,
                        background:cfg.bg, borderRadius:20, padding:"4px 12px" }}>
                        <div style={{ width:7, height:7, borderRadius:"50%", background:cfg.dot,
                          boxShadow: st.status === "connected" ? `0 0 0 3px ${cfg.dot}30` : "none" }}/>
                        <span style={{ fontSize:12, fontWeight:700, color:cfg.color }}>{cfg.label}</span>
                      </div>
                    </td>

                    {/* Instances count */}
                    <td style={{ padding:"14px 16px", fontSize:13, color:C.text }}>
                      {isMulti
                        ? <span style={{ fontWeight:700 }}>{instances.length} instance{instances.length !== 1 ? "s" : ""}</span>
                        : <span style={{ color:C.muted }}>—</span>}
                    </td>

                    {/* Last tested */}
                    <td style={{ padding:"14px 16px", fontSize:12, color:C.muted, whiteSpace:"nowrap" }}>
                      {st.last_tested
                        ? new Date(st.last_tested).toLocaleString()
                        : <span style={{ fontStyle:"italic" }}>Never</span>}
                    </td>

                    {/* Refresh interval */}
                    <td style={{ padding:"14px 16px" }}>
                      <span style={{ fontSize:12, background:"#f1f5f9", borderRadius:6,
                        padding:"3px 10px", color:C.text, fontWeight:600 }}>
                        Every {mins} min
                      </span>
                    </td>

                    {/* Last error */}
                    <td style={{ padding:"14px 16px", maxWidth:220 }}>
                      {st.last_error
                        ? <span style={{ fontSize:11, color:C.critical, background:"#fef2f2",
                            padding:"3px 8px", borderRadius:6, display:"block",
                            overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap",
                            maxWidth:200, title:st.last_error }}>
                            {st.last_error}
                          </span>
                        : <span style={{ fontSize:11, color:C.ok }}>—</span>}
                    </td>

                    {/* Actions */}
                    <td style={{ padding:"14px 16px" }}>
                      {!isMulti && st.status !== "unconfigured" && (
                        <button onClick={() => testTool(tool.key)}
                          disabled={testing === tool.key}
                          style={{ padding:"5px 14px", borderRadius:7, border:`1px solid ${C.primaryLight}`,
                            background:"white", color:C.primary, fontSize:12, fontWeight:600,
                            cursor:"pointer", whiteSpace:"nowrap" }}>
                          {testing === tool.key ? "Testing…" : "🔗 Test"}
                        </button>
                      )}
                      {isMulti && instances.length === 0 && (
                        <span style={{ fontSize:11, color:C.muted, fontStyle:"italic" }}>No instances</span>
                      )}
                    </td>
                  </tr>

                  {/* Test result for single-instance */}
                  {!isMulti && testResults[tool.key] && (
                    <tr style={{ borderBottom:`1px solid ${C.border}` }}>
                      <td colSpan={8} style={{ padding:"0 16px 12px 66px" }}>
                        <div style={{ background: testResults[tool.key].success ? "#f0fdf4" : "#fef2f2",
                          borderRadius:8, padding:"10px 14px", fontSize:12,
                          color: testResults[tool.key].success ? "#166534" : C.critical }}>
                          {testResults[tool.key].success ? "✅ Connected — " : "❌ Failed — "}
                          {testResults[tool.key].message || testResults[tool.key].error || ""}
                          {testResults[tool.key].sample && (
                            <pre style={{ marginTop:8, background:"white", borderRadius:6, padding:10,
                              fontSize:11, fontFamily:"monospace", maxHeight:100, overflow:"auto",
                              border:`1px solid ${C.border}` }}>
                              {JSON.stringify(testResults[tool.key].sample, null, 2)}
                            </pre>
                          )}
                        </div>
                      </td>
                    </tr>
                  )}

                  {/* Instance rows for multi-instance tools */}
                  {isMulti && instances.map((inst, idx) => {
                    const instKey = `${tool.key}__${idx}`;
                    const tr = testResults[instKey];
                    return (
                      <React.Fragment key={instKey}>
                        <tr style={{ background:"#f8fafc", borderBottom:`1px solid ${C.border}` }}>
                          <td style={{ padding:"10px 16px 10px 66px" }}>
                            <div style={{ fontSize:12, fontWeight:600, color:C.text }}>
                              {inst.name || `Instance ${idx + 1}`}
                            </div>
                            <div style={{ fontSize:11, color:C.muted }}>{inst.host || inst.tenantId || inst.subscriptionId || ""}</div>
                          </td>
                          <td style={{ padding:"10px 16px", fontSize:11, color:C.muted }}>Instance {idx + 1}</td>
                          <td colSpan={4}/>
                          <td/>
                          <td style={{ padding:"10px 16px" }}>
                            <button onClick={() => testTool(tool.key, idx)}
                              disabled={testing === instKey}
                              style={{ padding:"4px 12px", borderRadius:7, border:`1px solid ${C.primaryLight}`,
                                background:"white", color:C.primary, fontSize:11, fontWeight:600,
                                cursor:"pointer", whiteSpace:"nowrap" }}>
                              {testing === instKey ? "Testing…" : "🔗 Test"}
                            </button>
                          </td>
                        </tr>
                        {tr && (
                          <tr style={{ borderBottom:`1px solid ${C.border}` }}>
                            <td colSpan={8} style={{ padding:"0 16px 10px 66px" }}>
                              <div style={{ background: tr.success ? "#f0fdf4" : "#fef2f2",
                                borderRadius:8, padding:"8px 12px", fontSize:12,
                                color: tr.success ? "#166534" : C.critical }}>
                                {tr.success ? "✅ " : "❌ "}
                                {tr.message || tr.error || ""}
                                {tr.sample && (
                                  <pre style={{ marginTop:6, background:"white", borderRadius:6, padding:8,
                                    fontSize:11, fontFamily:"monospace", maxHeight:80, overflow:"auto",
                                    border:`1px solid ${C.border}` }}>
                                    {JSON.stringify(tr.sample, null, 2)}
                                  </pre>
                                )}
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    );
                  })}
                </React.Fragment>
              );
            })}
          </tbody>
        </table>
      </Card>
    </div>
  );
}

function IntegrationsPage({ onSave }) {
  const [statuses,    setStatuses]    = useState({});
  const [editing,     setEditing]     = useState(null);   // toolKey or "toolKey__idx"
  const [form,        setForm]        = useState({});
  const [saving,      setSaving]      = useState(false);
  const [testing,     setTesting]     = useState(null);
  const [testResults, setTestResults] = useState({});
  const [toast,       setToast]       = useState(null);

  useEffect(() => { loadStatuses(); }, []);

  async function loadStatuses() {
    try {
      const r = await fetch(`${API}/api/integrations`);
      if (r.ok) {
        const arr = await r.json();
        const m = {};
        arr.forEach(x => { m[x.tool_name] = x; });
        setStatuses(m);
      }
    } catch(e) { console.error("Could not load statuses:", e); }
  }

  function showToast(msg, ok=true) {
    setToast({msg, ok});
    setTimeout(()=>setToast(null), 4000);
  }

  /* Save credentials (single or multi-instance) */
  async function saveIntegration(toolKey, credentials, interval=300) {
    setSaving(true);
    try {
      const r = await fetch(`${API}/api/integrations/${toolKey}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ credentials, refresh_interval: interval }),
      });
      if (r.ok) {
        showToast("Credentials saved successfully ✅");
        setEditing(null);
        await loadStatuses();
        if (onSave) onSave();
      } else {
        const err = await r.json().catch(()=>({}));
        showToast(`Save failed: ${err.error || r.statusText}`, false);
      }
    } catch(e) { showToast(`Network error: ${e.message}`, false); }
    setSaving(false);
  }

  /* Save single-tool form */
  async function saveSingle(toolKey) {
    const { _interval, ...creds } = form;  // extract interval, rest = credentials
    await saveIntegration(toolKey, creds, _interval || 300);
  }

  /* Save one instance to the multi-instance list */
  async function saveInstance(toolKey, idx) {
    const st = statuses[toolKey] || {};
    const existing = st.credentials?.instances || [];
    const { _interval, ...instCreds } = form;
    const updated = [...existing];
    if (idx === -1) updated.push(instCreds);   // new instance
    else updated[idx] = instCreds;              // edit existing
    await saveIntegration(toolKey, { instances: updated }, _interval || 300);
  }

  async function deleteInstance(toolKey, idx) {
    if (!confirm("Remove this instance?")) return;
    const st = statuses[toolKey] || {};
    const updated = (st.credentials?.instances || []).filter((_,i)=>i!==idx);
    await saveIntegration(toolKey, { instances: updated });
  }

  /* Test connection and fetch sample data */
  async function testConnection(toolKey, instanceIdx=null) {
    const testKey = instanceIdx !== null ? `${toolKey}__${instanceIdx}` : toolKey;
    setTesting(testKey);
    try {
      const url = instanceIdx !== null
        ? `${API}/api/integrations/${toolKey}/test?instance=${instanceIdx}`
        : `${API}/api/integrations/${toolKey}/test`;
      const r = await fetch(url, { method:"POST" });
      const data = await r.json();
      setTestResults(prev => ({ ...prev, [testKey]: data }));
      showToast(data.success ? "Connection successful ✅" : `Test failed: ${data.error}`, data.success);
      loadStatuses();
    } catch(e) {
      setTestResults(prev => ({ ...prev, [testKey]: { success:false, error:e.message } }));
      showToast("Connection test failed", false);
    }
    setTesting(null);
  }

  async function deleteIntegration(toolKey) {
    if (!confirm(`Remove all credentials for ${toolKey}?`)) return;
    await fetch(`${API}/api/integrations/${toolKey}`, { method:"DELETE" });
    setTestResults(prev => { const n={...prev}; delete n[toolKey]; return n; });
    loadStatuses();
    showToast("Credentials removed");
  }

  /* ── Single-instance form ─────────────────────────────────────────────── */
  function SingleForm({ toolKey, tool }) {
    return (
      <div>
        {(FIELDS[toolKey]||[]).map(([field, label, placeholder])=>(
          <div key={field} style={{ marginBottom:12 }}>
            <label style={{ display:"block", fontSize:11, fontWeight:700, color:C.muted, marginBottom:4, textTransform:"uppercase", letterSpacing:0.5 }}>{label}</label>
            <input
              type={/pass|secret/i.test(field)?"password":/key|token/i.test(field)?"password":"text"}
              value={form[field]||""}
              onChange={e=>setForm(p=>({...p,[field]:e.target.value}))}
              placeholder={placeholder}
              style={{ width:"100%", padding:"8px 12px", borderRadius:8, border:`1px solid ${C.border}`, fontSize:13, outline:"none", boxSizing:"border-box" }}
            />
          </div>
        ))}
        <div style={{ marginBottom:14 }}>
          <label style={{ display:"block", fontSize:11, fontWeight:700, color:C.muted, marginBottom:4, textTransform:"uppercase", letterSpacing:0.5 }}>Refresh Interval</label>
          <select value={form._interval||300} onChange={e=>setForm(p=>({...p,_interval:parseInt(e.target.value)}))}
            style={{ width:"100%", padding:"8px 12px", borderRadius:8, border:`1px solid ${C.border}`, fontSize:13, background:"white" }}>
            {INTERVALS.map(i=><option key={i.value} value={i.value}>Every {i.label}</option>)}
          </select>
        </div>
        <div style={{ display:"flex", gap:8, flexWrap:"wrap" }}>
          <button onClick={()=>saveSingle(toolKey)} disabled={saving}
            style={{ flex:2, padding:"9px 0", borderRadius:8, border:"none", background:tool.color, color:"white", fontSize:13, fontWeight:700, cursor:"pointer" }}>
            {saving?"Saving…":"💾 Save"}
          </button>
          <button onClick={async ()=>{ await saveSingle(toolKey); await testConnection(toolKey); }}
            disabled={saving||testing===toolKey}
            style={{ flex:2, padding:"9px 0", borderRadius:8, border:`1px solid ${C.primaryLight}`, background:"white", color:C.primary, fontSize:13, fontWeight:700, cursor:"pointer" }}>
            {testing===toolKey?"Testing…":"🔗 Save & Test"}
          </button>
          <button onClick={()=>setEditing(null)}
            style={{ flex:1, padding:"9px 0", borderRadius:8, border:`1px solid ${C.border}`, background:"white", color:C.muted, fontSize:13, cursor:"pointer" }}>
            ✕
          </button>
        </div>
        <TestResultPanel resultKey={toolKey}/>
      </div>
    );
  }

  /* ── Instance form (for multi-instance tools) ─────────────────────────── */
  function InstanceForm({ toolKey, tool, idx }) {
    return (
      <div style={{ background:"#f8fafc", borderRadius:10, padding:16, marginTop:12, border:`1px solid ${C.border}` }}>
        <div style={{ fontSize:13, fontWeight:700, color:C.text, marginBottom:12 }}>
          {idx === -1 ? "➕ New Instance" : `✏️ Edit: ${form.name||"Instance"}`}
        </div>
        {(FIELDS[toolKey]||[]).map(([field, label, placeholder])=>(
          <div key={field} style={{ marginBottom:10 }}>
            <label style={{ display:"block", fontSize:11, fontWeight:700, color:C.muted, marginBottom:3, textTransform:"uppercase", letterSpacing:0.5 }}>{label}</label>
            <input
              type={/pass|secret/i.test(field)?"password":/key|token/i.test(field)?"password":"text"}
              value={form[field]||""}
              onChange={e=>setForm(p=>({...p,[field]:e.target.value}))}
              placeholder={placeholder}
              style={{ width:"100%", padding:"7px 11px", borderRadius:7, border:`1px solid ${C.border}`, fontSize:12, outline:"none", boxSizing:"border-box" }}
            />
          </div>
        ))}
        <div style={{ display:"flex", gap:8, marginTop:12 }}>
          <button onClick={()=>saveInstance(toolKey, idx)} disabled={saving}
            style={{ flex:1, padding:"8px 0", borderRadius:7, border:"none", background:tool.color, color:"white", fontSize:12, fontWeight:700, cursor:"pointer" }}>
            {saving?"Saving…":"💾 Save Instance"}
          </button>
          <button onClick={()=>setEditing(null)}
            style={{ padding:"8px 12px", borderRadius:7, border:`1px solid ${C.border}`, background:"white", color:C.muted, fontSize:12, cursor:"pointer" }}>
            Cancel
          </button>
        </div>
      </div>
    );
  }

  /* ── Test result preview ──────────────────────────────────────────────── */
  function TestResultPanel({ resultKey }) {
    const r = testResults[resultKey];
    if (!r) return null;
    return (
      <div style={{ marginTop:12, background:r.success?"#f0fdf4":"#fef2f2", borderRadius:8,
        padding:12, border:`1px solid ${r.success?"#bbf7d0":"#fecaca"}` }}>
        <div style={{ fontSize:12, fontWeight:700, color:r.success?C.ok:C.critical, marginBottom:r.sample?8:0 }}>
          {r.success?"✅ Connected":"❌ Connection Failed"} {r.message||r.error||""}
        </div>
        {r.sample && (
          <div style={{ fontSize:11, color:C.text, background:"white", borderRadius:6, padding:10, border:`1px solid ${C.border}`, fontFamily:"monospace", whiteSpace:"pre-wrap", maxHeight:120, overflow:"auto" }}>
            {JSON.stringify(r.sample, null, 2)}
          </div>
        )}
      </div>
    );
  }

  /* ── Main render ──────────────────────────────────────────────────────── */
  return (
    <div>
      <SectionTitle
        title="Integrations & Settings"
        subtitle="Connect your security tools. Credentials are stored securely in PostgreSQL — never in the browser."
      />
      {toast && (
        <div style={{ position:"fixed", bottom:24, right:24, zIndex:1000, background:toast.ok?C.ok:C.critical,
          color:"white", padding:"12px 20px", borderRadius:10, fontSize:13, fontWeight:600,
          boxShadow:"0 4px 20px rgba(0,0,0,0.25)", maxWidth:320 }}>
          {toast.msg}
        </div>
      )}

      <div style={{ display:"grid", gridTemplateColumns:"repeat(2,1fr)", gap:16 }}>
        {TOOLS.map(tool => {
          const st       = statuses[tool.key] || {};
          const isConn   = st.status === "connected";
          const isConf   = st.status && st.status !== "unconfigured";
          const isMulti  = MULTI_INSTANCE_TOOLS.includes(tool.key);
          const instances= st.credentials?.instances || [];
          const isEditing= editing === tool.key;

          return (
            <Card key={tool.key} style={{ padding:24, border:`2px solid ${isConn?C.ok+"40":C.border}` }}>
              {/* Header */}
              <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:14 }}>
                <div style={{ display:"flex", gap:12, alignItems:"center" }}>
                  <div style={{ width:44, height:44, borderRadius:10, background:`${tool.color}18`, display:"flex", alignItems:"center", justifyContent:"center", fontSize:24 }}>
                    {tool.icon}
                  </div>
                  <div>
                    <div style={{ fontSize:15, fontWeight:700, color:C.text }}>{tool.name}</div>
                    <div style={{ fontSize:11, color:C.muted }}>{tool.cat}</div>
                    {isMulti && <div style={{ fontSize:10, color:tool.color, fontWeight:700, marginTop:2 }}>MULTI-INSTANCE</div>}
                  </div>
                </div>
                <div style={{ display:"flex", alignItems:"center", gap:5 }}>
                  <div style={{ width:8, height:8, borderRadius:"50%", background:isConn?C.ok:isConf?C.warn:"#cbd5e1" }}/>
                  <span style={{ fontSize:11, fontWeight:600, color:isConn?C.ok:isConf?C.warn:C.muted }}>
                    {isConn?"Connected":isConf?"Configured":"Not Configured"}
                  </span>
                </div>
              </div>

              {st.last_tested && <div style={{ fontSize:11, color:C.muted, marginBottom:8 }}>Last tested: {new Date(st.last_tested).toLocaleString()}</div>}
              {st.last_error  && <div style={{ fontSize:11, color:C.critical, background:"#fef2f2", padding:"6px 10px", borderRadius:6, marginBottom:10 }}>⚠️ {st.last_error}</div>}

              {/* ── MULTI-INSTANCE (Fortinet / Azure) ──────────────────── */}
              {isMulti ? (
                <div>
                  {/* Instance list */}
                  {instances.map((inst, idx) => {
                    const instKey = `${tool.key}__${idx}`;
                    return (
                      <div key={idx}>
                        <div style={{ display:"flex", alignItems:"center", gap:8, padding:"8px 0", borderBottom:`1px solid ${C.border}` }}>
                          <div style={{ flex:1 }}>
                            <div style={{ fontSize:13, fontWeight:600, color:C.text }}>{inst.name||`Instance ${idx+1}`}</div>
                            <div style={{ fontSize:11, color:C.muted }}>{inst.host||inst.tenantId||""}</div>
                          </div>
                          <button onClick={()=>{ setEditing(instKey); setForm({...inst}); }}
                            style={{ padding:"4px 10px", borderRadius:6, border:`1px solid ${C.border}`, background:"white", color:C.muted, fontSize:11, cursor:"pointer" }}>✏️</button>
                          <button onClick={()=>testConnection(tool.key, idx)} disabled={testing===instKey}
                            style={{ padding:"4px 10px", borderRadius:6, border:`1px solid ${C.primaryLight}`, background:"white", color:C.primary, fontSize:11, cursor:"pointer", fontWeight:600 }}>
                            {testing===instKey?"…":"🔗 Test"}
                          </button>
                          <button onClick={()=>deleteInstance(tool.key, idx)}
                            style={{ padding:"4px 8px", borderRadius:6, border:`1px solid ${C.border}`, background:"white", color:C.critical, fontSize:11, cursor:"pointer" }}>🗑️</button>
                        </div>
                        <TestResultPanel resultKey={instKey}/>
                      </div>
                    );
                  })}

                  {/* Add instance button */}
                  {editing !== `${tool.key}__-1` && (
                    <button onClick={()=>{ setEditing(`${tool.key}__-1`); setForm({}); }}
                      style={{ width:"100%", marginTop:12, padding:"8px 0", borderRadius:8, border:`2px dashed ${tool.color}60`,
                        background:`${tool.color}08`, color:tool.color, fontSize:13, fontWeight:600, cursor:"pointer" }}>
                      ➕ Add {tool.name} Instance
                    </button>
                  )}

                  {/* Instance form */}
                  {editing && editing.startsWith(`${tool.key}__`) && (
                    <InstanceForm toolKey={tool.key} tool={tool} idx={parseInt(editing.split("__")[1])}/>
                  )}

                  {/* Refresh interval (stored globally for this tool) */}
                  {instances.length > 0 && !isEditing && (
                    <div style={{ marginTop:12, display:"flex", alignItems:"center", justifyContent:"space-between" }}>
                      <span style={{ fontSize:11, color:C.muted }}>Refresh interval:</span>
                      <select value={st.refresh_interval||300}
                        onChange={async e => {
                          await saveIntegration(tool.key, st.credentials||{}, parseInt(e.target.value));
                        }}
                        style={{ padding:"4px 10px", borderRadius:6, border:`1px solid ${C.border}`, fontSize:12, background:"white" }}>
                        {INTERVALS.map(i=><option key={i.value} value={i.value}>Every {i.label}</option>)}
                      </select>
                    </div>
                  )}
                </div>
              ) : (
                /* ── SINGLE-INSTANCE ──────────────────────────────────── */
                <div>
                  {isEditing ? (
                    <SingleForm toolKey={tool.key} tool={tool}/>
                  ) : (
                    <div>
                      <div style={{ display:"flex", gap:8, flexWrap:"wrap" }}>
                        <button onClick={()=>{ setEditing(tool.key); setForm({_interval:st.refresh_interval||300}); }}
                          style={{ padding:"7px 14px", borderRadius:8, border:`1px solid ${tool.color}`, color:tool.color, background:`${tool.color}08`, fontSize:12, fontWeight:600, cursor:"pointer" }}>
                          ✏️ {isConf?"Edit Credentials":"Configure"}
                        </button>
                        {isConf && <>
                          <button onClick={()=>testConnection(tool.key)} disabled={testing===tool.key}
                            style={{ padding:"7px 14px", borderRadius:8, border:`1px solid ${C.primaryLight}`, color:C.primary, background:"white", fontSize:12, fontWeight:600, cursor:"pointer" }}>
                            {testing===tool.key?"Testing…":"🔗 Test Connection"}
                          </button>
                          <button onClick={()=>deleteIntegration(tool.key)}
                            style={{ padding:"7px 12px", borderRadius:8, border:`1px solid ${C.border}`, color:C.critical, background:"white", fontSize:12, cursor:"pointer" }}>
                            🗑️
                          </button>
                        </>}
                      </div>
                      <TestResultPanel resultKey={tool.key}/>
                    </div>
                  )}
                </div>
              )}
            </Card>
          );
        })}
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════
   MAIN APP
═══════════════════════════════════════════════════════════════════════════ */
export default function CybersecurityDashboard() {
  const [role, setRole] = useState("executive");
  const [page, setPage] = useState("overview");
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [dateRange, setDateRange] = useState({ from:"", to:"" });

  const execNav = [
    { id:"overview", icon:"🏠", label:"Security Posture" },
    { id:"risk",     icon:"⚠️", label:"Risk & Compliance" },
    { id:"threats",  icon:"🎯", label:"Threat Intelligence" },
    { id:"cloud",    icon:"☁️", label:"Cloud Security" },
    { id:"report",   icon:"📊", label:"Executive Report" },
    { id:"admin",    icon:"🔌", label:"Admin" },
  ];
  const analystNav = [
    { id:"alerts",     icon:"🚨", label:"Alert Queue" },
    { id:"vulns",      icon:"🔍", label:"Vulnerabilities" },
    { id:"firewall",   icon:"🔥", label:"Firewall Analytics" },
    { id:"surface",    icon:"🌐", label:"Attack Surface" },
    { id:"assets",     icon:"💻", label:"Assets & Patches" },
    { id:"cloudanalyst",icon:"☁️",label:"Cloud Security" },
    { id:"siem",       icon:"📡", label:"SIEM / XDR" },
    { id:"admin",      icon:"🔌", label:"Admin" },
  ];
  const nav = role === "executive" ? execNav : analystNav;

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (dateRange.from) params.append("from", dateRange.from);
      if (dateRange.to)   params.append("to",   dateRange.to);
      const res = await fetch(`${API}/api/snapshot?${params}`);
      if (!res.ok) throw new Error("API error");
      const d   = await res.json();
      const raw = d.data || d;           // per-tool snapshot map
      setData(transformSnapshot(raw));   // transform to flat structure
    } catch (err) {
      console.warn("Snapshot fetch failed:", err.message);
      setData({});                       // empty — show "no data" states
    } finally {
      setLoading(false);
      setLastUpdated(new Date());
    }
  }, [dateRange]);

  useEffect(() => {
    loadData();
    const t = setInterval(loadData, 5 * 60 * 1000);
    return () => clearInterval(t);
  }, [loadData]);

  function renderPage() {
    const p = { data, dateRange };
    switch(page) {
      case "overview": return <OverviewPage {...p}/>;
      case "risk":     return <RiskCompliancePage {...p}/>;
      case "threats":  return <ThreatPage {...p}/>;
      case "cloud":    return <CloudPage {...p}/>;
      case "report":   return <ReportPage {...p}/>;
      case "alerts":   return <AlertsPage {...p}/>;
      case "vulns":    return <VulnerabilitiesPage {...p}/>;
      case "firewall": return <FirewallPage {...p}/>;
      case "surface":      return <AttackSurfacePage {...p}/>;
      case "assets":       return <AssetsPage {...p}/>;
      case "cloudanalyst": return <CloudAnalystPage {...p}/>;
      case "siem":         return <SIEMPage {...p}/>;
      case "admin":   return <AdminPage />;
      case "settings": return <IntegrationsPage onSave={loadData}/>;
      default:         return <OverviewPage {...p}/>;
    }
  }

  return (
    <div style={{ display:"flex", flexDirection:"column", height:"100vh",
      fontFamily:"'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif",
      background:C.bg, color:C.text }}>

      {/* ── HEADER ────────────────────────────────────────────────────────── */}
      <header style={{ background:C.header, color:"white", padding:"0 24px", height:60,
        display:"flex", alignItems:"center", gap:20, zIndex:10, boxShadow:"0 2px 12px rgba(0,0,0,0.25)", flexShrink:0 }}>

        {/* Logo */}
        <div style={{ display:"flex", alignItems:"center", gap:10, marginRight:"auto" }}>
          <div style={{ width:34, height:34, background:"linear-gradient(135deg,#3b82f6,#1d4ed8)", borderRadius:8,
            display:"flex", alignItems:"center", justifyContent:"center", fontSize:18, flexShrink:0 }}>🛡️</div>
          <div>
            <div style={{ fontWeight:700, fontSize:15, letterSpacing:0.3 }}>SecOps Command Center</div>
            <div style={{ fontSize:10, color:"#94a3b8", letterSpacing:1.2, textTransform:"uppercase" }}>Security Operations Dashboard • v{VER}</div>
          </div>
        </div>

        {/* Role toggle */}
        <div style={{ display:"flex", background:"rgba(0,0,0,0.25)", borderRadius:8, padding:3, gap:2 }}>
          {[["executive","🏢 Executive Board"],["analyst","🔬 Security Analyst"]].map(([r,l])=>(
            <button key={r} onClick={()=>{ setRole(r); setPage(r==="executive"?"overview":"alerts"); }}
              style={{ padding:"5px 14px", borderRadius:6, border:"none", cursor:"pointer", fontWeight:600, fontSize:12,
                background:role===r?"white":"transparent", color:role===r?C.header:"#94a3b8", transition:"all 0.15s" }}>
              {l}
            </button>
          ))}
        </div>

        {/* Date range */}
        <div style={{ display:"flex", alignItems:"center", gap:8, background:"rgba(255,255,255,0.06)",
          borderRadius:8, padding:"6px 12px", border:"1px solid rgba(255,255,255,0.1)", fontSize:12 }}>
          <span style={{ color:"#64748b", fontSize:10, textTransform:"uppercase", letterSpacing:1 }}>Period</span>
          <input type="date" value={dateRange.from} onChange={e=>setDateRange(p=>({...p,from:e.target.value}))}
            style={{ background:"transparent", border:"none", color:"white", fontSize:12, cursor:"pointer", width:120 }}/>
          <span style={{ color:"#475569" }}>–</span>
          <input type="date" value={dateRange.to} onChange={e=>setDateRange(p=>({...p,to:e.target.value}))}
            style={{ background:"transparent", border:"none", color:"white", fontSize:12, cursor:"pointer", width:120 }}/>
          {(dateRange.from||dateRange.to)&&(
            <button onClick={()=>setDateRange({from:"",to:""})} style={{ background:"none", border:"none", color:"#94a3b8", cursor:"pointer", fontSize:14, padding:0 }}>✕</button>
          )}
        </div>

        {/* Refresh indicator */}
        <div style={{ display:"flex", alignItems:"center", gap:6, fontSize:11, color:"#64748b" }}>
          <div style={{ width:7, height:7, borderRadius:"50%", background:loading?"#f59e0b":"#10b981",
            boxShadow:loading?"0 0 0 3px #f59e0b30":"0 0 0 3px #10b98130", transition:"all 0.3s" }}/>
          {loading?"Refreshing…":lastUpdated?`Updated ${lastUpdated.toLocaleTimeString([], {hour:"2-digit",minute:"2-digit"})}`:"-"}
        </div>

        {/* Settings gear */}
        <button onClick={()=>setPage("settings")}
          style={{ background:page==="settings"?"rgba(59,130,246,0.25)":"rgba(255,255,255,0.07)",
            border:`1px solid ${page==="settings"?"#3b82f6":"rgba(255,255,255,0.12)"}`,
            borderRadius:8, padding:"6px 12px", cursor:"pointer", color:page==="settings"?"#93c5fd":"#94a3b8",
            fontSize:17, lineHeight:1, transition:"all 0.15s" }}>
          ⚙️
        </button>
      </header>

      {/* ── BODY ──────────────────────────────────────────────────────────── */}
      <div style={{ display:"flex", flex:1, overflow:"hidden" }}>

        {/* Sidebar */}
        <aside style={{ width:216, background:C.sidebar, display:"flex", flexDirection:"column", flexShrink:0, overflow:"auto" }}>
          <div style={{ padding:"14px 16px 10px", borderBottom:"1px solid rgba(255,255,255,0.04)" }}>
            <div style={{ fontSize:9, color:"#334155", textTransform:"uppercase", letterSpacing:1.8, fontWeight:700 }}>
              {role==="executive"?"Board & Executive":"Security Team"}
            </div>
          </div>
          <nav style={{ flex:1, paddingTop:6 }}>
            {nav.map(n=>(
              <button key={n.id} onClick={()=>setPage(n.id)}
                style={{ display:"flex", alignItems:"center", gap:11, padding:"9px 16px", width:"100%", border:"none",
                  background:page===n.id?"rgba(59,130,246,0.14)":"transparent", cursor:"pointer", textAlign:"left",
                  borderLeft:`3px solid ${page===n.id?"#3b82f6":"transparent"}`, transition:"all 0.12s" }}>
                <span style={{ fontSize:15, lineHeight:1 }}>{n.icon}</span>
                <span style={{ fontSize:13, color:page===n.id?"#e2e8f0":"#94a3b8", fontWeight:page===n.id?600:400 }}>{n.label}</span>
              </button>
            ))}
          </nav>
          <div style={{ padding:16, borderTop:"1px solid rgba(255,255,255,0.04)" }}>
            <div style={{ fontSize:10, color:"#1e3a5f" }}>© 2024 SecOps Platform</div>
          </div>
        </aside>

        {/* Main */}
        <main style={{ flex:1, overflow:"auto", padding:24 }}>
          {loading && !data ? (
            <div style={{ display:"flex", alignItems:"center", justifyContent:"center", height:"100%", flexDirection:"column", gap:16 }}>
              <div style={{ width:44, height:44, border:"3px solid #3b82f6", borderTopColor:"transparent",
                borderRadius:"50%", animation:"spin 0.8s linear infinite" }}/>
              <div style={{ color:C.muted, fontSize:14 }}>Loading security data…</div>
            </div>
          ) : renderPage()}
        </main>
      </div>

      {/* Global styles */}
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
        @keyframes spin { to { transform:rotate(360deg); } }
        *, *::before, *::after { box-sizing:border-box; }
        body { margin:0; }
        input[type="date"]::-webkit-calendar-picker-indicator { filter:invert(0.6); opacity:0.5; cursor:pointer; }
        ::-webkit-scrollbar { width:5px; height:5px; }
        ::-webkit-scrollbar-track { background:transparent; }
        ::-webkit-scrollbar-thumb { background:#334155; border-radius:3px; }
        ::-webkit-scrollbar-thumb:hover { background:#475569; }
        button:hover { opacity:0.9; }
        @media print {
          aside, header button, nav { display:none !important; }
          main { padding:0 !important; }
        }
      `}</style>
    </div>
  );
}
