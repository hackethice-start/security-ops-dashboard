import { useState, useEffect, useCallback, useRef } from "react";
import {
  BarChart, Bar, LineChart, Line, AreaChart, Area,
  PieChart, Pie, Cell, RadarChart, Radar, PolarGrid,
  PolarAngleAxis, XAxis, YAxis, CartesianGrid, Tooltip,
  Legend, ResponsiveContainer
} from "recharts";

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

// ── Security Posture (Executive Home) ────────────────────────────────────────
function OverviewPage({ data }) {
  const d = data || buildMock();
  const critAlerts = d.alerts.filter(a=>a.severity==="Critical").length;
  const highAlerts = d.alerts.filter(a=>a.severity==="High").length;
  const critVulns = d.vulnerabilities?.filter(v=>v.severity==="Critical").length || 0;
  const openVulns = d.vulnerabilities?.filter(v=>v.status!=="Resolved").length || 0;
  const avgCompliance = d.compliance ? Math.round(d.compliance.reduce((s,c)=>s+c.score,0)/d.compliance.length) : 82;

  return (
    <div>
      <SectionTitle title="Security Posture Overview"
        subtitle={`Organisation-wide security health as of ${new Date().toLocaleDateString("en-AU",{weekday:"long",year:"numeric",month:"long",day:"numeric"})}`} />

      {/* Top KPI row */}
      <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:16, marginBottom:24 }}>
        <MetricCard icon="🛡️" label="Security Score" value={`${d.score}/100`}
          trend="↑ 3 pts this month" trendUp={true} color={C.primaryLight} />
        <MetricCard icon="🚨" label="Critical Alerts" value={critAlerts}
          sub={`${highAlerts} High, ${d.alerts.filter(a=>a.severity==="Medium").length} Medium`}
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
            <AreaChart data={d.trend} margin={{top:5,right:10,left:-20,bottom:0}}>
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
              <div style={{ fontSize:18, fontWeight:700, color:C.text }}>{Math.round(d.trend.reduce((s,t)=>s+t.alerts,0)/d.trend.length)}</div>
            </div>
            <div style={{ background:"#f8fafc", borderRadius:8, padding:"8px 12px" }}>
              <div style={{ fontSize:11, color:C.muted }}>Avg open vulns</div>
              <div style={{ fontSize:18, fontWeight:700, color:C.text }}>{Math.round(d.trend.reduce((s,t)=>s+t.vulns,0)/d.trend.length)}</div>
            </div>
          </div>
        </Card>

        {/* Risk summary */}
        <Card style={{ padding:20 }}>
          <div style={{ fontSize:14, fontWeight:700, color:C.text, marginBottom:16 }}>Risk by Domain</div>
          {d.riskByDomain.map(r=>(
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
            {d.alerts.filter(a=>["Critical","High"].includes(a.severity)).slice(0,5).map(a=>(
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
          {d.compliance.map(c=>(
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
  const d = data || buildMock();
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
                {d.compliance.map((c,i)=><Cell key={i} fill={c.color}/>)}
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
            {d.riskByDomain.map(r=>(
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
  const d = data || buildMock();
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

// ── Cloud Security ───────────────────────────────────────────────────────────
function CloudPage({ data }) {
  const d = data || buildMock();
  const cloudScore = 71;
  const cloudItems = [
    {cat:"Identity & Access",score:78,findings:3},{cat:"Data Protection",score:85,findings:1},
    {cat:"Network Security",score:72,findings:5},{cat:"Compute Security",score:69,findings:6},
    {cat:"Logging & Monitoring",score:88,findings:1},{cat:"App Security",score:63,findings:8},
  ];
  return (
    <div>
      <SectionTitle title="Cloud Security – Azure" subtitle="Microsoft Defender for Cloud posture and recommendations" />
      <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:16, marginBottom:24 }}>
        <MetricCard icon="☁️" label="Secure Score" value={`${cloudScore}%`} sub="Azure Defender target: 85%" trendUp={false} color={C.primaryLight}/>
        <MetricCard icon="⚠️" label="Recommendations" value="15" sub="7 high severity" trendUp={false} color={C.high}/>
        <MetricCard icon="🔒" label="Protected Resources" value="94%" sub="206 of 219 resources" trendUp={true} color={C.ok}/>
        <MetricCard icon="💡" label="Quick Wins" value="4" sub="Low effort, high impact" trendUp={true} color={C.primary}/>
      </div>
      <div style={{ display:"grid", gridTemplateColumns:"2fr 1fr", gap:16 }}>
        <Card style={{ padding:24 }}>
          <div style={{ fontSize:14, fontWeight:700, color:C.text, marginBottom:20 }}>Security Controls by Category</div>
          {cloudItems.map(c=>(
            <div key={c.cat} style={{ marginBottom:16 }}>
              <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:6 }}>
                <span style={{ fontSize:13, color:C.text, fontWeight:500 }}>{c.cat}</span>
                <div style={{ display:"flex", alignItems:"center", gap:10 }}>
                  <span style={{ fontSize:11, color:C.muted }}>{c.findings} findings</span>
                  <span style={{ fontSize:14, fontWeight:700, color:c.score>=80?C.ok:c.score>=70?C.warn:C.critical }}>{c.score}%</span>
                </div>
              </div>
              <div style={{ height:8, background:"#f1f5f9", borderRadius:4 }}>
                <div style={{ height:"100%", width:`${c.score}%`, background:`linear-gradient(90deg,${c.score>=80?C.ok:c.score>=70?C.warn:C.critical}bb,${c.score>=80?C.ok:c.score>=70?C.warn:C.critical})`, borderRadius:4 }}/>
              </div>
            </div>
          ))}
        </Card>
        <Card style={{ padding:24 }}>
          <div style={{ fontSize:14, fontWeight:700, color:C.text, marginBottom:16 }}>Resource Coverage</div>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie data={[{name:"Protected",value:94},{name:"Unprotected",value:6}]}
                cx="50%" cy="50%" innerRadius={55} outerRadius={80}
                paddingAngle={3} dataKey="value">
                <Cell fill={C.ok}/><Cell fill="#f1f5f9"/>
              </Pie>
              <Tooltip contentStyle={{borderRadius:8,fontSize:12}}/>
            </PieChart>
          </ResponsiveContainer>
          <div style={{ borderTop:`1px solid ${C.border}`, paddingTop:12 }}>
            {[
              {label:"Virtual Machines",total:45,prot:42},{label:"Storage Accounts",total:23,prot:23},
              {label:"Databases",total:12,prot:11},{label:"App Services",total:18,prot:15},
              {label:"Kubernetes",total:4,prot:3},
            ].map(r=>(
              <div key={r.label} style={{ display:"flex", justifyContent:"space-between", padding:"5px 0" }}>
                <span style={{ fontSize:12, color:C.text }}>{r.label}</span>
                <span style={{ fontSize:12, color:r.prot===r.total?C.ok:C.warn, fontWeight:600 }}>{r.prot}/{r.total}</span>
              </div>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
}

// ── Executive Report ─────────────────────────────────────────────────────────
function ReportPage({ data }) {
  const d = data || buildMock();
  const avgCompliance = d.compliance ? Math.round(d.compliance.reduce((s,c)=>s+c.score,0)/d.compliance.length) : 82;
  const critAlerts = d.alerts.filter(a=>a.severity==="Critical").length;
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
            <strong>{d.alerts.filter(a=>a.severity==="High").length} high</strong> severity alerts requiring attention, and <strong>{openVulns} open vulnerabilities</strong>{" "}
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
  const d = data || buildMock();
  const [filter, setFilter] = useState("All");
  const [search, setSearch] = useState("");
  const [toolFilter, setToolFilter] = useState("All");
  const severities = ["All","Critical","High","Medium","Low"];
  const filtered = d.alerts.filter(a=>
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
            <div style={{ fontSize:18, fontWeight:800, color:SEVERITY_COLORS[s]||C.text }}>{s==="All"?d.alerts.length:counts[s]||0}</div>
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
  const d = data || buildMock();
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
  const d = data || buildMock();
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
  const d = data || buildMock();
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
  const d = data || buildMock();
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
  const d = data || buildMock();
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
function IntegrationsPage({ onSave }) {
  const [statuses, setStatuses] = useState({});
  const [editing, setEditing] = useState(null);
  const [form, setForm] = useState({});
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(null);
  const [toast, setToast] = useState(null);

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
    } catch(e) {
      console.error("Could not load integration statuses:", e);
    }
  }

  function showToast(msg, ok=true) {
    setToast({msg, ok});
    setTimeout(()=>setToast(null), 3000);
  }

  const FIELDS = {
    fortinet:     [["host","Host URL","https://192.168.1.1"],["apikey","API Key","FortiGate REST API token"]],
    paloalto:     [["host","Host / Panorama URL","https://panorama.company.com"],["apikey","API Key","PAN-OS API key"]],
    upguard:      [["apikey","API Key","UpGuard API key"],["subdomain","Subdomain","company"]],
    azure:        [["tenantId","Tenant ID","xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"],["clientId","Client ID",""],["clientSecret","Client Secret",""],["subscriptionId","Subscription ID",""]],
    qualys:       [["username","Username","qualys-reader@company.com"],["password","Password",""],["platform","Platform URL","https://qualysapi.qualys.com"]],
    manageengine: [["host","Server URL","https://meserver:8443"],["apikey","API Key","Zoho OAuth token"]],
    taegis:       [["clientId","Client ID",""],["clientSecret","Client Secret",""],["region","Region","us1"]],
  };

  async function saveIntegration(toolKey) {
    setSaving(true);
    try {
      const payload = { credentials: form, refresh_interval: form._interval || 300 };
      delete payload.credentials._interval;
      const r = await fetch(`${API}/api/integrations/${toolKey}`, {
        method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(payload)
      });
      if (r.ok) {
        showToast("Credentials saved successfully");
        setEditing(null);
        loadStatuses();
        if (onSave) onSave();
      } else {
        showToast("Failed to save credentials", false);
      }
    } catch(e) { showToast("Network error saving credentials", false); }
    setSaving(false);
  }

  async function testConnection(toolKey) {
    setTesting(toolKey);
    try {
      const r = await fetch(`${API}/api/integrations/${toolKey}/test`, { method:"POST" });
      const data = await r.json();
      showToast(data.success ? `${toolKey} connected successfully` : `Test failed: ${data.error}`, data.success);
      loadStatuses();
    } catch(e) { showToast("Connection test failed", false); }
    setTesting(null);
  }

  async function deleteIntegration(toolKey) {
    if (!confirm(`Remove credentials for ${toolKey}?`)) return;
    await fetch(`${API}/api/integrations/${toolKey}`, { method:"DELETE" });
    loadStatuses();
    showToast("Credentials removed");
  }

  return (
    <div>
      <SectionTitle title="Integrations & Settings" subtitle="Connect and configure your security tools. Credentials are stored securely in the database." />
      {toast&&(
        <div style={{ position:"fixed", bottom:24, right:24, background:toast.ok?C.ok:C.critical, color:"white", padding:"12px 20px", borderRadius:10, fontSize:13, fontWeight:600, boxShadow:"0 4px 20px rgba(0,0,0,0.2)", zIndex:1000 }}>
          {toast.ok?"✅":"❌"} {toast.msg}
        </div>
      )}
      <div style={{ display:"grid", gridTemplateColumns:"repeat(2,1fr)", gap:16 }}>
        {TOOLS.map(tool => {
          const st = statuses[tool.key] || {};
          const isConfigured = st.status && st.status !== "unconfigured";
          const isConnected = st.status === "connected";
          const isEditing = editing === tool.key;
          return (
            <Card key={tool.key} style={{ padding:24, border: isConnected ? `2px solid ${C.ok}30` : `2px solid ${C.border}` }}>
              <div style={{ display:"flex", alignItems:"flex-start", justifyContent:"space-between", marginBottom:16 }}>
                <div style={{ display:"flex", alignItems:"center", gap:12 }}>
                  <div style={{ width:44, height:44, borderRadius:10, background:`${tool.color}18`, display:"flex", alignItems:"center", justifyContent:"center", fontSize:24 }}>{tool.icon}</div>
                  <div>
                    <div style={{ fontSize:15, fontWeight:700, color:C.text }}>{tool.name}</div>
                    <div style={{ fontSize:11, color:C.muted }}>{tool.cat}</div>
                  </div>
                </div>
                <div style={{ display:"flex", alignItems:"center", gap:6 }}>
                  <div style={{ width:8, height:8, borderRadius:"50%", background:isConnected?C.ok:isConfigured?C.warn:"#cbd5e1" }}/>
                  <span style={{ fontSize:11, fontWeight:600, color:isConnected?C.ok:isConfigured?C.warn:C.muted }}>
                    {isConnected?"Connected":isConfigured?`Status: ${st.status}`:"Not Configured"}
                  </span>
                </div>
              </div>

              {st.last_tested&&<div style={{ fontSize:11, color:C.muted, marginBottom:12 }}>Last tested: {new Date(st.last_tested).toLocaleString()}</div>}
              {st.last_error&&<div style={{ fontSize:11, color:C.critical, marginBottom:12, background:"#fef2f2", padding:"6px 10px", borderRadius:6 }}>⚠️ {st.last_error}</div>}

              {isEditing ? (
                <div>
                  {(FIELDS[tool.key]||[]).map(([field, label, placeholder])=>(
                    <div key={field} style={{ marginBottom:12 }}>
                      <label style={{ display:"block", fontSize:12, fontWeight:600, color:C.muted, marginBottom:4, textTransform:"uppercase", letterSpacing:0.5 }}>{label}</label>
                      <input type={field.toLowerCase().includes("pass")||field.toLowerCase().includes("secret")||field.toLowerCase().includes("key")?"password":"text"}
                        value={form[field]||""} onChange={e=>setForm(p=>({...p,[field]:e.target.value}))}
                        placeholder={placeholder}
                        style={{ width:"100%", padding:"8px 12px", borderRadius:8, border:`1px solid ${C.border}`, fontSize:13, outline:"none", boxSizing:"border-box" }}/>
                    </div>
                  ))}
                  <div style={{ marginBottom:12 }}>
                    <label style={{ display:"block", fontSize:12, fontWeight:600, color:C.muted, marginBottom:4, textTransform:"uppercase", letterSpacing:0.5 }}>Refresh Interval</label>
                    <select value={form._interval||300} onChange={e=>setForm(p=>({...p,_interval:parseInt(e.target.value)}))}
                      style={{ width:"100%", padding:"8px 12px", borderRadius:8, border:`1px solid ${C.border}`, fontSize:13, background:"white" }}>
                      {INTERVALS.map(i=><option key={i.value} value={i.value}>Every {i.label}</option>)}
                    </select>
                  </div>
                  <div style={{ display:"flex", gap:8 }}>
                    <button onClick={()=>saveIntegration(tool.key)} disabled={saving}
                      style={{ flex:1, padding:"9px 0", borderRadius:8, border:"none", background:tool.color, color:"white", fontSize:13, fontWeight:700, cursor:"pointer" }}>
                      {saving?"Saving…":"💾 Save"}
                    </button>
                    <button onClick={()=>setEditing(null)} style={{ padding:"9px 14px", borderRadius:8, border:`1px solid ${C.border}`, background:"white", color:C.muted, fontSize:13, cursor:"pointer" }}>Cancel</button>
                  </div>
                </div>
              ) : (
                <div style={{ display:"flex", gap:8, flexWrap:"wrap" }}>
                  <button onClick={()=>{ setEditing(tool.key); setForm({_interval:st.refresh_interval||300}); }}
                    style={{ padding:"7px 14px", borderRadius:8, border:`1px solid ${tool.color}`, color:tool.color, background:`${tool.color}08`, fontSize:12, fontWeight:600, cursor:"pointer" }}>
                    ✏️ {isConfigured?"Edit":"Configure"}
                  </button>
                  {isConfigured&&<>
                    <button onClick={()=>testConnection(tool.key)} disabled={testing===tool.key}
                      style={{ padding:"7px 14px", borderRadius:8, border:`1px solid ${C.border}`, color:C.text, background:"white", fontSize:12, fontWeight:600, cursor:"pointer" }}>
                      {testing===tool.key?"Testing…":"🔗 Test"}
                    </button>
                    <button onClick={()=>deleteIntegration(tool.key)}
                      style={{ padding:"7px 14px", borderRadius:8, border:`1px solid ${C.border}`, color:C.critical, background:"white", fontSize:12, cursor:"pointer" }}>
                      🗑️
                    </button>
                  </>}
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
  ];
  const analystNav = [
    { id:"alerts",  icon:"🚨", label:"Alert Queue" },
    { id:"vulns",   icon:"🔍", label:"Vulnerabilities" },
    { id:"firewall",icon:"🔥", label:"Firewall Analytics" },
    { id:"surface", icon:"🌐", label:"Attack Surface" },
    { id:"assets",  icon:"💻", label:"Assets & Patches" },
    { id:"siem",    icon:"📡", label:"SIEM / XDR" },
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
      const d = await res.json();
      setData(d.data || d);
    } catch {
      setData(buildMock());
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
      case "surface":  return <AttackSurfacePage {...p}/>;
      case "assets":   return <AssetsPage {...p}/>;
      case "siem":     return <SIEMPage {...p}/>;
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
