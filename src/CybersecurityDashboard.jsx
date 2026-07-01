import React, { useState, useEffect, useCallback, useRef } from "react";
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
  else if (ug.breachsight?.score)          score = ug.breachsight.score;
  else if (ug.risks?.score)                score = ug.risks.score;
  else if (ug.score)                       score = ug.score;

  // ── Vulnerabilities ─────────────────────────────────────────────────────
  // backend parseQualysXML returns lowercase fields: { qid, host, ip, severity (text), title, cve, status, lastFound, port, type }
  const rawDetections = ql.detections;
  const vulnerabilities = Array.isArray(rawDetections) ? rawDetections.map((d,i) => ({
    id:        d.qid  || `qid-${i}`,
    host:      d.host || d.ip || "Unknown",
    ip:        d.ip   || "",
    severity:  d.severity || "Low",   // already mapped text by backend
    title:     d.title    || `QID ${d.qid || i}`,
    cve:       d.cve      || "",
    qid:       d.qid      || "",
    status:    d.status   || "Active",
    lastFound: d.lastFound || "",
    port:      d.port     || "—",
    type:      d.type     || "",
  })) : [];

  // ── Firewall ────────────────────────────────────────────────────────────
  // Build per-instance firewall objects for the instance-selector UI
  function buildFortinetInstance(snap) {
    const policies = Array.isArray(snap.policies) ? snap.policies : [];
    const stats    = Array.isArray(snap.stats)    ? snap.stats    : [];
    const ifaces   = Array.isArray(snap.interfaces) ? snap.interfaces : [];
    const sys      = snap.sysGlobal || {};

    const statsById = {};
    stats.forEach(s => { if (s.policyid != null) statsById[s.policyid] = s; });

    const mappedPolicies = policies.map(p => {
      const st = statsById[p.policyid] || {};
      const srcAny = (p.srcaddr||[]).some(a => a.name==="all"||a.q_origin_key==="all");
      const dstAny = (p.dstaddr||[]).some(a => a.name==="all"||a.q_origin_key==="all");
      const svcAny = (p.service||[]).some(s => s.name==="ALL"||s.q_origin_key==="ALL");
      return {
        id:       p.policyid,
        name:     p.name || `Policy ${p.policyid}`,
        action:   (p.action||"").toLowerCase()==="accept" ? "Allow"
                : (p.action||"").toLowerCase()==="deny"   ? "Deny" : p.action||"Allow",
        srcaddr:  (p.srcaddr||[]).map(a=>a.name).join(", ")||"any",
        dstaddr:  (p.dstaddr||[]).map(a=>a.name).join(", ")||"any",
        service:  (p.service||[]).map(s=>s.name).join(", ")||"ALL",
        logtraffic: p.logtraffic || "disable",
        status:   p.status === "enable" ? "Enabled" : "Disabled",
        bytes:    st.bytes || 0,
        packets:  st.packets || 0,
        sessions: st.asic_sessions || st.software_sessions || 0,
        srcAny, dstAny, svcAny,
        overpermissive: srcAny && dstAny,
      };
    });

    const bandwidth = ifaces.filter(i=>i.rx_bytes||i.tx_bytes).map(i=>({
      name:    i.name,
      rxBytes: i.rx_bytes || 0,
      txBytes: i.tx_bytes || 0,
      rxBps:   i.rx_bps   || i.rxbps || 0,
      txBps:   i.tx_bps   || i.txbps || 0,
      link:    i.link ? "Up" : "Down",
      speed:   i.speed || "",
    }));

    // ── CIS FortiGate Benchmark controls (CIS Fortinet FortiGate Benchmark v1.0) ──
    const hasDefaultDeny   = mappedPolicies.some(p=>p.action==="Deny"&&p.srcAny&&p.dstAny);
    const allAllowLogged   = mappedPolicies.filter(p=>p.action==="Allow"&&p.status==="Enabled").every(p=>p.logtraffic&&p.logtraffic!=="disable");
    const noAnyAny         = !mappedPolicies.some(p=>p.overpermissive&&p.action==="Allow");
    const noSvcAll         = mappedPolicies.filter(p=>p.action==="Allow"&&p.status==="Enabled").every(p=>!p.svcAny);
    const noUnused         = mappedPolicies.filter(p=>p.action==="Allow"&&p.status==="Enabled").every(p=>p.packets>0);
    const noDisabled       = mappedPolicies.every(p=>p.status==="Enabled");
    const httpsOnly        = sys.admin_https_redirect !== "disable";
    const sshPortNonDef    = sys.admin_ssh_port ? sys.admin_ssh_port !== 22 : null;
    const httpsMgmtOnly    = sys.admintimeout ? true : null; // session timeout configured
    const ntpConfigured    = sys.ntpserver ? true : null;
    const hasAdminTimeout  = sys.admintimeout && sys.admintimeout <= 15;
    const cisBenchmark = [
      // ── 1. Account & Access Management ──────────────────────────────────
      { id:"1.1",  category:"Account Management",  check:"Ensure admin session timeout is 15 minutes or less",           pass: sys.admintimeout ? sys.admintimeout <= 15 : null,   remediation:"Set: config system global → set admintimeout 15" },
      { id:"1.2",  category:"Account Management",  check:"Ensure HTTPS-only management access (HTTP redirected to HTTPS)",pass: httpsOnly,                                           remediation:"Set: config system global → set admin-https-redirect enable" },
      { id:"1.3",  category:"Account Management",  check:"Ensure SSH management uses non-default port (not 22)",          pass: sshPortNonDef,                                       remediation:"Set: config system global → set admin-ssh-port <non-22>" },
      { id:"1.4",  category:"Account Management",  check:"Ensure management access restricted to trusted IPs only",       pass: mappedPolicies.filter(p=>p.name?.toLowerCase().match(/mgmt|admin|manage/)).every(p=>!p.srcAny)||null, remediation:"Create dedicated management policy with specific src addresses" },
      { id:"1.5",  category:"Account Management",  check:"Ensure pre-login banner is configured",                         pass: sys.pre_login_banner === "enable" ? true : sys.pre_login_banner ? null : false, remediation:"Set: config system global → set pre-login-banner enable" },
      { id:"1.6",  category:"Account Management",  check:"Ensure post-login banner is configured",                        pass: sys.post_login_banner === "enable" ? true : null,    remediation:"Set: config system global → set post-login-banner enable" },
      // ── 2. Network Security ─────────────────────────────────────────────
      { id:"2.1",  category:"Network Security",    check:"Ensure NTP server is configured",                               pass: ntpConfigured,                                       remediation:"Set: config system ntp → set server <ntp-server>" },
      { id:"2.2",  category:"Network Security",    check:"Ensure DNS servers are explicitly configured",                  pass: sys.primary_dns ? true : null,                       remediation:"Set: config system dns → set primary <ip>" },
      { id:"2.3",  category:"Network Security",    check:"Ensure SNMP v1/v2 is disabled (use SNMPv3 only)",               pass: null,                                                remediation:"Disable SNMPv1/v2: config system snmp community → delete all" },
      // ── 3. Logging & Monitoring ─────────────────────────────────────────
      { id:"3.1",  category:"Logging",             check:"Ensure traffic logging enabled on all allow policies",           pass: allAllowLogged,                                      remediation:"Set logtraffic=all on each allow policy" },
      { id:"3.2",  category:"Logging",             check:"Ensure syslog server is configured",                            pass: null,                                                remediation:"config log syslogd setting → set status enable → set server <ip>" },
      { id:"3.3",  category:"Logging",             check:"Ensure logging is set to record all event types",               pass: null,                                                remediation:"config log setting → set faz-override enable" },
      { id:"3.4",  category:"Logging",             check:"Ensure IPS logging is enabled",                                 pass: null,                                                remediation:"Enable IPS sensor with logging on all relevant policies" },
      // ── 4. Firewall Policy ──────────────────────────────────────────────
      { id:"4.1",  category:"Firewall Policy",     check:"Ensure default deny-all policy exists",                         pass: hasDefaultDeny,                                      remediation:"Add a deny-all policy at the bottom of the policy list" },
      { id:"4.2",  category:"Firewall Policy",     check:"Ensure no any→any allow rules exist",                           pass: noAnyAny,                                            remediation:"Replace any/any source-destination with specific addresses" },
      { id:"4.3",  category:"Firewall Policy",     check:"Ensure services are explicitly defined (no ALL service object)", pass: noSvcAll,                                           remediation:"Replace ALL service with specific application/port definitions" },
      { id:"4.4",  category:"Firewall Policy",     check:"Ensure no unused (zero-hit) allow rules exist",                 pass: noUnused,                                            remediation:"Review and remove allow policies with zero packet hits" },
      { id:"4.5",  category:"Firewall Policy",     check:"Ensure all allow policies have security profiles applied",       pass: mappedPolicies.filter(p=>p.action==="Allow"&&p.status==="Enabled").every(p=>p.profile)||null, remediation:"Apply AV, IPS, App Control profiles to all allow policies" },
      { id:"4.6",  category:"Firewall Policy",     check:"Ensure disabled policies are reviewed and removed",             pass: noDisabled,                                          remediation:"Remove or enable disabled policies after review" },
      // ── 5. System Hardening ─────────────────────────────────────────────
      { id:"5.1",  category:"System Hardening",    check:"Ensure auto-update for FortiGuard AV/IPS signatures is enabled",pass: null,                                               remediation:"config system autoupdate schedule → set status enable" },
      { id:"5.2",  category:"System Hardening",    check:"Ensure firmware is current (latest stable release)",            pass: null,                                                remediation:"Check FortiGuard: System → Firmware → upgrade to latest" },
      { id:"5.3",  category:"System Hardening",    check:"Ensure USB management port is disabled",                        pass: sys.usb_auto_install === "disable" ? true : sys.usb_auto_install ? false : null, remediation:"config system global → set usb-auto-install disable" },
      { id:"5.4",  category:"System Hardening",    check:"Ensure FortiGuard web filtering is licensed and active",        pass: null,                                                remediation:"Verify FortiGuard license: System → FortiGuard → Web Filter" },
      // ── 6. VPN ──────────────────────────────────────────────────────────
      { id:"6.1",  category:"VPN",                 check:"Ensure IKEv2 is used for IPsec VPN (not IKEv1)",               pass: null,                                                remediation:"Set keylife and use IKEv2 in VPN phase1 config" },
      { id:"6.2",  category:"VPN",                 check:"Ensure SSL-VPN uses strong TLS version (TLS 1.2+)",             pass: null,                                                remediation:"config vpn ssl settings → set tlsv1-2 enable → set tlsv1-0 disable" },
    ];

    return {
      vendor:      "fortinet",
      instance:    snap.instance,
      host:        snap.host,
      hostname:    sys.hostname || snap.instance,
      version:     sys.gui_firmware_upgrade_ui ? "" : (sys.firmware_version||""),
      policyCount: mappedPolicies.length,
      enabledCount:mappedPolicies.filter(p=>p.status==="Enabled").length,
      allowCount:  mappedPolicies.filter(p=>p.action==="Allow").length,
      denyCount:   mappedPolicies.filter(p=>p.action==="Deny").length,
      unusedRules: mappedPolicies.filter(p=>p.action==="Allow"&&p.status==="Enabled"&&p.packets===0).length,
      overpermissive: mappedPolicies.filter(p=>p.overpermissive&&p.action==="Allow").length,
      noLogging:   mappedPolicies.filter(p=>p.action==="Allow"&&p.status==="Enabled"&&(!p.logtraffic||p.logtraffic==="disable")).length,
      policies:    mappedPolicies,
      bandwidth,
      cisBenchmark,
      collectedAt: snap.collectedAt,
    };
  }

  function buildPaloAltoInstance(snap) {
    const rules  = Array.isArray(snap.rules)      ? snap.rules      : [];
    const ifaces = Array.isArray(snap.interfaces)  ? snap.interfaces : [];
    const sys    = snap.sysInfo || {};

    const mappedRules = rules.map((r,i) => {
      const name   = r["@name"] || r.name || `Rule ${i+1}`;
      const action = (r.action||"allow").toLowerCase()==="deny" ? "Deny" : "Allow";
      const src    = Array.isArray(r["source"]?.member) ? r["source"].member
                   : Array.isArray(r.from?.member) ? r.from.member : ["any"];
      const dst    = Array.isArray(r["destination"]?.member) ? r["destination"].member
                   : Array.isArray(r.to?.member) ? r.to.member : ["any"];
      const svc    = Array.isArray(r["service"]?.member) ? r["service"].member : ["any"];
      const srcAny = src.includes("any");
      const dstAny = dst.includes("any");
      const svcAny = svc.includes("any")||svc.includes("application-default");
      return {
        id: i+1, name, action,
        srcaddr: src.join(", "),
        dstaddr: dst.join(", "),
        service: svc.join(", "),
        status: r.disabled==="yes" ? "Disabled" : "Enabled",
        logtraffic: r["log-end"]==="yes"||r["log-start"]==="yes" ? "enable" : "disable",
        bytes: 0, packets: 0, sessions: 0,
        srcAny, dstAny, svcAny,
        overpermissive: srcAny && dstAny,
      };
    });

    // ── CIS Palo Alto Networks Firewall Benchmark controls (CIS PAN-OS v1.0) ──
    const paHasDefaultDeny = mappedRules.some(r=>r.action==="Deny"&&r.srcAny&&r.dstAny);
    const paAllLogged      = mappedRules.filter(r=>r.action==="Allow"&&r.status==="Enabled").every(r=>r.logtraffic==="enable");
    const paNoAnyAny       = !mappedRules.some(r=>r.overpermissive&&r.action==="Allow");
    const paNoSvcAny       = mappedRules.filter(r=>r.action==="Allow"&&r.status==="Enabled").every(r=>!r.svcAny);
    const cisBenchmark = [
      // ── 1. Management Interface ─────────────────────────────────────────
      { id:"1.1",  category:"Management",          check:"Ensure HTTPS-only access to management interface",              pass: null, remediation:"Device → Setup → Management → Management Interface Services → uncheck HTTP" },
      { id:"1.2",  category:"Management",          check:"Ensure Telnet access to management interface is disabled",      pass: null, remediation:"Device → Setup → Management → uncheck Telnet" },
      { id:"1.3",  category:"Management",          check:"Ensure SSH management uses non-default port",                   pass: sys.hostname ? null : null, remediation:"Device → Setup → Management → set SSH port to non-22" },
      { id:"1.4",  category:"Management",          check:"Ensure permitted IP addresses configured for management",       pass: null, remediation:"Device → Setup → Management → Permitted IP Addresses → add trusted IPs" },
      { id:"1.5",  category:"Management",          check:"Ensure idle session timeout is 10 minutes or less",            pass: null, remediation:"Device → Setup → Management → set Idle Timeout ≤ 10 min" },
      { id:"1.6",  category:"Management",          check:"Ensure login banners are configured",                           pass: null, remediation:"Device → Setup → Management → Login Banner → configure warning message" },
      // ── 2. Authentication ───────────────────────────────────────────────
      { id:"2.1",  category:"Authentication",      check:"Ensure minimum password complexity requirements are enforced",  pass: null, remediation:"Device → Setup → Management → Minimum Password Complexity → enable" },
      { id:"2.2",  category:"Authentication",      check:"Ensure account lockout is configured (max 3 failed attempts)",  pass: null, remediation:"Device → Setup → Management → Failed Attempts = 3; Lockout Time ≥ 30 min" },
      { id:"2.3",  category:"Authentication",      check:"Ensure MFA is enforced for administrator accounts",             pass: null, remediation:"Device → Authentication Profile → add MFA (Duo/RADIUS/SAML)" },
      { id:"2.4",  category:"Authentication",      check:"Ensure RADIUS/LDAP/SAML used for admin authentication",        pass: null, remediation:"Device → Server Profiles → configure external auth server" },
      // ── 3. Logging & Monitoring ─────────────────────────────────────────
      { id:"3.1",  category:"Logging",             check:"Ensure syslog forwarding is configured",                        pass: null, remediation:"Device → Server Profiles → Syslog → configure syslog server" },
      { id:"3.2",  category:"Logging",             check:"Ensure log forwarding profile applied to all security rules",   pass: paAllLogged, remediation:"Add Log Forwarding Profile to every security policy rule" },
      { id:"3.3",  category:"Logging",             check:"Ensure 'Log at Session End' enabled on all allow rules",        pass: mappedRules.filter(r=>r.action==="Allow"&&r.status==="Enabled").every(r=>r.logtraffic==="enable"), remediation:"Security policy → each Allow rule → Log at Session End = enabled" },
      { id:"3.4",  category:"Logging",             check:"Ensure threat logs are forwarded to SIEM",                      pass: null, remediation:"Objects → Log Forwarding → configure threat log forwarding" },
      // ── 4. Security Profiles ────────────────────────────────────────────
      { id:"4.1",  category:"Security Profiles",   check:"Ensure Antivirus profile applied to all allow rules",           pass: null, remediation:"Objects → Security Profiles → Antivirus → attach to all allow policies" },
      { id:"4.2",  category:"Security Profiles",   check:"Ensure Anti-Spyware profile applied to all allow rules",        pass: null, remediation:"Objects → Security Profiles → Anti-Spyware → attach to all allow policies" },
      { id:"4.3",  category:"Security Profiles",   check:"Ensure Vulnerability Protection profile applied",               pass: null, remediation:"Objects → Security Profiles → Vulnerability Protection → attach to policies" },
      { id:"4.4",  category:"Security Profiles",   check:"Ensure URL Filtering profile applied to outbound traffic",      pass: null, remediation:"Objects → Security Profiles → URL Filtering → attach to outbound policies" },
      { id:"4.5",  category:"Security Profiles",   check:"Ensure File Blocking profile applied to all allow rules",       pass: null, remediation:"Objects → Security Profiles → File Blocking → attach to allow policies" },
      { id:"4.6",  category:"Security Profiles",   check:"Ensure WildFire analysis profile is applied",                   pass: null, remediation:"Objects → Security Profiles → WildFire Analysis → attach to policies" },
      // ── 5. Security Policy ──────────────────────────────────────────────
      { id:"5.1",  category:"Security Policy",     check:"Ensure default deny-all rule exists at bottom of policy",       pass: paHasDefaultDeny, remediation:"Add a deny-all rule (any→any, action=deny) at the end of the ruleset" },
      { id:"5.2",  category:"Security Policy",     check:"Ensure no any-to-any allow rules exist",                        pass: paNoAnyAny,      remediation:"Replace any/any source-destination with specific address objects" },
      { id:"5.3",  category:"Security Policy",     check:"Ensure services not set to 'any' on allow rules",               pass: paNoSvcAny,      remediation:"Replace 'any' service with specific application or port definitions" },
      { id:"5.4",  category:"Security Policy",     check:"Ensure all security rules have a description",                  pass: mappedRules.every(r=>r.description||null),  remediation:"Add description to each security rule for audit trail" },
      { id:"5.5",  category:"Security Policy",     check:"Ensure disabled rules are reviewed and removed",                pass: mappedRules.every(r=>r.status==="Enabled"),  remediation:"Review and remove or re-enable all disabled security rules" },
      // ── 6. Network Security ─────────────────────────────────────────────
      { id:"6.1",  category:"Network Security",    check:"Ensure Zone Protection profiles are applied to all zones",      pass: null, remediation:"Network → Zones → attach Zone Protection Profile to each zone" },
      { id:"6.2",  category:"Network Security",    check:"Ensure DoS Protection policies are configured",                 pass: null, remediation:"Policies → DoS Protection → create rules for critical segments" },
      { id:"6.3",  category:"Network Security",    check:"Ensure Packet-Based Attack Protection is enabled in zone profile", pass: null, remediation:"Network → Zone Protection → enable Flood, Reconnaissance, Packet-Based protection" },
      // ── 7. PAN-OS Updates ───────────────────────────────────────────────
      { id:"7.1",  category:"System Hardening",    check:"Ensure PAN-OS is on the latest supported release",             pass: null, remediation:"Device → Dynamic Updates → check for and install latest PAN-OS" },
      { id:"7.2",  category:"System Hardening",    check:"Ensure Antivirus and WildFire updates are scheduled",           pass: null, remediation:"Device → Dynamic Updates → Antivirus → set schedule to every 30 min" },
      { id:"7.3",  category:"System Hardening",    check:"Ensure NTP is configured with at least two servers",            pass: null, remediation:"Device → Setup → Services → NTP Servers → add primary + secondary" },
      { id:"7.4",  category:"System Hardening",    check:"Ensure FIPS-CC mode is enabled if required",                   pass: null, remediation:"Device → Setup → Management → FIPS-CC Mode (if compliance required)" },
    ];

    return {
      vendor:      "paloalto",
      instance:    snap.instance || "Palo Alto",
      hostname:    sys.hostname  || snap.instance || "Palo Alto",
      version:     sys.version   || "",
      policyCount: mappedRules.length,
      enabledCount:mappedRules.filter(r=>r.status==="Enabled").length,
      allowCount:  mappedRules.filter(r=>r.action==="Allow").length,
      denyCount:   mappedRules.filter(r=>r.action==="Deny").length,
      unusedRules: 0, // no hit counters from config API
      overpermissive: mappedRules.filter(r=>r.overpermissive&&r.action==="Allow").length,
      noLogging:   mappedRules.filter(r=>r.action==="Allow"&&r.status==="Enabled"&&r.logtraffic==="disable").length,
      policies:    mappedRules,
      bandwidth:   [],
      cisBenchmark,
      collectedAt: null,
    };
  }

  // Build list of all firewall instances for the selector
  // Fortinet snap: { instances:[{source,vendor,instance,host,policies,stats,...},...] }
  // PaloAlto snap: { source, vendor, rules, interfaces, sysInfo }
  const ftInstanceList = Array.isArray(ft.instances) && ft.instances.length > 0
    ? ft.instances                    // new multi-instance format
    : (ft && Object.keys(ft).filter(k=>k!=="source"&&k!=="instances").length ? [ft] : []); // legacy single
  const firewallInstances = [
    ...ftInstanceList.map(inst => buildFortinetInstance(inst)),
    ...(pa && Object.keys(pa).length ? [buildPaloAltoInstance(pa)] : []),
  ];

  // Legacy flat shape kept for backward compat (overview widgets)
  const ftP = ft.policies || []; const ftS = ft.stats || []; const paR = pa.rules || [];
  const statsById2 = {}; ftS.forEach(s => { if (s.policyid!=null) statsById2[s.policyid]=s; });
  const ftM = ftP.map(p=>{ const st=statsById2[p.policyid]||{}; return { name:p.name||`P${p.policyid}`, hits:st.packets||0, action:(p.action||"").toLowerCase()==="accept"?"Allow":"Deny" }; });
  const paM = paR.map(r=>({ name:r["@name"]||"Rule", hits:0, action:(r.action||"allow").toLowerCase()==="deny"?"Deny":"Allow" }));
  const firewall = {
    instances:   firewallInstances,
    topPolicies: [...ftM,...paM].sort((a,b)=>b.hits-a.hits).slice(0,10),
    blockedToday: ftM.filter(p=>p.action==="Deny").reduce((s,p)=>s+p.hits,0),
    allowedToday: ftM.filter(p=>p.action==="Allow").reduce((s,p)=>s+p.hits,0),
    policyCount:  ftP.length + paR.length,
    trafficByHour:[], topThreatCountries:[],
    policies: ftP, stats: ftS, rules: paR,
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

  // ── UpGuard risks → surface ─────────────────────────────────────────────
  // Backend returns: { risks: { risks: [...] }, breachsight: { score: N } }
  const ugRisksArr  = Array.isArray(ug.risks?.risks) ? ug.risks.risks : [];
  const ugScore     = ug.breachsight?.score ?? ug.risks?.score ?? null;
  const ugGrade     = ug.breachsight?.grade ?? (
    ugScore === null ? null
    : ugScore >= 900 ? "A" : ugScore >= 800 ? "B+" : ugScore >= 700 ? "B"
    : ugScore >= 600 ? "C+" : ugScore >= 500 ? "C" : "D"
  );
  // UpGuard scores can be 0-950 scale — normalise to 0-100 for display
  const ugScoreDisplay = ugScore !== null ? (ugScore > 100 ? Math.round(ugScore/9.5) : ugScore) : null;

  // ── UpGuard: full surface data ───────────────────────────────────────────
  const ugDomainsRaw = Array.isArray(ug.domains?.domains) ? ug.domains.domains : [];
  const ugIpsRaw     = Array.isArray(ug.ips?.ips)         ? ug.ips.ips         : [];
  const risks = { risks: ugRisksArr, score: ugScore };   // kept for backward compat

  // Build enriched domains list
  const ugDomainsList = ugDomainsRaw.map(d => {
    const expStr = d.custom_domain_attributes?.expiry_date || d.expiry_date || null;
    const expDate = expStr ? new Date(expStr) : null;
    const daysToExp = expDate ? Math.ceil((expDate - Date.now()) / 86400000) : null;
    const grade = d.score != null
      ? (d.score >= 900 ? "A" : d.score >= 800 ? "B+" : d.score >= 700 ? "B" : d.score >= 600 ? "C+" : d.score >= 500 ? "C" : "D")
      : null;
    return {
      hostname:   d.hostname || d.primary_hostname || "—",
      score:      d.score != null ? (d.score > 100 ? Math.round(d.score / 9.5) : d.score) : null,
      grade,
      ips:        Array.isArray(d.ip_addresses) ? d.ip_addresses : [],
      expiry:     expDate ? expDate.toLocaleDateString("en-GB",{day:"2-digit",month:"short",year:"numeric"}) : "—",
      daysToExp,
      status:     !expDate ? "unknown" : daysToExp < 0 ? "expired" : daysToExp < 30 ? "critical" : daysToExp < 90 ? "warning" : "ok",
    };
  });

  // Build enriched IPs list
  const ugIpsList = ugIpsRaw.map(ip => ({
    ip:        ip.ip || "—",
    score:     ip.score != null ? (ip.score > 100 ? Math.round(ip.score / 9.5) : ip.score) : null,
    openPorts: Array.isArray(ip.open_ports)
      ? ip.open_ports.map(p => ({ port: p.port, service: p.service || "—", transport: p.transport || "tcp" }))
      : [],
  }));

  // Extract SSL certificate info from domains (when UpGuard provides ssl_certs field)
  const ugCertsList = ugDomainsRaw
    .filter(d => d.ssl_certificate || d.ssl_certs || d.certificates)
    .flatMap(d => {
      const certs = d.certificates || d.ssl_certs || (d.ssl_certificate ? [d.ssl_certificate] : []);
      return certs.map(c => {
        const expStr = c.valid_to || c.expiry_date || c.not_after || null;
        const expDate = expStr ? new Date(expStr) : null;
        const daysToExp = expDate ? Math.ceil((expDate - Date.now()) / 86400000) : null;
        return {
          domain:    d.hostname || d.primary_hostname || "—",
          subject:   c.subject || c.common_name || d.hostname || "—",
          issuer:    c.issuer || c.issuer_name || "—",
          validFrom: c.valid_from || c.not_before ? new Date(c.valid_from || c.not_before).toLocaleDateString("en-GB",{day:"2-digit",month:"short",year:"numeric"}) : "—",
          validTo:   expDate ? expDate.toLocaleDateString("en-GB",{day:"2-digit",month:"short",year:"numeric"}) : "—",
          daysToExp,
          status:    !expDate ? "unknown" : daysToExp < 0 ? "expired" : daysToExp < 14 ? "critical" : daysToExp < 30 ? "warning" : "ok",
        };
      });
    });

  // Count unique open ports across all IPs for the summary metric
  const ugAllOpenPorts = new Set(ugIpsList.flatMap(i => i.openPorts.map(p => p.port)));

  // Map to the shape AttackSurfacePage reads (d.surface)
  const surface = ugScore !== null || ugRisksArr.length > 0 || ugDomainsRaw.length > 0 ? {
    score:       ugScoreDisplay ?? 0,
    grade:       ugGrade ?? "N/A",
    findings:    ugRisksArr.map(r => ({
      severity: r.severity
        ? r.severity.charAt(0).toUpperCase() + r.severity.slice(1)
        : "Medium",
      title: r.finding || r.risk || "Risk finding",
      asset: (Array.isArray(r.hostnames) && r.hostnames[0]) || r.id || "—",
      first: r.firstDetected
        ? new Date(r.firstDetected).toLocaleDateString("en-GB",{day:"2-digit",month:"short",year:"numeric"})
        : "—",
    })),
    // Counts for summary cards
    domainCount:   ugDomainsRaw.length || null,
    ipCount:       ugIpsRaw.length || null,
    openPortCount: ugAllOpenPorts.size || null,
    certCount:     ugCertsList.length || null,
    // Detailed lists for tabs
    domainsList:   ugDomainsList,
    ipsList:       ugIpsList,
    certsList:     ugCertsList,
  } : null;

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
    surface,                // UpGuard attack surface — mapped from risks[]
    firewall,
    assets,
    siem,
    vulnerabilities,
    azure:        azFull,
    upguard:      ug,
    qualys:       ql,
    manageengine: me,
  };
}


/* ═══════════════════════════════════════════════════════════════════════════
   CONFIG
═══════════════════════════════════════════════════════════════════════════ */
const API = `http://${window.location.hostname}:4000`;

// All API calls include credentials (cookie) for auth
const apiFetch = (url, opts = {}) => fetch(url, {
  credentials: "include",
  ...opts,
  headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
});
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

// ── Vulnerability Detail Modal ───────────────────────────────────────────────
function VulnDetailModal({ vuln, onClose }) {
  if (!vuln) return null;
  const FIELDS = [
    ["QID",         vuln.qid],
    ["CVE",         vuln.cve || "—"],
    ["Host",        vuln.host],
    ["IP Address",  vuln.ip || vuln.host],
    ["Port",        vuln.port || "—"],
    ["Type",        vuln.type || "—"],
    ["Status",      vuln.status],
    ["Last Found",  vuln.lastFound ? new Date(vuln.lastFound).toLocaleString() : "—"],
  ];
  return (
    <div style={{ position:"fixed", inset:0, background:"rgba(0,0,0,0.55)", zIndex:1000,
      display:"flex", alignItems:"center", justifyContent:"center", padding:24 }}
      onClick={onClose}>
      <div style={{ background:"white", borderRadius:14, width:"100%", maxWidth:560,
        maxHeight:"85vh", overflow:"auto", boxShadow:"0 25px 60px rgba(0,0,0,0.4)" }}
        onClick={e=>e.stopPropagation()}>
        {/* Header */}
        <div style={{ padding:"18px 22px", borderBottom:`3px solid ${SEVERITY_COLORS[vuln.severity]||"#e2e8f0"}`,
          display:"flex", justifyContent:"space-between", alignItems:"flex-start", gap:12 }}>
          <div>
            <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:6 }}>
              <SeverityBadge level={vuln.severity}/>
              {vuln.cve && (
                <span style={{ fontFamily:"monospace", fontSize:12, fontWeight:700, color:C.primary,
                  background:`${C.primary}12`, padding:"2px 8px", borderRadius:4 }}>{vuln.cve}</span>
              )}
              {!vuln.cve && vuln.qid && (
                <span style={{ fontFamily:"monospace", fontSize:12, color:C.muted }}>QID {vuln.qid}</span>
              )}
            </div>
            <div style={{ fontSize:15, fontWeight:700, color:C.text, lineHeight:1.4 }}>{vuln.title}</div>
          </div>
          <button onClick={onClose} style={{ background:"none", border:"none", fontSize:20,
            cursor:"pointer", color:C.muted, lineHeight:1, flexShrink:0, padding:"2px 4px" }}>✕</button>
        </div>
        {/* Details grid */}
        <div style={{ padding:"16px 22px" }}>
          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:"1px",
            background:C.border, borderRadius:8, overflow:"hidden", border:`1px solid ${C.border}` }}>
            {FIELDS.map(([label, val])=>(
              <div key={label} style={{ padding:"10px 14px", background:"white" }}>
                <div style={{ fontSize:10, fontWeight:700, color:C.muted, textTransform:"uppercase",
                  letterSpacing:0.5, marginBottom:3 }}>{label}</div>
                <div style={{ fontSize:13, fontWeight:600, color:C.text, wordBreak:"break-all" }}>{val}</div>
              </div>
            ))}
          </div>
          {/* Full title / results */}
          <div style={{ marginTop:14, padding:"12px 14px", borderRadius:8,
            background:"#f8fafc", border:`1px solid ${C.border}` }}>
            <div style={{ fontSize:10, fontWeight:700, color:C.muted, textTransform:"uppercase",
              letterSpacing:0.5, marginBottom:6 }}>Full Description</div>
            <div style={{ fontSize:12, color:C.text, lineHeight:1.6, fontFamily:"monospace",
              whiteSpace:"pre-wrap", wordBreak:"break-word" }}>{vuln.title}</div>
          </div>
          <div style={{ marginTop:12, display:"flex", justifyContent:"flex-end" }}>
            <button onClick={onClose}
              style={{ padding:"8px 20px", borderRadius:8, border:`1px solid ${C.border}`,
                background:"white", color:C.muted, fontSize:13, cursor:"pointer" }}>Close</button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Vulnerability Deep Dive ──────────────────────────────────────────────────
function VulnerabilitiesPage({ data }) {
  const d = data || {};
  if (!d._hasData) return <NoData icon="🔍" title="No vulnerability data yet" message="Connect Qualys VMDR in ⚙️ Settings to see live vulnerability scan results." />;
  const [sort,    setSort]    = useState("severity");
  const [selected, setSelected] = useState(null);
  const SEV_ORDER = { Critical:0, High:1, Medium:2, Low:3 };
  const all = d.vulnerabilities || [];
  const vulns = [...all].sort((a,b) => {
    if (sort === "host") return (a.host||"").localeCompare(b.host||"");
    if (sort === "date") return new Date(b.lastFound||0) - new Date(a.lastFound||0);
    return (SEV_ORDER[a.severity]||3) - (SEV_ORDER[b.severity]||3);
  });
  const bySev = {};
  all.forEach(v => { bySev[v.severity] = (bySev[v.severity]||0) + 1; });
  const pieData = Object.entries(bySev).map(([k,v]) => ({ name:k, value:v, color:SEVERITY_COLORS[k] }));
  return (
    <div>
      <VulnDetailModal vuln={selected} onClose={()=>setSelected(null)}/>
      <SectionTitle title="Vulnerability Management – Qualys VMDR" subtitle={`${all.length} detections from live scan · sorted by ${sort}`} />
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
          <div style={{ fontSize:14, fontWeight:700, color:C.text }}>Detection List – Live Qualys VMDR Results</div>
          <div style={{ display:"flex", gap:8 }}>
            {[["severity","By Severity"],["host","By Host"],["date","By Date"]].map(([v,l])=>(
              <button key={v} onClick={()=>setSort(v)}
                style={{ padding:"6px 14px", borderRadius:6, border:`1px solid ${sort===v?C.primary:C.border}`,
                  background:sort===v?`${C.primary}12`:"white", color:sort===v?C.primary:C.muted, fontSize:12, cursor:"pointer", fontWeight:600 }}>{l}</button>
            ))}
          </div>
        </div>
        {vulns.length === 0 && (
          <div style={{ textAlign:"center", padding:40, color:C.muted, fontSize:13 }}>
            No detections found. Run a Qualys scan or check your credentials in ⚙️ Settings.
          </div>
        )}
        {vulns.length > 0 && (
        <table style={{ width:"100%", borderCollapse:"collapse" }}>
          <thead><tr style={{ background:"#f8fafc" }}>
            {["Severity","QID / CVE","Host / IP","Title","Port","Last Found","Status"].map(h=>(
              <th key={h} style={{ padding:"10px 12px", textAlign:"left", fontSize:11, fontWeight:700, color:C.muted, textTransform:"uppercase", letterSpacing:0.5, borderBottom:`2px solid ${C.border}` }}>{h}</th>
            ))}
          </tr></thead>
          <tbody>
            {vulns.map((v,i)=>(
              <tr key={v.id||i} onClick={()=>setSelected(v)}
                style={{ borderBottom:`1px solid ${C.border}`, background:v.severity==="Critical"?"#fef2f220":"transparent",
                  cursor:"pointer", transition:"background 0.1s" }}
                onMouseEnter={e=>e.currentTarget.style.background="#f0f9ff"}
                onMouseLeave={e=>e.currentTarget.style.background=v.severity==="Critical"?"#fef2f220":"transparent"}>
                <td style={{ padding:"11px 12px" }}><SeverityBadge level={v.severity}/></td>
                <td style={{ padding:"11px 12px", fontFamily:"monospace", fontSize:11, fontWeight:700, color:C.primary }}>
                  {v.cve ? <span title={`QID: ${v.qid}`}>{v.cve}</span> : <span style={{color:C.muted}}>QID {v.qid}</span>}
                </td>
                <td style={{ padding:"11px 12px", fontSize:12 }}>
                  <div style={{ fontWeight:600, color:C.text }}>{v.host}</div>
                  {v.ip && v.ip !== v.host && <div style={{ fontSize:10, color:C.muted }}>{v.ip}</div>}
                </td>
                <td style={{ padding:"11px 12px", fontSize:12, color:C.text, maxWidth:280 }}>
                  <div style={{ overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }} title={v.title}>{v.title}</div>
                </td>
                <td style={{ padding:"11px 12px", fontSize:12, color:C.muted, textAlign:"center" }}>{v.port}</td>
                <td style={{ padding:"11px 12px", fontSize:11, color:C.muted, whiteSpace:"nowrap" }}>
                  {v.lastFound ? new Date(v.lastFound).toLocaleDateString() : "—"}
                </td>
                <td style={{ padding:"11px 12px" }}>
                  <span style={{ fontSize:11, fontWeight:600, padding:"3px 10px", borderRadius:20,
                    background:v.status==="Active"?"#fef2f2":v.status==="New"?"#fff7ed":"#f0fdf4",
                    color:v.status==="Active"?C.critical:v.status==="New"?C.warn:C.ok }}>{v.status}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        )}
      </Card>
    </div>
  );
}

// ── Firewall Analytics ───────────────────────────────────────────────────────
function FirewallPage({ data }) {
  const d = data || {};
  if (!d._hasData) return <NoData icon="🔥" title="No firewall data yet" message="Connect Fortinet or Palo Alto in ⚙️ Settings to see live firewall analytics." />;

  const instances = d.firewall?.instances || [];
  const [selIdx,   setSelIdx]   = React.useState(0);
  const [tab,      setTab]      = React.useState("overview");  // overview | rules | bandwidth | cis
  const [ruleFilter, setRuleFilter] = React.useState("all");   // all | allow | deny | disabled | risk

  const fw = instances[selIdx] || instances[0] || {};
  const policies  = fw.policies  || [];
  const bandwidth = fw.bandwidth || [];
  const cis       = fw.cisBenchmark || [];

  const cisPass    = cis.filter(c=>c.pass===true).length;
  const cisFail    = cis.filter(c=>c.pass===false).length;
  const cisUnknown = cis.filter(c=>c.pass===null).length;
  const cisScore   = cis.length ? Math.round((cisPass / (cisPass+cisFail||1))*100) : null;

  const filteredRules = policies.filter(p => {
    if (ruleFilter === "allow")    return p.action === "Allow";
    if (ruleFilter === "deny")     return p.action === "Deny";
    if (ruleFilter === "disabled") return p.status === "Disabled";
    if (ruleFilter === "risk")     return p.overpermissive || (p.action==="Allow"&&(!p.logtraffic||p.logtraffic==="disable"));
    return true;
  });

  const tabBtn = (id, label, badge) => (
    <button onClick={()=>setTab(id)} style={{
      padding:"8px 18px", borderRadius:8, border:"none", cursor:"pointer", fontSize:13, fontWeight:600,
      background: tab===id ? C.primary : "transparent",
      color: tab===id ? "white" : C.muted,
      display:"flex", alignItems:"center", gap:6,
    }}>
      {label}
      {badge != null && <span style={{ fontSize:10, fontWeight:800, padding:"1px 6px", borderRadius:8,
        background: tab===id ? "rgba(255,255,255,0.25)" : C.border, color: tab===id?"white":C.text }}>{badge}</span>}
    </button>
  );

  return (
    <div>
      <SectionTitle title="Firewall Analytics" subtitle="Per-device policy review, bandwidth utilisation and CIS benchmark assessment" />

      {/* ── Instance selector ── */}
      {instances.length > 1 && (
        <div style={{ display:"flex", gap:8, marginBottom:20, flexWrap:"wrap" }}>
          {instances.map((inst,i) => (
            <button key={i} onClick={()=>{ setSelIdx(i); setTab("overview"); }} style={{
              padding:"8px 16px", borderRadius:10, border:`2px solid ${selIdx===i?C.primary:C.border}`,
              background: selIdx===i ? `${C.primary}10` : "white",
              color: selIdx===i ? C.primary : C.text,
              fontSize:13, fontWeight:600, cursor:"pointer", display:"flex", alignItems:"center", gap:8,
            }}>
              <span>{inst.vendor==="fortinet"?"🛡️":"🔵"}</span>
              <span>{inst.hostname||inst.instance}</span>
              <span style={{ fontSize:10, color:C.muted, fontWeight:400 }}>{inst.vendor==="fortinet"?"FortiGate":"PAN-OS"}</span>
            </button>
          ))}
        </div>
      )}

      {instances.length === 0 ? (
        <Card style={{ padding:32, textAlign:"center", color:C.muted }}>No firewall data collected yet. Save credentials and click Collect Now.</Card>
      ) : (
      <div>
        {/* ── Device header ── */}
        <Card style={{ padding:16, marginBottom:16, display:"flex", alignItems:"center", gap:20, flexWrap:"wrap" }}>
          <div style={{ fontSize:36 }}>{fw.vendor==="fortinet"?"🛡️":"🔵"}</div>
          <div style={{ flex:1 }}>
            <div style={{ fontSize:16, fontWeight:700, color:C.text }}>{fw.hostname||fw.instance}</div>
            <div style={{ fontSize:12, color:C.muted }}>{fw.vendor==="fortinet"?"Fortinet FortiGate":"Palo Alto Networks"} {fw.version&&`• v${fw.version}`} {fw.host&&`• ${fw.host}`}</div>
            {fw.collectedAt && <div style={{ fontSize:11, color:C.muted }}>Last collected: {new Date(fw.collectedAt).toLocaleString()}</div>}
          </div>
          <div style={{ display:"flex", gap:24 }}>
            {[
              {label:"Total Rules", value:fw.policyCount||0, color:C.primary},
              {label:"Allow",       value:fw.allowCount||0,  color:C.ok},
              {label:"Deny",        value:fw.denyCount||0,   color:C.critical},
              {label:"Disabled",    value:(fw.policyCount||0)-(fw.enabledCount||0), color:C.muted},
            ].map(m=>(
              <div key={m.label} style={{ textAlign:"center" }}>
                <div style={{ fontSize:24, fontWeight:800, color:m.color }}>{m.value}</div>
                <div style={{ fontSize:11, color:C.muted }}>{m.label}</div>
              </div>
            ))}
          </div>
        </Card>

        {/* ── Risk indicators ── */}
        {(fw.unusedRules>0||fw.overpermissive>0||fw.noLogging>0) && (
          <div style={{ display:"flex", gap:10, marginBottom:16, flexWrap:"wrap" }}>
            {fw.unusedRules>0 && <div style={{ padding:"8px 14px", borderRadius:8, background:"#fef3c7", border:"1px solid #fcd34d", fontSize:12, fontWeight:600, color:"#92400e" }}>⚠️ {fw.unusedRules} unused rules (zero hits)</div>}
            {fw.overpermissive>0 && <div style={{ padding:"8px 14px", borderRadius:8, background:"#fef2f2", border:"1px solid #fca5a5", fontSize:12, fontWeight:600, color:C.critical }}>🚨 {fw.overpermissive} any→any allow rules</div>}
            {fw.noLogging>0 && <div style={{ padding:"8px 14px", borderRadius:8, background:"#fef2f2", border:"1px solid #fca5a5", fontSize:12, fontWeight:600, color:C.critical }}>📋 {fw.noLogging} allow rules with logging off</div>}
          </div>
        )}

        {/* ── Tab bar ── */}
        <div style={{ display:"flex", gap:4, marginBottom:16, background:"#f8fafc", borderRadius:10, padding:4, width:"fit-content" }}>
          {tabBtn("overview",  "Overview")}
          {tabBtn("rules",     "Security Rules", fw.policyCount||0)}
          {tabBtn("bandwidth", "Bandwidth", bandwidth.length||null)}
          {tabBtn("cis",       "CIS Benchmark", cis.length||null)}
        </div>

        {/* ════ OVERVIEW TAB ════ */}
        {tab==="overview" && (
          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:16 }}>
            <Card style={{ padding:20 }}>
              <div style={{ fontSize:14, fontWeight:700, color:C.text, marginBottom:16 }}>Policy Summary</div>
              {[
                {label:"Total configured rules",    value:fw.policyCount||0},
                {label:"Enabled rules",             value:fw.enabledCount||0},
                {label:"Allow policies",            value:fw.allowCount||0},
                {label:"Deny / Block policies",     value:fw.denyCount||0},
                {label:"Unused rules (zero hits)",  value:fw.unusedRules??0,   warn:fw.unusedRules>0},
                {label:"Any→Any allow rules",       value:fw.overpermissive??0, warn:fw.overpermissive>0},
                {label:"Allow rules without logging",value:fw.noLogging??0,    warn:fw.noLogging>0},
              ].map(r=>(
                <div key={r.label} style={{ display:"flex", justifyContent:"space-between", padding:"7px 0", borderBottom:`1px solid ${C.border}` }}>
                  <span style={{ fontSize:13, color:C.muted }}>{r.label}</span>
                  <span style={{ fontSize:13, fontWeight:700, color:r.warn?C.critical:C.text }}>{r.value}</span>
                </div>
              ))}
            </Card>
            <Card style={{ padding:20 }}>
              <div style={{ fontSize:14, fontWeight:700, color:C.text, marginBottom:16 }}>Security Posture</div>
              <div style={{ textAlign:"center", marginBottom:16 }}>
                <div style={{ fontSize:56, fontWeight:900, color:cisScore>=80?C.ok:cisScore>=60?C.warn:C.critical }}>{cisScore??0}%</div>
                <div style={{ fontSize:12, color:C.muted }}>CIS Benchmark Compliance</div>
              </div>
              <div style={{ display:"flex", gap:8, justifyContent:"center", marginBottom:16 }}>
                <span style={{ padding:"4px 12px", borderRadius:8, background:"#f0fdf4", color:C.ok, fontSize:12, fontWeight:700 }}>✓ {cisPass} Pass</span>
                <span style={{ padding:"4px 12px", borderRadius:8, background:"#fef2f2", color:C.critical, fontSize:12, fontWeight:700 }}>✗ {cisFail} Fail</span>
                <span style={{ padding:"4px 12px", borderRadius:8, background:"#f8fafc", color:C.muted, fontSize:12, fontWeight:700 }}>? {cisUnknown} N/A</span>
              </div>
              <div style={{ height:8, background:C.border, borderRadius:4, overflow:"hidden" }}>
                <div style={{ height:"100%", width:`${cisScore||0}%`, background:cisScore>=80?C.ok:cisScore>=60?C.warn:C.critical, borderRadius:4 }}/>
              </div>
              <button onClick={()=>setTab("cis")} style={{ marginTop:12, width:"100%", padding:"7px 0", borderRadius:8, border:`1px solid ${C.primary}`, background:`${C.primary}08`, color:C.primary, fontSize:12, fontWeight:600, cursor:"pointer" }}>
                View Full CIS Report →
              </button>
            </Card>
            {/* Top rules by hit count */}
            <Card style={{ padding:20, gridColumn:"1/-1" }}>
              <div style={{ fontSize:14, fontWeight:700, color:C.text, marginBottom:16 }}>Top Rules by Packet Hits</div>
              <table style={{ width:"100%", borderCollapse:"collapse" }}>
                <thead><tr style={{ background:"#f8fafc" }}>
                  {["Rule Name","Action","Src","Dst","Packets","Bytes","Logging"].map(h=>(
                    <th key={h} style={{ padding:"8px 10px", textAlign:h==="Packets"||h==="Bytes"?"right":"left", fontSize:11, fontWeight:700, color:C.muted, textTransform:"uppercase", borderBottom:`2px solid ${C.border}` }}>{h}</th>
                  ))}
                </tr></thead>
                <tbody>{[...policies].sort((a,b)=>b.packets-a.packets).slice(0,8).map((p,i)=>(
                  <tr key={i} style={{ borderBottom:`1px solid ${C.border}` }}>
                    <td style={{ padding:"9px 10px", fontSize:12, fontWeight:500, color:C.text }}>{p.name}</td>
                    <td style={{ padding:"9px 10px" }}>
                      <span style={{ fontSize:11, fontWeight:600, padding:"2px 8px", borderRadius:8, background:p.action==="Allow"?"#f0fdf4":"#fef2f2", color:p.action==="Allow"?C.ok:C.critical }}>{p.action}</span>
                    </td>
                    <td style={{ padding:"9px 10px", fontSize:11, color:C.muted, maxWidth:120, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{p.srcaddr}</td>
                    <td style={{ padding:"9px 10px", fontSize:11, color:C.muted, maxWidth:120, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{p.dstaddr}</td>
                    <td style={{ padding:"9px 10px", fontSize:12, fontWeight:700, color:C.text, textAlign:"right" }}>{p.packets>0?p.packets.toLocaleString():"—"}</td>
                    <td style={{ padding:"9px 10px", fontSize:12, color:C.muted, textAlign:"right" }}>{p.bytes>0?(p.bytes/1024/1024).toFixed(1)+"MB":"—"}</td>
                    <td style={{ padding:"9px 10px", textAlign:"left" }}>
                      <span style={{ fontSize:10, padding:"2px 6px", borderRadius:6, background:p.logtraffic&&p.logtraffic!=="disable"?"#f0fdf4":"#fef2f2", color:p.logtraffic&&p.logtraffic!=="disable"?C.ok:C.critical }}>{p.logtraffic&&p.logtraffic!=="disable"?"On":"Off"}</span>
                    </td>
                  </tr>
                ))}</tbody>
              </table>
            </Card>
          </div>
        )}

        {/* ════ SECURITY RULES TAB ════ */}
        {tab==="rules" && (
          <div>
            <div style={{ display:"flex", gap:8, marginBottom:14, flexWrap:"wrap", alignItems:"center" }}>
              <span style={{ fontSize:12, color:C.muted, fontWeight:600 }}>Filter:</span>
              {[["all","All"],["allow","Allow"],["deny","Deny"],["disabled","Disabled"],["risk","⚠️ At Risk"]].map(([v,l])=>(
                <button key={v} onClick={()=>setRuleFilter(v)} style={{
                  padding:"5px 12px", borderRadius:7, border:`1px solid ${ruleFilter===v?C.primary:C.border}`,
                  background:ruleFilter===v?`${C.primary}10`:"white", color:ruleFilter===v?C.primary:C.muted,
                  fontSize:12, fontWeight:600, cursor:"pointer",
                }}>{l}</button>
              ))}
              <span style={{ marginLeft:"auto", fontSize:12, color:C.muted }}>{filteredRules.length} rule{filteredRules.length!==1?"s":""}</span>
            </div>
            <Card style={{ padding:0, overflow:"hidden" }}>
              <table style={{ width:"100%", borderCollapse:"collapse" }}>
                <thead><tr style={{ background:"#f8fafc" }}>
                  {["#","Rule Name","Action","Source","Destination","Service","Logging","Status","Hits"].map(h=>(
                    <th key={h} style={{ padding:"10px 10px", textAlign:h==="#"||h==="Hits"?"center":"left", fontSize:10, fontWeight:700, color:C.muted, textTransform:"uppercase", borderBottom:`2px solid ${C.border}`, whiteSpace:"nowrap" }}>{h}</th>
                  ))}
                </tr></thead>
                <tbody>{filteredRules.length === 0 ? (
                  <tr><td colSpan={9} style={{ padding:24, textAlign:"center", color:C.muted, fontSize:13 }}>No rules match the selected filter</td></tr>
                ) : filteredRules.map((p,i)=>{
                  const isRisk = p.overpermissive || (p.action==="Allow"&&(!p.logtraffic||p.logtraffic==="disable"));
                  return (
                  <tr key={i} style={{ borderBottom:`1px solid ${C.border}`, background:isRisk?"#fffbeb":"white" }}>
                    <td style={{ padding:"9px 10px", fontSize:11, color:C.muted, textAlign:"center" }}>{p.id}</td>
                    <td style={{ padding:"9px 10px", fontSize:12, fontWeight:600, color:C.text }}>
                      {isRisk && <span title="Risk: overpermissive or logging off" style={{ marginRight:4 }}>⚠️</span>}
                      {p.name}
                    </td>
                    <td style={{ padding:"9px 10px" }}>
                      <span style={{ fontSize:11, fontWeight:600, padding:"2px 7px", borderRadius:8, background:p.action==="Allow"?"#f0fdf4":p.action==="Deny"?"#fef2f2":"#f8fafc", color:p.action==="Allow"?C.ok:p.action==="Deny"?C.critical:C.muted }}>{p.action}</span>
                    </td>
                    <td style={{ padding:"9px 10px", fontSize:11, color:p.srcAny?C.critical:C.muted, maxWidth:120, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }} title={p.srcaddr}>{p.srcaddr}</td>
                    <td style={{ padding:"9px 10px", fontSize:11, color:p.dstAny?C.critical:C.muted, maxWidth:120, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }} title={p.dstaddr}>{p.dstaddr}</td>
                    <td style={{ padding:"9px 10px", fontSize:11, color:p.svcAny?C.warn:C.muted, maxWidth:100, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }} title={p.service}>{p.service}</td>
                    <td style={{ padding:"9px 10px", textAlign:"center" }}>
                      <span style={{ fontSize:10, padding:"2px 6px", borderRadius:6, background:p.logtraffic&&p.logtraffic!=="disable"?"#f0fdf4":"#fef2f2", color:p.logtraffic&&p.logtraffic!=="disable"?C.ok:C.critical }}>{p.logtraffic&&p.logtraffic!=="disable"?"On":"Off"}</span>
                    </td>
                    <td style={{ padding:"9px 10px", textAlign:"center" }}>
                      <span style={{ fontSize:10, padding:"2px 6px", borderRadius:6, background:p.status==="Enabled"?"#f0fdf4":"#f8fafc", color:p.status==="Enabled"?C.ok:C.muted }}>{p.status}</span>
                    </td>
                    <td style={{ padding:"9px 10px", fontSize:12, fontWeight:700, color:C.text, textAlign:"center" }}>{p.packets>0?p.packets.toLocaleString():"—"}</td>
                  </tr>
                )})}</tbody>
              </table>
            </Card>
          </div>
        )}

        {/* ════ BANDWIDTH TAB ════ */}
        {tab==="bandwidth" && (
          bandwidth.length === 0 ? (
            <Card style={{ padding:32, textAlign:"center" }}>
              <div style={{ fontSize:32, marginBottom:12 }}>📡</div>
              <div style={{ fontSize:14, fontWeight:600, color:C.text, marginBottom:6 }}>Bandwidth data not available</div>
              <div style={{ fontSize:13, color:C.muted }}>Interface counters are fetched from FortiGate's monitor API.<br/>Ensure the API key has System → Monitor read access.</div>
            </Card>
          ) : (
          <div>
            <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fill,minmax(200px,1fr))", gap:12, marginBottom:16 }}>
              {bandwidth.map((iface,i)=>(
                <Card key={i} style={{ padding:16 }}>
                  <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:8 }}>
                    <span style={{ fontSize:13, fontWeight:700, color:C.text }}>{iface.name}</span>
                    <span style={{ fontSize:10, padding:"2px 7px", borderRadius:6, background:iface.link==="Up"?"#f0fdf4":"#fef2f2", color:iface.link==="Up"?C.ok:C.critical, fontWeight:700 }}>{iface.link}</span>
                  </div>
                  {iface.speed && <div style={{ fontSize:11, color:C.muted, marginBottom:8 }}>{iface.speed}</div>}
                  <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:6 }}>
                    <div style={{ textAlign:"center", background:"#f0fdf4", borderRadius:6, padding:"6px 4px" }}>
                      <div style={{ fontSize:14, fontWeight:700, color:C.ok }}>{iface.rxBps>0?(iface.rxBps/1024).toFixed(1)+"K":(iface.rxBytes/1024/1024).toFixed(1)+"MB"}</div>
                      <div style={{ fontSize:10, color:C.muted }}>↓ RX{iface.rxBps>0?" bps":" total"}</div>
                    </div>
                    <div style={{ textAlign:"center", background:"#eff6ff", borderRadius:6, padding:"6px 4px" }}>
                      <div style={{ fontSize:14, fontWeight:700, color:C.primary }}>{iface.txBps>0?(iface.txBps/1024).toFixed(1)+"K":(iface.txBytes/1024/1024).toFixed(1)+"MB"}</div>
                      <div style={{ fontSize:10, color:C.muted }}>↑ TX{iface.txBps>0?" bps":" total"}</div>
                    </div>
                  </div>
                </Card>
              ))}
            </div>
            <Card style={{ padding:20 }}>
              <div style={{ fontSize:14, fontWeight:700, color:C.text, marginBottom:16 }}>Interface Bandwidth Detail</div>
              <table style={{ width:"100%", borderCollapse:"collapse" }}>
                <thead><tr style={{ background:"#f8fafc" }}>
                  {["Interface","Status","RX Total","TX Total","RX Rate","TX Rate"].map(h=>(
                    <th key={h} style={{ padding:"8px 12px", textAlign:"left", fontSize:11, fontWeight:700, color:C.muted, textTransform:"uppercase", borderBottom:`2px solid ${C.border}` }}>{h}</th>
                  ))}
                </tr></thead>
                <tbody>{bandwidth.map((iface,i)=>(
                  <tr key={i} style={{ borderBottom:`1px solid ${C.border}` }}>
                    <td style={{ padding:"10px 12px", fontSize:13, fontWeight:600, color:C.text }}>{iface.name}</td>
                    <td style={{ padding:"10px 12px" }}>
                      <span style={{ fontSize:11, fontWeight:700, padding:"2px 8px", borderRadius:8, background:iface.link==="Up"?"#f0fdf4":"#fef2f2", color:iface.link==="Up"?C.ok:C.critical }}>{iface.link}</span>
                    </td>
                    <td style={{ padding:"10px 12px", fontSize:12, color:C.text }}>{(iface.rxBytes/1024/1024).toFixed(1)} MB</td>
                    <td style={{ padding:"10px 12px", fontSize:12, color:C.text }}>{(iface.txBytes/1024/1024).toFixed(1)} MB</td>
                    <td style={{ padding:"10px 12px", fontSize:12, color:C.ok }}>{iface.rxBps>0?(iface.rxBps/1024).toFixed(1)+" Kbps":"—"}</td>
                    <td style={{ padding:"10px 12px", fontSize:12, color:C.primary }}>{iface.txBps>0?(iface.txBps/1024).toFixed(1)+" Kbps":"—"}</td>
                  </tr>
                ))}</tbody>
              </table>
            </Card>
          </div>
          )
        )}

        {/* ════ CIS BENCHMARK TAB ════ */}
        {tab==="cis" && (
          <div>
            {/* Header score card */}
            <Card style={{ padding:20, marginBottom:16 }}>
              <div style={{ display:"flex", gap:24, alignItems:"center", flexWrap:"wrap" }}>
                <div style={{ textAlign:"center", minWidth:100 }}>
                  <div style={{ fontSize:52, fontWeight:900, lineHeight:1, color:cisScore>=80?C.ok:cisScore>=60?C.warn:C.critical }}>{cisScore??0}%</div>
                  <div style={{ fontSize:12, color:C.muted, marginTop:4 }}>CIS Score</div>
                </div>
                <div style={{ flex:1 }}>
                  <div style={{ fontSize:15, fontWeight:700, color:C.text, marginBottom:4 }}>
                    {fw.vendor==="fortinet"?"CIS FortiGate Benchmark v1.0":"CIS Palo Alto Networks Firewall Benchmark v1.0"} — Configuration Review
                  </div>
                  <div style={{ fontSize:12, color:C.muted, marginBottom:12 }}>
                    Automated checks derived from live configuration via API. Controls marked N/A require manual verification in the device console.
                  </div>
                  <div style={{ display:"flex", gap:16, flexWrap:"wrap" }}>
                    <span style={{ fontSize:13, color:C.ok,       fontWeight:700 }}>✓ {cisPass} Passing</span>
                    <span style={{ fontSize:13, color:C.critical, fontWeight:700 }}>✗ {cisFail} Failing</span>
                    <span style={{ fontSize:13, color:C.muted,    fontWeight:700 }}>? {cisUnknown} Manual review</span>
                    <span style={{ fontSize:13, color:C.text,     fontWeight:700 }}>∑ {cis.length} Total controls</span>
                  </div>
                </div>
                <div style={{ width:180 }}>
                  <div style={{ display:"flex", justifyContent:"space-between", fontSize:11, color:C.muted, marginBottom:4 }}>
                    <span>Compliance</span><span>{cisScore??0}%</span>
                  </div>
                  <div style={{ height:10, background:C.border, borderRadius:5, overflow:"hidden" }}>
                    <div style={{ height:"100%", width:`${cisScore??0}%`, background:cisScore>=80?C.ok:cisScore>=60?C.warn:C.critical, borderRadius:5 }}/>
                  </div>
                  <div style={{ fontSize:10, color:C.muted, marginTop:6, textAlign:"center" }}>
                    {cisScore>=80?"Good posture — keep reviewing":"Remediation recommended"}
                  </div>
                </div>
              </div>
            </Card>

            {/* Category accordions */}
            {[...new Set(cis.map(c=>c.category))].map(cat => {
              const checks = cis.filter(c=>c.category===cat);
              const catPass = checks.filter(c=>c.pass===true).length;
              const catFail = checks.filter(c=>c.pass===false).length;
              const catIcon = {
                "Account Management":"🔐","Management":"🔐","Authentication":"🛡️",
                "Logging":"📋","Firewall Policy":"🔥","Security Policy":"🔥",
                "Security Profiles":"🛡️","Rule Hygiene":"🧹","System Hardening":"⚙️",
                "Network Security":"🌐","VPN":"🔒",
              }[cat] || "📌";
              return (
                <Card key={cat} style={{ padding:0, marginBottom:10, overflow:"hidden" }}>
                  <div style={{ padding:"14px 20px", background: catFail>0?"#fffbeb":"#f8fafc", borderBottom:`1px solid ${C.border}`, display:"flex", alignItems:"center", gap:10 }}>
                    <span style={{ fontSize:18 }}>{catIcon}</span>
                    <span style={{ fontSize:13, fontWeight:700, color:C.text, flex:1 }}>{cat}</span>
                    <span style={{ fontSize:11, padding:"2px 8px", borderRadius:8, background:catFail===0?"#f0fdf4":"#fef2f2", color:catFail===0?C.ok:C.critical, fontWeight:700 }}>
                      {catPass}/{checks.length} passing
                    </span>
                  </div>
                  <div style={{ padding:"0 20px" }}>
                    {checks.map((c,i)=>(
                      <div key={c.id} style={{ display:"flex", alignItems:"flex-start", gap:12, padding:"12px 0", borderBottom: i<checks.length-1?`1px solid ${C.border}`:"none" }}>
                        <div style={{ width:22, height:22, borderRadius:"50%", flexShrink:0, marginTop:1, display:"flex", alignItems:"center", justifyContent:"center", fontSize:12, fontWeight:700,
                          background:c.pass===true?"#dcfce7":c.pass===false?"#fee2e2":"#f1f5f9",
                          color:c.pass===true?C.ok:c.pass===false?C.critical:C.muted }}>
                          {c.pass===true?"✓":c.pass===false?"✗":"?"}
                        </div>
                        <div style={{ flex:1 }}>
                          <div style={{ fontSize:12, fontWeight:600, color:C.text, marginBottom:2 }}>
                            <span style={{ color:C.muted, fontWeight:400, marginRight:6 }}>{c.id}</span>{c.check}
                          </div>
                          {c.pass===false && c.remediation && (
                            <div style={{ fontSize:11, color:"#92400e", background:"#fffbeb", padding:"4px 8px", borderRadius:6, marginTop:4 }}>
                              🔧 <strong>Remediation:</strong> {c.remediation}
                            </div>
                          )}
                          {c.pass===null && (
                            <div style={{ fontSize:11, color:C.muted, marginTop:2 }}>Requires manual verification in device console</div>
                          )}
                        </div>
                        <span style={{ fontSize:10, fontWeight:700, padding:"3px 9px", borderRadius:8, flexShrink:0, whiteSpace:"nowrap",
                          background:c.pass===true?"#dcfce7":c.pass===false?"#fee2e2":"#f1f5f9",
                          color:c.pass===true?C.ok:c.pass===false?C.critical:C.muted }}>
                          {c.pass===true?"PASS":c.pass===false?"FAIL":"N/A"}
                        </span>
                      </div>
                    ))}
                  </div>
                </Card>
              );
            })}
          </div>
        )}
      </div>
      )}
    </div>
  );
}


// ── Attack Surface ───────────────────────────────────────────────────────────
// ── Attack Surface helpers ────────────────────────────────────────────────────
function ExpiryBadge({ daysToExp, status }) {
  const cfg = {
    expired:  { bg:"#fef2f2", color:C.critical, label:"Expired" },
    critical: { bg:"#fef2f2", color:C.critical, label:`${daysToExp}d` },
    warning:  { bg:"#fffbeb", color:C.warn,     label:`${daysToExp}d` },
    ok:       { bg:"#f0fdf4", color:C.ok,        label:`${daysToExp}d` },
    unknown:  { bg:"#f8fafc", color:C.muted,     label:"Unknown" },
  }[status || "unknown"];
  return (
    <span style={{ background:cfg.bg, color:cfg.color, padding:"2px 8px", borderRadius:10, fontSize:11, fontWeight:700 }}>
      {cfg.label}
    </span>
  );
}

function GradeChip({ grade }) {
  if (!grade) return <span style={{ color:C.muted }}>—</span>;
  const color = grade.startsWith("A") ? C.ok : grade.startsWith("B") ? "#2563eb" : grade.startsWith("C") ? C.warn : C.critical;
  return (
    <span style={{ background:color+"20", color, padding:"2px 8px", borderRadius:6, fontWeight:800, fontSize:12 }}>{grade}</span>
  );
}

function ScoreBar({ score }) {
  if (score == null) return <span style={{ color:C.muted, fontSize:12 }}>—</span>;
  const color = score >= 80 ? C.ok : score >= 60 ? "#2563eb" : score >= 40 ? C.warn : C.critical;
  return (
    <div style={{ display:"flex", alignItems:"center", gap:8 }}>
      <div style={{ flex:1, background:"#e5e7eb", borderRadius:4, height:6 }}>
        <div style={{ width:`${score}%`, background:color, borderRadius:4, height:6 }} />
      </div>
      <span style={{ fontSize:12, fontWeight:700, color, minWidth:28 }}>{score}</span>
    </div>
  );
}

function PortTag({ port, service }) {
  const risky = [21,22,23,25,445,3389,8080,8443,3306,5432,27017,6379].includes(port);
  return (
    <span style={{ background:risky?"#fef2f2":"#f1f5f9", color:risky?C.critical:C.muted, padding:"2px 7px", borderRadius:8, fontSize:11, fontWeight:600, marginRight:4, marginBottom:4, display:"inline-block" }}>
      {port}{service && service !== "—" ? `/${service}` : ""}
    </span>
  );
}

const ATTACK_SURFACE_TABS = [
  { id:"overview",   label:"Overview",        icon:"📊" },
  { id:"domains",    label:"Domains",         icon:"🌐" },
  { id:"ips",        label:"IP Addresses",    icon:"📡" },
  { id:"certs",      label:"SSL Certificates",icon:"🔒" },
  { id:"expiry",     label:"Domain Expiry",   icon:"📅" },
];

function AttackSurfacePage({ data }) {
  const d = data || {};
  if (!d._hasData) return <NoData icon="🌐" title="No attack surface data yet" message="Connect UpGuard in ⚙️ Settings to see your external attack surface data." />;
  const s = d.surface;
  const [tab, setTab] = useState("overview");
  const [riskFilter, setRiskFilter] = useState("All");
  const [domainSearch, setDomainSearch] = useState("");
  const [ipSearch, setIpSearch] = useState("");
  const [expandedIp, setExpandedIp] = useState(null);

  const gradeColor = !s?.grade ? C.muted
    : s.grade.startsWith("A") ? C.ok : s.grade.startsWith("B") ? "#2563eb" : s.grade.startsWith("C") ? C.warn : C.critical;

  // Risk severity breakdown counts
  const sevCount = { Critical:0, High:0, Medium:0, Low:0 };
  (s?.findings||[]).forEach(f => { if (sevCount[f.severity] !== undefined) sevCount[f.severity]++; else sevCount.Low++; });

  const filteredFindings = (s?.findings||[]).filter(f => riskFilter === "All" || f.severity === riskFilter);
  const filteredDomains  = (s?.domainsList||[]).filter(d => !domainSearch || d.hostname.toLowerCase().includes(domainSearch.toLowerCase()));
  const filteredIps      = (s?.ipsList||[]).filter(i => !ipSearch || i.ip.includes(ipSearch));

  const inputStyle = { background:"#f8fafc", border:`1px solid ${C.border}`, borderRadius:8, padding:"6px 12px", fontSize:12, color:C.text, outline:"none", width:220 };

  return (
    <div>
      <SectionTitle title="Attack Surface – UpGuard" subtitle="External exposure monitoring, domains, IPs, certificates and risk findings" />

      {/* ── Summary Strip ── */}
      <div style={{ display:"grid", gridTemplateColumns:"180px repeat(5,1fr)", gap:12, marginBottom:20 }}>
        {/* Grade card */}
        <Card style={{ padding:20, display:"flex", flexDirection:"column", alignItems:"center", justifyContent:"center", background:`linear-gradient(135deg, ${gradeColor}15, ${gradeColor}05)`, border:`2px solid ${gradeColor}30` }}>
          <div style={{ fontSize:56, fontWeight:900, color:gradeColor, lineHeight:1 }}>{s?.grade||"—"}</div>
          <div style={{ fontSize:11, color:C.muted, marginTop:6, textAlign:"center" }}>Security Grade</div>
          <div style={{ fontSize:22, fontWeight:800, color:C.text, marginTop:4 }}>{s?.score != null ? `${s.score}/100` : "—"}</div>
        </Card>
        {/* Metric cards */}
        {[
          { icon:"🌐", label:"Domains",       value:s?.domainCount,   tab:"domains", warn: s?.domainsList?.some(d=>d.status==="critical"||d.status==="expired") },
          { icon:"📡", label:"IP Addresses",  value:s?.ipCount,       tab:"ips",     warn: false },
          { icon:"🔌", label:"Open Ports",    value:s?.openPortCount, tab:"ips",     warn: (s?.openPortCount||0) > 10 },
          { icon:"🔒", label:"Certificates",  value:s?.certCount,     tab:"certs",   warn: s?.certsList?.some(c=>c.status==="critical"||c.status==="expired") },
          { icon:"⚠️", label:"Risk Findings", value:s?.findings?.length||null, tab:"overview", warn: (sevCount.Critical||0)+(sevCount.High||0) > 0 },
        ].map(m => (
          <Card key={m.label} style={{ padding:16, cursor:"pointer", border: m.warn ? `2px solid ${C.warn}` : `1px solid ${C.border}` }}
                onClick={()=>setTab(m.tab)}>
            <div style={{ fontSize:22 }}>{m.icon}</div>
            <div style={{ fontSize:26, fontWeight:800, color: m.value!=null ? (m.warn ? C.warn : C.text) : C.muted, marginTop:4 }}>
              {m.value ?? "—"}
            </div>
            <div style={{ fontSize:11, color:C.muted }}>{m.label}</div>
            {m.warn && <div style={{ fontSize:10, color:C.warn, marginTop:2 }}>⚠ Action needed</div>}
          </Card>
        ))}
      </div>

      {/* ── Tabs ── */}
      <div style={{ display:"flex", gap:4, marginBottom:16 }}>
        {ATTACK_SURFACE_TABS.map(t => (
          <button key={t.id} onClick={()=>setTab(t.id)} style={{
            padding:"8px 16px", borderRadius:8, border:"none", cursor:"pointer", fontSize:13, fontWeight:600,
            background: tab===t.id ? C.primary : "#f1f5f9",
            color:      tab===t.id ? "#fff" : C.muted,
          }}>{t.icon} {t.label}</button>
        ))}
      </div>

      {/* ═══ OVERVIEW TAB ═══ */}
      {tab === "overview" && (
        <div style={{ display:"grid", gridTemplateColumns:"300px 1fr", gap:16 }}>
          {/* Severity donut / breakdown */}
          <Card style={{ padding:20 }}>
            <div style={{ fontSize:14, fontWeight:700, color:C.text, marginBottom:16 }}>Risk Breakdown by Severity</div>
            {[
              { sev:"Critical", color:C.critical, icon:"🔴" },
              { sev:"High",     color:C.high,     icon:"🟠" },
              { sev:"Medium",   color:C.warn,     icon:"🟡" },
              { sev:"Low",      color:"#6b7280",  icon:"⚪" },
            ].map(({sev,color,icon}) => {
              const cnt = sevCount[sev] || 0;
              const pct = s?.findings?.length ? Math.round(cnt/s.findings.length*100) : 0;
              return (
                <div key={sev} style={{ marginBottom:12 }}>
                  <div style={{ display:"flex", justifyContent:"space-between", marginBottom:4 }}>
                    <span style={{ fontSize:12, color:C.text, fontWeight:600 }}>{icon} {sev}</span>
                    <span style={{ fontSize:12, fontWeight:700, color }}>{cnt}</span>
                  </div>
                  <div style={{ background:"#e5e7eb", borderRadius:4, height:8 }}>
                    <div style={{ width:`${pct}%`, background:color, borderRadius:4, height:8 }} />
                  </div>
                </div>
              );
            })}
            <div style={{ marginTop:16, padding:"10px 12px", background:"#f8fafc", borderRadius:8, fontSize:12, color:C.muted, textAlign:"center" }}>
              {s?.findings?.length || 0} total findings
            </div>
          </Card>

          {/* Risk findings table */}
          <Card style={{ padding:20 }}>
            <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:14 }}>
              <div style={{ fontSize:14, fontWeight:700, color:C.text }}>External Risk Findings</div>
              <div style={{ display:"flex", gap:6 }}>
                {["All","Critical","High","Medium","Low"].map(sev => (
                  <button key={sev} onClick={()=>setRiskFilter(sev)} style={{
                    padding:"4px 10px", borderRadius:6, border:"none", cursor:"pointer", fontSize:11, fontWeight:600,
                    background: riskFilter===sev ? C.primary : "#f1f5f9",
                    color:      riskFilter===sev ? "#fff" : C.muted,
                  }}>{sev}</button>
                ))}
              </div>
            </div>
            {filteredFindings.length === 0 ? (
              <div style={{ textAlign:"center", padding:40, color:C.muted, fontSize:13 }}>
                {riskFilter === "All" ? "✅ No risk findings" : `No ${riskFilter} findings`}
              </div>
            ) : (
              <div style={{ overflowX:"auto" }}>
                <table style={{ width:"100%", borderCollapse:"collapse" }}>
                  <thead><tr style={{ background:"#f8fafc" }}>
                    {["Severity","Finding","Asset / Domain","First Detected"].map(h=>(
                      <th key={h} style={{ padding:"10px 12px", textAlign:"left", fontSize:11, fontWeight:700, color:C.muted, textTransform:"uppercase", borderBottom:`2px solid ${C.border}` }}>{h}</th>
                    ))}
                  </tr></thead>
                  <tbody>{filteredFindings.map((f,i)=>(
                    <tr key={i} style={{ borderBottom:`1px solid ${C.border}` }}>
                      <td style={{ padding:"10px 12px" }}><SeverityBadge level={f.severity}/></td>
                      <td style={{ padding:"10px 12px", fontSize:13, color:C.text }}>{f.title}</td>
                      <td style={{ padding:"10px 12px", fontFamily:"monospace", fontSize:12, color:C.muted }}>{f.asset}</td>
                      <td style={{ padding:"10px 12px", fontSize:12, color:C.muted }}>{f.first}</td>
                    </tr>
                  ))}</tbody>
                </table>
              </div>
            )}
          </Card>
        </div>
      )}

      {/* ═══ DOMAINS TAB ═══ */}
      {tab === "domains" && (
        <Card style={{ padding:20 }}>
          <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:16 }}>
            <div style={{ fontSize:14, fontWeight:700, color:C.text }}>Monitored Domains</div>
            <input placeholder="Search domain…" value={domainSearch} onChange={e=>setDomainSearch(e.target.value)} style={inputStyle} />
          </div>
          {filteredDomains.length === 0 ? (
            <div style={{ textAlign:"center", padding:48, color:C.muted, fontSize:13 }}>
              {(s?.domainsList||[]).length === 0
                ? "No domains found in UpGuard response. Ensure domains are registered in your UpGuard account."
                : "No domains match search."}
            </div>
          ) : (
            <table style={{ width:"100%", borderCollapse:"collapse" }}>
              <thead><tr style={{ background:"#f8fafc" }}>
                {["Domain","Score","Grade","IP Addresses","Expiry","Status"].map(h=>(
                  <th key={h} style={{ padding:"10px 12px", textAlign:"left", fontSize:11, fontWeight:700, color:C.muted, textTransform:"uppercase", borderBottom:`2px solid ${C.border}` }}>{h}</th>
                ))}
              </tr></thead>
              <tbody>{filteredDomains.map((dom,i)=>(
                <tr key={i} style={{ borderBottom:`1px solid ${C.border}` }}>
                  <td style={{ padding:"12px 12px", fontFamily:"monospace", fontSize:13, fontWeight:600, color:C.text }}>{dom.hostname}</td>
                  <td style={{ padding:"12px 12px", minWidth:120 }}><ScoreBar score={dom.score}/></td>
                  <td style={{ padding:"12px 12px" }}><GradeChip grade={dom.grade}/></td>
                  <td style={{ padding:"12px 12px", fontSize:12, color:C.muted }}>
                    {dom.ips.length > 0 ? (
                      <span style={{ fontFamily:"monospace" }}>{dom.ips.slice(0,2).join(", ")}{dom.ips.length>2?` +${dom.ips.length-2}`:""}</span>
                    ) : "—"}
                  </td>
                  <td style={{ padding:"12px 12px", fontSize:12, color:C.muted }}>{dom.expiry}</td>
                  <td style={{ padding:"12px 12px" }}><ExpiryBadge daysToExp={dom.daysToExp} status={dom.status}/></td>
                </tr>
              ))}</tbody>
            </table>
          )}
        </Card>
      )}

      {/* ═══ IP ADDRESSES TAB ═══ */}
      {tab === "ips" && (
        <Card style={{ padding:20 }}>
          <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:16 }}>
            <div>
              <div style={{ fontSize:14, fontWeight:700, color:C.text }}>IP Address Inventory</div>
              <div style={{ fontSize:12, color:C.muted, marginTop:2 }}>Click a row to expand open ports</div>
            </div>
            <input placeholder="Search IP…" value={ipSearch} onChange={e=>setIpSearch(e.target.value)} style={inputStyle} />
          </div>
          {filteredIps.length === 0 ? (
            <div style={{ textAlign:"center", padding:48, color:C.muted, fontSize:13 }}>
              {(s?.ipsList||[]).length === 0
                ? "No IP data found. UpGuard /ips endpoint requires appropriate subscription."
                : "No IPs match search."}
            </div>
          ) : (
            <table style={{ width:"100%", borderCollapse:"collapse" }}>
              <thead><tr style={{ background:"#f8fafc" }}>
                {["IP Address","Score","Open Ports","Risk"].map(h=>(
                  <th key={h} style={{ padding:"10px 12px", textAlign:"left", fontSize:11, fontWeight:700, color:C.muted, textTransform:"uppercase", borderBottom:`2px solid ${C.border}` }}>{h}</th>
                ))}
              </tr></thead>
              <tbody>{filteredIps.map((ip,i)=>{
                const isExpanded = expandedIp === i;
                const riskyPorts = ip.openPorts.filter(p=>[21,22,23,25,445,3389,8080,3306,5432,27017,6379].includes(p.port));
                return (
                  <React.Fragment key={i}>
                    <tr style={{ borderBottom:`1px solid ${C.border}`, cursor:"pointer", background:isExpanded?"#f8fafc":"#fff" }}
                        onClick={()=>setExpandedIp(isExpanded?null:i)}>
                      <td style={{ padding:"12px 12px", fontFamily:"monospace", fontSize:13, fontWeight:600, color:C.text }}>
                        {isExpanded?"▼":"▶"} {ip.ip}
                      </td>
                      <td style={{ padding:"12px 12px", minWidth:120 }}><ScoreBar score={ip.score}/></td>
                      <td style={{ padding:"12px 12px", fontSize:13, color:C.text }}>{ip.openPorts.length}</td>
                      <td style={{ padding:"12px 12px" }}>
                        {riskyPorts.length > 0
                          ? <span style={{ background:"#fef2f2", color:C.critical, padding:"2px 8px", borderRadius:8, fontSize:11, fontWeight:700 }}>⚠ {riskyPorts.length} risky</span>
                          : <span style={{ background:"#f0fdf4", color:C.ok, padding:"2px 8px", borderRadius:8, fontSize:11, fontWeight:700 }}>✓ Clean</span>}
                      </td>
                    </tr>
                    {isExpanded && (
                      <tr style={{ borderBottom:`1px solid ${C.border}` }}>
                        <td colSpan={4} style={{ padding:"12px 16px 16px", background:"#f8fafc" }}>
                          <div style={{ fontSize:12, fontWeight:600, color:C.muted, marginBottom:8 }}>OPEN PORTS ON {ip.ip}</div>
                          {ip.openPorts.length === 0
                            ? <span style={{ fontSize:12, color:C.muted }}>No open ports reported</span>
                            : <div style={{ display:"flex", flexWrap:"wrap", gap:4 }}>
                                {ip.openPorts.map((p,j)=><PortTag key={j} port={p.port} service={p.service}/>)}
                              </div>}
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}</tbody>
            </table>
          )}
        </Card>
      )}

      {/* ═══ SSL CERTIFICATES TAB ═══ */}
      {tab === "certs" && (
        <Card style={{ padding:20 }}>
          <div style={{ fontSize:14, fontWeight:700, color:C.text, marginBottom:16 }}>SSL Certificate Status</div>
          {(s?.certsList||[]).length === 0 ? (
            <div style={{ textAlign:"center", padding:48 }}>
              <div style={{ fontSize:48, marginBottom:12 }}>🔒</div>
              <div style={{ fontSize:14, color:C.muted, fontWeight:600 }}>No certificate data available</div>
              <div style={{ fontSize:12, color:C.muted, marginTop:8 }}>
                UpGuard returns SSL certificate details when they are associated with monitored domains.<br/>
                Ensure your domains are correctly added and monitored in your UpGuard account.
              </div>
            </div>
          ) : (
            <>
              {/* Expiry summary */}
              <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:12, marginBottom:20 }}>
                {[
                  { label:"Expired",    color:C.critical, certs:(s.certsList||[]).filter(c=>c.status==="expired") },
                  { label:"< 14 days",  color:C.critical, certs:(s.certsList||[]).filter(c=>c.status==="critical") },
                  { label:"< 30 days",  color:C.warn,     certs:(s.certsList||[]).filter(c=>c.status==="warning") },
                  { label:"Valid",      color:C.ok,       certs:(s.certsList||[]).filter(c=>c.status==="ok") },
                ].map(g=>(
                  <div key={g.label} style={{ padding:14, background:g.color+"10", borderRadius:10, border:`1px solid ${g.color}30`, textAlign:"center" }}>
                    <div style={{ fontSize:22, fontWeight:800, color:g.color }}>{g.certs.length}</div>
                    <div style={{ fontSize:11, color:C.muted }}>{g.label}</div>
                  </div>
                ))}
              </div>
              <table style={{ width:"100%", borderCollapse:"collapse" }}>
                <thead><tr style={{ background:"#f8fafc" }}>
                  {["Domain","Subject / CN","Issuer","Valid From","Expires","Days Left"].map(h=>(
                    <th key={h} style={{ padding:"10px 12px", textAlign:"left", fontSize:11, fontWeight:700, color:C.muted, textTransform:"uppercase", borderBottom:`2px solid ${C.border}` }}>{h}</th>
                  ))}
                </tr></thead>
                <tbody>{(s.certsList||[]).sort((a,b)=>(a.daysToExp??999)-(b.daysToExp??999)).map((c,i)=>(
                  <tr key={i} style={{ borderBottom:`1px solid ${C.border}` }}>
                    <td style={{ padding:"12px 12px", fontFamily:"monospace", fontSize:12, color:C.text }}>{c.domain}</td>
                    <td style={{ padding:"12px 12px", fontSize:12, color:C.text }}>{c.subject}</td>
                    <td style={{ padding:"12px 12px", fontSize:12, color:C.muted }}>{c.issuer}</td>
                    <td style={{ padding:"12px 12px", fontSize:12, color:C.muted }}>{c.validFrom}</td>
                    <td style={{ padding:"12px 12px", fontSize:12, color:C.muted }}>{c.validTo}</td>
                    <td style={{ padding:"12px 12px" }}><ExpiryBadge daysToExp={c.daysToExp} status={c.status}/></td>
                  </tr>
                ))}</tbody>
              </table>
            </>
          )}
        </Card>
      )}

      {/* ═══ DOMAIN EXPIRY TAB ═══ */}
      {tab === "expiry" && (
        <div>
          {/* Expiry urgency buckets */}
          <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:12, marginBottom:16 }}>
            {[
              { label:"Expired",     color:C.critical, filter:d=>d.status==="expired" },
              { label:"< 30 days",   color:C.critical, filter:d=>d.status==="critical" },
              { label:"< 90 days",   color:C.warn,     filter:d=>d.status==="warning" },
              { label:"Safe",        color:C.ok,       filter:d=>d.status==="ok" },
            ].map(g => {
              const cnt = (s?.domainsList||[]).filter(g.filter).length;
              return (
                <Card key={g.label} style={{ padding:16, textAlign:"center", border:`2px solid ${g.color}30`, background:g.color+"08" }}>
                  <div style={{ fontSize:28, fontWeight:800, color:g.color }}>{cnt}</div>
                  <div style={{ fontSize:11, color:C.muted }}>{g.label}</div>
                </Card>
              );
            })}
          </div>

          <Card style={{ padding:20 }}>
            <div style={{ fontSize:14, fontWeight:700, color:C.text, marginBottom:16 }}>Domain Registration Expiry</div>
            {(s?.domainsList||[]).length === 0 ? (
              <div style={{ textAlign:"center", padding:48 }}>
                <div style={{ fontSize:48, marginBottom:12 }}>📅</div>
                <div style={{ fontSize:14, color:C.muted, fontWeight:600 }}>No domain expiry data available</div>
                <div style={{ fontSize:12, color:C.muted, marginTop:8 }}>
                  Domain registration expiry dates are provided by UpGuard when available.<br/>
                  Some domains may show "Unknown" if WHOIS data is restricted.
                </div>
              </div>
            ) : (
              <table style={{ width:"100%", borderCollapse:"collapse" }}>
                <thead><tr style={{ background:"#f8fafc" }}>
                  {["Domain","Security Score","Grade","Expiry Date","Days Remaining","Status"].map(h=>(
                    <th key={h} style={{ padding:"10px 12px", textAlign:"left", fontSize:11, fontWeight:700, color:C.muted, textTransform:"uppercase", borderBottom:`2px solid ${C.border}` }}>{h}</th>
                  ))}
                </tr></thead>
                <tbody>{[...(s?.domainsList||[])]
                  .sort((a,b) => {
                    if (a.status==="expired" && b.status!=="expired") return -1;
                    if (b.status==="expired" && a.status!=="expired") return  1;
                    return (a.daysToExp??99999) - (b.daysToExp??99999);
                  })
                  .map((dom,i) => (
                    <tr key={i} style={{ borderBottom:`1px solid ${C.border}`, background: dom.status==="expired"||dom.status==="critical" ? "#fef2f208" : "#fff" }}>
                      <td style={{ padding:"12px 12px", fontFamily:"monospace", fontSize:13, fontWeight:600, color:C.text }}>{dom.hostname}</td>
                      <td style={{ padding:"12px 12px", minWidth:120 }}><ScoreBar score={dom.score}/></td>
                      <td style={{ padding:"12px 12px" }}><GradeChip grade={dom.grade}/></td>
                      <td style={{ padding:"12px 12px", fontSize:12, color:C.muted }}>{dom.expiry}</td>
                      <td style={{ padding:"12px 12px", fontSize:13, fontWeight:700, color:
                        dom.status==="expired"||dom.status==="critical" ? C.critical : dom.status==="warning" ? C.warn : dom.status==="ok" ? C.ok : C.muted }}>
                        {dom.daysToExp != null ? (dom.daysToExp < 0 ? "Expired" : `${dom.daysToExp} days`) : "Unknown"}
                      </td>
                      <td style={{ padding:"12px 12px" }}><ExpiryBadge daysToExp={dom.daysToExp} status={dom.status}/></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Card>
        </div>
      )}
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
function AdminPage({ user, onLogout }) {
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

  const [fetchError, setFetchError] = useState(null);

  async function fetchStatuses() {
    try {
      const r = await apiFetch(`${API}/api/integrations`);
      if (!r.ok) {
        const txt = await r.text().catch(() => "");
        const msg = `API returned ${r.status}${txt ? ": " + txt.slice(0, 200) : ""}`;
        console.error("GET /api/integrations failed:", msg);
        setFetchError(msg);
        return;
      }
      const arr = await r.json();
      setFetchError(null);
      const m = {};
      arr.forEach(x => { m[x.tool_name] = x; });
      setStatuses(m);
      setLastRefresh(new Date());
    } catch(e) {
      console.error("Admin fetch failed:", e);
      setFetchError(e.message);
    }
  }

  function showToast(msg, ok=true) {
    setToast({ msg, ok });
    setTimeout(() => setToast(null), 4000);
  }

  async function testTool(toolKey, instanceIdx=null) {
    const key = instanceIdx !== null ? `${toolKey}__${instanceIdx}` : toolKey;
    setTesting(key);
    const ctrl = new AbortController();
    // Qualys API is slow — give it 70s. Other tools: 30s.
    const timeoutMs = toolKey === "qualys" ? 70000 : 30000;
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const url = instanceIdx !== null
        ? `${API}/api/integrations/${toolKey}/test?instance=${instanceIdx}`
        : `${API}/api/integrations/${toolKey}/test`;
      const r = await apiFetch(url, {
        method: "POST",
        body: "{}",
        signal: ctrl.signal,
      });
      clearTimeout(timer);
      if (!r.ok) {
        const txt = await r.text().catch(()=>"");
        throw new Error(`Server returned ${r.status}${txt ? ": "+txt.slice(0,120) : ""}`);
      }
      const d = await r.json();
      setTestResults(prev => ({ ...prev, [key]: d }));
      showToast(d.success ? `${toolKey} — connected ✅` : `${toolKey} — ${d.error}`, d.success);
      fetchStatuses();
      // Trigger data collection immediately after successful test
      if (d.success) {
        apiFetch(`${API}/api/collect/${toolKey}`, { method:"POST" }).catch(()=>{});
      }
    } catch(e) {
      clearTimeout(timer);
      const msg = e.name === "AbortError"
        ? "Test timed out (25s) — device/API unreachable from server"
        : e.message || "Failed to reach backend";
      setTestResults(prev => ({ ...prev, [key]: { success: false, error: msg } }));
      showToast(`Test failed: ${msg.slice(0,80)}`, false);
    }
    setTesting(null);
  }

  async function collectNow() {
    setCollecting(true);
    setCollectLog("Triggering collection for all configured integrations…");
    try {
      const r = await apiFetch(`${API}/api/collect`, { method: "POST" });
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
      {fetchError && (
        <div style={{ margin:"0 0 16px 0", padding:"12px 16px", borderRadius:10,
          background:"#fef2f2", border:"1px solid #fecaca", color:C.critical, fontSize:13 }}>
          <strong>⚠️ Backend API Error</strong> — Cannot load integration statuses.<br/>
          <span style={{ fontFamily:"monospace", fontSize:11 }}>{fetchError}</span><br/>
          <span style={{ fontSize:11, color:C.muted }}>Check: docker compose logs backend --tail 30</span>
        </div>
      )}
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
              const instances= st.instances || [];
          const instCount = st.instance_count || 0;
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
      {/* User management — admin only */}
      {user?.role === "admin" && <UserManagementSection />}
    </div>
  );
}

/* ── User Management (Admin only) ─────────────────────────────────────── */
function UserManagementSection() {
  const [users,   setUsers]   = useState([]);
  const [loading, setLoading] = useState(true);
  const [form,    setForm]    = useState({ username:"", password:"", role:"analyst", display_name:"" });
  const [saving,  setSaving]  = useState(false);
  const [msg,     setMsg]     = useState(null);

  async function fetchUsers() {
    setLoading(true);
    try {
      const r = await apiFetch(`${API}/api/auth/users`);
      if (r.ok) setUsers(await r.json());
    } catch {}
    setLoading(false);
  }

  useEffect(() => { fetchUsers(); }, []);

  async function createUser(e) {
    e.preventDefault();
    if (form.password.length < 8) { setMsg({ ok:false, text:"Password must be at least 8 characters" }); return; }
    setSaving(true); setMsg(null);
    try {
      const r = await apiFetch(`${API}/api/auth/users`, {
        method:"POST", body: JSON.stringify(form),
      });
      const d = await r.json();
      if (!r.ok) setMsg({ ok:false, text: d.error || "Failed" });
      else {
        setMsg({ ok:true, text:`User "${form.username}" created` });
        setForm({ username:"", password:"", role:"analyst", display_name:"" });
        fetchUsers();
      }
    } catch { setMsg({ ok:false, text:"Network error" }); }
    setSaving(false);
  }

  async function deleteUser(id, username) {
    if (!confirm(`Delete user "${username}"?`)) return;
    await apiFetch(`${API}/api/auth/users/${id}`, { method:"DELETE" });
    fetchUsers();
  }

  const inp = { width:"100%", padding:"8px 11px", borderRadius:7, border:`1px solid ${C.border}`, fontSize:13, outline:"none", boxSizing:"border-box" };
  const ROLE_COLOR = { admin:"#8b5cf6", analyst:"#3b82f6", executive:"#f59e0b" };

  return (
    <div style={{ marginTop:32 }}>
      <SectionTitle title="User Management" subtitle="Create and manage user accounts with role-based access" />
      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:20 }}>
        {/* User list */}
        <Card style={{ padding:20 }}>
          <div style={{ fontSize:14, fontWeight:700, color:C.text, marginBottom:14 }}>
            Active Users ({users.length})
          </div>
          {loading ? <div style={{ color:C.muted, fontSize:13 }}>Loading…</div> : (
            <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
              {users.map(u=>(
                <div key={u.id} style={{ display:"flex", alignItems:"center", gap:10, padding:"10px 12px",
                  borderRadius:8, border:`1px solid ${C.border}`, background:"#f8fafc" }}>
                  <div style={{ width:32, height:32, borderRadius:"50%",
                    background:ROLE_COLOR[u.role]||"#64748b",
                    display:"flex", alignItems:"center", justifyContent:"center",
                    fontSize:13, fontWeight:700, color:"white", flexShrink:0 }}>
                    {(u.display_name||u.username).charAt(0).toUpperCase()}
                  </div>
                  <div style={{ flex:1, overflow:"hidden" }}>
                    <div style={{ fontSize:13, fontWeight:600, color:C.text }}>{u.display_name||u.username}</div>
                    <div style={{ fontSize:11, color:C.muted }}>
                      @{u.username} ·
                      <span style={{ fontWeight:600, color:ROLE_COLOR[u.role]||C.muted, textTransform:"capitalize" }}> {u.role}</span>
                    </div>
                    {u.last_login && (
                      <div style={{ fontSize:10, color:C.muted }}>Last login: {new Date(u.last_login).toLocaleString()}</div>
                    )}
                  </div>
                  <button onClick={()=>deleteUser(u.id, u.username)}
                    style={{ padding:"4px 10px", borderRadius:6, border:`1px solid #fecaca`,
                      background:"white", color:C.critical, fontSize:11, cursor:"pointer" }}>Delete</button>
                </div>
              ))}
            </div>
          )}
        </Card>
        {/* Create user form */}
        <Card style={{ padding:20 }}>
          <div style={{ fontSize:14, fontWeight:700, color:C.text, marginBottom:14 }}>Add New User</div>
          <form onSubmit={createUser} style={{ display:"flex", flexDirection:"column", gap:12 }}>
            {[["Username","username","text"],["Display Name","display_name","text"],["Password","password","password"]].map(([l,k,t])=>(
              <div key={k}>
                <label style={{ display:"block", fontSize:11, fontWeight:700, color:C.muted, marginBottom:4, textTransform:"uppercase", letterSpacing:0.5 }}>{l}</label>
                <input type={t} value={form[k]} onChange={e=>setForm(p=>({...p,[k]:e.target.value}))} style={inp} placeholder={k==="password"?"Min 8 characters":""} />
              </div>
            ))}
            <div>
              <label style={{ display:"block", fontSize:11, fontWeight:700, color:C.muted, marginBottom:4, textTransform:"uppercase", letterSpacing:0.5 }}>Role</label>
              <select value={form.role} onChange={e=>setForm(p=>({...p,role:e.target.value}))}
                style={{ ...inp, background:"white" }}>
                <option value="analyst">Analyst — Security views + Admin</option>
                <option value="executive">Executive — Board view only</option>
                <option value="admin">Admin — Full access + User Management</option>
              </select>
            </div>
            {msg && (
              <div style={{ padding:"8px 12px", borderRadius:7, fontSize:12,
                background:msg.ok?"#f0fdf4":"#fef2f2", color:msg.ok?C.ok:C.critical,
                border:`1px solid ${msg.ok?"#bbf7d0":"#fecaca"}` }}>{msg.ok?"✅":"⚠️"} {msg.text}</div>
            )}
            <button type="submit" disabled={saving||!form.username||!form.password}
              style={{ padding:"9px", borderRadius:8, border:"none", background:C.primary,
                color:"white", fontSize:13, fontWeight:700, cursor:"pointer", opacity:saving?0.6:1 }}>
              {saving?"Creating…":"➕ Create User"}
            </button>
          </form>
        </Card>
      </div>
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
      const r = await apiFetch(`${API}/api/integrations`);
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
      const r = await apiFetch(`${API}/api/integrations/${toolKey}`, {
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
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 25000); // 25s hard timeout
    try {
      const url = instanceIdx !== null
        ? `${API}/api/integrations/${toolKey}/test?instance=${instanceIdx}`
        : `${API}/api/integrations/${toolKey}/test`;
      const r = await apiFetch(url, {
        method: "POST",
        body: "{}",
        signal: ctrl.signal,
      });
      clearTimeout(timer);
      if (!r.ok) {
        const txt = await r.text().catch(()=>"");
        throw new Error(`Server returned ${r.status}${txt ? ": "+txt.slice(0,120) : ""}`);
      }
      const data = await r.json();
      setTestResults(prev => ({ ...prev, [testKey]: data }));
      showToast(data.success ? "Connection successful ✅" : `Test failed: ${data.error}`, data.success);
      loadStatuses();
      if (data.success) {
        apiFetch(`${API}/api/collect/${toolKey}`, { method:"POST" }).catch(()=>{});
      }
    } catch(e) {
      clearTimeout(timer);
      const msg = e.name === "AbortError"
        ? "Test timed out (25s) — the device or API may be unreachable from the server"
        : e.message || "Failed to reach backend";
      setTestResults(prev => ({ ...prev, [testKey]: { success:false, error:msg } }));
      showToast(`Test failed: ${msg.slice(0,80)}`, false);
    }
    setTesting(null);
  }

  async function deleteIntegration(toolKey) {
    if (!confirm(`Remove all credentials for ${toolKey}?`)) return;
    await apiFetch(`${API}/api/integrations/${toolKey}`, { method:"DELETE" });
    setTestResults(prev => { const n={...prev}; delete n[toolKey]; return n; });
    loadStatuses();
    showToast("Credentials removed");
  }

  /* ── Single-instance form ─────────────────────────────────────────────── */
  function SingleForm({ toolKey, tool }) {
    const isExisting = !!(statuses[toolKey]?.safe_credentials || statuses[toolKey]?.status === "configured" || statuses[toolKey]?.status === "ok" || statuses[toolKey]?.status === "error");
    return (
      <div>
        {(FIELDS[toolKey]||[]).map(([field, label, placeholder])=>{
          const isSecret = /pass|secret/i.test(field) || /key|token/i.test(field);
          const effectivePlaceholder = isSecret && isExisting
            ? "Leave blank to keep current value"
            : placeholder;
          return (
          <div key={field} style={{ marginBottom:12 }}>
            <label style={{ display:"block", fontSize:11, fontWeight:700, color:C.muted, marginBottom:4, textTransform:"uppercase", letterSpacing:0.5 }}>{label}</label>
            <input
              type={isSecret?"password":"text"}
              value={form[field]||""}
              onChange={e=>setForm(p=>({...p,[field]:e.target.value}))}
              placeholder={effectivePlaceholder}
              style={{ width:"100%", padding:"8px 12px", borderRadius:8, border:`1px solid ${C.border}`, fontSize:13, outline:"none", boxSizing:"border-box" }}
            />
            {isSecret && isExisting && !form[field] && (
              <div style={{ fontSize:10, color:C.muted, marginTop:2, fontStyle:"italic" }}>🔒 Saved value will be kept</div>
            )}
          </div>
        )})}
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
    const isExistingInst = idx >= 0;
    return (
      <div style={{ background:"#f8fafc", borderRadius:10, padding:16, marginTop:12, border:`1px solid ${C.border}` }}>
        <div style={{ fontSize:13, fontWeight:700, color:C.text, marginBottom:12 }}>
          {idx === -1 ? "➕ New Instance" : `✏️ Edit: ${form.name||"Instance"}`}
        </div>
        {(FIELDS[toolKey]||[]).map(([field, label, placeholder])=>{
          const isSecret = /pass|secret/i.test(field) || /key|token/i.test(field);
          const effectivePlaceholder = isSecret && isExistingInst
            ? "Leave blank to keep current value"
            : placeholder;
          return (
          <div key={field} style={{ marginBottom:10 }}>
            <label style={{ display:"block", fontSize:11, fontWeight:700, color:C.muted, marginBottom:3, textTransform:"uppercase", letterSpacing:0.5 }}>{label}</label>
            <input
              type={isSecret?"password":"text"}
              value={form[field]||""}
              onChange={e=>setForm(p=>({...p,[field]:e.target.value}))}
              placeholder={effectivePlaceholder}
              style={{ width:"100%", padding:"7px 11px", borderRadius:7, border:`1px solid ${C.border}`, fontSize:12, outline:"none", boxSizing:"border-box" }}
            />
            {isSecret && isExistingInst && !form[field] && (
              <div style={{ fontSize:10, color:C.muted, marginTop:2, fontStyle:"italic" }}>🔒 Saved value will be kept</div>
            )}
          </div>
        )})}
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
          const instances= st.instances || [];
          const instCount = st.instance_count || 0;
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
                        <button onClick={()=>{ setEditing(tool.key); setForm({_interval:st.refresh_interval||300, ...(st.safe_credentials||{})}); }}
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
   LOGIN PAGE
═══════════════════════════════════════════════════════════════════════════ */
function LoginPage({ onLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error,    setError]    = useState("");
  const [loading,  setLoading]  = useState(false);

  async function handleLogin(e) {
    e.preventDefault();
    setLoading(true); setError("");
    try {
      const r = await fetch(`${API}/api/auth/login`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: username.trim().toLowerCase(), password }),
      });
      const d = await r.json();
      if (!r.ok) { setError(d.error || "Login failed"); }
      else        { onLogin(d); }
    } catch {
      setError("Cannot connect to server — is the backend running?");
    }
    setLoading(false);
  }

  const inp = {
    width:"100%", padding:"10px 14px", borderRadius:8,
    border:"1.5px solid #e2e8f0", fontSize:14, outline:"none",
    boxSizing:"border-box", fontFamily:"inherit",
  };

  return (
    <div style={{ minHeight:"100vh", display:"flex", alignItems:"center", justifyContent:"center",
      background:"linear-gradient(135deg,#0f172a 0%,#1e3a5f 55%,#0f172a 100%)",
      fontFamily:"'Inter',-apple-system,sans-serif" }}>
      <style>{`@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap'); *{box-sizing:border-box;}`}</style>

      <div style={{ display:"flex", gap:64, alignItems:"center", maxWidth:900, width:"100%", padding:24 }}>

        {/* ── Branding panel ── */}
        <div style={{ flex:1, color:"white" }}>
          <div style={{ display:"flex", alignItems:"center", gap:12, marginBottom:28 }}>
            <div style={{ width:48, height:48, background:"linear-gradient(135deg,#3b82f6,#1d4ed8)",
              borderRadius:12, display:"flex", alignItems:"center", justifyContent:"center", fontSize:26 }}>🛡️</div>
            <div>
              <div style={{ fontSize:19, fontWeight:700 }}>SecOps Command Center</div>
              <div style={{ fontSize:10, color:"#94a3b8", letterSpacing:1.5, textTransform:"uppercase" }}>Security Operations Dashboard v2.0</div>
            </div>
          </div>
          <h1 style={{ fontSize:34, fontWeight:800, lineHeight:1.2, margin:"0 0 14px 0" }}>
            Your Security<br/>Operations Hub
          </h1>
          <p style={{ color:"#94a3b8", fontSize:14, lineHeight:1.75, margin:"0 0 28px 0" }}>
            Real-time visibility across Qualys VMDR, Fortinet,<br/>
            Azure Defender, Taegis XDR and more — all in one place.
          </p>
          <div style={{ display:"flex", flexDirection:"column", gap:10 }}>
            {[
              { role:"executive", icon:"🏢", label:"Executive",  desc:"Board view — Posture, Risk, Cloud, Reports" },
              { role:"analyst",   icon:"🔬", label:"Analyst",    desc:"Alerts, Vulnerabilities, Firewall, SIEM, Admin" },
              { role:"admin",     icon:"⚙️", label:"Admin",      desc:"All views + User Management" },
            ].map(r=>(
              <div key={r.role} style={{ display:"flex", alignItems:"center", gap:12, padding:"10px 14px",
                borderRadius:10, background:"rgba(255,255,255,0.05)", border:"1px solid rgba(255,255,255,0.08)" }}>
                <span style={{ fontSize:18 }}>{r.icon}</span>
                <div>
                  <div style={{ fontSize:12, fontWeight:700, color:"white" }}>{r.label}</div>
                  <div style={{ fontSize:11, color:"#64748b" }}>{r.desc}</div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* ── Login form ── */}
        <div style={{ width:380, background:"white", borderRadius:16, padding:"36px 32px",
          boxShadow:"0 25px 60px rgba(0,0,0,0.5)", flexShrink:0 }}>
          <div style={{ marginBottom:26 }}>
            <h2 style={{ margin:"0 0 4px 0", fontSize:22, fontWeight:700, color:"#0f172a" }}>Sign in</h2>
            <p style={{ margin:0, color:"#64748b", fontSize:13 }}>Enter your credentials to continue</p>
          </div>
          <form onSubmit={handleLogin} style={{ display:"flex", flexDirection:"column", gap:14 }}>
            <div>
              <label style={{ display:"block", fontSize:11, fontWeight:700, color:"#374151",
                marginBottom:5, textTransform:"uppercase", letterSpacing:0.5 }}>Username</label>
              <input type="text" value={username} onChange={e=>setUsername(e.target.value)}
                placeholder="admin / analyst / executive" autoFocus style={inp}
                onFocus={e=>e.target.style.borderColor="#3b82f6"}
                onBlur={e=>e.target.style.borderColor="#e2e8f0"}/>
            </div>
            <div>
              <label style={{ display:"block", fontSize:11, fontWeight:700, color:"#374151",
                marginBottom:5, textTransform:"uppercase", letterSpacing:0.5 }}>Password</label>
              <input type="password" value={password} onChange={e=>setPassword(e.target.value)}
                placeholder="••••••••" style={inp}
                onFocus={e=>e.target.style.borderColor="#3b82f6"}
                onBlur={e=>e.target.style.borderColor="#e2e8f0"}/>
            </div>
            {error && (
              <div style={{ padding:"10px 14px", borderRadius:8, background:"#fef2f2",
                border:"1px solid #fecaca", color:"#dc2626", fontSize:13 }}>⚠️ {error}</div>
            )}
            <button type="submit" disabled={loading||!username||!password}
              style={{ padding:"11px", borderRadius:8, border:"none",
                background:"linear-gradient(135deg,#3b82f6,#1d4ed8)", color:"white",
                fontSize:14, fontWeight:700, cursor:"pointer",
                opacity:(loading||!username||!password)?0.6:1, marginTop:4 }}>
              {loading ? "Signing in…" : "Sign In →"}
            </button>
          </form>
          {/* Default credentials */}
          <div style={{ marginTop:22, padding:"12px 14px", borderRadius:8, background:"#f8fafc", border:"1px solid #e2e8f0" }}>
            <div style={{ fontSize:10, fontWeight:700, color:"#94a3b8", marginBottom:7,
              textTransform:"uppercase", letterSpacing:0.8 }}>Default Credentials</div>
            {[["admin","Admin@1234","Full access"],["analyst","Analyst@1234","Analyst + Admin"],["executive","Exec@1234","Board view only"]].map(([u,p,d])=>(
              <div key={u} style={{ display:"flex", justifyContent:"space-between", alignItems:"center",
                fontSize:11, padding:"3px 0", borderBottom:"1px solid #f1f5f9" }}>
                <span><strong style={{color:"#1e293b"}}>{u}</strong>
                  <span style={{color:"#94a3b8"}}> / </span>
                  <span style={{color:"#475569",fontFamily:"monospace"}}>{p}</span>
                </span>
                <span style={{ fontSize:10, color:"#94a3b8", marginLeft:8 }}>{d}</span>
              </div>
            ))}
            <div style={{ fontSize:10, color:"#cbd5e1", marginTop:6 }}>⚠️ Change passwords after first login.</div>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════
   MAIN DASHBOARD  (shown after login)
═══════════════════════════════════════════════════════════════════════════ */
function Dashboard({ user, onLogout }) {
  // Role determines which views are accessible
  // executive → board only | analyst → analyst+admin | admin → both+admin
  const isExec  = user.role === "executive";
  const isAdmin = user.role === "admin";

  const [viewRole, setViewRole] = useState(isExec ? "executive" : "analyst");
  const [page,     setPage]     = useState(isExec ? "overview" : "alerts");
  const [data,     setData]     = useState(null);
  const [loading,  setLoading]  = useState(true);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [dateRange,   setDateRange]   = useState({ from:"", to:"" });
  const [showUserMenu, setShowUserMenu] = useState(false);

  // Executive board nav — no Admin
  const execNav = [
    { id:"overview", icon:"🏠", label:"Security Posture" },
    { id:"risk",     icon:"⚠️", label:"Risk & Compliance" },
    { id:"threats",  icon:"🎯", label:"Threat Intelligence" },
    { id:"cloud",    icon:"☁️", label:"Cloud Security" },
    { id:"report",   icon:"📊", label:"Executive Report" },
  ];
  // Analyst nav — Admin visible here
  const analystNav = [
    { id:"alerts",      icon:"🚨", label:"Alert Queue" },
    { id:"vulns",       icon:"🔍", label:"Vulnerabilities" },
    { id:"firewall",    icon:"🔥", label:"Firewall Analytics" },
    { id:"surface",     icon:"🌐", label:"Attack Surface" },
    { id:"assets",      icon:"💻", label:"Assets & Patches" },
    { id:"cloudanalyst",icon:"☁️", label:"Cloud Security" },
    { id:"siem",        icon:"📡", label:"SIEM / XDR" },
    { id:"admin",       icon:"🔌", label:"Admin" },
  ];

  const nav = viewRole === "executive" ? execNav : analystNav;

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (dateRange.from) params.append("from", dateRange.from);
      if (dateRange.to)   params.append("to",   dateRange.to);
      const res = await apiFetch(`${API}/api/snapshot?${params}`);
      if (res.status === 401) { onLogout(); return; }
      if (!res.ok) throw new Error("API error");
      const d   = await res.json();
      setData(transformSnapshot(d.data || d));
    } catch (err) {
      console.warn("Snapshot fetch failed:", err.message);
      setData({});
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

  // Close user menu on outside click
  useEffect(() => {
    if (!showUserMenu) return;
    const h = () => setShowUserMenu(false);
    setTimeout(() => document.addEventListener("click", h), 0);
    return () => document.removeEventListener("click", h);
  }, [showUserMenu]);

  function renderPage() {
    const p = { data, dateRange };
    switch(page) {
      case "overview":     return <OverviewPage {...p}/>;
      case "risk":         return <RiskCompliancePage {...p}/>;
      case "threats":      return <ThreatPage {...p}/>;
      case "cloud":        return <CloudPage {...p}/>;
      case "report":       return <ReportPage {...p}/>;
      case "alerts":       return <AlertsPage {...p}/>;
      case "vulns":        return <VulnerabilitiesPage {...p}/>;
      case "firewall":     return <FirewallPage {...p}/>;
      case "surface":      return <AttackSurfacePage {...p}/>;
      case "assets":       return <AssetsPage {...p}/>;
      case "cloudanalyst": return <CloudAnalystPage {...p}/>;
      case "siem":         return <SIEMPage {...p}/>;
      case "admin":        return <AdminPage user={user} onLogout={onLogout}/>;
      case "settings":     return <IntegrationsPage onSave={loadData}/>;
      default:             return <OverviewPage {...p}/>;
    }
  }

  const ROLE_COLOR = { admin:"#8b5cf6", analyst:"#3b82f6", executive:"#f59e0b" };
  const userColor  = ROLE_COLOR[user.role] || "#64748b";

  return (
    <div style={{ display:"flex", flexDirection:"column", height:"100vh",
      fontFamily:"'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif",
      background:C.bg, color:C.text }}>

      {/* ── HEADER ────────────────────────────────────────────────────────── */}
      <header style={{ background:C.header, color:"white", padding:"0 24px", height:60,
        display:"flex", alignItems:"center", gap:16, zIndex:10,
        boxShadow:"0 2px 12px rgba(0,0,0,0.25)", flexShrink:0 }}>

        {/* Logo */}
        <div style={{ display:"flex", alignItems:"center", gap:10, marginRight:"auto" }}>
          <div style={{ width:34, height:34, background:"linear-gradient(135deg,#3b82f6,#1d4ed8)",
            borderRadius:8, display:"flex", alignItems:"center", justifyContent:"center", fontSize:18 }}>🛡️</div>
          <div>
            <div style={{ fontWeight:700, fontSize:15, letterSpacing:0.3 }}>SecOps Command Center</div>
            <div style={{ fontSize:10, color:"#94a3b8", letterSpacing:1.2, textTransform:"uppercase" }}>Security Operations Dashboard • v{VER}</div>
          </div>
        </div>

        {/* View toggle — hidden for pure executives */}
        {!isExec && (
          <div style={{ display:"flex", background:"rgba(0,0,0,0.25)", borderRadius:8, padding:3, gap:2 }}>
            {[["executive","🏢 Executive Board"],["analyst","🔬 Security Analyst"]].map(([r,l])=>(
              <button key={r} onClick={()=>{ setViewRole(r); setPage(r==="executive"?"overview":"alerts"); }}
                style={{ padding:"5px 14px", borderRadius:6, border:"none", cursor:"pointer", fontWeight:600, fontSize:12,
                  background:viewRole===r?"white":"transparent", color:viewRole===r?C.header:"#94a3b8", transition:"all 0.15s" }}>
                {l}
              </button>
            ))}
          </div>
        )}
        {isExec && (
          <div style={{ padding:"5px 14px", borderRadius:6, background:"rgba(245,158,11,0.2)",
            border:"1px solid rgba(245,158,11,0.3)", fontSize:12, fontWeight:600, color:"#fbbf24" }}>
            🏢 Executive Board
          </div>
        )}

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
            <button onClick={()=>setDateRange({from:"",to:""})}
              style={{ background:"none", border:"none", color:"#94a3b8", cursor:"pointer", fontSize:14, padding:0 }}>✕</button>
          )}
        </div>

        {/* Refresh status */}
        <div style={{ display:"flex", alignItems:"center", gap:6, fontSize:11, color:"#64748b" }}>
          <div style={{ width:7, height:7, borderRadius:"50%",
            background:loading?"#f59e0b":"#10b981",
            boxShadow:loading?"0 0 0 3px #f59e0b30":"0 0 0 3px #10b98130", transition:"all 0.3s" }}/>
          {loading?"Refreshing…":lastUpdated?`Updated ${lastUpdated.toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"})}`:"-"}
        </div>

        {/* Settings */}
        {!isExec && (
          <button onClick={()=>setPage("settings")}
            style={{ background:page==="settings"?"rgba(59,130,246,0.25)":"rgba(255,255,255,0.07)",
              border:`1px solid ${page==="settings"?"#3b82f6":"rgba(255,255,255,0.12)"}`,
              borderRadius:8, padding:"6px 10px", cursor:"pointer",
              color:page==="settings"?"#93c5fd":"#94a3b8", fontSize:16, transition:"all 0.15s" }}>⚙️</button>
        )}

        {/* User menu */}
        <div style={{ position:"relative" }}>
          <button onClick={e=>{ e.stopPropagation(); setShowUserMenu(v=>!v); }}
            style={{ display:"flex", alignItems:"center", gap:8, background:"rgba(255,255,255,0.08)",
              border:"1px solid rgba(255,255,255,0.12)", borderRadius:8,
              padding:"5px 12px", cursor:"pointer", color:"white" }}>
            <div style={{ width:24, height:24, borderRadius:"50%", background:userColor,
              display:"flex", alignItems:"center", justifyContent:"center", fontSize:11, fontWeight:700 }}>
              {(user.display_name||user.username).charAt(0).toUpperCase()}
            </div>
            <div style={{ textAlign:"left" }}>
              <div style={{ fontSize:12, fontWeight:600 }}>{user.display_name || user.username}</div>
              <div style={{ fontSize:10, color:"#94a3b8", textTransform:"capitalize" }}>{user.role}</div>
            </div>
            <span style={{ fontSize:10, color:"#64748b" }}>▼</span>
          </button>
          {showUserMenu && (
            <div style={{ position:"absolute", right:0, top:"calc(100% + 8px)", width:200,
              background:"white", borderRadius:10, boxShadow:"0 10px 40px rgba(0,0,0,0.3)",
              border:"1px solid #e2e8f0", overflow:"hidden", zIndex:100 }}
              onClick={e=>e.stopPropagation()}>
              <div style={{ padding:"10px 14px", borderBottom:"1px solid #f1f5f9" }}>
                <div style={{ fontSize:12, fontWeight:700, color:"#0f172a" }}>{user.display_name||user.username}</div>
                <div style={{ fontSize:11, color:"#64748b", textTransform:"capitalize" }}>{user.role} access</div>
              </div>
              <button onClick={()=>{ setPage("change-password"); setShowUserMenu(false); }}
                style={{ width:"100%", padding:"9px 14px", border:"none", background:"transparent",
                  textAlign:"left", fontSize:12, color:"#374151", cursor:"pointer" }}>🔒 Change Password</button>
              {isAdmin && (
                <button onClick={()=>{ setPage("admin"); setViewRole("analyst"); setShowUserMenu(false); }}
                  style={{ width:"100%", padding:"9px 14px", border:"none", background:"transparent",
                    textAlign:"left", fontSize:12, color:"#374151", cursor:"pointer" }}>👥 User Management</button>
              )}
              <div style={{ borderTop:"1px solid #f1f5f9" }}>
                <button onClick={onLogout}
                  style={{ width:"100%", padding:"9px 14px", border:"none", background:"transparent",
                    textAlign:"left", fontSize:12, color:"#dc2626", cursor:"pointer", fontWeight:600 }}>
                  ⟵ Sign Out
                </button>
              </div>
            </div>
          )}
        </div>
      </header>

      {/* ── BODY ──────────────────────────────────────────────────────────── */}
      <div style={{ display:"flex", flex:1, overflow:"hidden" }}>

        {/* Sidebar */}
        <aside style={{ width:216, background:C.sidebar, display:"flex", flexDirection:"column", flexShrink:0, overflow:"auto" }}>
          <div style={{ padding:"14px 16px 10px", borderBottom:"1px solid rgba(255,255,255,0.04)" }}>
            <div style={{ fontSize:9, color:"#334155", textTransform:"uppercase", letterSpacing:1.8, fontWeight:700 }}>
              {viewRole==="executive"?"Board & Executive":"Security Team"}
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
          <div style={{ padding:12, borderTop:"1px solid rgba(255,255,255,0.04)" }}>
            <div style={{ display:"flex", alignItems:"center", gap:8, padding:"8px 10px",
              borderRadius:8, background:"rgba(255,255,255,0.04)" }}>
              <div style={{ width:26, height:26, borderRadius:"50%", background:userColor,
                display:"flex", alignItems:"center", justifyContent:"center", fontSize:11, fontWeight:700, color:"white", flexShrink:0 }}>
                {(user.display_name||user.username).charAt(0).toUpperCase()}
              </div>
              <div style={{ overflow:"hidden" }}>
                <div style={{ fontSize:11, color:"#94a3b8", fontWeight:600, whiteSpace:"nowrap",
                  overflow:"hidden", textOverflow:"ellipsis" }}>{user.display_name||user.username}</div>
                <div style={{ fontSize:9, color:"#475569", textTransform:"capitalize" }}>{user.role}</div>
              </div>
            </div>
          </div>
        </aside>

        {/* Main content */}
        <main style={{ flex:1, overflow:"auto", padding:24 }}>
          {loading && !data ? (
            <div style={{ display:"flex", alignItems:"center", justifyContent:"center", height:"100%", flexDirection:"column", gap:16 }}>
              <div style={{ width:44, height:44, border:"3px solid #3b82f6", borderTopColor:"transparent",
                borderRadius:"50%", animation:"spin 0.8s linear infinite" }}/>
              <div style={{ color:C.muted, fontSize:14 }}>Loading security data…</div>
            </div>
          ) : page === "change-password" ? (
            <ChangePasswordPage onBack={()=>setPage(viewRole==="executive"?"overview":"alerts")} />
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

/* ── Change Password Page ───────────────────────────────────────────────── */
function ChangePasswordPage({ onBack }) {
  const [form,    setForm]    = useState({ current:"", next:"", confirm:"" });
  const [msg,     setMsg]     = useState(null);
  const [saving,  setSaving]  = useState(false);

  async function handleSave(e) {
    e.preventDefault();
    if (form.next !== form.confirm) { setMsg({ ok:false, text:"Passwords do not match" }); return; }
    if (form.next.length < 8)       { setMsg({ ok:false, text:"Password must be at least 8 characters" }); return; }
    setSaving(true); setMsg(null);
    try {
      const r = await apiFetch(`${API}/api/auth/change-password`, {
        method:"POST",
        body: JSON.stringify({ current_password: form.current, new_password: form.next }),
      });
      const d = await r.json();
      if (!r.ok) setMsg({ ok:false, text: d.error || "Failed" });
      else       { setMsg({ ok:true, text:"Password changed successfully!" }); setForm({ current:"", next:"", confirm:"" }); }
    } catch { setMsg({ ok:false, text:"Network error" }); }
    setSaving(false);
  }

  const inp = { width:"100%", padding:"9px 12px", borderRadius:8, border:"1.5px solid #e2e8f0", fontSize:13, outline:"none", boxSizing:"border-box" };
  return (
    <div>
      <SectionTitle title="Change Password" subtitle="Update your account password" />
      <Card style={{ maxWidth:420, padding:28 }}>
        <form onSubmit={handleSave} style={{ display:"flex", flexDirection:"column", gap:14 }}>
          {[["current","Current Password"],["next","New Password"],["confirm","Confirm New Password"]].map(([k,l])=>(
            <div key={k}>
              <label style={{ display:"block", fontSize:11, fontWeight:700, color:C.muted, marginBottom:5, textTransform:"uppercase", letterSpacing:0.5 }}>{l}</label>
              <input type="password" value={form[k]} onChange={e=>setForm(p=>({...p,[k]:e.target.value}))} style={inp}/>
            </div>
          ))}
          {msg && (
            <div style={{ padding:"10px 12px", borderRadius:8, fontSize:13,
              background:msg.ok?"#f0fdf4":"#fef2f2", color:msg.ok?C.ok:C.critical,
              border:`1px solid ${msg.ok?"#bbf7d0":"#fecaca"}` }}>{msg.ok?"✅":"⚠️"} {msg.text}</div>
          )}
          <div style={{ display:"flex", gap:8, marginTop:4 }}>
            <button type="button" onClick={onBack}
              style={{ flex:1, padding:"9px", borderRadius:8, border:`1px solid ${C.border}`, background:"white", color:C.muted, fontSize:13, cursor:"pointer" }}>Cancel</button>
            <button type="submit" disabled={saving||!form.current||!form.next||!form.confirm}
              style={{ flex:2, padding:"9px", borderRadius:8, border:"none", background:C.primary, color:"white", fontSize:13, fontWeight:700, cursor:"pointer", opacity:saving?0.6:1 }}>
              {saving?"Saving…":"Save Password"}
            </button>
          </div>
        </form>
      </Card>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════
   APP ROOT  (auth gate)
═══════════════════════════════════════════════════════════════════════════ */
export default function App() {
  const [user,     setUser]     = useState(null);
  const [checking, setChecking] = useState(true);

  useEffect(() => {
    fetch(`${API}/api/auth/me`, { credentials:"include" })
      .then(r => r.ok ? r.json() : null)
      .then(u => { setUser(u); setChecking(false); })
      .catch(() => setChecking(false));
  }, []);

  async function handleLogout() {
    await fetch(`${API}/api/auth/logout`, { method:"POST", credentials:"include" }).catch(()=>{});
    setUser(null);
  }

  if (checking) return (
    <div style={{ minHeight:"100vh", display:"flex", alignItems:"center", justifyContent:"center",
      background:"#0f172a", fontFamily:"'Inter',sans-serif" }}>
      <div style={{ textAlign:"center", color:"white" }}>
        <div style={{ width:40, height:40, border:"3px solid #3b82f6", borderTopColor:"transparent",
          borderRadius:"50%", animation:"spin 0.8s linear infinite", margin:"0 auto 16px" }}/>
        <div style={{ color:"#64748b", fontSize:13 }}>Checking session…</div>
      </div>
      <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
    </div>
  );

  if (!user) return <LoginPage onLogin={setUser} />;
  return <Dashboard user={user} onLogout={handleLogout} />;
}
