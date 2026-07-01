/**
 * GRC Compliance Microservice — port 4001
 * Manages DPDPA 2023, PCI DSS 4.0.1, ISO 27001:2022 controls
 * Shares the same PostgreSQL instance as the main SecOps backend
 */
const express      = require("express");
const cors         = require("cors");
const { Pool }     = require("pg");
const jwt          = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

const PORT       = process.env.GRC_PORT || 4001;
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

/* ── Control definitions (same as main server) ─────────────────────────────── */
const GRC_DEFAULTS = {
  dpdpa: [
    { control_id:"S5",   category:"Data Processing",       title:"Purpose Limitation",                 description:"Process personal data only for the specific lawful purpose for which it was collected (Section 5 DPDPA 2023)." },
    { control_id:"S6",   category:"Consent",               title:"Consent Management",                 description:"Obtain free, specific, informed, and unambiguous consent from Data Principals. Maintain consent records and provide withdrawal mechanism." },
    { control_id:"S7",   category:"Legitimate Use",        title:"Legitimate Processing Bases",        description:"Document and enforce legitimate bases for processing personal data without consent (legal obligation, vital interests, public interest)." },
    { control_id:"S8.1", category:"Data Quality",          title:"Accuracy and Completeness",          description:"Ensure personal data processed is accurate, complete, and updated where necessary." },
    { control_id:"S8.2", category:"Security",              title:"Data Security Safeguards",           description:"Implement reasonable security safeguards to prevent personal data breach. Conduct risk assessments and maintain security controls." },
    { control_id:"S8.3", category:"Breach Response",       title:"Data Breach Notification",           description:"Notify Data Protection Board and affected Data Principals of personal data breaches in the prescribed manner and timeline." },
    { control_id:"S8.4", category:"Retention",             title:"Data Retention and Erasure",         description:"Erase personal data as soon as the purpose is served or consent is withdrawn. Implement retention schedules." },
    { control_id:"S9",   category:"Children's Data",       title:"Children's Data Protection",         description:"Obtain verifiable parental consent before processing personal data of children under 18." },
    { control_id:"S10",  category:"Governance",            title:"Significant Data Fiduciary Obligations", description:"If classified as SDF: appoint DPO, conduct DPIA, implement data audits, register with Data Protection Board." },
    { control_id:"S11",  category:"Data Principal Rights", title:"Right to Information",               description:"Provide Data Principals with information about personal data being processed upon request." },
    { control_id:"S12",  category:"Data Principal Rights", title:"Right to Correction and Erasure",    description:"Allow Data Principals to correct inaccurate data and erase personal data upon request." },
    { control_id:"S13",  category:"Data Principal Rights", title:"Grievance Redressal Mechanism",      description:"Establish a grievance redressal mechanism with a Data Protection Officer or designated officer." },
    { control_id:"S14",  category:"Data Principal Rights", title:"Right to Nominate",                  description:"Allow Data Principals to nominate another person to exercise their rights in case of death or incapacity." },
    { control_id:"S16",  category:"Governance",            title:"Data Protection Officer",            description:"Appoint a Data Protection Officer and publish contact details on website." },
    { control_id:"S17",  category:"Cross-Border Transfer", title:"Cross-Border Data Transfers",        description:"Ensure personal data is transferred only to countries/territories permitted by the Central Government." },
    { control_id:"S19",  category:"Third Parties",         title:"Data Processor Agreements",          description:"Ensure Data Processors process personal data only under valid contract and per Data Fiduciary instructions." },
    { control_id:"S22",  category:"Governance",            title:"Privacy Notice",                     description:"Provide clear, accessible privacy notice describing categories of personal data, purposes, and rights of Data Principals." },
    { control_id:"S29",  category:"Compliance",            title:"Compliance with Board Directions",   description:"Comply with all directions, inquiries, and investigations initiated by the Data Protection Board." },
  ],
  pcidss: [
    { control_id:"1.1",  category:"Req 1 – Network Security",  title:"Network Security Controls Policy",      description:"Establish, implement, and maintain network security controls configuration standards." },
    { control_id:"1.2",  category:"Req 1 – Network Security",  title:"Network Access Controls",               description:"Restrict inbound and outbound traffic to only what is necessary for the CDE." },
    { control_id:"1.3",  category:"Req 1 – Network Security",  title:"Network Access Between CDE and Untrusted Networks", description:"Restrict inbound and outbound traffic to that which is necessary for the CDE." },
    { control_id:"1.4",  category:"Req 1 – Network Security",  title:"Network Connections CDE to Untrusted",  description:"Network security controls implemented between trusted and untrusted networks." },
    { control_id:"1.5",  category:"Req 1 – Network Security",  title:"Risks from Computing Devices",         description:"Risks to the CDE from computing devices that connect to both untrusted networks and CDE are addressed." },
    { control_id:"2.1",  category:"Req 2 – Secure Config",     title:"Secure Configuration Processes",       description:"Processes and mechanisms for applying secure configurations to all system components are defined." },
    { control_id:"2.2",  category:"Req 2 – Secure Config",     title:"System Components Configured Securely", description:"Change default vendor-supplied credentials. Develop configuration standards." },
    { control_id:"2.3",  category:"Req 2 – Secure Config",     title:"Wireless Environments",                description:"Wireless environments are configured and managed securely." },
    { control_id:"3.1",  category:"Req 3 – Stored Data",       title:"Account Data Storage Policies",        description:"Processes and mechanisms for protecting stored account data are defined." },
    { control_id:"3.3",  category:"Req 3 – Stored Data",       title:"SAD Not Retained After Authorization",  description:"Sensitive authentication data (SAD) is not retained after authorization." },
    { control_id:"3.4",  category:"Req 3 – Stored Data",       title:"PAN Protection",                       description:"Access to displays of full PAN and ability to copy PAN are restricted." },
    { control_id:"3.5",  category:"Req 3 – Stored Data",       title:"Primary Account Number Secured",        description:"PAN is secured wherever stored." },
    { control_id:"4.2",  category:"Req 4 – Transmission",      title:"PAN Secured During Transmission",       description:"PAN is protected with strong cryptography during transmission over open, public networks." },
    { control_id:"5.2",  category:"Req 5 – Anti-Malware",      title:"Anti-Malware Deployed",                description:"Malware is prevented or detected and addressed." },
    { control_id:"5.3",  category:"Req 5 – Anti-Malware",      title:"Anti-Malware Mechanisms Active",       description:"Anti-malware mechanisms and processes are active, maintained, and monitored." },
    { control_id:"6.2",  category:"Req 6 – Secure Systems",    title:"Bespoke and Custom Software Security",  description:"Bespoke and custom software are developed securely." },
    { control_id:"6.3",  category:"Req 6 – Secure Systems",    title:"Security Vulnerabilities Identified",   description:"Security vulnerabilities are identified and addressed." },
    { control_id:"6.4",  category:"Req 6 – Secure Systems",    title:"Web-Facing Applications Protected",     description:"Public-facing web applications are protected against attacks." },
    { control_id:"7.2",  category:"Req 7 – Access Control",    title:"Access to System Components Restricted", description:"Access to system components and data is appropriately defined and assigned." },
    { control_id:"8.2",  category:"Req 8 – Identity & Auth",   title:"User Identification and Authentication", description:"All users are assigned a unique ID before allowing access to system components." },
    { control_id:"8.4",  category:"Req 8 – Identity & Auth",   title:"MFA Implemented",                      description:"Multi-factor authentication (MFA) is implemented to secure access into the CDE." },
    { control_id:"9.2",  category:"Req 9 – Physical Access",   title:"Physical Access to CDE Controlled",    description:"Physical access controls manage entry into facilities and systems containing cardholder data." },
    { control_id:"9.4",  category:"Req 9 – Physical Access",   title:"Media with Cardholder Data Protected",  description:"Media with cardholder data is protected." },
    { control_id:"10.2", category:"Req 10 – Logging",          title:"Audit Logs Implemented",               description:"Audit logs that capture user activities, exceptions, and security events are implemented." },
    { control_id:"10.3", category:"Req 10 – Logging",          title:"Audit Logs Protected",                 description:"Audit logs are protected from destruction and unauthorized modifications." },
    { control_id:"10.4", category:"Req 10 – Logging",          title:"Audit Logs Reviewed",                  description:"Audit logs are reviewed to identify anomalies or suspicious activity." },
    { control_id:"11.3", category:"Req 11 – Testing",          title:"Vulnerability Scanning",               description:"External and internal vulnerabilities are regularly identified and resolved." },
    { control_id:"11.4", category:"Req 11 – Testing",          title:"Penetration Testing",                  description:"External and internal penetration testing is regularly performed." },
    { control_id:"12.1", category:"Req 12 – Policy",           title:"Information Security Policy",          description:"A comprehensive information security policy is defined, published, maintained, and disseminated." },
    { control_id:"12.3", category:"Req 12 – Policy",           title:"Risk Management",                      description:"Risks to the cardholder data environment are formally identified, evaluated, and managed." },
    { control_id:"12.6", category:"Req 12 – Policy",           title:"Security Awareness Program",           description:"A security awareness program is implemented to make all personnel aware of the policy." },
    { control_id:"12.8", category:"Req 12 – Policy",           title:"Third-Party Risk Management",          description:"Risks from third-party entities with access to cardholder data are managed." },
    { control_id:"12.10",category:"Req 12 – Policy",           title:"Incident Response Plan",               description:"Suspected and confirmed security incidents that could impact the CDE are responded to immediately." },
  ],
  iso27001: [
    { control_id:"4.1",   category:"Clause 4 – Context",       title:"Understanding the Organisation",       description:"Determine external and internal issues relevant to the ISMS." },
    { control_id:"4.2",   category:"Clause 4 – Context",       title:"Interested Parties",                   description:"Determine interested parties relevant to the ISMS and their requirements." },
    { control_id:"4.3",   category:"Clause 4 – Context",       title:"ISMS Scope",                           description:"Determine the boundaries and applicability of the ISMS and document its scope." },
    { control_id:"5.1",   category:"Clause 5 – Leadership",    title:"Leadership and Commitment",            description:"Top management shall demonstrate leadership and commitment to the ISMS." },
    { control_id:"5.2",   category:"Clause 5 – Leadership",    title:"Information Security Policy",          description:"Establish, maintain, and communicate an information security policy." },
    { control_id:"5.3",   category:"Clause 5 – Leadership",    title:"Organisational Roles",                 description:"Assign and communicate roles and responsibilities for information security." },
    { control_id:"6.1",   category:"Clause 6 – Planning",      title:"Risk Assessment",                      description:"Define and apply an information security risk assessment process." },
    { control_id:"6.2",   category:"Clause 6 – Planning",      title:"Risk Treatment",                       description:"Define and apply an information security risk treatment process. Produce Statement of Applicability." },
    { control_id:"7.2",   category:"Clause 7 – Support",       title:"Competence",                           description:"Determine, maintain, and document staff competence for information security." },
    { control_id:"7.3",   category:"Clause 7 – Support",       title:"Awareness",                            description:"Ensure persons are aware of the IS policy and their contribution." },
    { control_id:"7.5",   category:"Clause 7 – Support",       title:"Documented Information",               description:"Maintain documented information required by ISO 27001." },
    { control_id:"8.2",   category:"Clause 8 – Operation",     title:"Risk Assessment (Operational)",        description:"Perform risk assessments at planned intervals or when significant changes occur." },
    { control_id:"9.1",   category:"Clause 9 – Evaluation",    title:"Monitoring and Measurement",           description:"Evaluate IS performance and effectiveness of the ISMS." },
    { control_id:"9.2",   category:"Clause 9 – Evaluation",    title:"Internal Audit",                       description:"Conduct internal audits of the ISMS at planned intervals." },
    { control_id:"9.3",   category:"Clause 9 – Evaluation",    title:"Management Review",                    description:"Top management shall review the ISMS at planned intervals." },
    { control_id:"10.2",  category:"Clause 10 – Improvement",  title:"Nonconformity and Corrective Action",  description:"React to nonconformities, take corrective action, review effectiveness." },
    { control_id:"A.5.1", category:"A.5 Organisational",       title:"Information Security Policies",        description:"Define, approve, publish, and review information security policies." },
    { control_id:"A.5.9", category:"A.5 Organisational",       title:"Inventory of Assets",                  description:"Identify assets associated with information and information processing facilities." },
    { control_id:"A.5.12",category:"A.5 Organisational",       title:"Classification of Information",        description:"Information shall be classified according to security needs of the organisation." },
    { control_id:"A.5.15",category:"A.5 Organisational",       title:"Access Control",                       description:"Rules to control physical and logical access to information and assets." },
    { control_id:"A.5.19",category:"A.5 Organisational",       title:"IS in Supplier Relationships",         description:"Processes to manage IS risks in supplier relationships." },
    { control_id:"A.5.24",category:"A.5 Organisational",       title:"IS Incident Management Planning",      description:"Plan and prepare for managing IS incidents." },
    { control_id:"A.5.29",category:"A.5 Organisational",       title:"IS During Disruption",                 description:"Plan how to maintain IS at an appropriate level during disruption." },
    { control_id:"A.5.31",category:"A.5 Organisational",       title:"Legal and Regulatory Requirements",    description:"Identify, document, and keep up to date all legal, statutory, regulatory requirements." },
    { control_id:"A.6.1", category:"A.6 People",               title:"Screening",                            description:"Background verification checks on all candidates for employment." },
    { control_id:"A.6.3", category:"A.6 People",               title:"IS Awareness and Training",            description:"Personnel shall receive appropriate IS awareness and training." },
    { control_id:"A.6.8", category:"A.6 People",               title:"IS Event Reporting",                   description:"Personnel shall be required to report IS events through appropriate channels." },
    { control_id:"A.7.1", category:"A.7 Physical",             title:"Physical Security Perimeters",         description:"Security perimeters shall be defined and used to protect areas containing sensitive information." },
    { control_id:"A.7.4", category:"A.7 Physical",             title:"Physical Security Monitoring",         description:"Premises shall be continuously monitored for unauthorised physical access." },
    { control_id:"A.7.10",category:"A.7 Physical",             title:"Storage Media",                        description:"Storage media shall be managed through their life cycle." },
    { control_id:"A.8.2", category:"A.8 Technological",        title:"Privileged Access Rights",             description:"Allocation and use of privileged access rights shall be restricted and managed." },
    { control_id:"A.8.5", category:"A.8 Technological",        title:"Secure Authentication",                description:"Secure authentication technologies and procedures shall be implemented." },
    { control_id:"A.8.7", category:"A.8 Technological",        title:"Protection Against Malware",           description:"Protection against malware shall be implemented." },
    { control_id:"A.8.8", category:"A.8 Technological",        title:"Management of Technical Vulnerabilities", description:"Timely identification and remediation of technical vulnerabilities." },
    { control_id:"A.8.12",category:"A.8 Technological",        title:"Data Leakage Prevention",              description:"Measures to prevent data leakage shall be applied." },
    { control_id:"A.8.13",category:"A.8 Technological",        title:"Information Backup",                   description:"Backup copies of information shall be maintained and regularly tested." },
    { control_id:"A.8.15",category:"A.8 Technological",        title:"Logging",                              description:"Logs recording activities, exceptions, faults, and events shall be produced and reviewed." },
    { control_id:"A.8.20",category:"A.8 Technological",        title:"Networks Security",                    description:"Networks and network devices shall be secured, managed, and controlled." },
    { control_id:"A.8.24",category:"A.8 Technological",        title:"Use of Cryptography",                  description:"Rules for effective use of cryptography, including key management, shall be defined." },
    { control_id:"A.8.25",category:"A.8 Technological",        title:"Secure Development Life Cycle",        description:"Rules for secure development of software and systems shall be established." },
    { control_id:"A.8.32",category:"A.8 Technological",        title:"Change Management",                    description:"Changes to IS processing facilities and IS shall be subject to change management procedures." },
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

/* ── Health ───────────────────────────────────────────────────────────────── */
app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, service: "grc", port: PORT });
  } catch(e) { res.status(503).json({ ok: false, error: e.message }); }
});

/* ── GRC Routes ───────────────────────────────────────────────────────────── */
app.get("/api/grc/:framework", requireAuth, async (req, res) => {
  const fw = req.params.framework.toLowerCase();
  try {
    const cnt = await pool.query("SELECT COUNT(*) FROM grc_controls WHERE framework=$1", [fw]);
    if (parseInt(cnt.rows[0].count) === 0) await seedGRCControls(fw);
    const r = await pool.query(
      "SELECT * FROM grc_controls WHERE framework=$1 ORDER BY control_id", [fw]
    );
    res.json(r.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put("/api/grc/:framework/:controlId", requireAuth, async (req, res) => {
  const fw  = req.params.framework.toLowerCase();
  const cid = req.params.controlId;
  const { status, evidence, notes, owner, due_date } = req.body;
  try {
    const r = await pool.query(
      `UPDATE grc_controls SET
         status    = COALESCE($1, status),
         evidence  = COALESCE($2, evidence),
         notes     = COALESCE($3, notes),
         owner     = COALESCE($4, owner),
         due_date  = COALESCE($5::date, due_date),
         updated_at = NOW(),
         updated_by = $6
       WHERE framework=$7 AND control_id=$8 RETURNING *`,
      [status, evidence, notes, owner, due_date || null, req.user.username, fw, cid]
    );
    if (r.rowCount === 0) return res.status(404).json({ error: "Control not found" });
    res.json(r.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post("/api/grc/:framework/reset", requireAuth, async (req, res) => {
  const fw = req.params.framework.toLowerCase();
  try {
    await pool.query("DELETE FROM grc_controls WHERE framework=$1", [fw]);
    await seedGRCControls(fw);
    const r = await pool.query(
      "SELECT * FROM grc_controls WHERE framework=$1 ORDER BY control_id", [fw]
    );
    res.json(r.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* ── Compliance summary (all frameworks) ─────────────────────────────────── */
app.get("/api/grc", requireAuth, async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT framework,
        COUNT(*) AS total,
        COUNT(*) FILTER (WHERE status='compliant') AS compliant,
        COUNT(*) FILTER (WHERE status='partial') AS partial,
        COUNT(*) FILTER (WHERE status='non-compliant') AS non_compliant,
        COUNT(*) FILTER (WHERE status='not-assessed') AS not_assessed
      FROM grc_controls GROUP BY framework
    `);
    res.json(r.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* ── Start ────────────────────────────────────────────────────────────────── */
app.listen(PORT, async () => {
  console.log(`GRC Service running on :${PORT}`);
  let retries = 10;
  while (retries > 0) {
    try { await pool.query("SELECT 1"); console.log("DB connected"); break; }
    catch { retries--; await new Promise(r => setTimeout(r, 3000)); }
  }
  await ensureGRCTable().catch(e => console.error("ensureGRCTable:", e.message));
  console.log("GRC Service ready — frameworks: DPDPA, PCI DSS 4.0.1, ISO 27001:2022");
});
