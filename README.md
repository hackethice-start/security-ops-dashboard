# Security Operations Dashboard

A real-time cybersecurity dashboard integrating 6 security tools with Docker, PostgreSQL, and CI/CD.

## Tools Integrated
- **Fortinet FortiGate** — Firewall health & traffic
- **Palo Alto** — Threat intelligence & blocked attacks  
- **UpGuard** — External attack surface monitoring
- **Azure Defender for Cloud** — Cloud security posture
- **Qualys VMDR** — Vulnerability management & VAPT
- **ManageEngine** — Asset & patch management, disk encryption

## Quick Start

```bash
cp .env.example .env
# Fill in your credentials in .env
docker compose up -d --build
```

Dashboard → http://localhost:3000  
Backend API → http://localhost:4000/api/health

## Architecture

```
dashboard  (React 18 + Nginx)   :3000
backend    (Node.js + Express)  :4000  — collects every 15 min
db         (PostgreSQL 16)      :5432  — 1-year rolling data
```

## CI/CD

Push to `main` → GitHub Actions builds images → pushes to ghcr.io → deploys to Ubuntu server via SSH.

See `.github/workflows/deploy.yml` and `server-setup.sh` for setup.

## Environment Variables

Copy `.env.example` to `.env` and fill in all credentials.  
Add the same values as GitHub Secrets for CI/CD deployment.
