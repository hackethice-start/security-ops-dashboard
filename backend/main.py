"""
SecOps Dashboard — FastAPI backend
Replaces the previous Node.js implementation.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import asyncpg
from passlib.context import CryptContext

_pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
import httpx
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import Cookie, Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from lxml import etree
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("secops")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://secops:secops@db:5432/secops")
JWT_SECRET = os.getenv("JWT_SECRET", "secops-secret-change-in-production")
JWT_ALGORITHM = "HS256"
COOKIE_NAME = "session"

# ---------------------------------------------------------------------------
# DB pool (module-level, initialised at startup)
# ---------------------------------------------------------------------------
_pool: asyncpg.Pool | None = None


async def get_pool() -> asyncpg.Pool:
    if _pool is None:
        raise RuntimeError("DB pool not initialised")
    return _pool


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(title="SecOps Dashboard", version="2.0.0")

# CORS: reflect Origin header so cookies work with credentials: "include"
# allow_origins=["*"] + allow_credentials=True is invalid per spec — browsers block it.
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https?://.*",   # matches any HTTP/HTTPS origin
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

scheduler = AsyncIOScheduler()


# ---------------------------------------------------------------------------
# Startup / shutdown
# ---------------------------------------------------------------------------
@app.on_event("startup")
async def startup():
    """Startup: connect DB, seed users, ensure partitions, start scheduler."""
    global _pool

    # 1. Wait for DB (up to 90 seconds)
    log.info("Waiting for database…")
    connected = False
    for attempt in range(30):
        try:
            _pool = await asyncpg.create_pool(DATABASE_URL, min_size=2, max_size=10)
            log.info("Database connected.")
            connected = True
            break
        except Exception as exc:
            log.warning("DB not ready (attempt %d/30): %s", attempt + 1, exc)
            await asyncio.sleep(3)

    if not connected:
        log.error("Could not connect to database after 30 attempts. Routes will fail until DB is available.")
        return  # Don't crash — let health endpoint respond, Docker will handle restart

    # 2. Ensure tables / partitions (non-fatal)
    try:
        await ensure_users_table()
        await ensure_partitions()
        await seed_users()
    except Exception as e:
        log.error("Table setup error (continuing): %s", e)

    # 3. Start scheduler
    try:
        scheduler.start()
        scheduler.add_job(ensure_partitions, "interval", hours=24, id="partition_maintenance",
                          replace_existing=True)
        await schedule_all_integrations()
    except Exception as e:
        log.error("Scheduler error (continuing): %s", e)

    log.info("Startup complete.")


@app.on_event("shutdown")
async def shutdown():
    scheduler.shutdown(wait=False)
    if _pool:
        await _pool.close()


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------
async def ensure_users_table():
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                username VARCHAR UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role VARCHAR NOT NULL CHECK (role IN ('admin','analyst','executive')),
                display_name VARCHAR,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                last_login TIMESTAMPTZ
            )
        """)
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS integrations (
                tool_name VARCHAR PRIMARY KEY,
                credentials JSONB DEFAULT '{}',
                enabled BOOLEAN DEFAULT true,
                status VARCHAR DEFAULT 'unconfigured',
                refresh_interval INTEGER DEFAULT 300,
                last_tested TIMESTAMPTZ,
                last_error TEXT,
                updated_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        # Ensure known tools exist as rows
        tools = ["upguard", "qualys", "fortinet", "azure", "manageengine", "paloalto"]
        for tool in tools:
            await conn.execute("""
                INSERT INTO integrations (tool_name) VALUES ($1)
                ON CONFLICT (tool_name) DO NOTHING
            """, tool)


async def ensure_partitions():
    """Create monthly partitions for snapshots table for current month + 13 forward."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        try:
            await conn.execute("""
                DO $$
                DECLARE
                    i INTEGER;
                    start_date DATE;
                    end_date DATE;
                    tbl_name TEXT;
                BEGIN
                    FOR i IN 0..13 LOOP
                        start_date := DATE_TRUNC('month', NOW() + (i || ' months')::INTERVAL)::DATE;
                        end_date   := (start_date + INTERVAL '1 month')::DATE;
                        tbl_name   := 'snapshots_' || TO_CHAR(start_date, 'YYYY_MM');
                        IF NOT EXISTS (
                            SELECT 1 FROM pg_class
                            WHERE relname = tbl_name
                        ) THEN
                            EXECUTE FORMAT(
                                'CREATE TABLE IF NOT EXISTS %I PARTITION OF snapshots
                                 FOR VALUES FROM (%L) TO (%L)',
                                tbl_name, start_date, end_date
                            );
                        END IF;
                    END LOOP;
                END;
                $$;
            """)
        except asyncpg.exceptions.UndefinedTableError:
            log.warning("snapshots table not found — partitions skipped.")
        except Exception as exc:
            log.warning("ensurePartitions error: %s", exc)


async def seed_users():
    """Upsert default users with pre-computed passlib/bcrypt hashes.
    Always runs ON CONFLICT DO UPDATE so hash format is never stale."""
    pool = await get_pool()
    # Hashes pre-computed with passlib bcrypt rounds=12
    # Passwords: Admin@1234 / Analyst@1234 / Exec@1234
    defaults = [
        ("admin",     "$2b$12$hzBTZK9tJ.fy93F4Q14v9OqN34xAIjxBVpcRQsPCbNvi1BYGGLTOG", "admin",     "Administrator"),
        ("analyst",   "$2b$12$Dnhj4GsnW7FlR2WVbZFQEesMAATnH8ju5ERQTK1IAnGlsyuxv2dGK", "analyst",   "Security Analyst"),
        ("executive", "$2b$12$WSTZ7yuCuCtawP/JqhyO/uOecCmqfll3UBSRIocdu5esza95EK1Wm", "executive", "Executive"),
    ]
    async with pool.acquire() as conn:
        for username, pw_hash, role, display_name in defaults:
            await conn.execute("""
                INSERT INTO users (id, username, password_hash, role, display_name)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (username) DO UPDATE
                SET password_hash=$3, role=$4, display_name=$5
            """, uuid.uuid4(), username, pw_hash, role, display_name)
    log.info("Default users seeded/refreshed (admin / analyst / executive)")


async def getCreds(tool: str) -> dict | None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT credentials FROM integrations WHERE tool_name=$1 AND enabled=true",
            tool,
        )
    if row is None:
        return None
    creds = dict(row["credentials"])
    if not creds:
        return None
    return creds


async def saveSnapshot(tool: str, data: dict):
    await ensure_partitions()
    pool = await get_pool()
    import json as _json
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO snapshots (tool, collected_at, payload)
            VALUES ($1, NOW(), $2::jsonb)
            """,
            tool,
            _json.dumps(data),
        )


async def setStatus(tool: str, status_val: str, error: str = None):
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE integrations
            SET status=$2, last_tested=NOW(), last_error=$3, updated_at=NOW()
            WHERE tool_name=$1
            """,
            tool, status_val, error,
        )


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------
def create_jwt(payload: dict) -> str:
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_jwt(token: str) -> dict:
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])


async def get_current_user(session: str | None = Cookie(default=None, alias=COOKIE_NAME)):
    if not session:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = decode_jwt(session)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid session token")
    return payload


async def require_admin(user: dict = Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


def _safe_credentials(creds: dict) -> dict:
    """Return credentials with sensitive fields redacted."""
    sensitive = {"password", "secret", "key", "token", "client_secret", "secretkey", "api_key", "apikey"}
    return {
        k: "***" if any(s in k.lower() for s in sensitive) else v
        for k, v in creds.items()
    }


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------
class LoginRequest(BaseModel):
    username: str
    password: str


class CredentialsRequest(BaseModel):
    credentials: Dict[str, Any]


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------
@app.post("/api/auth/login")
async def login(body: LoginRequest, response: Response):
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, username, password_hash, role, display_name FROM users WHERE username=$1",
            body.username,
        )
    if not row:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not _pwd_ctx.verify(body.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Update last_login
    pool2 = await get_pool()
    async with pool2.acquire() as conn:
        await conn.execute(
            "UPDATE users SET last_login=NOW() WHERE id=$1", row["id"]
        )

    token_data = {
        "username": row["username"],
        "role": row["role"],
        "display_name": row["display_name"],
    }
    token = create_jwt(token_data)
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        path="/",
        max_age=36000,
    )
    return token_data


@app.get("/api/auth/me")
async def me(user: dict = Depends(get_current_user)):
    return {
        "username": user.get("username"),
        "role": user.get("role"),
        "display_name": user.get("display_name"),
    }


@app.post("/api/auth/logout")
async def logout(response: Response):
    response.delete_cookie(key=COOKIE_NAME, path="/")
    return {"ok": True}


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
@app.get("/api/health")
async def health():
    return {"status": "ok", "ts": datetime.now(timezone.utc).isoformat()}


# ---------------------------------------------------------------------------
# Integrations routes
# ---------------------------------------------------------------------------
@app.get("/api/integrations")
async def list_integrations(_user: dict = Depends(get_current_user)):
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT tool_name, enabled, status, last_tested, last_error, credentials FROM integrations ORDER BY tool_name"
        )
    result = []
    for row in rows:
        creds = dict(row["credentials"]) if row["credentials"] else {}
        result.append({
            "tool_name": row["tool_name"],
            "enabled": row["enabled"],
            "status": row["status"],
            "last_tested": row["last_tested"].isoformat() if row["last_tested"] else None,
            "last_error": row["last_error"],
            "safe_credentials": _safe_credentials(creds),
        })
    return result


@app.post("/api/integrations/{tool}")
async def save_integration(
    tool: str,
    body: CredentialsRequest,
    _user: dict = Depends(get_current_user),
):
    import json as _json
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO integrations (tool_name, credentials, enabled, status, updated_at)
            VALUES ($1, $2::jsonb, true, 'configured', NOW())
            ON CONFLICT (tool_name) DO UPDATE
            SET credentials=$2::jsonb, enabled=true, status='configured', updated_at=NOW()
            """,
            tool,
            _json.dumps(body.credentials),
        )
    return {"ok": True}


@app.post("/api/integrations/{tool}/test")
async def test_integration(tool: str, _user: dict = Depends(get_current_user)):
    data = await run_collector(tool)
    if data is None:
        pool = await get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT last_error FROM integrations WHERE tool_name=$1", tool
            )
        error_msg = row["last_error"] if row else "Unknown error"
        return {"success": False, "message": error_msg, "sample": None}

    sample: Any = None
    if isinstance(data, dict):
        keys = list(data.keys())
        sample = {k: data[k] for k in keys[:3]}
    return {"success": True, "message": "Collection successful", "sample": sample}


@app.delete("/api/integrations/{tool}")
async def delete_integration(tool: str, _user: dict = Depends(get_current_user)):
    import json as _json
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE integrations SET credentials='{}', status='unconfigured', updated_at=NOW() WHERE tool_name=$1",
            tool,
        )
    return {"ok": True}


# ---------------------------------------------------------------------------
# Snapshot route
# ---------------------------------------------------------------------------
@app.get("/api/snapshot")
async def get_snapshot(_user: dict = Depends(get_current_user)):
    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT DISTINCT ON (tool) tool, payload, collected_at
                FROM snapshots
                ORDER BY tool, collected_at DESC
                """
            )
    except asyncpg.exceptions.UndefinedTableError:
        return {"data": {}, "ts": datetime.now(timezone.utc).isoformat()}

    data: Dict[str, Any] = {}
    for row in rows:
        payload = dict(row["payload"])
        payload["_collected_at"] = row["collected_at"].isoformat()
        data[row["tool"]] = payload

    return {"data": data, "ts": datetime.now(timezone.utc).isoformat()}


# ---------------------------------------------------------------------------
# Collection route
# ---------------------------------------------------------------------------
@app.post("/api/collect/{tool}")
async def collect_tool(tool: str, _user: dict = Depends(get_current_user)):
    data = await run_collector(tool)
    if data is None:
        pool = await get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT last_error FROM integrations WHERE tool_name=$1", tool
            )
        error = row["last_error"] if row else "Collection failed"
        return {"ok": False, "error": error}
    return {"ok": True, "error": None}


# ---------------------------------------------------------------------------
# Debug route (admin only)
# ---------------------------------------------------------------------------
@app.get("/api/debug/snapshots")
async def debug_snapshots(_user: dict = Depends(require_admin)):
    pool = await get_pool()
    async with pool.acquire() as conn:
        try:
            counts = await conn.fetch(
                "SELECT tool, COUNT(*) as cnt FROM snapshots GROUP BY tool ORDER BY tool"
            )
            latest = await conn.fetch(
                """
                SELECT DISTINCT ON (tool) tool, collected_at
                FROM snapshots
                ORDER BY tool, collected_at DESC
                """
            )
        except asyncpg.exceptions.UndefinedTableError:
            counts, latest = [], []

        integrations = await conn.fetch(
            "SELECT tool_name, enabled, status, last_tested, last_error FROM integrations ORDER BY tool_name"
        )

    return {
        "snapshot_counts": {r["tool"]: r["cnt"] for r in counts},
        "latest_per_tool": {
            r["tool"]: r["collected_at"].isoformat() for r in latest
        },
        "integration_statuses": [
            {
                "tool_name": r["tool_name"],
                "enabled": r["enabled"],
                "status": r["status"],
                "last_tested": r["last_tested"].isoformat() if r["last_tested"] else None,
                "last_error": r["last_error"],
            }
            for r in integrations
        ],
    }


# ---------------------------------------------------------------------------
# Collector dispatcher
# ---------------------------------------------------------------------------
COLLECTOR_MAP: Dict[str, Any] = {}


async def run_collector(tool: str) -> dict | None:
    fn = COLLECTOR_MAP.get(tool)
    if fn is None:
        log.warning("No collector registered for tool: %s", tool)
        await setStatus(tool, "error", f"No collector implemented for '{tool}'")
        return None
    try:
        data = await fn()
        if data is not None:
            await saveSnapshot(tool, data)
            await setStatus(tool, "connected")
        return data
    except Exception as exc:
        log.error("Collector %s failed: %s", tool, exc, exc_info=True)
        await setStatus(tool, "error", str(exc))
        return None


# ---------------------------------------------------------------------------
# UpGuard collector
# ---------------------------------------------------------------------------
async def collect_upguard() -> dict:
    creds = await getCreds("upguard")
    api_key = creds.get("api_key") or creds.get("apikey")
    if not api_key:
        raise ValueError("UpGuard: missing api_key credential")
    base = "https://cyber-risk.upguard.com/api/public/v2"
    headers = {"Authorization": f"Bearer {api_key}"}
    result: Dict[str, Any] = {"source": "upguard"}

    async with httpx.AsyncClient(timeout=30.0) as client:
        endpoints = {
            "risks": f"{base}/risks/details",
            "breachsight": f"{base}/breachsight",
            "domains": f"{base}/domains",
            "ips": f"{base}/ips",
        }
        for key, url in endpoints.items():
            try:
                resp = await client.get(url, headers=headers)
                resp.raise_for_status()
                result[key] = resp.json()
            except httpx.HTTPStatusError as exc:
                log.warning("UpGuard %s error: %s", key, exc)
                result[key] = {"error": str(exc)}
            except Exception as exc:
                log.warning("UpGuard %s exception: %s", key, exc)
                result[key] = {"error": str(exc)}

    return result


COLLECTOR_MAP["upguard"] = collect_upguard


# ---------------------------------------------------------------------------
# Qualys collector
# ---------------------------------------------------------------------------
async def collect_qualys() -> dict:
    creds = await getCreds("qualys")
    if not creds:
        raise ValueError("Qualys: no credentials configured")
    username = creds.get("username")
    password = creds.get("password")
    api_url = (creds.get("platform_url") or creds.get("api_url") or "").rstrip("/")
    if not all([username, password, api_url]):
        raise ValueError("Qualys: requires username, password, and platform_url")

    url = (
        f"{api_url}/api/2.0/fo/asset/host/vm/detection/"
        "?action=list&show_results=1&output_format=XML&status=Active"
    )

    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.get(url, auth=(username, password))
        resp.raise_for_status()

    raw_xml = resp.text
    top_vulns = _parse_qualys_xml(raw_xml)
    return {"source": "qualys", "detections": raw_xml, "top_vulnerabilities": top_vulns}


def _parse_qualys_xml(xml_text: str) -> List[Dict[str, Any]]:
    """Extract top vulnerabilities from Qualys XML response."""
    vulns: Dict[int, Dict[str, Any]] = {}
    try:
        root = etree.fromstring(xml_text.encode())
        for detection in root.iter("DETECTION"):
            qid_el = detection.find("QID")
            severity_el = detection.find("SEVERITY")
            title_el = detection.find("RESULTS")
            if qid_el is not None:
                qid = int(qid_el.text or 0)
                severity = int(severity_el.text or 0) if severity_el is not None else 0
                if qid not in vulns:
                    vulns[qid] = {
                        "qid": qid,
                        "severity": severity,
                        "count": 0,
                        "title": (title_el.text or "")[:120] if title_el is not None else "",
                    }
                vulns[qid]["count"] += 1
    except Exception as exc:
        log.warning("Qualys XML parse error: %s", exc)

    sorted_vulns = sorted(vulns.values(), key=lambda x: (-x["severity"], -x["count"]))
    return sorted_vulns[:20]


COLLECTOR_MAP["qualys"] = collect_qualys


# ---------------------------------------------------------------------------
# Fortinet collector
# ---------------------------------------------------------------------------
async def collect_fortinet() -> dict:
    creds = await getCreds("fortinet")
    if not creds:
        raise ValueError("Fortinet: no credentials configured")

    # Normalise: support both single-instance and multi-instance
    if "instances" in creds:
        instances = creds["instances"]
    else:
        instances = [creds]

    if not instances:
        raise ValueError("Fortinet: no instances defined in credentials")

    results = []
    for inst in instances:
        host = inst.get("host", "").rstrip("/")
        username = inst.get("username")
        password = inst.get("password")
        name = inst.get("name", host)
        if not host or not username or not password:
            results.append({"name": name, "error": "Missing host/username/password"})
            continue
        data = await _collect_fortinet_instance(host, username, password, name)
        results.append(data)

    return {"source": "fortinet", "instances": results}


async def _collect_fortinet_instance(host: str, username: str, password: str, name: str) -> dict:
    base = f"https://{host}"
    result: Dict[str, Any] = {"name": name, "host": host}

    async with httpx.AsyncClient(verify=False, timeout=15.0) as client:  # noqa: S501
        # Login
        try:
            login_resp = await client.post(
                f"{base}/logincheck",
                data=f"username={username}&secretkey={password}",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            login_resp.raise_for_status()
        except Exception as exc:
            result["error"] = f"Login failed: {exc}"
            return result

        cookies = login_resp.cookies

        endpoints = {
            "policies": f"{base}/api/v2/monitor/firewall/policy/select",
            "interfaces": f"{base}/api/v2/monitor/system/interface/select?global=1",
            "topApps": f"{base}/api/v2/monitor/firewall/traffic-by-application?count=10",
            "topWeb": f"{base}/api/v2/monitor/webfilter/category/usage-statistics?count=10",
            "sysGlobal": f"{base}/api/v2/monitor/system/status",
        }

        for key, url in endpoints.items():
            try:
                resp = await client.get(url, cookies=cookies)
                resp.raise_for_status()
                result[key] = resp.json()
            except Exception as exc:
                log.warning("Fortinet %s/%s error: %s", name, key, exc)
                result[key] = {"error": str(exc)}

        # Logout
        try:
            await client.post(f"{base}/logout", cookies=cookies)
        except Exception:
            pass

    return result


COLLECTOR_MAP["fortinet"] = collect_fortinet


# ---------------------------------------------------------------------------
# Azure collector
# ---------------------------------------------------------------------------
async def collect_azure() -> dict:
    creds = await getCreds("azure")
    if not creds:
        raise ValueError("Azure: no credentials configured")

    if "instances" in creds:
        instances = creds["instances"]
    else:
        instances = [creds]

    if not instances:
        raise ValueError("Azure: no instances defined")

    results = []
    for inst in instances:
        data = await _collect_azure_instance(inst)
        results.append(data)

    return {"source": "azure", "instances": results}


async def _collect_azure_instance(inst: dict) -> dict:
    tenant_id = inst.get("tenant_id")
    client_id = inst.get("client_id")
    client_secret = inst.get("client_secret")
    subscription_id = inst.get("subscription_id")
    name = inst.get("name", tenant_id)

    result: Dict[str, Any] = {"name": name}

    if not all([tenant_id, client_id, client_secret, subscription_id]):
        result["error"] = "Missing required Azure credentials"
        return result

    async with httpx.AsyncClient(timeout=30.0) as client:
        # OAuth2 token
        try:
            token_resp = await client.post(
                f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "scope": "https://management.azure.com/.default",
                },
            )
            token_resp.raise_for_status()
            access_token = token_resp.json()["access_token"]
        except Exception as exc:
            result["error"] = f"Azure auth failed: {exc}"
            return result

        headers = {"Authorization": f"Bearer {access_token}"}
        base = f"https://management.azure.com/subscriptions/{subscription_id}"

        endpoints = {
            "alerts": f"{base}/providers/Microsoft.Security/alerts?api-version=2022-01-01",
            "secureScore": f"{base}/providers/Microsoft.Security/secureScores?api-version=2020-01-01",
            "recommendations": f"{base}/providers/Microsoft.Security/assessments?api-version=2021-06-01",
        }

        for key, url in endpoints.items():
            try:
                resp = await client.get(url, headers=headers)
                resp.raise_for_status()
                result[key] = resp.json()
            except Exception as exc:
                log.warning("Azure %s/%s error: %s", name, key, exc)
                result[key] = {"error": str(exc)}

    return result


COLLECTOR_MAP["azure"] = collect_azure


# ---------------------------------------------------------------------------
# ManageEngine collector
# ---------------------------------------------------------------------------
async def collect_manageengine() -> dict:
    creds = await getCreds("manageengine")
    if not creds:
        raise ValueError("ManageEngine: no credentials configured")

    url_base = (creds.get("server_url") or creds.get("url") or "").rstrip("/")
    api_key = creds.get("api_key")
    if not url_base or not api_key:
        raise ValueError("ManageEngine: requires url and api_key")

    result: Dict[str, Any] = {"source": "manageengine"}

    async with httpx.AsyncClient(timeout=30.0) as client:
        for key, path in [
            ("assets", f"/api/v3/computers?api_key={api_key}"),
            ("patch", f"/api/v3/patch/status?api_key={api_key}"),
        ]:
            try:
                resp = await client.get(f"{url_base}{path}")
                resp.raise_for_status()
                result[key] = resp.json()
            except Exception as exc:
                log.warning("ManageEngine %s error: %s", key, exc)
                result[key] = {"error": str(exc)}

    return result


COLLECTOR_MAP["manageengine"] = collect_manageengine


# ---------------------------------------------------------------------------
# Palo Alto collector
# ---------------------------------------------------------------------------
async def collect_paloalto() -> dict:
    creds = await getCreds("paloalto")
    if not creds:
        raise ValueError("Palo Alto: no credentials configured")

    if "instances" in creds:
        instances = creds["instances"]
    else:
        instances = [creds]

    if not instances:
        raise ValueError("Palo Alto: no instances defined")

    results = []
    for inst in instances:
        data = await _collect_paloalto_instance(inst)
        results.append(data)

    return {"source": "paloalto", "instances": results}


async def _collect_paloalto_instance(inst: dict) -> dict:
    host = inst.get("host", "").rstrip("/")
    username = inst.get("username")
    password = inst.get("password")
    name = inst.get("name", host)
    result: Dict[str, Any] = {"name": name, "host": host}

    if not host or not username or not password:
        result["error"] = "Missing host/username/password"
        return result

    base = f"https://{host}"

    async with httpx.AsyncClient(verify=False, timeout=30.0) as client:  # noqa: S501
        # 1. Generate API key
        try:
            keygen_resp = await client.get(
                f"{base}/api/?type=keygen&user={username}&password={password}"
            )
            keygen_resp.raise_for_status()
            key = _parse_pa_key(keygen_resp.text)
        except Exception as exc:
            result["error"] = f"Key generation failed: {exc}"
            return result

        if not key:
            result["error"] = "Failed to parse API key from Palo Alto response"
            return result

        # 2. Fetch security rules
        xpath = (
            "/config/devices/entry[@name='localhost.localdomain']"
            "/vsys/entry[@name='vsys1']/rulebase/security"
        )
        try:
            rules_resp = await client.get(
                f"{base}/api/?type=config&action=get&xpath={xpath}&key={key}"
            )
            rules_resp.raise_for_status()
            result["rules_xml"] = rules_resp.text
            result["rules"] = _parse_pa_rules(rules_resp.text)
        except Exception as exc:
            log.warning("Palo Alto %s rules error: %s", name, exc)
            result["rules"] = {"error": str(exc)}

    return result


def _parse_pa_key(xml_text: str) -> str | None:
    try:
        root = etree.fromstring(xml_text.encode())
        key_el = root.find(".//key")
        return key_el.text if key_el is not None else None
    except Exception:
        return None


def _parse_pa_rules(xml_text: str) -> List[Dict[str, Any]]:
    rules = []
    try:
        root = etree.fromstring(xml_text.encode())
        for entry in root.iter("entry"):
            rule: Dict[str, Any] = {"name": entry.get("name", "")}
            for child in entry:
                rule[child.tag] = child.text or ""
            rules.append(rule)
    except Exception as exc:
        log.warning("Palo Alto XML parse error: %s", exc)
    return rules


COLLECTOR_MAP["paloalto"] = collect_paloalto


# ---------------------------------------------------------------------------
# Background scheduling
# ---------------------------------------------------------------------------
async def schedule_all_integrations():
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT tool_name, refresh_interval, credentials FROM integrations WHERE enabled=true"
        )

    for row in rows:
        tool = row["tool_name"]
        interval = row["refresh_interval"] or 300
        creds = dict(row["credentials"]) if row["credentials"] else {}

        if not creds:
            log.info("Skipping scheduler for %s — no credentials", tool)
            continue

        job_id = f"collect_{tool}"
        if scheduler.get_job(job_id):
            scheduler.remove_job(job_id)

        scheduler.add_job(
            run_collector,
            "interval",
            seconds=interval,
            id=job_id,
            args=[tool],
            replace_existing=True,
        )
        log.info("Scheduled %s every %ds", tool, interval)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=4000, reload=False)
