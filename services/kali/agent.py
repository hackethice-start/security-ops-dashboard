#!/usr/bin/env python3
"""
Kali Linux Scan Agent — SecOps Integration
Port 5000  |  REST API for orchestrated security scanning

Endpoints:
  GET  /health          → service health + tool inventory
  GET  /api/tools       → list installed tools with versions
  POST /api/scan        → run a scan (tool, target, options)
  POST /api/scan/nmap   → nmap shortcut
  POST /api/scan/nikto  → nikto shortcut
  POST /api/scan/gobuster → gobuster shortcut
  POST /api/scan/sqlmap → sqlmap shortcut
  POST /api/scan/sslscan → sslscan shortcut
  POST /api/scan/masscan → masscan shortcut
  POST /api/scan/whatweb → whatweb shortcut
  POST /api/scan/custom → run arbitrary whitelisted command
"""

import os
import subprocess
import shlex
import json
import re
import time
import threading
from flask import Flask, request, jsonify, Response
from flask_cors import CORS

app = Flask(__name__)
CORS(app, supports_credentials=True)

AGENT_TOKEN = os.environ.get("AGENT_TOKEN", "secops-kali-agent-token-change-me")
MAX_RUNTIME  = int(os.environ.get("MAX_SCAN_SECONDS", "600"))   # 10 min max per scan

# ── Tool definitions ───────────────────────────────────────────────────────────
TOOLS = {
    "nmap": {
        "bin":    "nmap",
        "desc":   "Network exploration and security auditing",
        "profiles": {
            "quick":    "-sV -T4 --top-ports 100",
            "standard": "-sV -sC -T4 --top-ports 1000",
            "deep":     "-sV -sC -O -A --script vuln -T4",
            "udp":      "-sU -T4 --top-ports 50",
            "full":     "-sV -sC -p- -T4",
        },
    },
    "masscan": {
        "bin":    "masscan",
        "desc":   "Massively fast port scanner",
        "profiles": {
            "quick":    "--rate 1000 --top-ports 100",
            "standard": "--rate 5000 --top-ports 1000",
            "deep":     "--rate 10000 -p0-65535",
        },
    },
    "nikto": {
        "bin":    "nikto",
        "desc":   "Web server vulnerability scanner",
        "profiles": {
            "quick":    "-Tuning 1 -maxtime 60",
            "standard": "-Tuning 1,2,3,5 -maxtime 300",
            "deep":     "-Tuning 1,2,3,4,5,6,7,8,9 -maxtime 600",
        },
    },
    "gobuster": {
        "bin":    "gobuster",
        "desc":   "Directory/file brute-forcer",
        "profiles": {
            "quick":    "dir -w /usr/share/wordlists/dirb/common.txt -q -t 20",
            "standard": "dir -w /usr/share/wordlists/dirb/big.txt -q -t 30",
            "deep":     "dir -w /usr/share/wordlists/dirb/big.txt -q -t 50 -x php,asp,aspx,html,txt",
        },
    },
    "sqlmap": {
        "bin":    "sqlmap",
        "desc":   "SQL injection scanner",
        "profiles": {
            "quick":    "--level=1 --risk=1 --batch --forms",
            "standard": "--level=3 --risk=2 --batch --forms --crawl=2",
            "deep":     "--level=5 --risk=3 --batch --forms --crawl=5 --dbs",
        },
    },
    "sslscan": {
        "bin":    "sslscan",
        "desc":   "SSL/TLS configuration scanner",
        "profiles": {
            "quick":    "",
            "standard": "--show-certificate",
            "deep":     "--show-certificate --show-ciphers",
        },
    },
    "sslyze": {
        "bin":    "sslyze",
        "desc":   "Fast SSL/TLS scanner",
        "profiles": {
            "quick":    "--regular",
            "standard": "--regular --certinfo",
            "deep":     "--regular --certinfo --early_data",
        },
    },
    "whatweb": {
        "bin":    "whatweb",
        "desc":   "Web application fingerprinter",
        "profiles": {
            "quick":    "-a 1",
            "standard": "-a 3",
            "deep":     "-a 4 --log-verbose=/dev/stdout",
        },
    },
    "dnsenum": {
        "bin":    "dnsenum",
        "desc":   "DNS enumeration tool",
        "profiles": {
            "quick":    "--noreverse --nocolor",
            "standard": "--nocolor",
            "deep":     "--nocolor --enum",
        },
    },
    "enum4linux": {
        "bin":    "enum4linux",
        "desc":   "Windows/Samba enumeration",
        "profiles": {
            "quick":    "-a",
            "standard": "-a",
            "deep":     "-a -v",
        },
    },
    "hydra": {
        "bin":    "hydra",
        "desc":   "Network login brute-forcer (use responsibly)",
        "profiles": {
            "quick":    "-t 4",
            "standard": "-t 8",
            "deep":     "-t 16",
        },
    },
}


def check_tool(name):
    """Return tool version string or None if not installed."""
    try:
        r = subprocess.run(
            [TOOLS[name]["bin"], "--version"],
            capture_output=True, text=True, timeout=5
        )
        output = (r.stdout or r.stderr or "").strip().split("\n")[0]
        return output[:120] if output else "installed"
    except Exception:
        try:
            r = subprocess.run(
                ["which", TOOLS[name]["bin"]],
                capture_output=True, text=True, timeout=3
            )
            return "installed" if r.returncode == 0 else None
        except Exception:
            return None


def auth_required(f):
    """Decorator: check AGENT_TOKEN in Authorization header."""
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if token != AGENT_TOKEN:
            return jsonify({"error": "Unauthorized — invalid agent token"}), 401
        return f(*args, **kwargs)
    return decorated


def run_scan_cmd(cmd, timeout=MAX_RUNTIME):
    """Run a shell command and return stdout+stderr, truncated to 50KB."""
    try:
        result = subprocess.run(
            cmd, shell=True,
            capture_output=True, text=True,
            timeout=timeout
        )
        output = result.stdout + ("\n" + result.stderr if result.stderr else "")
        return output[:50000], result.returncode
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] Scan exceeded {timeout}s time limit.", 124
    except Exception as e:
        return f"[ERROR] {str(e)}", 1


def parse_nmap_output(raw):
    """Parse nmap text output into structured JSON."""
    ports = []
    port_rx = re.compile(r'^(\d+)/(tcp|udp)\s+(\w+)\s+(.*)$', re.MULTILINE)
    for m in port_rx.finditer(raw):
        ports.append({
            "port":     int(m.group(1)),
            "protocol": m.group(2),
            "state":    m.group(3),
            "service":  m.group(4).strip(),
        })
    os_match = re.search(r'OS details: (.+)', raw)
    host_match = re.search(r'Nmap scan report for (.+)', raw)
    return {
        "ports": ports,
        "os":    os_match.group(1) if os_match else None,
        "host":  host_match.group(1) if host_match else None,
        "open_count": len([p for p in ports if p["state"] == "open"]),
    }


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    """Health check + quick tool inventory."""
    available = {}
    for name in TOOLS:
        v = check_tool(name)
        available[name] = {"installed": v is not None, "version": v}
    return jsonify({
        "ok":      True,
        "service": "kali-scan-agent",
        "tools":   available,
    })


@app.route("/api/tools")
@auth_required
def list_tools():
    """Full tool inventory with versions and profiles."""
    result = {}
    for name, info in TOOLS.items():
        v = check_tool(name)
        result[name] = {
            "installed": v is not None,
            "version":   v,
            "description": info["desc"],
            "profiles":  list(info["profiles"].keys()),
        }
    return jsonify(result)


@app.route("/api/scan", methods=["POST"])
@auth_required
def generic_scan():
    """
    Generic scan endpoint.
    Body: { tool, target, profile, extra_flags, timeout }
    """
    data    = request.get_json() or {}
    tool    = data.get("tool", "nmap")
    target  = data.get("target", "")
    profile = data.get("profile", "standard")
    extra   = data.get("extra_flags", "")
    timeout = min(int(data.get("timeout", MAX_RUNTIME)), MAX_RUNTIME)

    if not target:
        return jsonify({"error": "target is required"}), 400
    if tool not in TOOLS:
        return jsonify({"error": f"Unknown tool: {tool}. Available: {list(TOOLS.keys())}"}), 400

    info  = TOOLS[tool]
    flags = info["profiles"].get(profile, info["profiles"].get("standard", ""))
    cmd   = f"{info['bin']} {flags} {extra} {shlex.quote(target)} 2>&1"

    start = time.time()
    raw, code = run_scan_cmd(cmd, timeout)
    elapsed = round(time.time() - start, 1)

    structured = None
    if tool == "nmap":
        structured = parse_nmap_output(raw)

    return jsonify({
        "tool":       tool,
        "target":     target,
        "profile":    profile,
        "command":    cmd,
        "exit_code":  code,
        "elapsed_s":  elapsed,
        "success":    code == 0,
        "output":     raw,
        "structured": structured,
    })


# ── Tool-specific shortcut routes ──────────────────────────────────────────────

@app.route("/api/scan/nmap", methods=["POST"])
@auth_required
def scan_nmap():
    data    = request.get_json() or {}
    target  = data.get("target", "")
    profile = data.get("profile", "standard")
    if not target: return jsonify({"error": "target required"}), 400

    flags = TOOLS["nmap"]["profiles"].get(profile, TOOLS["nmap"]["profiles"]["standard"])
    cmd   = f"nmap {flags} {shlex.quote(target)} 2>&1"
    raw, code = run_scan_cmd(cmd)
    parsed = parse_nmap_output(raw)
    return jsonify({"tool":"nmap","target":target,"profile":profile,
                    "success":code==0,"output":raw,"structured":parsed})


@app.route("/api/scan/nikto", methods=["POST"])
@auth_required
def scan_nikto():
    data    = request.get_json() or {}
    target  = data.get("target", "")
    profile = data.get("profile", "standard")
    if not target: return jsonify({"error": "target required"}), 400
    # Ensure target has scheme for nikto
    if not target.startswith("http"): target = f"http://{target}"
    flags = TOOLS["nikto"]["profiles"].get(profile, "")
    raw, code = run_scan_cmd(f"nikto -h {shlex.quote(target)} {flags} 2>&1")

    # Parse nikto findings
    findings = []
    for line in raw.splitlines():
        if line.startswith("+ "): findings.append(line[2:].strip())
    return jsonify({"tool":"nikto","target":target,"profile":profile,
                    "success":code==0,"output":raw,"findings":findings})


@app.route("/api/scan/gobuster", methods=["POST"])
@auth_required
def scan_gobuster():
    data    = request.get_json() or {}
    target  = data.get("target", "")
    profile = data.get("profile", "standard")
    wordlist = data.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
    if not target: return jsonify({"error": "target required"}), 400
    if not target.startswith("http"): target = f"http://{target}"
    flags = TOOLS["gobuster"]["profiles"].get(profile, "")
    raw, code = run_scan_cmd(f"gobuster dir -u {shlex.quote(target)} {flags} 2>&1")

    found = [l.strip() for l in raw.splitlines() if l.startswith("/") or "(Status:" in l]
    return jsonify({"tool":"gobuster","target":target,"profile":profile,
                    "success":code==0,"output":raw,"found_paths":found})


@app.route("/api/scan/sslscan", methods=["POST"])
@auth_required
def scan_sslscan():
    data    = request.get_json() or {}
    target  = data.get("target", "")
    profile = data.get("profile", "standard")
    if not target: return jsonify({"error": "target required"}), 400
    flags = TOOLS["sslscan"]["profiles"].get(profile, "")
    raw, code = run_scan_cmd(f"sslscan {flags} {shlex.quote(target)} 2>&1")

    # Parse SSL issues
    issues = []
    for kw in ["VULNERABLE", "deprecated", "weak", "insecure", "SSLv", "TLSv1.0", "TLSv1.1", "RC4", "DES", "NULL"]:
        for line in raw.splitlines():
            if kw.lower() in line.lower() and line.strip():
                issues.append(line.strip())
    return jsonify({"tool":"sslscan","target":target,"profile":profile,
                    "success":code==0,"output":raw,"issues":list(set(issues))})


@app.route("/api/scan/whatweb", methods=["POST"])
@auth_required
def scan_whatweb():
    data    = request.get_json() or {}
    target  = data.get("target", "")
    profile = data.get("profile", "standard")
    if not target: return jsonify({"error": "target required"}), 400
    flags = TOOLS["whatweb"]["profiles"].get(profile, "")
    raw, code = run_scan_cmd(f"whatweb {flags} {shlex.quote(target)} 2>&1")
    return jsonify({"tool":"whatweb","target":target,"profile":profile,
                    "success":code==0,"output":raw})


@app.route("/api/scan/sqlmap", methods=["POST"])
@auth_required
def scan_sqlmap():
    data    = request.get_json() or {}
    target  = data.get("target", "")
    profile = data.get("profile", "standard")
    if not target: return jsonify({"error": "target required"}), 400
    if not target.startswith("http"): target = f"http://{target}"
    flags = TOOLS["sqlmap"]["profiles"].get(profile, "")
    raw, code = run_scan_cmd(f"sqlmap -u {shlex.quote(target)} {flags} 2>&1", timeout=300)

    vulnerable = "sqlmap identified the following injection point" in raw.lower()
    return jsonify({"tool":"sqlmap","target":target,"profile":profile,
                    "success":code==0,"vulnerable":vulnerable,"output":raw})


@app.route("/api/scan/masscan", methods=["POST"])
@auth_required
def scan_masscan():
    data    = request.get_json() or {}
    target  = data.get("target", "")
    profile = data.get("profile", "quick")
    if not target: return jsonify({"error": "target required"}), 400
    flags = TOOLS["masscan"]["profiles"].get(profile, "--rate 1000 --top-ports 100")
    raw, code = run_scan_cmd(f"masscan {flags} {shlex.quote(target)} 2>&1", timeout=120)

    ports = []
    for m in re.finditer(r'Discovered open port (\d+)/(\w+) on (.+)', raw):
        ports.append({"port": int(m.group(1)), "protocol": m.group(2), "host": m.group(3).strip()})
    return jsonify({"tool":"masscan","target":target,"profile":profile,
                    "success":code==0,"output":raw,"open_ports":ports})


@app.route("/api/scan/dnsenum", methods=["POST"])
@auth_required
def scan_dnsenum():
    data   = request.get_json() or {}
    target = data.get("target", "")
    if not target: return jsonify({"error": "target required"}), 400
    # Strip http(s):// for DNS tools
    target = re.sub(r'^https?://', '', target).split('/')[0]
    raw, code = run_scan_cmd(f"dnsenum --nocolor {shlex.quote(target)} 2>&1", timeout=120)
    return jsonify({"tool":"dnsenum","target":target,"success":code==0,"output":raw})


@app.route("/api/scan/custom", methods=["POST"])
@auth_required
def scan_custom():
    """
    Run a custom command — only whitelisted tool binaries allowed.
    Body: { command: "nmap -sV 192.168.1.1" }
    """
    data = request.get_json() or {}
    command = data.get("command", "").strip()
    if not command:
        return jsonify({"error": "command is required"}), 400

    # Safety: only allow whitelisted binaries as the first word
    allowed_bins = set(info["bin"] for info in TOOLS.values())
    first_word = command.split()[0]
    if first_word not in allowed_bins:
        return jsonify({"error": f"Binary '{first_word}' not in allowed list: {sorted(allowed_bins)}"}), 400

    # Block dangerous flags
    dangerous = ["--script=", "exec", "$(", "`", ";", "&&", "||", ">", "<", "|"]
    for d in dangerous:
        if d in command and d not in ["--script="]:  # nmap scripts are OK
            return jsonify({"error": f"Forbidden pattern in command: {d}"}), 400

    raw, code = run_scan_cmd(command + " 2>&1")
    return jsonify({"tool": first_word, "command": command,
                    "success": code == 0, "output": raw})


if __name__ == "__main__":
    port = int(os.environ.get("AGENT_PORT", 5000))
    print(f"[*] Kali Scan Agent starting on port {port}")
    print(f"[*] Max scan runtime: {MAX_RUNTIME}s")

    # Print tool inventory at startup
    print("[*] Checking installed tools...")
    for name in TOOLS:
        v = check_tool(name)
        status = f"✓ {v}" if v else "✗ not found"
        print(f"    {name:15} {status}")

    app.run(host="0.0.0.0", port=port, threaded=True)
