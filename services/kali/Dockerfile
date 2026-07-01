# ── Kali Linux Security Scanner — SecOps Integration ─────────────────────────
# Base: latest official Kali Rolling from Docker Hub
FROM kalilinux/kali-rolling:latest

LABEL service="secops-kali" \
      description="Kali Linux with full security toolset + SecOps scan agent API"

ENV DEBIAN_FRONTEND=noninteractive

# ── Update and install security tools ─────────────────────────────────────────
RUN apt-get update -q && apt-get install -y --no-install-recommends \
    # Core recon & scanning
    nmap masscan \
    # Web scanning
    nikto gobuster dirb wfuzz ffuf whatweb \
    # Vulnerability assessment
    sqlmap sslscan sslyze \
    # Enumeration
    enum4linux netcat-openbsd dnsutils \
    # Password / brute force
    hydra john hashcat \
    # Wordlists
    wordlists \
    # DNS recon
    dnsenum dnsrecon \
    # SSL/TLS testing
    openssl \
    # Network utils
    curl wget net-tools iputils-ping \
    # Python for scan agent
    python3 python3-pip python3-flask \
    # Cleanup
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Unzip rockyou wordlist if compressed
RUN test -f /usr/share/wordlists/rockyou.txt.gz \
    && gunzip /usr/share/wordlists/rockyou.txt.gz || true

# ── Install Python agent dependencies ─────────────────────────────────────────
COPY requirements.txt /app/requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages -r /app/requirements.txt

# ── Copy scan agent ────────────────────────────────────────────────────────────
COPY agent.py /app/agent.py

WORKDIR /app

# Agent runs as root inside container (needed for nmap raw sockets / masscan)
# The container itself is isolated via Docker

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD curl -sf http://localhost:5000/health || exit 1

CMD ["python3", "-u", "agent.py"]
