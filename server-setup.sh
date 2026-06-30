#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Security Ops Dashboard – Ubuntu Server Bootstrap
# Run once as root on your Ubuntu 22.04/24.04 server:
#   curl -sL https://raw.githubusercontent.com/<org>/<repo>/main/server-setup.sh | sudo bash
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

DEPLOY_USER="deploy"
DEPLOY_PATH="/opt/secops"
GITHUB_REPO="your-org/security-ops-dashboard"   # ← change this

echo "════════════════════════════════════════"
echo " Security Ops Dashboard – Server Setup"
echo "════════════════════════════════════════"

# ── 1. System updates ─────────────────────────────────────────────────────────
echo "[1/7] Updating system packages..."
apt-get update -qq && apt-get upgrade -y -qq

# ── 2. Install Docker ─────────────────────────────────────────────────────────
echo "[2/7] Installing Docker..."
if ! command -v docker &>/dev/null; then
  curl -fsSL https://get.docker.com | sh
  systemctl enable docker
  systemctl start docker
else
  echo "  Docker already installed: $(docker --version)"
fi

# ── 3. Create deploy user ─────────────────────────────────────────────────────
echo "[3/7] Creating deploy user '$DEPLOY_USER'..."
if ! id "$DEPLOY_USER" &>/dev/null; then
  useradd -m -s /bin/bash "$DEPLOY_USER"
fi
usermod -aG docker "$DEPLOY_USER"

# Set up SSH authorized_keys (GitHub Actions will use this)
DEPLOY_HOME=$(getent passwd "$DEPLOY_USER" | cut -d: -f6)
mkdir -p "$DEPLOY_HOME/.ssh"
chmod 700 "$DEPLOY_HOME/.ssh"
touch "$DEPLOY_HOME/.ssh/authorized_keys"
chmod 600 "$DEPLOY_HOME/.ssh/authorized_keys"
chown -R "$DEPLOY_USER:$DEPLOY_USER" "$DEPLOY_HOME/.ssh"

echo ""
echo "  ⚠️  Add the GitHub Actions public key to:"
echo "  $DEPLOY_HOME/.ssh/authorized_keys"
echo "  (Generate with: ssh-keygen -t ed25519 -C 'github-actions-deploy')"
echo ""

# ── 4. Create deploy directory ────────────────────────────────────────────────
echo "[4/7] Creating deploy directory $DEPLOY_PATH..."
mkdir -p "$DEPLOY_PATH/db"
chown -R "$DEPLOY_USER:$DEPLOY_USER" "$DEPLOY_PATH"
chmod 750 "$DEPLOY_PATH"

# ── 5. UFW Firewall rules ─────────────────────────────────────────────────────
echo "[5/7] Configuring UFW firewall..."
apt-get install -y -qq ufw
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 3000/tcp comment "secops-dashboard"
ufw allow 4000/tcp comment "secops-backend-api"
# Restrict 5432 to localhost only (postgres not exposed publicly)
ufw deny 5432/tcp
ufw --force enable
ufw status verbose

# ── 6. Install fail2ban ───────────────────────────────────────────────────────
echo "[6/7] Installing fail2ban..."
apt-get install -y -qq fail2ban
systemctl enable fail2ban
systemctl start fail2ban

# ── 7. Docker log rotation ────────────────────────────────────────────────────
echo "[7/7] Configuring Docker daemon..."
cat > /etc/docker/daemon.json << 'JSON'
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "live-restore": true
}
JSON
systemctl reload docker || systemctl restart docker

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════"
echo " ✅ Server setup complete!"
echo "════════════════════════════════════════"
echo ""
echo " Next steps:"
echo " 1. Generate an SSH key pair for GitHub Actions:"
echo "    ssh-keygen -t ed25519 -C 'github-actions' -f ~/.ssh/github_actions_deploy"
echo ""
echo " 2. Add the PUBLIC key to the server:"
echo "    cat ~/.ssh/github_actions_deploy.pub >> $DEPLOY_HOME/.ssh/authorized_keys"
echo ""
echo " 3. Add these GitHub Secrets (Settings → Secrets → Actions):"
echo "    SERVER_HOST        → $(curl -s ifconfig.me 2>/dev/null || echo '<your-server-ip>')"
echo "    SERVER_USER        → $DEPLOY_USER"
echo "    SERVER_SSH_KEY     → (paste contents of ~/.ssh/github_actions_deploy)"
echo "    SERVER_PORT        → 22"
echo "    SERVER_DEPLOY_PATH → $DEPLOY_PATH"
echo "    POSTGRES_PASSWORD  → $(openssl rand -base64 24)"
echo "    ... (all other tool API secrets)"
echo ""
echo " 4. Push to main branch → GitHub Actions will deploy automatically"
echo ""
