#!/usr/bin/env bash
# Run ONCE on the server to fix Docker DNS — lets containers resolve external hostnames.
set -e

DAEMON_JSON=/etc/docker/daemon.json

if command -v jq &>/dev/null && [ -f "$DAEMON_JSON" ]; then
  TMP=$(mktemp)
  jq '. + {"dns": ["8.8.8.8", "8.8.4.4", "1.1.1.1"]}' "$DAEMON_JSON" > "$TMP"
  sudo cp "$TMP" "$DAEMON_JSON"
else
  sudo bash -c 'echo "{\"dns\":[\"8.8.8.8\",\"8.8.4.4\",\"1.1.1.1\"]}" > /etc/docker/daemon.json'
fi

echo "daemon.json updated:"
cat "$DAEMON_JSON"
echo ""
echo "Restarting Docker daemon..."
sudo systemctl restart docker
echo "Done. Re-run: docker compose up -d"
