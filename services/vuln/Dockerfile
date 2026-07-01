# ── Vulnerability Assessment Microservice ────────────────────────────────────
FROM node:22-alpine

LABEL service="secops-vuln-assessment" \
      description="Vuln Assessment Service — Nmap, ZAProxy, Nessus, Qualys, Kali, Claude AI"

WORKDIR /app

# Install nmap + ssh client for direct scanning and Kali SSH
RUN apk add --no-cache nmap nmap-scripts openssh-client wkhtmltopdf \
    && apk add --no-cache --virtual .build-deps python3 make g++ \
    && apk del .build-deps || true

# Install Node dependencies
COPY package.json ./
RUN npm install --omit=dev

# Copy source
COPY server.js ./

# Non-root user
RUN addgroup -S vuln && adduser -S vuln -G vuln
USER vuln

EXPOSE 4002

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
  CMD wget -qO- http://localhost:4002/health || exit 1

CMD ["node", "server.js"]
