# ── GRC Compliance Microservice ──────────────────────────────────────────────
FROM node:22-alpine

LABEL service="secops-grc" \
      description="GRC Compliance Service — DPDPA, PCI DSS 4.0.1, ISO 27001:2022"

WORKDIR /app

# Install dependencies
COPY package.json ./
RUN npm install --omit=dev

# Copy source
COPY server.js ./

# Non-root user
RUN addgroup -S grc && adduser -S grc -G grc
USER grc

EXPOSE 4001

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
  CMD wget -qO- http://localhost:4001/health || exit 1

CMD ["node", "server.js"]
