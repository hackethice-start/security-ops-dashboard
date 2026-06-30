FROM node:20-alpine AS builder

WORKDIR /app

ARG REACT_APP_FORTINET_HOST=""
ARG REACT_APP_FORTINET_APIKEY=""
ARG REACT_APP_PALOALTO_HOST=""
ARG REACT_APP_PALOALTO_APIKEY=""
ARG REACT_APP_UPGUARD_APIKEY=""
ARG REACT_APP_AZURE_TENANT_ID=""
ARG REACT_APP_AZURE_CLIENT_ID=""
ARG REACT_APP_AZURE_CLIENT_SECRET=""
ARG REACT_APP_AZURE_SUBSCRIPTION_ID=""
ARG REACT_APP_QUALYS_USERNAME=""
ARG REACT_APP_QUALYS_PASSWORD=""
ARG REACT_APP_ME_HOST=""
ARG REACT_APP_ME_APIKEY=""
ARG REACT_APP_API_BASE_URL=""

ENV REACT_APP_FORTINET_HOST=$REACT_APP_FORTINET_HOST \
    REACT_APP_FORTINET_APIKEY=$REACT_APP_FORTINET_APIKEY \
    REACT_APP_PALOALTO_HOST=$REACT_APP_PALOALTO_HOST \
    REACT_APP_PALOALTO_APIKEY=$REACT_APP_PALOALTO_APIKEY \
    REACT_APP_UPGUARD_APIKEY=$REACT_APP_UPGUARD_APIKEY \
    REACT_APP_AZURE_TENANT_ID=$REACT_APP_AZURE_TENANT_ID \
    REACT_APP_AZURE_CLIENT_ID=$REACT_APP_AZURE_CLIENT_ID \
    REACT_APP_AZURE_CLIENT_SECRET=$REACT_APP_AZURE_CLIENT_SECRET \
    REACT_APP_AZURE_SUBSCRIPTION_ID=$REACT_APP_AZURE_SUBSCRIPTION_ID \
    REACT_APP_QUALYS_USERNAME=$REACT_APP_QUALYS_USERNAME \
    REACT_APP_QUALYS_PASSWORD=$REACT_APP_QUALYS_PASSWORD \
    REACT_APP_ME_HOST=$REACT_APP_ME_HOST \
    REACT_APP_ME_APIKEY=$REACT_APP_ME_APIKEY \
    REACT_APP_API_BASE_URL=$REACT_APP_API_BASE_URL \
    CI=false \
    DISABLE_ESLINT_PLUGIN=true \
    GENERATE_SOURCEMAP=false \
    NODE_OPTIONS=--max-old-space-size=4096

COPY package.json ./
RUN npm install --legacy-peer-deps

COPY . .
RUN npm run build

FROM nginx:1.27-alpine AS production

RUN rm -rf /usr/share/nginx/html/*

COPY --from=builder /app/build /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

RUN addgroup -S appgroup && adduser -S appuser -G appgroup \
    && chown -R appuser:appgroup /usr/share/nginx/html \
    && chown -R appuser:appgroup /var/cache/nginx \
    && chown -R appuser:appgroup /var/log/nginx \
    && touch /var/run/nginx.pid \
    && chown appuser:appgroup /var/run/nginx.pid

USER appuser
EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://localhost:80/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
