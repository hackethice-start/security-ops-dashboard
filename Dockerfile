FROM node:22-alpine AS builder
WORKDIR /app

ENV CI=false
ENV DISABLE_ESLINT_PLUGIN=true
ENV GENERATE_SOURCEMAP=false

COPY package.json ./
RUN npm install --legacy-peer-deps

COPY . .
RUN npm run build

FROM nginx:1.27-alpine AS production
RUN rm -rf /usr/share/nginx/html/*
COPY --from=builder /app/build /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD wget -qO- http://localhost:80/ || exit 1
CMD ["nginx", "-g", "daemon off;"]
