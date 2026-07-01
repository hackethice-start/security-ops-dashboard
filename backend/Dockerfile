FROM node:22-alpine
WORKDIR /app
COPY package.json ./
RUN npm install --production
COPY . .
EXPOSE 4000
HEALTHCHECK --interval=30s --timeout=5s --retries=5 \
  CMD wget -qO- http://localhost:4000/api/health || exit 1
CMD ["node", "server.js"]
