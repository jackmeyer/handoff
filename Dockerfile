FROM node:24-alpine

# zip: folder -> archive. su-exec: drop to PUID/PGID like every other Unraid app.
RUN apk add --no-cache zip su-exec tzdata

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund
COPY src ./src
COPY public ./public
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENV NODE_ENV=production \
    DATA_DIR=/data \
    LIBRARY_DIR=/library \
    PORT=8080

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD wget -qO- "http://127.0.0.1:${PORT}/healthz" >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
