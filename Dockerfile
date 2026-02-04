# Drista Web App
# Post-quantum secure chat - self-hosted version
#
# Build:  docker build -t drista .
# Run:    docker run -p 3000:3000 drista
# Access: http://localhost:3000

FROM node:20-alpine AS builder
WORKDIR /app

# Install dependencies
COPY web/package*.json ./
RUN npm ci

# Build web app
COPY web/ ./
RUN npm run build

# Production image
FROM node:20-alpine
WORKDIR /app

# Copy built assets and bridge
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/bridge ./bridge
COPY --from=builder /app/package*.json ./

# Install production deps only (for bridge)
RUN npm ci --omit=dev

# Expose port
EXPOSE 3000

# Simple static server + bridge
RUN npm install -g serve

# Start script
COPY <<'EOF' /app/start.sh
#!/bin/sh
# Start bridge in background (connects to Nostr relays)
node bridge/index.js &

# Serve static files
serve -s dist -l 3000
EOF
RUN chmod +x /app/start.sh

CMD ["/app/start.sh"]
