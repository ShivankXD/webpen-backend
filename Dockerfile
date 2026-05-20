# ─────────────────────────────────────────────────────────────────
# WebPen Backend — Dockerfile
# Optimised for Render free-tier (512 MB RAM, shared CPU)
#
# Strategy:
#   1. "deps"  stage  — install production dependencies only
#   2. "runner" stage — copy only what's needed; run as non-root user
# ─────────────────────────────────────────────────────────────────

# ── Stage 1: install dependencies ─────────────────────────────────
FROM node:22-alpine AS deps

# Install build tools needed for native addons (e.g. bcrypt)
RUN apk add --no-cache libc6-compat

WORKDIR /app

# Copy manifests first for better layer caching
COPY package*.json ./

# Install production dependencies only (no devDeps like nodemon)
RUN npm ci --omit=dev


# ── Stage 2: production runner ────────────────────────────────────
FROM node:22-alpine AS runner

# Security: drop all Linux capabilities by default
RUN apk add --no-cache dumb-init

# Create a non-root user so the process can't write to the FS
RUN addgroup -S webpen && adduser -S webpen -G webpen

WORKDIR /app

# Copy only the installed modules and the source code
COPY --from=deps /app/node_modules ./node_modules
COPY server.js    ./
COPY package.json ./

# Drop to non-root user
USER webpen

# Render will set $PORT automatically; expose the default for local runs
EXPOSE 3000

# dumb-init reaps zombie processes and forwards signals correctly
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "server.js"]
