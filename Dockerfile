# =============================================
# Stage 1: Build Go Agent (linux-amd64)
# =============================================
FROM golang:1.22-alpine AS agent-builder

WORKDIR /agent

COPY agent/go.mod agent/go.sum ./
RUN go mod download

COPY agent/ .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o dist/oat-agent-linux-amd64 .

# =============================================
# Stage 2: Build Frontend (Vite) & Backend (esbuild)
# =============================================
FROM node:20-alpine AS builder

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .

# Build frontend dengan Vite
RUN npx vite build

# Build backend dengan esbuild (packages tetap external → disupply oleh npm ci --omit=dev)
RUN npx esbuild server.ts \
    --bundle \
    --platform=node \
    --format=cjs \
    --packages=external \
    --outfile=dist/server.cjs

# =============================================
# Stage 3: Production Image
# =============================================
FROM node:20-alpine AS production

WORKDIR /app

# Tambah tools penting
RUN apk add --no-cache dumb-init curl

# Install hanya production dependencies
COPY package*.json ./
RUN npm ci --omit=dev --ignore-scripts

# Copy hasil build frontend + backend
COPY --from=builder /app/dist ./dist

# Copy Go agent binary
COPY --from=agent-builder /agent/dist ./agent/dist

# Expose port aplikasi
EXPOSE 3000

ENV NODE_ENV=production
ENV HOST=0.0.0.0
ENV PORT=3000

# dumb-init untuk proper signal handling di container
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "dist/server.cjs"]

