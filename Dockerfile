# =============================================
# Stage 1: Build Go Agent (linux-amd64 & linux-arm64)
# =============================================
FROM golang:1.22-alpine AS agent-builder

WORKDIR /agent

# Install git (dibutuhkan go mod tidy)
RUN apk add --no-cache git

# Copy semua file agent
COPY agent/ .

# Generate go.sum jika belum ada, lalu download dependencies
RUN go mod tidy && go mod download

# Build binary agent untuk linux-amd64 dan linux-arm64
RUN mkdir -p dist && \
    cp install.sh dist/install.sh && \
    cp install.ps1 dist/install.ps1 && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o dist/oat-agent-linux-amd64 . && \
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o dist/oat-agent-linux-arm64 .

# =============================================
# Stage 2: Build Frontend (Vite) + Backend (esbuild)
# =============================================
FROM node:20-alpine AS builder

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .

# Build React frontend dengan Vite
RUN npx vite build

# Build Express backend dengan esbuild (semua npm package tetap external)
RUN npx esbuild server.ts \
    --bundle \
    --platform=node \
    --format=cjs \
    --packages=external \
    --outfile=dist/server.cjs

# =============================================
# Stage 3: Production Image (lean)
# =============================================
FROM node:20-alpine AS production

WORKDIR /app

# Tool tambahan untuk health check dan signal handling
RUN apk add --no-cache dumb-init curl

# Install HANYA production dependencies
COPY package*.json ./
RUN npm ci --omit=dev --ignore-scripts

# Copy hasil build frontend + backend dari stage 2
COPY --from=builder /app/dist ./dist

# Copy Go agent binaries dan installer scripts
COPY --from=agent-builder /agent/dist ./agent/dist
COPY agent/install.sh agent/install.ps1 ./agent/

EXPOSE 3000

ENV NODE_ENV=production
ENV HOST=0.0.0.0
ENV PORT=3000

# dumb-init: proper PID 1 & signal forwarding di container
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "dist/server.cjs"]
