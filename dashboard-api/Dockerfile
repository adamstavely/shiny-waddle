# Build stage
FROM node:18-alpine AS builder

WORKDIR /app

# Copy package files
COPY package.json package-lock.json* ./
COPY dashboard-api/package.json ./dashboard-api/
COPY heimdall-framework/package.json ./heimdall-framework/ 2>/dev/null || true

# Install root dependencies (if any)
RUN npm ci --ignore-scripts || true

# Install API dependencies
WORKDIR /app/dashboard-api
RUN npm ci

# Copy source code
WORKDIR /app
COPY dashboard-api/ ./dashboard-api/
COPY heimdall-framework/ ./heimdall-framework/

# Build the API
WORKDIR /app/dashboard-api
RUN npm run build

# Production stage
FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY dashboard-api/package.json ./
COPY dashboard-api/package-lock.json* ./

# Install production dependencies only
RUN npm ci --only=production && npm cache clean --force

# Copy built application
COPY --from=builder /app/dashboard-api/dist ./dist

# Create data directory
RUN mkdir -p /app/data && chown -R node:node /app/data

# Switch to non-root user
USER node

EXPOSE 3001

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3001/', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"

CMD ["node", "dist/main"]
