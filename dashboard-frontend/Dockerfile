# Build stage
FROM node:18-alpine AS builder

WORKDIR /app

# Copy package files
COPY dashboard-frontend/package.json dashboard-frontend/package-lock.json* ./

# Install dependencies
RUN npm ci

# Copy source code
COPY dashboard-frontend/ ./

# Build the application
RUN npm run build

# Production stage
FROM nginx:alpine

# Copy built files
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy nginx configuration
COPY dashboard-frontend/nginx.conf /etc/nginx/conf.d/default.conf 2>/dev/null || \
  echo 'server { listen 80; root /usr/share/nginx/html; index index.html; location / { try_files $uri $uri/ /index.html; } location /api { proxy_pass http://heimdall-api:3001; proxy_set_header Host $host; proxy_set_header X-Real-IP $remote_addr; } }' > /etc/nginx/conf.d/default.conf

EXPOSE 80

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://localhost/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
