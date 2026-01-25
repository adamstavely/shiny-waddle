# Heimdall Helm Chart

This Helm chart deploys the Heimdall application, which includes:
- **API Backend** (NestJS) - The dashboard API server
- **Frontend** (Vue.js) - The web UI
- **Framework** - The core testing framework (bundled with the API)

## Prerequisites

- Kubernetes 1.19+
- Helm 3.0+
- PersistentVolume support (for API data storage)

## Installation

### Quick Start

```bash
# Add your Helm repository (if using a chart repository)
helm repo add heimdall https://your-chart-repo.com
helm repo update

# Install with default values
helm install heimdall heimdall/heimdall

# Or install from local chart directory
helm install heimdall ./helm/heimdall
```

### Custom Installation

```bash
# Install with custom values file
helm install heimdall ./helm/heimdall -f my-values.yaml

# Install with custom values
helm install heimdall ./helm/heimdall \
  --set api.replicaCount=3 \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=heimdall.example.com
```

## Configuration

The following table lists the configurable parameters and their default values:

### Global Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `global.imageRegistry` | Global Docker image registry | `""` |
| `global.imagePullSecrets` | Global Docker registry secret names | `[]` |

### API Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `api.enabled` | Enable API deployment | `true` |
| `api.image.repository` | API image repository | `heimdall-api` |
| `api.image.tag` | API image tag | `latest` |
| `api.image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `api.replicaCount` | Number of API replicas | `2` |
| `api.service.type` | API service type | `ClusterIP` |
| `api.service.port` | API service port | `3001` |
| `api.resources.limits.cpu` | CPU limit | `1000m` |
| `api.resources.limits.memory` | Memory limit | `1Gi` |
| `api.resources.requests.cpu` | CPU request | `500m` |
| `api.resources.requests.memory` | Memory request | `512Mi` |
| `api.env.NODE_ENV` | Node environment | `production` |
| `api.env.PORT` | API port | `3001` |
| `api.env.LOG_LEVEL` | Log level | `INFO` |
| `api.env.LOG_FORMAT` | Log format | `json` |
| `api.env.DATA_DIR` | Data directory | `/app/data` |
| `api.env.HTTPS_ENABLED` | Enable HTTPS | `false` |
| `api.env.ENCRYPTION_KEY` | Encryption key (hex-encoded 32-byte) | `""` |

### Frontend Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `frontend.enabled` | Enable frontend deployment | `true` |
| `frontend.image.repository` | Frontend image repository | `heimdall-frontend` |
| `frontend.image.tag` | Frontend image tag | `latest` |
| `frontend.image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `frontend.replicaCount` | Number of frontend replicas | `2` |
| `frontend.service.type` | Frontend service type | `ClusterIP` |
| `frontend.service.port` | Frontend service port | `80` |
| `frontend.resources.limits.cpu` | CPU limit | `500m` |
| `frontend.resources.limits.memory` | Memory limit | `512Mi` |

### Ingress Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `ingress.enabled` | Enable ingress | `true` |
| `ingress.className` | Ingress class name | `""` |
| `ingress.annotations` | Ingress annotations | `{}` |
| `ingress.hosts` | Ingress hosts configuration | See values.yaml |
| `ingress.tls` | TLS configuration | `[]` |

### Persistence Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `persistence.enabled` | Enable persistence | `true` |
| `persistence.api.storageClass` | Storage class for API PVC | `""` |
| `persistence.api.accessMode` | Access mode | `ReadWriteOnce` |
| `persistence.api.size` | Storage size | `10Gi` |

### Autoscaling Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `autoscaling.api.enabled` | Enable API autoscaling | `false` |
| `autoscaling.api.minReplicas` | Minimum replicas | `2` |
| `autoscaling.api.maxReplicas` | Maximum replicas | `10` |
| `autoscaling.api.targetCPUUtilizationPercentage` | Target CPU utilization | `80` |
| `autoscaling.frontend.enabled` | Enable frontend autoscaling | `false` |
| `autoscaling.frontend.minReplicas` | Minimum replicas | `2` |
| `autoscaling.frontend.maxReplicas` | Maximum replicas | `10` |

## Building Docker Images

Before deploying, you need to build Docker images for both the API and frontend:

### API Image

Create a `Dockerfile` in `dashboard-api/`:

```dockerfile
FROM node:18-alpine AS builder
WORKDIR /app
COPY dashboard-api/package*.json ./
RUN npm ci
COPY dashboard-api/ ./
COPY heimdall-framework/ ../heimdall-framework/
RUN npm run build

FROM node:18-alpine
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./
EXPOSE 3001
CMD ["node", "dist/main"]
```

Build and push:
```bash
docker build -t heimdall-api:latest -f dashboard-api/Dockerfile .
docker tag heimdall-api:latest your-registry/heimdall-api:latest
docker push your-registry/heimdall-api:latest
```

### Frontend Image

Create a `Dockerfile` in `dashboard-frontend/`:

```dockerfile
FROM node:18-alpine AS builder
WORKDIR /app
COPY dashboard-frontend/package*.json ./
RUN npm ci
COPY dashboard-frontend/ ./
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY dashboard-frontend/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

Build and push:
```bash
docker build -t heimdall-frontend:latest -f dashboard-frontend/Dockerfile .
docker tag heimdall-frontend:latest your-registry/heimdall-frontend:latest
docker push your-registry/heimdall-frontend:latest
```

## Deployment Examples

### Basic Deployment

```bash
helm install heimdall ./helm/heimdall
```

### Production Deployment with Ingress

```yaml
# production-values.yaml
api:
  replicaCount: 3
  image:
    repository: your-registry/heimdall-api
    tag: "v1.0.0"
  env:
    LOG_LEVEL: WARN
    ENCRYPTION_KEY: "your-32-byte-hex-encryption-key-here"
    HTTPS_ENABLED: "true"
    HTTPS_KEY_PATH: "/etc/ssl/private/key.pem"
    HTTPS_CERT_PATH: "/etc/ssl/certs/cert.pem"

frontend:
  replicaCount: 3
  image:
    repository: your-registry/heimdall-frontend
    tag: "v1.0.0"

ingress:
  enabled: true
  className: "nginx"
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
  hosts:
    - host: heimdall.example.com
      paths:
        - path: /
          pathType: Prefix
        - path: /api
          pathType: Prefix
  tls:
    - secretName: heimdall-tls
      hosts:
        - heimdall.example.com

persistence:
  enabled: true
  api:
    storageClass: "fast-ssd"
    size: 50Gi

autoscaling:
  api:
    enabled: true
    minReplicas: 3
    maxReplicas: 10
  frontend:
    enabled: true
    minReplicas: 3
    maxReplicas: 10
```

Deploy:
```bash
helm install heimdall ./helm/heimdall -f production-values.yaml
```

### Development Deployment

```yaml
# dev-values.yaml
api:
  replicaCount: 1
  image:
    tag: "dev"
  env:
    NODE_ENV: development
    LOG_LEVEL: DEBUG
    LOG_FORMAT: pretty

frontend:
  replicaCount: 1
  image:
    tag: "dev"

ingress:
  enabled: false
```

## Upgrading

```bash
# Upgrade with new values
helm upgrade heimdall ./helm/heimdall -f production-values.yaml

# Upgrade with new image tag
helm upgrade heimdall ./helm/heimdall \
  --set api.image.tag=v1.1.0 \
  --set frontend.image.tag=v1.1.0
```

## Uninstalling

```bash
helm uninstall heimdall
```

## Troubleshooting

### Check Pod Status

```bash
kubectl get pods -l app.kubernetes.io/name=heimdall
```

### View Logs

```bash
# API logs
kubectl logs -l app.kubernetes.io/component=api --tail=100

# Frontend logs
kubectl logs -l app.kubernetes.io/component=frontend --tail=100
```

### Check Services

```bash
kubectl get svc -l app.kubernetes.io/name=heimdall
```

### Port Forward for Local Access

```bash
# API
kubectl port-forward svc/heimdall-api 3001:3001

# Frontend
kubectl port-forward svc/heimdall-frontend 8080:80
```

## Security Considerations

1. **Encryption Key**: Always set `api.env.ENCRYPTION_KEY` in production. Generate a secure 32-byte hex key:
   ```bash
   openssl rand -hex 32
   ```

2. **HTTPS**: Enable HTTPS in production by setting:
   - `api.env.HTTPS_ENABLED: "true"`
   - `api.env.HTTPS_KEY_PATH` and `api.env.HTTPS_CERT_PATH`
   - Configure TLS secrets in Kubernetes

3. **Secrets Management**: Use Kubernetes Secrets or external secret management (e.g., Sealed Secrets, External Secrets Operator) for sensitive values.

4. **Network Policies**: Consider implementing NetworkPolicies to restrict pod-to-pod communication.

5. **RBAC**: The chart creates a ServiceAccount. Configure RBAC as needed for your cluster.

## Notes

- The framework (`heimdall-framework`) is bundled with the API image and doesn't require a separate deployment.
- Health checks use the root endpoint `/` since there's no dedicated `/health` endpoint. Consider adding a health endpoint to the API for better monitoring.
- The frontend is served via nginx in production builds.
- CORS is automatically configured based on ingress settings.
