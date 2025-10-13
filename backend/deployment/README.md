# PhishNet Deployment

This directory contains all deployment configurations for PhishNet.

## Directory Structure

```
deployment/
├── docker-compose.yml          # Main development setup
├── docker-compose.prod.yml     # Production configuration
├── Dockerfile                  # Application container
├── .dockerignore               # Docker ignore rules
├── k8s/                        # Kubernetes manifests
├── helm/                       # Helm charts
├── monitoring/                 # Monitoring configurations
└── docker/                     # Specialized Docker configs
```

## Usage

### Development with Docker Compose
```bash
# Start all services (from root directory)
cd deployment
docker-compose up

# Start specific services
docker-compose up postgres redis
docker-compose up phishnet-api

# View logs
docker-compose logs -f phishnet-api
```

### Production Deployment
```bash
# Production build
cd deployment
docker-compose -f docker-compose.prod.yml up -d

# Or using the Makefile from tools directory
cd ../tools
make docker-prod
```

### Kubernetes Deployment
```bash
# Apply Kubernetes manifests
kubectl apply -f k8s/

# Or using Helm
helm install phishnet helm/phishnet
```

## Environment Variables

Environment variables should be set in the backend `.env` file:
- Backend env: `../backend/.env`
- Frontend env: `../frontend/.env`

## Monitoring

Monitoring stack includes:
- Prometheus (metrics)
- Grafana (dashboards)  
- Alertmanager (alerts)
- ELK Stack (logging)

Access monitoring dashboards:
- Grafana: http://localhost:3000
- Prometheus: http://localhost:9090

## Notes

- All paths in docker-compose.yml are relative to the project root
- The Dockerfile builds from the project root context
- Database and other persistent data is stored in Docker volumes