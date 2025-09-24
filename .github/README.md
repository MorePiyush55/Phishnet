# PhishNet CI/CD Configuration

This directory contains the CI/CD pipeline configuration for PhishNet with comprehensive observability and quality gates.

## Pipeline Overview

The CI/CD pipeline implements a comprehensive approach with the following stages:

1. **Code Quality & Security** - Linting, formatting, type checking, security scanning
2. **Backend Tests** - Unit tests with observability integration
3. **Frontend Tests** - React component and integration testing  
4. **Integration Tests** - End-to-end API testing
5. **Database Migration Tests** - MongoDB schema validation
6. **Performance Tests** - Load testing and benchmarking
7. **Security Scanning** - Vulnerability analysis
8. **Build & Deploy** - Container building and deployment

## Key Features

### Observability Integration
- **Tracing**: OpenTelemetry with Jaeger integration
- **Metrics**: Prometheus metrics collection
- **Logging**: Structured JSON logging with Sentry
- **Monitoring**: Health checks and performance monitoring

### Quality Gates
- **Code Coverage**: 80% backend, 75% frontend minimum
- **Security**: Zero high vulnerabilities allowed
- **Performance**: <2s response time 95th percentile
- **Code Quality**: Max complexity 10, maintainability grade B+

### Branch Protection
- Requires 2 approving reviews
- Dismisses stale reviews on new pushes
- Enforces status checks
- Code owner reviews required
- No force pushes allowed

## Required Secrets

The following secrets must be configured in GitHub:

```yaml
# Container Registry
CONTAINER_REGISTRY: ghcr.io
REGISTRY_USERNAME: ${{ github.actor }}
REGISTRY_PASSWORD: ${{ secrets.GITHUB_TOKEN }}

# Deployment
DEPLOY_KEY: SSH private key for deployment
DEPLOY_HOST: Production server hostname
DEPLOY_USER: Deployment user

# Notifications
SLACK_WEBHOOK: Slack webhook for notifications

# Code Coverage
CODECOV_TOKEN: Codecov upload token

# Observability
SENTRY_DSN: Sentry error tracking DSN

# OAuth Integration
GMAIL_CLIENT_ID: Google OAuth client ID
GMAIL_CLIENT_SECRET: Google OAuth client secret
```

## Deployment Flow

### Development Branch (`develop`)
- Runs all tests and quality checks
- Deploys to staging environment
- Sends notification to development channel

### Main Branch (`main`)
- Full pipeline with performance tests
- Deploys to production
- Creates GitHub release
- Sends notification to production channel

### Pull Requests
- Runs quality checks and tests
- Requires passing status checks
- Blocks merge if quality gates fail

## Local Development

### Pre-commit Setup
```bash
pip install pre-commit
pre-commit install
```

### Running Tests Locally
```bash
# Backend tests
cd backend
pytest tests/ -v --cov=app

# Frontend tests  
cd frontend
npm test -- --coverage

# Integration tests
docker-compose -f docker-compose.test.yml up --build
```

## Monitoring and Alerting

The pipeline integrates with the following observability tools:

- **Jaeger**: Distributed tracing
- **Prometheus**: Metrics collection
- **Grafana**: Dashboards and visualization
- **Sentry**: Error tracking and performance monitoring
- **Codecov**: Code coverage tracking

### Alert Conditions
- Test failure: Immediate Slack notification
- Security vulnerabilities: Blocks deployment
- Coverage drop: Warning notification
- Performance regression: Blocks production deployment

## Troubleshooting

### Common Issues

1. **MongoDB Connection Failures**
   - Check service health in GitHub Actions
   - Verify connection string format
   - Ensure sufficient startup time

2. **Redis Connection Issues**
   - Validate Redis service configuration
   - Check port mapping
   - Verify health check commands

3. **Observability Integration**
   - Check Jaeger service availability
   - Validate environment variables
   - Review tracing configuration

### Debug Commands
```bash
# Check service status
docker ps
docker logs <container_id>

# Test database connection
mongosh --eval "db.adminCommand('ping')"

# Verify Redis connection
redis-cli ping

# Test API endpoints
curl http://localhost:8000/health
```

## Performance Optimization

The pipeline is optimized for:
- Parallel job execution
- Docker layer caching
- Dependency caching
- Artifact reuse between jobs

### Cache Strategy
- Python dependencies: pip cache
- Node.js dependencies: npm cache
- Docker images: GitHub Actions cache
- Test databases: Service containers