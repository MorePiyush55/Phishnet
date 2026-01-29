#!/bin/bash
# Mode 1 Production Deployment Script
# Run this to deploy Mode 1 to production

set -e  # Exit on error

echo "🚀 PhishNet Mode 1 Production Deployment"
echo "========================================"
echo ""

# Check prerequisites
echo "📋 Checking prerequisites..."

if ! command -v docker &> /dev/null; then
    echo "❌ Docker not found. Please install Docker."
    exit 1
fi

if ! command -v kubectl &> /dev/null; then
    echo "⚠️  kubectl not found. Skipping Kubernetes deployment."
    SKIP_K8S=true
fi

if ! command -v aws &> /dev/null; then
    echo "⚠️  AWS CLI not found. Skipping AWS Secrets Manager setup."
    SKIP_AWS=true
fi

echo "✅ Prerequisites check complete"
echo ""

# Step 1: Deploy Monitoring Stack
echo "📊 Step 1/5: Deploying Monitoring Stack..."
cd docker/monitoring
docker-compose up -d
echo "✅ Monitoring stack deployed (Prometheus: :9090, Grafana: :3000)"
echo ""

# Step 2: Configure Secrets
echo "🔐 Step 2/5: Configuring Secrets..."
if [ "$SKIP_AWS" != true ]; then
    echo "Setting up AWS Secrets Manager..."
    # Create IMAP credentials secret
    aws secretsmanager create-secret \
        --name phishnet/mode1/imap/default \
        --secret-string file://secrets/imap-credentials.json \
        --region us-east-1 || echo "Secret already exists"
    
    # Create API keys secret
    aws secretsmanager create-secret \
        --name phishnet/mode1/api-keys \
        --secret-string file://secrets/api-keys.json \
        --region us-east-1 || echo "Secret already exists"
    
    echo "✅ Secrets configured in AWS Secrets Manager"
else
    echo "⚠️  Skipping AWS Secrets Manager setup"
fi
echo ""

# Step 3: Create Database Indexes
echo "🗄️  Step 3/5: Creating Database Indexes..."
python scripts/create_indexes.py
echo "✅ Database indexes created"
echo ""

# Step 4: Run Tests
echo "🧪 Step 4/5: Running Test Suite..."
python -m pytest tests/ -v --cov=app --cov-report=html
TEST_EXIT_CODE=$?

if [ $TEST_EXIT_CODE -ne 0 ]; then
    echo "❌ Tests failed! Aborting deployment."
    exit 1
fi
echo "✅ All tests passed"
echo ""

# Step 5: Deploy Application
echo "🚢 Step 5/5: Deploying Application..."
if [ "$SKIP_K8S" != true ]; then
    kubectl apply -f k8s/production/
    echo "✅ Application deployed to Kubernetes"
else
    docker-compose -f docker-compose.prod.yml up -d
    echo "✅ Application deployed via Docker Compose"
fi
echo ""

# Verify deployment
echo "🔍 Verifying Deployment..."
sleep 10

# Check health endpoint
HEALTH_CHECK=$(curl -s http://localhost:8000/api/v1/mode1/health | jq -r '.status')
if [ "$HEALTH_CHECK" == "healthy" ]; then
    echo "✅ Mode 1 health check passed"
else
    echo "❌ Mode 1 health check failed"
    exit 1
fi

echo ""
echo "🎉 Deployment Complete!"
echo "======================="
echo ""
echo "📊 Monitoring:"
echo "  - Prometheus: http://localhost:9090"
echo "  - Grafana: http://localhost:3000 (admin/admin)"
echo "  - Alertmanager: http://localhost:9093"
echo ""
echo "🔍 Mode 1 Status:"
echo "  - Status: http://localhost:8000/api/v1/mode1/status"
echo "  - Metrics: http://localhost:8000/api/v1/mode1/pipeline/stats"
echo ""
echo "📚 Next Steps:"
echo "  1. Configure Slack webhook in alertmanager.yml"
echo "  2. Configure PagerDuty service key in alertmanager.yml"
echo "  3. Import Grafana dashboards from grafana/dashboards/"
echo "  4. Run load tests: locust -f tests/load/mode1_load_test.py"
echo ""
