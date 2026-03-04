#!/bin/bash

# AI-NIDS Kubernetes Deployment Script
# This script deploys the complete AI-NIDS system to Kubernetes

set -e

NAMESPACE="ai-nids"
DOCKER_IMAGE="ai-nids:latest"

echo "🚀 Starting AI-NIDS Kubernetes deployment..."

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    echo "❌ kubectl not found. Please install kubectl first."
    exit 1
fi

# Check if we're connected to a cluster
if ! kubectl cluster-info &> /dev/null; then
    echo "❌ Not connected to a Kubernetes cluster."
    exit 1
fi

# Create namespace
echo "📦 Creating namespace..."
kubectl create namespace $NAMESPACE --dry-run=client -o yaml | kubectl apply -f -

# Build and push Docker image (optional - comment out if using pre-built image)
echo "🐳 Building Docker image..."
docker build -t $DOCKER_IMAGE .

# Apply configurations in order
echo "⚙️  Applying configurations..."
kubectl apply -f k8s/01-config.yaml
kubectl apply -f k8s/02-database.yaml
kubectl apply -f k8s/03-cache.yaml
kubectl apply -f k8s/04-federated-server.yaml
kubectl apply -f k8s/05-federated-clients.yaml
kubectl apply -f k8s/06-app.yaml
kubectl apply -f k8s/07-monitoring.yaml
kubectl apply -f k8s/08-ingress.yaml

# Wait for deployments to be ready
echo "⏳ Waiting for deployments to be ready..."
kubectl wait --for=condition=available --timeout=300s deployment/postgres -n $NAMESPACE
kubectl wait --for=condition=available --timeout=300s deployment/redis -n $NAMESPACE
kubectl wait --for=condition=available --timeout=300s deployment/federated-server -n $NAMESPACE
kubectl wait --for=condition=available --timeout=300s deployment/federated-client -n $NAMESPACE
kubectl wait --for=condition=available --timeout=300s deployment/ai-nids-app -n $NAMESPACE
kubectl wait --for=condition=available --timeout=300s deployment/prometheus -n $NAMESPACE
kubectl wait --for=condition=available --timeout=300s deployment/grafana -n $NAMESPACE

# Initialize database
echo "🗄️  Initializing database..."
kubectl exec -n $NAMESPACE deployment/postgres -- bash -c "
until pg_isready -U nids; do
  echo 'Waiting for PostgreSQL...'
  sleep 2
done
"

# Run database migrations
echo "🔄 Running database migrations..."
kubectl exec -n $NAMESPACE deployment/ai-nids-app -- python -c "
import time
from app import create_app, db

time.sleep(10)  # Wait for database to be ready
app = create_app()
with app.app_context():
    db.create_all()
    print('Database initialized successfully')
"

echo "✅ Deployment completed successfully!"
echo ""
echo "🌐 Service URLs:"
echo "   Main Application: http://ai-nids-app.$NAMESPACE.svc.cluster.local"
echo "   Federated Server: http://federated-server.$NAMESPACE.svc.cluster.local:5001"
echo "   Prometheus: http://prometheus.$NAMESPACE.svc.cluster.local:9090"
echo "   Grafana: http://grafana.$NAMESPACE.svc.cluster.local:3000"
echo ""
echo "🔍 Check status with: kubectl get pods -n $NAMESPACE"
echo "📊 View logs with: kubectl logs -f deployment/ai-nids-app -n $NAMESPACE"