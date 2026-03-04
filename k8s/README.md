# AI-NIDS Kubernetes Deployment

This directory contains Kubernetes manifests for deploying the AI-NIDS system in a production environment.

## Architecture

The deployment includes the following components:

- **PostgreSQL**: Primary database for storing detection data and models
- **Redis**: Caching layer for real-time data processing
- **Federated Server**: Coordinates federated learning across multiple clients
- **Federated Clients**: Distributed ML clients that collect local data and participate in federated learning
- **AI-NIDS App**: Main application with real-time orchestrator, detection, and mitigation
- **Prometheus**: Monitoring and metrics collection
- **Grafana**: Visualization dashboard for metrics
- **Ingress**: External access routing

## Prerequisites

- Kubernetes cluster (v1.19+)
- kubectl configured to access the cluster
- Docker registry access (if building custom images)
- NGINX Ingress Controller installed in the cluster
- cert-manager (optional, for TLS certificates)

## Quick Start

1. **Clone and navigate to the project:**
   ```bash
   cd zd-nids/k8s
   ```

2. **Make the deployment script executable:**
   ```bash
   chmod +x deploy.sh
   ```

3. **Update configuration:**
   - Edit `01-config.yaml` with your environment settings
   - Update secrets in `01-config.yaml` (base64 encoded)
   - Modify `08-ingress.yaml` with your domain name

4. **Deploy the system:**
   ```bash
   ./deploy.sh
   ```

## Configuration

### Environment Variables

Key configuration options in `01-config.yaml`:

- `FLASK_ENV`: Set to "production" for production deployment
- `LOG_LEVEL`: Logging verbosity (DEBUG, INFO, WARNING, ERROR)
- `PACKET_CAPTURE_ENABLED`: Enable/disable real-time packet capture
- `CAPTURE_INTERFACE`: Network interface for packet capture (default: eth0)
- `CAPTURE_FILTER`: Packet capture filter (default: "tcp or udp")
- `MAX_PACKETS_PER_SECOND`: Rate limiting for packet processing

### Scaling

Adjust replica counts in the deployment files:

- `federated-client` deployment: Scale based on number of network segments
- `ai-nids-app` deployment: Scale based on traffic load

### Storage

The deployment uses PersistentVolumeClaims for data persistence:

- `postgres-pvc`: Database storage (50Gi)
- `redis-pvc`: Cache storage (10Gi)
- `models-pvc`: ML model storage (20Gi, ReadWriteMany)

## Monitoring

### Prometheus Metrics

The system exposes metrics at:
- Main app: `http://ai-nids-app:80/metrics`
- Federated server: `http://federated-server:5001/metrics`

### Grafana Dashboards

Access Grafana at `http://grafana:3000` (default credentials: admin/admin)

Pre-configured dashboards include:
- System performance metrics
- Packet capture statistics
- Detection accuracy
- Federated learning progress

## Security Considerations

1. **Secrets Management**: Replace default secrets with strong, randomly generated values
2. **Network Policies**: Implement Kubernetes Network Policies to restrict pod communication
3. **RBAC**: Configure Role-Based Access Control for cluster access
4. **TLS**: Enable TLS encryption using cert-manager
5. **Packet Capture**: Federated clients run with privileged access for packet capture

## Troubleshooting

### Common Issues

1. **Pod fails to start**: Check resource limits and node capacity
2. **Database connection fails**: Verify PostgreSQL deployment and secrets
3. **Packet capture fails**: Ensure privileged containers and correct network interface
4. **Federated learning fails**: Check network connectivity between clients and server

### Debugging Commands

```bash
# Check pod status
kubectl get pods -n ai-nids

# View pod logs
kubectl logs -f deployment/ai-nids-app -n ai-nids

# Check service endpoints
kubectl get endpoints -n ai-nids

# Execute commands in pods
kubectl exec -it deployment/ai-nids-app -n ai-nids -- /bin/bash

# Check persistent volumes
kubectl get pvc -n ai-nids
```

## Production Deployment Checklist

- [ ] Update all default passwords and secrets
- [ ] Configure proper domain name and TLS certificates
- [ ] Set up external database backups
- [ ] Configure log aggregation (e.g., ELK stack)
- [ ] Set up alerting for critical metrics
- [ ] Configure horizontal pod autoscaling
- [ ] Implement proper CI/CD pipeline
- [ ] Set up disaster recovery procedures

## Scaling Considerations

- **Horizontal Scaling**: Increase replica counts for federated clients and app servers
- **Vertical Scaling**: Adjust resource requests/limits based on load testing
- **Federated Learning**: Add more clients by scaling the federated-client deployment
- **Storage**: Monitor PVC usage and scale storage as needed

## Backup and Recovery

- **Database**: Regular PostgreSQL backups using pg_dump or cloud-native tools
- **Models**: Backup the models PVC to object storage
- **Configuration**: Store manifests in Git with proper versioning
- **Logs**: Implement centralized logging with retention policies