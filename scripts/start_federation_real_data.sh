#!/bin/bash

# Federated Learning System - Real Data Startup Script
# ====================================================
# Starts the complete federation system:
# 1. Federated server (port 8765)
# 2. Three client instances (ports 8001, 8002, 8003)
# 3. Metrics reporters for each client
# 4. Main Flask app dashboard (port 5000)

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

WORKSPACE="/workspaces/codespaces-blank"

function log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

function log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

function log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

function log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

function cleanup() {
    log_warning "Shutting down federation system..."
    pkill -f "python.*federated_server" || true
    pkill -f "python.*application.py" || true
    pkill -f "python.*client_metrics_reporter" || true
    sleep 1
    log_success "All processes stopped"
}

trap cleanup EXIT

cd "$WORKSPACE"

log_info "=================================================="
log_info "Federated Learning System - Real Data Setup"
log_info "=================================================="
log_info ""

# Check Python
log_info "Verifying Python environment..."
python --version
python -c "import flask, torch, xgboost; log_success('All dependencies available')" 2>/dev/null || {
    log_error "Dependencies missing. Running pip install..."
    pip install -q -r requirements.txt
}
log_success "Python environment ready"
log_info ""

# Seed data for each client
log_info "Seeding data for each client organization..."

for i in 1 2 3; do
    CLIENT_ID="client-$i"
    CLIENT_PORT=$((8000 + i))
    
    if [ $i -eq 1 ]; then CLIENT_NAME="Hospital"; fi
    if [ $i -eq 2 ]; then CLIENT_NAME="Bank"; fi
    if [ $i -eq 3 ]; then CLIENT_NAME="University"; fi
    
    log_info "  Seeding $CLIENT_NAME ($CLIENT_ID)..."
    
    # Seed with network flows and alerts
    # This populates detection data that will trigger zero-day detection
    CLIENT_ID="$CLIENT_ID" CLIENT_PORT=$CLIENT_PORT python -m utils.seed_data \
        --flows 300 --alerts 30 > /dev/null 2>&1
    
    log_success "  Created isolated database for $CLIENT_NAME (300 flows, 30 alerts)"
done

log_info "✓ All client databases seeded with data"
log_info ""

# Start Federated Server (production mode)
log_info "Starting Federated Server on port 8765..."
# Start the server with proper timeout and error handling
timeout --signal=KILL 300 python -m federated.federated_server > /tmp/federated_server.log 2>&1 &
SERVER_PID=$!
# Give it time to initialize
sleep 4
if kill -0 $SERVER_PID 2>/dev/null; then
    log_success "Federated Server running (PID: $SERVER_PID)"
else
    log_error "Failed to start Federated Server"
    tail -30 /tmp/federated_server.log | grep -E "(Error|Exception|Traceback)" || cat /tmp/federated_server.log
fi
log_info ""

# Start Three Client Instances
log_info "Starting three client instances..."

for i in 1 2 3; do
    CLIENT_PORT=$((8000 + i))
    CLIENT_ID="client-$i"
    
    if [ $i -eq 1 ]; then CLIENT_NAME="Hospital"; ORG="Healthcare"; fi
    if [ $i -eq 2 ]; then CLIENT_NAME="Bank"; ORG="Finance"; fi
    if [ $i -eq 3 ]; then CLIENT_NAME="University"; ORG="Education"; fi
    
    log_info "  Starting $CLIENT_NAME instance (port $CLIENT_PORT)..."
    # set environment variables and launch via new entrypoint
    CLIENT_ID="$CLIENT_ID" CLIENT_PORT=$CLIENT_PORT python application.py \
        --port $CLIENT_PORT --client-id "$CLIENT_ID" > /tmp/client_$i.log 2>&1 &
    CLIENT_PID=$!
    sleep 2
    
    if kill -0 $CLIENT_PID 2>/dev/null; then
        log_success "  $CLIENT_NAME client running on port $CLIENT_PORT (PID: $CLIENT_PID)"
    else
        log_error "  Failed to start $CLIENT_NAME client"
        cat /tmp/client_$i.log
    fi
done
log_info ""

# Wait for clients to be ready
log_info "Waiting for client instances to initialize..."
sleep 3

# Start Metrics Reporters
log_info "Starting metrics reporters for each client..."

REPORTERS=()
for i in 1 2 3; do
    CLIENT_PORT=$((8000 + i))
    CLIENT_ID="client-$i"
    ORG_NAME="org-$i"
    
    log_info "  Starting metrics reporter for $CLIENT_ID..."
    python scripts/client_metrics_reporter.py \
        --client-id "$CLIENT_ID" \
        --port $CLIENT_PORT \
        --server-url http://localhost:5000 \
        --organization "$ORG_NAME" \
        --interval 10 > /tmp/reporter_$i.log 2>&1 &
    REPORTER_PID=$!
    REPORTERS+=($REPORTER_PID)
    sleep 1
    
    if kill -0 $REPORTER_PID 2>/dev/null; then
        log_success "  Metrics reporter for $CLIENT_ID running (PID: $REPORTER_PID)"
    else
        log_warning "  Metrics reporter startup delayed..."
    fi
done
log_info ""

# Start Main Dashboard (if not already running)
log_info "Starting main Flask app on port 5000..."
# run in production mode to disable the debug reloader, which previously
# caused the server to restart mid-demo and produced confusing 404s.
if ! lsof -Pi :5000 -sTCP:LISTEN -t >/dev/null 2>&1; then
    FLASK_ENV=production python application.py --port 5000 > /tmp/dashboard.log 2>&1 &
    DASHBOARD_PID=$!
    sleep 3
    
    if kill -0 $DASHBOARD_PID 2>/dev/null; then
        log_success "Dashboard running on port 5000 (PID: $DASHBOARD_PID)"
    else
        log_error "Failed to start Dashboard"
        cat /tmp/dashboard.log
    fi
else
    log_success "Dashboard already running on port 5000"
fi
log_info ""

# Display Access Information
log_info "=================================================="
log_success "Federation System is RUNNING"
log_info "=================================================="
log_info ""

# Forward ports for external access
log_info "Forwarding ports for external access..."
gh codespace ports forward 8765:8765 || log_warning "Port 8765 forwarding failed (may already be forwarded)"
gh codespace ports forward 5000:5000 || log_warning "Port 5000 forwarding failed (may already be forwarded)"
gh codespace ports forward 8001:8001 || log_warning "Port 8001 forwarding failed (may already be forwarded)"
gh codespace ports forward 8002:8002 || log_warning "Port 8002 forwarding failed (may already be forwarded)"
gh codespace ports forward 8003:8003 || log_warning "Port 8003 forwarding failed (may already be forwarded)"
log_success "Port forwarding completed"
log_info ""

log_success "✓ Data Status:"
log_info "  • Hospital: 300 flows, 30 alerts"
log_info "  • Bank: 300 flows, 30 alerts"
log_info "  • University: 300 flows, 30 alerts"
log_info ""
log_success "✓ Federated Learning:"
log_info "  • Server: http://localhost:8765 (aggregating)"
log_info "  • Clients: 8001, 8002, 8003 (training locally)"
log_info "  • Metrics: Flowing every 10 seconds"
log_info ""
log_info "Real-Time Dashboards:"
log_info "  → Federation Aggregation: http://localhost:5000/federation/dashboard"
log_info "  → Hospital Zero-Day:      http://localhost:8001/dashboard (login: admin/admin)"
log_info "  → Bank Zero-Day:          http://localhost:8002/dashboard (login: admin/admin)"
log_info "  → University Zero-Day:    http://localhost:8003/dashboard (login: admin/admin)"
log_info ""
log_info "Client Instance Dashboards:"
log_info "  → Hospital Client:    http://localhost:8001/client/dashboard"
log_info "  → Bank Client:        http://localhost:8002/client/dashboard"
log_info "  → University Client:  http://localhost:8003/client/dashboard"
log_info ""
log_info "API Endpoints:"
log_info "  → Server Status:  http://localhost:8765/api/federated/server-status"
log_info "  → Metrics Stream: http://localhost:5000/federation/stream"
log_info ""
log_info "Logs (Monitor for Real-Time Updates):"
log_info "  → Server:    tail -f /tmp/federated_server.log"
log_info "  → Clients:   tail -f /tmp/client_1.log"
log_info "  → Reporters: tail -f /tmp/reporter_1.log"
log_info ""
log_warning "Press Ctrl+C to stop all services"
log_info ""

# Keep running
wait
