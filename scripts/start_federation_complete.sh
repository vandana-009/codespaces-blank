#!/bin/bash

# Federation System - Complete Setup (Server + Dashboard)
# This script ensures BOTH the federated server AND Flask dashboard are running

set -e

WORKSPACE="/workspaces/codespaces-blank"
cd "$WORKSPACE"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

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

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║   Federation System - Complete Setup                       ║"
echo "║   Federated Server (8765) + Flask Dashboard (5000)         ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Check Python
if ! command -v python &> /dev/null; then
    log_error "Python not found"
    exit 1
fi
log_success "Python available"

# Kill any existing processes
log_info "Cleaning up any existing federation processes..."
pkill -f "python -m federated.federated_server" || true
pkill -f "python application.py.*5000" || true
pkill -f "python.*federated_client" || true
sleep 1

# Start Federated Server
log_info "Starting Federated Server on port 8765..."
python -m federated.federated_server > /tmp/federated_server.log 2>&1 &
FEDERATED_PID=$!
log_success "Federated Server started (PID: $FEDERATED_PID)"

# Wait for federated server to be ready
sleep 2

# Start Flask Dashboard on port 5000
log_info "Starting Flask Dashboard on port 5000..."
FLASK_ENV=development python application.py --port 5000 > /tmp/flask_dashboard.log 2>&1 &
FLASK_PID=$!
log_success "Flask Dashboard started (PID: $FLASK_PID)"

# Wait for Flask to be ready
sleep 2

# Verify Flask is reachable
log_info "Verifying Flask dashboard is reachable..."
for i in {1..5}; do
    if curl -s http://localhost:5000/api/federation/health > /dev/null 2>&1; then
        log_success "Flask dashboard is responding on port 5000"
        break
    fi
    if [ $i -eq 5 ]; then
        log_error "Flask dashboard not responding after 5 seconds"
        log_warning "Check /tmp/flask_dashboard.log for errors"
    fi
    sleep 1
done

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║   🎉 Federation System is Running!                         ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "📊 Components:"
echo "  ✓ Federated Server:  http://localhost:8765"
echo "  ✓ Flask Dashboard:   http://localhost:5000"
echo "  ✓ Metrics API:       http://localhost:5000/federation/api/metrics"
echo ""
echo "🎮 Next Steps:"
echo "  1. Open Dashboard:   open http://localhost:5000/federation/dashboard"
echo "  2. View Server Logs: tail -f /tmp/federated_server.log"
echo "  3. View Flask Logs:  tail -f /tmp/flask_dashboard.log"
echo ""
echo "📈 Metrics Should Start in 10 seconds..."
echo ""
echo "To stop the system, press Ctrl+C"
echo ""

# Wait for Ctrl+C
trap "log_warning 'Shutting down federation system...'; kill $FEDERATED_PID $FLASK_PID 2>/dev/null; log_success 'Federation system stopped'" EXIT

wait
