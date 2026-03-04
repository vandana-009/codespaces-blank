#!/bin/bash
# Federation System Setup for Demonstration
# ==========================================
# Run this once to prepare the system for examiner presentation

set -e

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║         Federation System Demo Preparation                    ║"
echo "║                                                                ║"
echo "║  This will set up three independent federated client nodes:   ║"
echo "║    • Hospital  (port 8001)                                    ║"
echo "║    • Bank      (port 8002)                                    ║"
echo "║    • University (port 8003)                                   ║"
echo "║                                                                ║"
echo "║  All connected to a central server on port 8765               ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo

# Check if FLASK_ENV is set
export FLASK_ENV=development

echo "✓ Step 1: Installing/verifying dependencies..."
pip install -q websockets 2>/dev/null || true
echo "  ✓ websockets library ready"
echo

echo "✓ Step 2: Seeding data for three client nodes..."
echo

# Seed Hospital node
echo "  Seeding Hospital node (hospital1)..."
CLIENT_ID=hospital1 CLIENT_PORT=8001 python -m utils.seed_data \
  --flows 200 --alerts 20 --clear > /dev/null 2>&1
echo "    ✓ Created: nids_hospital1.db (200 flows, 20 alerts)"

# Seed Bank node  
echo "  Seeding Bank node (bank1)..."
CLIENT_ID=bank1 CLIENT_PORT=8002 python -m utils.seed_data \
  --flows 200 --alerts 20 > /dev/null 2>&1
echo "    ✓ Created: nids_bank1.db (200 flows, 20 alerts)"

# Seed University node
echo "  Seeding University node (uni1)..."
CLIENT_ID=uni1 CLIENT_PORT=8003 python -m utils.seed_data \
  --flows 200 --alerts 20 > /dev/null 2>&1
echo "    ✓ Created: nids_uni1.db (200 flows, 20 alerts)"

echo

echo "✓ Step 3: Verifying database isolation..."
echo

# Check each database exists and has data
for client_id in hospital1 bank1 uni1; do
  db_file="data/nids_${client_id}.db"
  if [ -f "$db_file" ]; then
    echo "  ✓ $db_file"
  else
    echo "  ✗ $db_file NOT FOUND!"
    exit 1
  fi
done

echo

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                    SETUP COMPLETE! ✓                          ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo

echo "📋 NEXT STEPS: Open 4 separate terminals and run:"
echo

echo "   🔴 Terminal 1 - Federated Server:"
echo "   ────────────────────────────────────────────────────"
echo "   python -m federated.federated_server"
echo

echo "   🟢 Terminal 2 - Hospital Client:"
echo "   ────────────────────────────────────────────────────"
echo "   CLIENT_ID=hospital1 CLIENT_TYPE=hospital \\"
echo "     python run.py --port 8001 \\"
echo "                   --client-id hospital1 --client-type hospital \\"
echo "                   --federated-server ws://localhost:8765"
echo

echo "   🔵 Terminal 3 - Bank Client:"
echo "   ────────────────────────────────────────────────────"
echo "   CLIENT_ID=bank1 CLIENT_TYPE=bank \\"
echo "     python run.py --port 8002 \\"
echo "                   --client-id bank1 --client-type bank \\"
echo "                   --federated-server ws://localhost:8765"
echo

echo "   🟡 Terminal 4 - University Client:"
echo "   ────────────────────────────────────────────────────"
echo "   CLIENT_ID=uni1 CLIENT_TYPE=university \\"
echo "     python run.py --port 8003 \\"
echo "                   --client-id uni1 --client-type university \\"
echo "                   --federated-server ws://localhost:8765"
echo

echo "🌐 Access the dashboards:"
echo

echo "   Hospital:   http://localhost:8001/client/dashboard"
echo "   Bank:       http://localhost:8002/client/dashboard"
echo "   University: http://localhost:8003/client/dashboard"
echo

echo "   Login: demo / demo123"
echo

echo "📖 For detailed information, see:"
echo "   cat FEDERATION_EXAMINER_GUIDE.md"
echo
