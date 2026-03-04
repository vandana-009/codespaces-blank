#!/usr/bin/env python3
"""
Real-Time Federated Server (Production Mode)
=============================================
This server accepts REAL connections from client instances and aggregates
their model updates in real-time for the dashboard.

Usage:
    python scripts/start_federated_server.py

This will:
    1. Start the federated aggregation server
    2. Listen for WebSocket connections from clients on ws://localhost:8765
    3. Show real-time metrics on dashboard at http://localhost:5000/federation/dashboard
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import asyncio
import threading
import time
import logging
from datetime import datetime

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

from federated.federated_server import create_federated_server
from federated.federated_client import LocalModel


def start_real_federated_server():
    """Start the real federated server that listens for client connections."""
    
    print("\n" + "="*80)
    print("REAL-TIME FEDERATED SERVER".center(80))
    print("="*80)
    print()
    
    # Create server
    logger.info("Creating federated server...")
    model = LocalModel(input_dim=78, num_classes=10)
    server = create_federated_server(
        model,
        aggregation_strategy="fedavg",
        min_clients=2
    )
    
    print(f"✓ Server created: {server.config.server_id}")
    print(f"✓ Strategy: {server.config.aggregation_strategy.value.upper()}")
    print()
    
    # Start WebSocket streaming server for real client connections
    print("📡 Starting WebSocket streaming server...")
    print("   Listening on: ws://localhost:8765")
    print()
    print("   Waiting for client connections from:")
    print("   • localhost:8001 (hospital)")
    print("   • localhost:8002 (bank)")
    print("   • localhost:8003 (university)")
    print()
    
    try:
        server.start_streaming_server(host='0.0.0.0', port=8765)
        logger.info("WebSocket server started on port 8765")
    except Exception as e:
        logger.error(f"Failed to start WebSocket server: {e}")
        print(f"Note: WebSocket may not be available. Server will still accept HTTP updates.")
    
    print("="*80)
    print("✓ FEDERATED SERVER READY FOR REAL CLIENT CONNECTIONS".center(80))
    print("="*80)
    print()
    print("🎯 NEXT STEPS:")
    print()
    print("  1. In separate terminals, start your client instances:")
    print("     Terminal 2: CLIENT_ID=hospital1 python run.py --port 8001 --federated-server ws://localhost:8765")
    print("     Terminal 3: CLIENT_ID=bank1 python run.py --port 8002 --federated-server ws://localhost:8765")
    print("     Terminal 4: CLIENT_ID=uni1 python run.py --port 8003 --federated-server ws://localhost:8765")
    print()
    print("  2. View the real-time dashboard:")
    print("     http://localhost:5000/federation/dashboard")
    print()
    print("  3. As clients connect and train, you'll see:")
    print("     • Client registrations in real-time")
    print("     • Model aggregation rounds happening")
    print("     • Metrics updating live on the dashboard")
    print()
    print("💡 The server will run indefinitely, aggregating updates as clients connect.")
    print("   Press Ctrl+C to stop.")
    print()
    
    # Keep the server running indefinitely
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n✓ Federated server shutting down...")
        logger.info("Server shutdown")


if __name__ == '__main__':
    start_real_federated_server()
