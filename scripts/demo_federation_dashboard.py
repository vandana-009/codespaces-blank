#!/usr/bin/env python3
"""
Federation Dashboard Demo
=========================
Demonstrates the federation server dashboard with real-time metrics.

Run this script to show examiners the federation happening in real-time:
    python scripts/demo_federation_dashboard.py

Then open: http://localhost:5000/federation/dashboard

The dashboard will show:
- Connected clients
- Aggregation rounds
- Model versions
- Real-time metrics
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
import threading
import torch
import numpy as np
from datetime import datetime

# Create Flask app with federation dashboard
from app import create_app
from federated.federated_server import create_federated_server
from federated.federated_client import LocalModel
from federated.metrics_bridge import notify_client_connected, notify_round_completed

def simulate_federated_learning():
    """Simulate federated learning rounds with client updates."""
    print("\n" + "="*80)
    print("FEDERATION DASHBOARD DEMO".center(80))
    print("="*80)
    print()
    print("🚀 Creating federated server...")
    
    # Create server
    model = LocalModel(input_dim=78, num_classes=10)
    server = create_federated_server(model, aggregation_strategy="fedavg", min_clients=2)
    
    print(f"✓ Server created: {server.config.server_id}")
    print()
    
    # Simulate clients connecting
    clients_config = [
        ('hospital-node-1', 'hospital', '192.168.1.0/24'),
        ('bank-node-1', 'bank', '10.0.0.0/24'),
        ('university-node-1', 'university', '172.16.0.0/24'),
    ]
    
    print("📡 Simulating client connections...")
    for client_id, org, subnet in clients_config:
        server.register_client(client_id, organization=org, subnet=subnet)
        print(f"  ✓ {client_id} ({org}) connected")
        time.sleep(0.5)
    
    print()
    print("🔄 Simulating federated learning rounds...")
    print()
    
    # Simulate multiple rounds
    for round_num in range(1, 5):
        print(f"  Round {round_num}:")
        
        # Get global model weights
        global_weights = server.get_global_model()
        
        # Select 2-3 clients for this round
        selected_clients = list(server.clients.values())[:np.random.randint(2, 4)]
        
        # Simulate client updates
        client_updates = []
        total_samples = 0
        
        for client in selected_clients:
            # Simulate local training
            local_loss = np.random.uniform(0.5, 2.0)
            local_accuracy = np.random.uniform(0.6, 0.95)
            num_samples = np.random.randint(100, 500)
            total_samples += num_samples
            
            # Generate fake gradients (only for float tensors)
            gradients = {
                key: torch.randn_like(value) * 0.01
                for key, value in global_weights.items()
                if value.dtype in (torch.float32, torch.float64)
            }
            
            metrics = {
                'samples': num_samples,
                'loss': local_loss,
                'accuracy': local_accuracy,
                'time': np.random.uniform(10, 60)
            }
            
            client_updates.append((client.client_id, gradients, metrics))
            
            print(f"    • {client.client_id}: {num_samples} samples, loss={local_loss:.4f}")
        
        # Run round
        round_info = server.run_round(client_updates)
        
        print(f"    ✓ Model version: {round_info.model_version}")
        print(f"    ✓ Avg accuracy: {round_info.avg_accuracy:.4f}")
        print()
        
        # Small delay before next round
        time.sleep(1)
    
    print("="*80)
    print("✓ Simulation complete!".center(80))
    print("="*80)
    print()
    print("📊 View the dashboard at:")
    print("   http://localhost:5000/federation/dashboard")
    print()
    return server


def main():
    """Run the demo."""
    print()
    
    # Create Flask app
    app = create_app('development')
    
    # Run simulation in a background thread
    def run_sim():
        with app.app_context():
            simulate_federated_learning()
            print("\n💡 Keep this window open. The dashboard will continue streaming metrics.")
            print("   Close the Flask server when done (Ctrl+C).\n")
    
    sim_thread = threading.Thread(target=run_sim, daemon=False)
    sim_thread.start()
    
    # Start Flask app
    print()
    print("🌐 Starting Flask dashboard server...")
    print()
    
    app.run(
        host='127.0.0.1',
        port=5000,
        debug=False,
        use_reloader=False,
        threaded=True
    )


if __name__ == '__main__':
    main()
