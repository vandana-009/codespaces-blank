#!/usr/bin/env python3
"""
Initialize Federated Server
===========================
Script to initialize the global federated server for testing.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import torch
import torch.nn as nn

from federated.federated_server import create_federated_server

def create_simple_model():
    """Create a simple neural network model for NIDS."""
    model = nn.Sequential(
        nn.Linear(80, 64),  # 80 features input
        nn.ReLU(),
        nn.Linear(64, 32),
        nn.ReLU(),
        nn.Linear(32, 10)   # 10 output classes
    )
    return model

if __name__ == "__main__":
    print("Initializing Federated Server...")
    
    # Create model
    model = create_simple_model()
    
    # Create server
    server = create_federated_server(
        model=model,
        aggregation_strategy="fedavg",
        min_clients=2,
        device='cpu',
        auto_start_scheduler=False  # Don't start scheduler yet
    )
    
    print(f"Federated Server initialized with ID: {server.config.server_id}")
    print("Server is ready for client connections.")