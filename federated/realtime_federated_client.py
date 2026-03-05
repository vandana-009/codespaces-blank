"""
Real-Time Federated Client
==========================
Federated learning client that runs in real-time, collecting local traffic data
and participating in federated learning rounds.
"""

import asyncio
import logging
import threading
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
import json
import requests
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

from federated.federated_client import FederatedClient, ClientConfig, LocalModel
from collectors.live_capture import LiveCaptureManager, DetectionCallback
from detection.detector import DetectionEngine

logger = logging.getLogger(__name__)


@dataclass
class RealtimeFederatedConfig:
    """Configuration for real-time federated client."""
    client_id: str
    server_url: str = "http://localhost:8080"
    organization: str = "default"
    subnet: str = "0.0.0.0/0"

    # Real-time settings
    capture_interface: str = "eth0"
    capture_filter: str = "tcp or udp"
    max_packets_per_second: int = 5000

    # Training settings
    local_epochs: int = 3
    batch_size: int = 32
    learning_rate: float = 0.001

    # Federated settings
    heartbeat_interval: int = 60
    sync_interval: int = 300
    min_samples_for_training: int = 1000

    # Privacy settings
    differential_privacy: bool = True
    noise_multiplier: float = 1.0


class RealtimeFederatedClient:
    """
    Real-time federated learning client.

    Features:
    - Live packet capture and feature extraction
    - Continuous local model training
    - Real-time participation in federated rounds
    - Privacy-preserving gradient sharing
    """

    def __init__(self, config: RealtimeFederatedConfig):
        self.config = config
        self.running = False

        # Core components
        self.federated_client = None
        self.capture_manager = None
        self.detection_engine = None

        # Data collection
        self.local_data = []
        self.data_lock = threading.Lock()

        # Training state
        self.model = None
        self.is_training = False

        # Stats
        self.stats = {
            'packets_captured': 0,
            'samples_collected': 0,
            'training_rounds': 0,
            'federated_rounds': 0,
            'start_time': None
        }

        logger.info(f"Real-time federated client {config.client_id} initialized")

    async def initialize(self):
        """Initialize the federated client."""
        logger.info("Initializing real-time federated client...")

        # Create federated client config
        fed_config = ClientConfig(
            client_id=self.config.client_id,
            organization=self.config.organization,
            subnet=self.config.subnet,
            server_url=self.config.server_url,
            local_epochs=self.config.local_epochs,
            batch_size=self.config.batch_size,
            learning_rate=self.config.learning_rate,
            heartbeat_interval=self.config.heartbeat_interval
        )

        # Initialize federated client
        self.federated_client = FederatedClient(fed_config)
        # If streaming support is available, establish connection immediately
        if hasattr(self.federated_client, 'connect_stream'):
            try:
                asyncio.create_task(self.federated_client.connect_stream())
            except Exception as e:
                logger.warning(f"Failed to start streaming connection: {e}")

        # Initialize detection engine for feature extraction
        self.detection_engine = DetectionEngine()

        # Initialize packet capture
        detection_callback = RealtimeDetectionCallback(
            detector=self.detection_engine,
            data_collector=self._collect_sample
        )
        self.capture_manager = LiveCapture()
        self.capture_manager.add_callback(detection_callback)

        # Initialize local model
        self.model = LocalModel()

        logger.info("Real-time federated client initialized")

    async def start(self):
        """Start real-time operations."""
        logger.info(f"Starting real-time federated client {self.config.client_id}")
        self.running = True
        self.stats['start_time'] = datetime.utcnow()

        try:
            # Start packet capture
            await self._start_packet_capture()

            # Start federated client
            await self._start_federated_client()

            # Start training loop
            await self._start_training_loop()

            # Start heartbeat
            await self._start_heartbeat()

        except Exception as e:
            logger.error(f"Error starting real-time client: {e}")
            raise

    async def stop(self):
        """Stop all operations."""
        logger.info(f"Stopping real-time federated client {self.config.client_id}")
        self.running = False

        if self.capture_manager:
            await self.capture_manager.stop()

        if self.federated_client:
            await self.federated_client.stop()

    async def _start_packet_capture(self):
        """Start live packet capture."""
        logger.info(f"Starting packet capture on {self.config.capture_interface}")

        def capture_thread():
            try:
                self.capture_manager.start_capture(
                    interface=self.config.capture_interface,
                    filter_str=self.config.capture_filter,
                    max_packets_per_second=self.config.max_packets_per_second
                )
            except Exception as e:
                logger.error(f"Packet capture error: {e}")

        thread = threading.Thread(target=capture_thread, daemon=True)
        thread.start()

    async def _start_federated_client(self):
        """Start federated learning client."""
        logger.info("Starting federated learning client")

        def federated_thread():
            try:
                # Register with server
                self.federated_client.register_with_server()

                # Start heartbeat
                while self.running:
                    try:
                        self.federated_client.send_heartbeat()
                        time.sleep(self.config.heartbeat_interval)
                    except Exception as e:
                        logger.error(f"Heartbeat error: {e}")
                        time.sleep(30)

            except Exception as e:
                logger.error(f"Federated client error: {e}")

        thread = threading.Thread(target=federated_thread, daemon=True)
        thread.start()

    async def _start_training_loop(self):
        """Start continuous training loop."""
        logger.info("Starting training loop")

        def training_thread():
            while self.running:
                try:
                    # Check if we have enough data
                    with self.data_lock:
                        if len(self.local_data) >= self.config.min_samples_for_training:
                            # Prepare training data
                            features = [sample['features'] for sample in self.local_data]
                            labels = [sample['label'] for sample in self.local_data]

                            # Convert to tensors
                            X = torch.tensor(features, dtype=torch.float32)
                            y = torch.tensor(labels, dtype=torch.long)

                            dataset = TensorDataset(X, y)
                            dataloader = DataLoader(dataset, batch_size=self.config.batch_size, shuffle=True)

                            # Train local model
                            self._train_local_model(dataloader)

                            # Clear used data
                            self.local_data = []

                            self.stats['training_rounds'] += 1

                    time.sleep(60)  # Check every minute

                except Exception as e:
                    logger.error(f"Training loop error: {e}")
                    time.sleep(30)

        thread = threading.Thread(target=training_thread, daemon=True)
        thread.start()

    async def _start_heartbeat(self):
        """Start heartbeat to server."""
        def heartbeat_thread():
            while self.running:
                try:
                    # Send stats to server
                    stats_payload = {
                        'client_id': self.config.client_id,
                        'timestamp': datetime.utcnow().isoformat(),
                        'stats': self.stats,
                        'status': 'active'
                    }

                    # Send to server (if endpoint exists)
                    # requests.post(f"{self.config.server_url}/client/stats", json=stats_payload)

                    time.sleep(self.config.heartbeat_interval)

                except Exception as e:
                    logger.error(f"Heartbeat error: {e}")
                    time.sleep(30)

        thread = threading.Thread(target=heartbeat_thread, daemon=True)
        thread.start()

    def _collect_sample(self, features: Dict[str, Any], label: int):
        """Collect training sample from detection."""
        with self.data_lock:
            self.local_data.append({
                'features': list(features.values()),
                'label': label,
                'timestamp': datetime.utcnow()
            })

            # Limit data size
            if len(self.local_data) > 10000:
                self.local_data = self.local_data[-5000:]

            self.stats['samples_collected'] += 1

    def _train_local_model(self, dataloader: DataLoader):
        """Train the local model."""
        if self.is_training:
            return

        self.is_training = True
        try:
            logger.info("Starting local model training")

            optimizer = torch.optim.Adam(self.model.parameters(), lr=self.config.learning_rate)
            criterion = nn.CrossEntropyLoss()

            self.model.train()
            for epoch in range(self.config.local_epochs):
                epoch_loss = 0.0
                for batch_X, batch_y in dataloader:
                    optimizer.zero_grad()
                    outputs = self.model(batch_X)
                    loss = criterion(outputs, batch_y)
                    loss.backward()
                    optimizer.step()
                    epoch_loss += loss.item()

                logger.debug(f"Epoch {epoch + 1}/{self.config.local_epochs}, Loss: {epoch_loss/len(dataloader):.4f}")

            logger.info("Local model training completed")

        except Exception as e:
            logger.error(f"Training error: {e}")
        finally:
            self.is_training = False

    def get_stats(self) -> Dict[str, Any]:
        """Get client statistics."""
        runtime = None
        if self.stats['start_time']:
            runtime = (datetime.utcnow() - self.stats['start_time']).total_seconds()

        return {
            **self.stats,
            'runtime_seconds': runtime,
            'is_training': self.is_training,
            'data_buffer_size': len(self.local_data),
            'model_version': 'local_v1'
        }


class RealtimeDetectionCallback(DetectionCallback):
    """Detection callback that collects training data."""

    def __init__(self, detector: DetectionEngine, data_collector: callable):
        super().__init__(detector)
        self.data_collector = data_collector

    def on_detection_result(self, result, features):
        """Handle detection result and collect training data."""
        # Call parent for normal processing
        super().on_detection_result(result, features)

        # Forward relevant metrics to the client dashboard (if available)
        try:
            from app.routes.client_dashboard import record_alert, record_anomaly, record_latency
            # result may be an object or dict; convert if necessary
            if isinstance(result, dict):
                if result.get('is_attack'):
                    record_alert(result)
                if 'anomaly_score' in result:
                    record_anomaly(result['anomaly_score'])
            else:
                # object with attributes
                if getattr(result, 'is_attack', False):
                    record_alert(result)
                if hasattr(result, 'anomaly_score'):
                    record_anomaly(result.anomaly_score)
        except ImportError:
            pass

        # Collect data for training
        if features:
            label = 1 if result.get('is_attack', False) else 0
            self.data_collector(features, label)


def create_realtime_federated_client(config: RealtimeFederatedConfig) -> RealtimeFederatedClient:
    """Create a real-time federated client."""
    return RealtimeFederatedClient(config)


async def run_federated_client(
    client_id: str,
    server_url: str = "http://localhost:8080",
    interface: str = "eth0"
):
    """Run a federated client with default settings."""
    config = RealtimeFederatedConfig(
        client_id=client_id,
        server_url=server_url,
        capture_interface=interface
    )

    client = create_realtime_federated_client(config)

    try:
        await client.initialize()
        await client.start()
    except KeyboardInterrupt:
        logger.info("Client interrupted")
    except Exception as e:
        logger.error(f"Client error: {e}")
    finally:
        await client.stop()


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python realtime_federated_client.py <client_id> [server_url] [interface]")
        sys.exit(1)

    client_id = sys.argv[1]
    server_url = sys.argv[2] if len(sys.argv) > 2 else "http://localhost:8080"
    interface = sys.argv[3] if len(sys.argv) > 3 else "eth0"

    asyncio.run(run_federated_client(client_id, server_url, interface))