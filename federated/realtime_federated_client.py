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
import numpy as np

from federated.federated_client import FederatedClient, ClientConfig, LocalModel
from collectors.live_capture import LiveCaptureManager, DetectionCallback
from detection.detector import DetectionEngine
from app.routes.client_dashboard import record_anomaly, update_metrics, set_model_versions

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
    min_samples_for_training: int = 10

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

    def _load_initial_data(self):
        """Load initial training data from database."""
        try:
            from app import create_app
            from app.models.database import NetworkFlow
            
            app = create_app()
            with app.app_context():
                # Get recent flows from database
                flows = NetworkFlow.query.order_by(NetworkFlow.timestamp.desc()).limit(50).all()
                
                for flow in flows:
                    # Create features dict from flow data
                    features = self._flow_to_features(flow)
                    label = 1 if flow.is_anomaly or flow.label != 'BENIGN' else 0
                    
                    # Collect sample
                    self._collect_sample(features, label)
                
                logger.info(f"Loaded {len(flows)} initial samples from database")
                
        except Exception as e:
            logger.warning(f"Failed to load initial data: {e}")

    def _flow_to_features(self, flow):
        """Convert NetworkFlow to feature dict."""
        # Calculate some derived features
        total_packets = (flow.packets_sent or 0) + (flow.packets_recv or 0)
        packets_forward = flow.packets_sent or 0
        packets_backward = flow.packets_recv or 0
        
        # Estimate packet lengths
        avg_packet_len = (flow.total_bytes or 0) / max(total_packets, 1)
        
        return {
            'duration': flow.duration or 0.0,
            'protocol': flow.protocol or 'tcp',
            'src_port': flow.source_port or 0,
            'dst_port': flow.destination_port or 0,
            'total_packets': total_packets,
            'packets_forward': packets_forward,
            'packets_backward': packets_backward,
            'total_bytes': flow.total_bytes or 0,
            'packet_length_mean': avg_packet_len,
            'packet_length_std': 0.0,  # Not available
            'packet_length_min': avg_packet_len,
            'packet_length_max': avg_packet_len,
            'iat_mean': 0.0,  # Not available
            'iat_std': 0.0,
            'syn_count': flow.syn_count or 0,
            'ack_count': flow.ack_count or 0,
            'fin_count': flow.fin_count or 0,
            'rst_count': flow.rst_count or 0
        }

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

        # Load initial training data from database
        self._load_initial_data()

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
                self.capture_manager.start(
                    interface=self.config.capture_interface,
                    filter=self.config.capture_filter,
                    async_capture=True
                )
            except Exception as e:
                logger.error(f"Packet capture error: {e}")
                # don't automatically fall back to synthetic traffic; seeded data should be
                # used for demonstration.  Synthetic generation can be enabled explicitly
                # with the USE_SYNTHETIC_DATA env var if needed.
                if os.environ.get('USE_SYNTHETIC_DATA', 'false').lower() in ('1','true'):
                    self._start_synthetic_generation()

        thread = threading.Thread(target=capture_thread, daemon=True)
        thread.start()

    def _start_synthetic_generation(self):
        """Generate synthetic network traffic for testing."""
        logger.info("Starting synthetic data generation for testing")

        def synthetic_thread():
            import random
            import time
            
            while self.running:
                try:
                    # Generate synthetic flow features
                    features = {
                        'duration': random.uniform(0.1, 10.0),
                        'protocol': random.choice(['TCP', 'UDP']),
                        'src_port': random.randint(1024, 65535),
                        'dst_port': random.randint(1, 1024),
                        'total_packets': random.randint(1, 100),
                        'packets_forward': random.randint(1, 50),
                        'packets_backward': random.randint(0, 50),
                        'total_bytes': random.randint(100, 10000),
                        'packet_length_mean': random.uniform(50, 1500),
                        'packet_length_std': random.uniform(10, 500),
                        'packet_length_min': random.uniform(40, 100),
                        'packet_length_max': random.uniform(100, 1500),
                        'iat_mean': random.uniform(0.001, 1.0),
                        'iat_std': random.uniform(0.0001, 0.5),
                        'syn_count': random.randint(0, 5),
                        'ack_count': random.randint(0, 20),
                        'fin_count': random.randint(0, 2),
                        'rst_count': random.randint(0, 1)
                    }
                    
                    # Random label (mostly benign)
                    label = 1 if random.random() < 0.05 else 0  # 5% anomalies
                    
                    # Collect sample
                    self._collect_sample(features, label)
                    
                    # Update stats
                    self.stats['packets_captured'] += features['total_packets']
                    
                    time.sleep(random.uniform(0.1, 2.0))  # Random interval
                    
                except Exception as e:
                    logger.error(f"Synthetic generation error: {e}")
                    time.sleep(5)

        thread = threading.Thread(target=synthetic_thread, daemon=True)
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

                            # Participate in federated round
                            self._participate_in_federated_round(dataloader)

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
    def _send_metrics_to_server(self):
        """Send training metrics to the federated server."""
        try:
            if not self.federated_client or len(self.federated_client.history) == 0:
                return
            
            # Get latest metrics
            latest_metrics = self.federated_client.history[-1]
            
            # Prepare payload
            payload = {
                'client_id': self.config.client_id,
                'round': latest_metrics.round_number,
                'samples': latest_metrics.samples_trained,
                'loss': latest_metrics.loss,
                'accuracy': latest_metrics.accuracy,
                'timestamp': latest_metrics.timestamp.isoformat()
            }
            
            # Send to server
            # Use HTTP endpoint (Flask app on port 5000)
            if self.config.server_url.startswith('ws://'):
                http_url = self.config.server_url.replace('ws://', 'http://').replace(':8765', ':5000')
            else:
                http_url = self.config.server_url
            url = f"{http_url}/api/federated/submit-metrics"
            response = requests.post(url, json=payload, timeout=10)
            
            if response.status_code == 200:
                logger.info(f"Sent metrics to server: round {latest_metrics.round_number}")
            else:
                logger.warning(f"Failed to send metrics: {response.status_code}")
                
        except Exception as e:
            logger.error(f"Error sending metrics to server: {e}")
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
            
            # Also add to federated client
            if self.federated_client:
                feature_values = list(features.values())
                self.federated_client.add_sample(np.array(feature_values), label)
            
            # Update client metrics for dashboard
            if label == 1:  # Anomaly
                record_anomaly(0.8)  # High anomaly score

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

    def _participate_in_federated_round(self, dataloader):
        """Participate in a federated learning round."""
        try:
            if not self.federated_client:
                logger.warning("No federated client available")
                return

            # Get global model from server
            global_model = None
            try:
                # Try to get global model via HTTP
                http_url = self.config.server_url.replace('ws://', 'http://').replace(':8765', ':5000')
                response = requests.get(f"{http_url}/federation/api/model", timeout=10)
                if response.status_code == 200:
                    model_data = response.json()
                    # Convert to tensor dict
                    global_model = {k: torch.tensor(v) for k, v in model_data.items()}
                    logger.info("Retrieved global model from server")
            except Exception as e:
                logger.warning(f"Could not retrieve global model: {e}")

            # Participate in round
            gradients, metrics = self.federated_client.participate_in_round(global_model)

            # Send update to server
            self._send_federated_update(gradients, metrics)

            # Update local metrics for dashboard
            update_metrics(
                avg_loss=metrics.loss,
                avg_accuracy=metrics.accuracy
            )
            set_model_versions(f"local_v{metrics.round_number}", None)

            logger.info(f"Participated in federated round {metrics.round_number}")

        except Exception as e:
            logger.error(f"Federated round participation error: {e}")

    def _send_federated_update(self, gradients, metrics):
        """Send federated update to server."""
        try:
            # Prepare payload
            payload = {
                'client_id': self.config.client_id,
                'gradients': {k: v.cpu().tolist() for k, v in gradients.items()},
                'samples': metrics.samples_trained,
                'loss': metrics.loss,
                'accuracy': metrics.accuracy,
                'timestamp': metrics.timestamp.isoformat()
            }

            # Send to server
            http_url = self.config.server_url.replace('ws://', 'http://').replace(':8765', ':5000')
            response = requests.post(f"{http_url}/federation/api/update", json=payload, timeout=10)

            if response.status_code == 200:
                logger.info(f"Sent federated update to server: round {metrics.round_number}")
            else:
                logger.warning(f"Failed to send federated update: {response.status_code}")

        except Exception as e:
            logger.error(f"Error sending federated update: {e}")

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