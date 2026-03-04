"""
Real-Time AI-NIDS Orchestrator
==============================
Coordinates real-time packet capture, detection, mitigation, and federated learning.
"""

import asyncio
import logging
import threading
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
import signal
import sys

from collectors.live_capture import LiveCaptureManager, DetectionCallback
from detection.detector import DetectionEngine
from detection.alert_manager import AlertManager, create_alert_manager
from mitigation.mitigation_module import create_mitigation_module
from response.firewall_manager import FirewallManager
from federated.federated_server import FederatedServer
from federated.federated_client_manager import FederatedClientManager
from app.models.database import db
from app import create_app

logger = logging.getLogger(__name__)


@dataclass
class RealtimeConfig:
    """Configuration for real-time operations."""
    # Packet capture
    capture_interface: str = "eth0"
    capture_filter: str = "tcp or udp"
    max_packets_per_second: int = 10000

    # Detection
    detection_batch_size: int = 100
    detection_interval: float = 1.0  # seconds

    # Federated learning
    federated_enabled: bool = True
    federated_round_interval: int = 300  # 5 minutes
    min_clients_for_round: int = 3

    # Mitigation
    auto_mitigation_threshold: float = 0.85
    mitigation_enabled: bool = True

    # General
    max_workers: int = 4
    log_level: str = "INFO"


class RealtimeOrchestrator:
    """
    Main orchestrator for real-time AI-NIDS operations.

    Coordinates:
    - Live packet capture
    - Real-time detection
    - Automatic mitigation
    - Federated learning
    - System monitoring
    """

    def __init__(self, config: RealtimeConfig):
        self.config = config
        self.running = False
        self.shutdown_event = asyncio.Event()

        # Core components
        self.capture_manager = None
        self.detection_engine = None
        self.alert_manager = None
        self.mitigation_module = None
        self.federated_server = None
        self.federated_manager = None

        # Stats
        self.stats = {
            'packets_captured': 0,
            'detections_made': 0,
            'alerts_generated': 0,
            'mitigations_applied': 0,
            'federated_rounds': 0,
            'start_time': None
        }

        # Threads
        self.threads = []

        logger.info("Real-time orchestrator initialized")

    async def initialize(self):
        """Initialize all components."""
        logger.info("Initializing real-time components...")

        # Create Flask app context for database access
        app = create_app()
        self.app = app

        with app.app_context():
            # Initialize detection engine
            self.detection_engine = DetectionEngine()

            # Initialize alert manager with mitigation
            firewall_manager = FirewallManager()
            self.mitigation_module = create_mitigation_module(
                firewall_manager=firewall_manager,
                db_session=db.session
            )
            self.alert_manager = create_alert_manager(
                db_session=db.session,
                mitigation_module=self.mitigation_module
            )

            # Initialize packet capture
            detection_callback = DetectionCallback(
                detector=self.detection_engine,
                alert_manager=self.alert_manager
            )
            self.capture_manager = LiveCaptureManager(detection_callback=detection_callback)

            # Initialize federated learning
            if self.config.federated_enabled:
                self.federated_server = FederatedServer()
                self.federated_manager = FederatedClientManager()

        logger.info("All components initialized successfully")

    async def start(self):
        """Start real-time operations."""
        logger.info("Starting real-time AI-NIDS operations...")
        self.running = True
        self.stats['start_time'] = datetime.utcnow()

        try:
            # Start packet capture
            await self._start_packet_capture()

            # Start federated learning if enabled
            if self.config.federated_enabled:
                await self._start_federated_learning()

            # Start monitoring
            await self._start_monitoring()

            # Wait for shutdown signal
            await self.shutdown_event.wait()

        except Exception as e:
            logger.error(f"Error in real-time operations: {e}")
            raise
        finally:
            await self.stop()

    async def stop(self):
        """Stop all operations."""
        logger.info("Stopping real-time operations...")
        self.running = False

        # Stop packet capture
        if self.capture_manager:
            await self.capture_manager.stop()

        # Stop federated learning
        if self.federated_server:
            await self.federated_server.stop()

        # Stop threads
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=5)

        logger.info("Real-time operations stopped")

    async def _start_packet_capture(self):
        """Start live packet capture."""
        logger.info(f"Starting packet capture on interface {self.config.capture_interface}")

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
        self.threads.append(thread)

        logger.info("Packet capture started")

    async def _start_federated_learning(self):
        """Start federated learning operations."""
        logger.info("Starting federated learning operations")

        def federated_thread():
            try:
                # Start federated server
                self.federated_server.start()

                # Start client manager
                self.federated_manager.start()

                # Run federated rounds
                while self.running:
                    try:
                        # Check if we have enough clients
                        active_clients = len(self.federated_manager.get_active_clients())
                        if active_clients >= self.config.min_clients_for_round:
                            logger.info(f"Starting federated round with {active_clients} clients")

                            # Run federated learning round
                            round_result = self.federated_server.run_federated_round()
                            if round_result:
                                self.stats['federated_rounds'] += 1
                                logger.info(f"Federated round {self.stats['federated_rounds']} completed")

                        time.sleep(self.config.federated_round_interval)

                    except Exception as e:
                        logger.error(f"Federated learning round error: {e}")
                        time.sleep(60)  # Wait before retry

            except Exception as e:
                logger.error(f"Federated learning error: {e}")

        thread = threading.Thread(target=federated_thread, daemon=True)
        thread.start()
        self.threads.append(thread)

        logger.info("Federated learning started")

    async def _start_monitoring(self):
        """Start system monitoring."""
        logger.info("Starting system monitoring")

        def monitoring_thread():
            while self.running:
                try:
                    # Update stats
                    if self.capture_manager:
                        self.stats['packets_captured'] = self.capture_manager.get_packet_count()

                    if self.alert_manager:
                        self.stats['alerts_generated'] = len(self.alert_manager.get_recent_alerts(hours=1))

                    if self.mitigation_module:
                        mitigation_stats = self.mitigation_module.get_mitigation_stats()
                        self.stats['mitigations_applied'] = mitigation_stats.get('executed_strategies', 0)

                    # Log stats every minute
                    if int(time.time()) % 60 == 0:
                        logger.info(f"Realtime stats: {self.stats}")

                    time.sleep(10)

                except Exception as e:
                    logger.error(f"Monitoring error: {e}")
                    time.sleep(30)

        thread = threading.Thread(target=monitoring_thread, daemon=True)
        thread.start()
        self.threads.append(thread)

        logger.info("System monitoring started")

    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics."""
        runtime = None
        if self.stats['start_time']:
            runtime = (datetime.utcnow() - self.stats['start_time']).total_seconds()

        return {
            **self.stats,
            'runtime_seconds': runtime,
            'components_status': {
                'packet_capture': self.capture_manager is not None and self.capture_manager.is_running(),
                'detection': self.detection_engine is not None,
                'alert_manager': self.alert_manager is not None,
                'mitigation': self.mitigation_module is not None,
                'federated_server': self.federated_server is not None and self.config.federated_enabled,
                'federated_manager': self.federated_manager is not None and self.config.federated_enabled
            }
        }

    async def reload_config(self, new_config: RealtimeConfig):
        """Reload configuration."""
        logger.info("Reloading configuration...")
        old_config = self.config
        self.config = new_config

        # Restart components if necessary
        if old_config.capture_interface != new_config.capture_interface:
            logger.info("Restarting packet capture with new interface")
            if self.capture_manager:
                await self.capture_manager.stop()
            await self._start_packet_capture()

        logger.info("Configuration reloaded")


def create_realtime_orchestrator(config: Optional[RealtimeConfig] = None) -> RealtimeOrchestrator:
    """Create a real-time orchestrator with default config."""
    if config is None:
        config = RealtimeConfig()
    return RealtimeOrchestrator(config)


async def main():
    """Main entry point for real-time operations."""
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Create orchestrator
    config = RealtimeConfig()
    orchestrator = create_realtime_orchestrator(config)

    # Setup signal handlers
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}, shutting down...")
        asyncio.create_task(orchestrator.stop())

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        # Initialize and start
        await orchestrator.initialize()
        await orchestrator.start()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())