"""Client node service launcher
===============================

When the Flask application is started with CLIENT_ID set in the
configuration, this module will spin up background tasks that perform
all of the work that a federated client is expected to do:

* live packet capture and feature extraction (or a seeded data pipeline)
* run the detection engine and alert manager
* participate in federated learning (via RealtimeFederatedClient)
* feed metrics into the local dashboard

The implementation here is intentionally lightweight; for a production
setup you would replace the dummy capture logic with the real
`collectors` modules and integrate with the local network.
"""

import asyncio
import threading
import logging
import os

from config import Config

logger = logging.getLogger(__name__)


def start_client_services(app):
    """Start federated client related background services if configured."""
    cfg = app.config
    client_id = cfg.get('CLIENT_ID')
    if not client_id:
        return

    server_url = cfg.get('FEDERATED_SERVER_URL')
    client_type = cfg.get('CLIENT_TYPE', 'unknown')
    capture_interface = os.environ.get('CAPTURE_INTERFACE', 'eth0')

    from federated.realtime_federated_client import RealtimeFederatedConfig, RealtimeFederatedClient

    def _run_client_loop():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        config = RealtimeFederatedConfig(
            client_id=client_id,
            server_url=server_url,
            capture_interface=capture_interface
        )
        client = RealtimeFederatedClient(config)
        try:
            loop.run_until_complete(client.initialize())
            loop.run_until_complete(client.start())
            app.logger.info(f"Federated client {client_id} started (type={client_type})")
            loop.run_forever()
        except Exception as e:
            app.logger.error(f"Error running federated client: {e}")

    thread = threading.Thread(target=_run_client_loop, daemon=True)
    thread.start()
    app.logger.info("Spawned federated client background thread")
