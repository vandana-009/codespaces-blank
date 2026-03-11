"""
Federation Metrics Bridge
========================
Integrates FederatedServer with the Federation Dashboard.
"""

# we may need to peek at the running server when pushing metrics so that the
# HTTP payload can include the server identifier.  import lazily to avoid
# circular import problems during server creation.
from .federated_server import get_global_server
import logging

logger = logging.getLogger(__name__)

def initialize_federation_dashboard_metrics(server):
    """Initialize federation dashboard with server data."""
    try:
        from app.routes.federation_dashboard import (
            update_federation_metrics, add_client_connection
        )
        
        update_federation_metrics(
            server_id=server.config.server_id,
            aggregation_strategy=server.config.aggregation_strategy.value,
            current_round=server.current_round,
            global_model_version=getattr(server, 'global_model_hash', None)
        )
        
        # Register existing clients
        for client in server.clients.values():
            add_client_connection(
                client.client_id,
                client.organization,
                client.subnet
            )
    except ImportError:
        # Fallback: if running as a separate process, POST initial server
        # state to the Flask ingest endpoints so the dashboard can be primed.
        try:
            import os
            import requests
            dashboard_url = os.environ.get('DASHBOARD_PUSH_URL', 'http://localhost:5000')
            requests.post(
                f"{dashboard_url.rstrip('/')}/api/federation/push-round",
                json={
                    'round': server.current_round,
                    'participants': len(server.clients),
                    'samples': sum(c.total_samples_contributed for c in server.clients.values()),
                    'loss': 0.0,
                    'accuracy': 0.0,
                    'model_version': getattr(server, 'global_model_hash', None)
                },
                timeout=3
            )
            for client in server.clients.values():
                try:
                    requests.post(
                        f"{dashboard_url.rstrip('/')}/api/federation/push-client",
                        json={'client_id': client.client_id, 'organization': client.organization, 'subnet': client.subnet},
                        timeout=3
                    )
                except Exception:
                    continue
        except Exception:
            pass


def notify_client_connected(client_id, org, subnet):
    """Notify dashboard of client connection."""
    # First try in-process update (works if server and Flask share memory)
    try:
        from app.routes.federation_dashboard import add_client_connection
        add_client_connection(client_id, org, subnet)
    except Exception:
        # Fallback: POST to the Flask ingest endpoint so an external server
        # process can still push updates to the dashboard.
        try:
            import os
            import requests
            dashboard_url = os.environ.get('DASHBOARD_PUSH_URL', 'http://localhost:5000')
            requests.post(
                f"{dashboard_url.rstrip('/')}/api/federation/push-client",
                json={'client_id': client_id, 'organization': org, 'subnet': subnet},
                timeout=3
            )
        except Exception:
            pass


def notify_round_completed(round_num, participants, samples, loss, accuracy, model_version):
    """Notify dashboard of completed round.

    When running the server in a separate process the bridge uses the HTTP
    ingest endpoints.  Previously the payload only included round-specific
    stats which meant the dashboard never learned the server's identifier
    or aggregation strategy.  As a result `GET /federation/api/metrics`
    could return ``server_id: null`` which confused operators.  We now send
    the server_id with every push so the dashboard can stay in-sync even
    when the two processes are isolated.
    """
    # Prefer HTTP push so separate server processes can notify the dashboard.
    try:
        import os
        import requests
        dashboard_url = os.environ.get('DASHBOARD_PUSH_URL', 'http://localhost:5000')
        payload = {
            'round': round_num,
            'participants': participants,
            'samples': samples,
            'loss': loss,
            'accuracy': accuracy,
            'model_version': model_version
        }
        server = get_global_server()
        if server and hasattr(server, 'config'):
            payload['server_id'] = server.config.server_id
            payload['aggregation_strategy'] = server.config.aggregation_strategy.value

        logger.info(f"Pushing round {round_num} to dashboard at {dashboard_url}/api/federation/push-round")
        response = requests.post(
            f"{dashboard_url.rstrip('/')}/api/federation/push-round",
            json=payload,
            timeout=3
        )
        logger.info(f"Dashboard push-round response: {response.status_code} - {response.text}")
        # If POST succeeded, we're done
        if response.status_code == 200:
            return
    except requests.exceptions.ConnectionError as e_conn:
        logger.warning(f"Could not connect to dashboard at {dashboard_url}: {e_conn}")
    except Exception as e_http:
        logger.warning(f"HTTP push to dashboard failed: {e_http}")

    # Fallback: try in-process update (only works when Flask is imported in same process)
    try:
        from app.routes.federation_dashboard import record_round_completion
        record_round_completion(
            round_num, participants, samples, loss, accuracy, model_version
        )
        logger.info(f"Round {round_num} recorded in dashboard via direct import (fallback)")
    except Exception as e_direct:
        logger.error(f"Failed to notify dashboard of round {round_num}: {e_direct}")

    # Also write a durable, cross-process last-round file so external dashboard
    # processes can pick it up even if HTTP or in-process notifications fail.
    try:
        import json
        last_round_path = '/tmp/federation_last_round.json'
        with open(last_round_path, 'w') as fh:
            json.dump({
                'round': round_num,
                'participants': participants,
                'samples': samples,
                'loss': loss,
                'accuracy': accuracy,
                'model_version': model_version,
                'server_id': payload.get('server_id') if isinstance(payload, dict) else None,
                'aggregation_strategy': payload.get('aggregation_strategy') if isinstance(payload, dict) else None,
                'ts': __import__('datetime').datetime.utcnow().isoformat()
            }, fh)
        logger.info(f"Wrote last-round file to {last_round_path}")
    except Exception as e_file:
        logger.warning(f"Failed to write last-round file: {e_file}")


def notify_client_update(client_id, samples_contributed=0, rounds_participated=0, status='connected', **extra):
    """Notify dashboard of client metrics update.

    ``extra`` keyword arguments are forwarded to the dashboard so it can
    display additional information such as ``avg_accuracy`` or
    ``total_anomalies``.
    """
    try:
        from app.routes.federation_dashboard import update_client_status
        update_client_status(client_id, samples_contributed, rounds_participated, status, **extra)
    except Exception:
        try:
            import os
            import requests
            dashboard_url = os.environ.get('DASHBOARD_PUSH_URL', 'http://localhost:5000')
            payload = {
                'client_id': client_id,
                'samples_contributed': samples_contributed,
                'rounds_participated': rounds_participated,
                'status': status
            }
            payload.update(extra)
            requests.post(
                f"{dashboard_url.rstrip('/')}/api/federation/push-update",
                json=payload,
                timeout=3
            )
        except Exception:
            pass


# Alias for federated_api.py usage
update_client_status = notify_client_update
