"""
Federation Metrics Bridge
========================
Integrates FederatedServer with the Federation Dashboard.
"""

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
    """Notify dashboard of completed round."""
    try:
        from app.routes.federation_dashboard import record_round_completion
        record_round_completion(
            round_num, participants, samples, loss, accuracy, model_version
        )
    except Exception:
        try:
            import os
            import requests
            dashboard_url = os.environ.get('DASHBOARD_PUSH_URL', 'http://localhost:5000')
            requests.post(
                f"{dashboard_url.rstrip('/')}/api/federation/push-round",
                json={
                    'round': round_num,
                    'participants': participants,
                    'samples': samples,
                    'loss': loss,
                    'accuracy': accuracy,
                    'model_version': model_version
                },
                timeout=3
            )
        except Exception:
            pass


def notify_client_update(client_id, samples_contributed=0, rounds_participated=0, status='connected'):
    """Notify dashboard of client metrics update."""
    try:
        from app.routes.federation_dashboard import update_client_status
        update_client_status(client_id, samples_contributed, rounds_participated, status)
    except Exception:
        try:
            import os
            import requests
            dashboard_url = os.environ.get('DASHBOARD_PUSH_URL', 'http://localhost:5000')
            requests.post(
                f"{dashboard_url.rstrip('/')}/api/federation/push-update",
                json={
                    'client_id': client_id,
                    'samples_contributed': samples_contributed,
                    'rounds_participated': rounds_participated,
                    'status': status
                },
                timeout=3
            )
        except Exception:
            pass


# Alias for federated_api.py usage
update_client_status = notify_client_update
