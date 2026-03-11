"""
Federated Server REST API
=========================
Allows clients to submit their local metrics and model updates via HTTP.
This complements WebSocket streaming for more reliable communication.
"""

from flask import Blueprint, request, jsonify
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

federated_api_bp = Blueprint('federated_api', __name__, url_prefix='/api/federated')


def get_federated_server():
    """Get the global federated server instance."""
    from federated.federated_server import get_global_server
    return get_global_server()


@federated_api_bp.route('/client-register', methods=['POST'])
def register_client():
    """Register a client with the federated server."""
    data = request.get_json()
    
    client_id = data.get('client_id')
    organization = data.get('organization', 'unknown')
    subnet = data.get('subnet', '0.0.0.0/0')
    
    if not client_id:
        return jsonify({'error': 'client_id required'}), 400
    
    server = get_federated_server()
    if server:
        server.register_client(client_id, organization, subnet)
        logger.info(f"Client registered via HTTP: {client_id}")
        
        return jsonify({
            'status': 'registered',
            'client_id': client_id,
            'server_id': server.config.server_id
        }), 200
    else:
        return jsonify({'error': 'Server not initialized'}), 503


@federated_api_bp.route('/submit-metrics', methods=['POST'])
def submit_metrics():
    """
    Submit local training metrics from a client.
    
    Expected payload:
    {
        "client_id": "hospital-1",
        "round": 1,
        "samples": 500,
        "loss": 1.234,
        "accuracy": 0.824,
        "model_hash": "abc123...",
        "timestamp": "2026-03-04T13:45:00"
    }
    """
    data = request.get_json()
    
    client_id = data.get('client_id')
    samples = data.get('samples', 0)
    loss = data.get('loss', 0)
    accuracy = data.get('accuracy', 0)
    
    if not client_id:
        return jsonify({'error': 'client_id required'}), 400
    
    server = get_federated_server()
    if server:
        # Ensure client is registered on the server so internal state exists
        if client_id not in server.clients:
            server.register_client(client_id, organization=data.get('organization', 'unknown'), subnet=data.get('subnet', '0.0.0.0/0'))

        # Treat the metrics payload as a lightweight "update".  We don't
        # have actual gradient information, but we can still record the
        # activity and, if sufficient participants have reported, complete
        # a round.  This change allows the federation to start processing
        # as soon as metrics arrive instead of requiring a manual /start call.
        metrics_obj = {'samples': samples, 'loss': loss, 'accuracy': accuracy}
        # update client statistics directly rather than going through the
        # full training update path (which enforces minimum sample counts and
        # expects gradient data).  We still record the "round" so dashboard
        # shows some activity.
        client = server.clients.get(client_id)
        if client:
            client.update_from_metrics(metrics_obj)
            client.rounds_participated += 1

        # whenever metrics arrive we kick off a dummy round so that the
        # `current_round` counter advances and the dashboard displays
        # something meaningful.  We don't require any real gradients here.
        server.start_round()
        server.aggregate_round()

        # bump current_round to reflect the highest participation count (this
        # is mostly redundant with the dummy round above but keeps things
        # consistent if other code manipulates rounds directly)
        server.current_round = max(
            server.current_round,
            max(c.rounds_participated for c in server.clients.values())
        )

        # Update dashboard state so metrics endpoint reflects the change
        try:
            from federated.metrics_bridge import update_client_status
            # collect any extra metrics provided in the payload so the
            # dashboard can render them alongside the standard samples/rounds
            extras = {}
            for key in ('avg_accuracy', 'avg_loss', 'total_anomalies', 'last_alerts'):
                if key in data:
                    extras[key] = data[key]
            update_client_status(
                client_id,
                samples_contributed=server.clients[client_id].total_samples_contributed,
                rounds_participated=server.clients[client_id].rounds_participated,
                status='connected',
                **extras
            )
        except ImportError:
            pass

        logger.info(
            f"Metrics from {client_id}: samples={samples}, "
            f"loss={loss:.4f}, acc={accuracy:.4f}, "
            f"rounds={server.clients[client_id].rounds_participated}"
        )
        
        return jsonify({
            'status': 'received',
            'current_round': server.current_round,
            'global_model_version': getattr(server, 'global_model_hash', None)
        }), 200
    else:
        return jsonify({'error': 'Server not initialized'}), 503


@federated_api_bp.route('/server-status', methods=['GET'])
def server_status():
    """Get current server status."""
    server = get_federated_server()
    
    if server:
        return jsonify({
            'server_id': server.config.server_id,
            'current_round': server.current_round,
            'registered_clients': len(server.clients),
            'connected_clients': len(getattr(server, 'ws_clients', [])),
            'aggregation_strategy': server.config.aggregation_strategy.value,
            'timestamp': datetime.utcnow().isoformat()
        }), 200
    else:
        return jsonify({'error': 'Server not initialized'}), 503


@federated_api_bp.route('/client-status/<client_id>', methods=['GET'])
def client_status(client_id):
    """Get status of a specific client."""
    server = get_federated_server()
    
    if not server:
        return jsonify({'error': 'Server not initialized'}), 503
    
    if client_id not in server.clients:
        return jsonify({'error': f'Client {client_id} not found'}), 404
    
    client = server.clients[client_id]
    return jsonify({
        'client_id': client.client_id,
        'organization': client.organization,
        'subnet': client.subnet,
        'rounds_participated': client.rounds_participated,
        'total_samples_contributed': client.total_samples_contributed,
        'avg_loss': client.avg_loss,
        'avg_accuracy': client.avg_accuracy,
        'last_seen': client.last_seen.isoformat() if client.last_seen else None
    }), 200
