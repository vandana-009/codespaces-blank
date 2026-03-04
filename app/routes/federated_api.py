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
        # Update client metrics in the server
        try:
            from federated.metrics_bridge import update_client_status
            update_client_status(client_id, samples_contributed=samples, status='connected')
        except ImportError:
            pass
        
        logger.info(
            f"Metrics from {client_id}: samples={samples}, "
            f"loss={loss:.4f}, acc={accuracy:.4f}"
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
