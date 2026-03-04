"""
Federation Ingest API
=====================
Lightweight endpoints that allow an external federated server process to
push aggregation events into the Flask dashboard. This is used in demo mode
when the server runs in a separate process and cannot import the
`app.routes.federation_dashboard` module directly.
"""

from flask import Blueprint, request, jsonify, current_app
import logging

logger = logging.getLogger(__name__)

federation_ingest_bp = Blueprint('federation_ingest', __name__, url_prefix='/api/federation')


@federation_ingest_bp.route('/push-client', methods=['POST'])
def push_client():
    data = request.get_json() or {}
    client_id = data.get('client_id')
    org = data.get('organization', data.get('org', 'unknown'))
    subnet = data.get('subnet', '0.0.0.0/0')

    if not client_id:
        return jsonify({'error': 'client_id required'}), 400

    try:
        from app.routes.federation_dashboard import add_client_connection
        add_client_connection(client_id, org, subnet)
        return jsonify({'status': 'ok'}), 200
    except Exception as e:
        logger.exception('Failed to push client')
        return jsonify({'error': str(e)}), 500


@federation_ingest_bp.route('/push-round', methods=['POST'])
def push_round():
    data = request.get_json() or {}
    round_num = data.get('round') or data.get('round_num')
    participants = data.get('participants') or data.get('participants_count') or 0
    samples = data.get('samples') or 0
    loss = data.get('loss') or 0.0
    accuracy = data.get('accuracy') or 0.0
    model_version = data.get('model_version') or data.get('model_hash')

    if round_num is None:
        return jsonify({'error': 'round number required'}), 400

    try:
        from app.routes.federation_dashboard import record_round_completion
        record_round_completion(int(round_num), participants, int(samples), float(loss), float(accuracy), model_version)
        return jsonify({'status': 'ok'}), 200
    except Exception as e:
        logger.exception('Failed to push round')
        return jsonify({'error': str(e)}), 500


@federation_ingest_bp.route('/push-update', methods=['POST'])
def push_update():
    data = request.get_json() or {}
    client_id = data.get('client_id')
    samples = data.get('samples_contributed') or data.get('samples') or 0
    rounds = data.get('rounds_participated') or data.get('rounds') or 0
    status = data.get('status', 'connected')

    if not client_id:
        return jsonify({'error': 'client_id required'}), 400

    try:
        from app.routes.federation_dashboard import update_client_status
        update_client_status(client_id, samples=int(samples), rounds=int(rounds), status=status)
        return jsonify({'status': 'ok'}), 200
    except Exception as e:
        logger.exception('Failed to push update')
        return jsonify({'error': str(e)}), 500
