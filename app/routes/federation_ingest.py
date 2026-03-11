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


@federation_ingest_bp.route('/health', methods=['GET', 'POST'])
def health_check():
    """Health check endpoint to verify ingest API is running."""
    return jsonify({
        'status': 'ok',
        'service': 'federation-ingest-api',
        'message': 'Federation Ingest API is ready to receive metrics from federated server'
    }), 200


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

    # optional metadata that clients may include
    server_id = data.get('server_id')
    aggregation_strategy = data.get('aggregation_strategy')

    if round_num is None:
        logger.warning(f"push_round: Missing round number in payload: {data}")
        return jsonify({'error': 'round number required'}), 400

    logger.info(f"push_round: Received round {round_num} from server {server_id or 'unknown'}: "
                f"participants={participants}, samples={samples}, loss={loss:.4f}, accuracy={accuracy:.4f}")

    try:
        from app.routes.federation_dashboard import record_round_completion, update_federation_metrics

        # if the server posts a server_id (and maybe strategy) make sure the
        # dashboard state stays in-sync; this fixes the case where the
        # federation server runs in a distinct process and never imported the
        # dashboard module directly.
        if server_id or aggregation_strategy:
            kwargs = {}
            if server_id:
                kwargs['server_id'] = server_id
            if aggregation_strategy:
                kwargs['aggregation_strategy'] = aggregation_strategy
            logger.info(f"Updating federation metrics with {kwargs}")
            update_federation_metrics(**kwargs)

        record_round_completion(int(round_num), participants, int(samples), float(loss), float(accuracy), model_version)
        logger.info(f"✓ Round {round_num} successfully recorded in dashboard")
        return jsonify({'status': 'ok', 'message': f'Round {round_num} recorded'}), 200
    except Exception as e:
        logger.exception(f'✗ Failed to push round {round_num}')
        return jsonify({'error': str(e)}), 500


@federation_ingest_bp.route('/push-update', methods=['POST'])
def push_update():
    data = request.get_json() or {}
    client_id = data.get('client_id')
    samples = data.get('samples_contributed') or data.get('samples') or 0
    rounds = data.get('rounds_participated') or data.get('rounds') or 0
    status = data.get('status', 'connected')

    # optional extras that dashboard may display
    extras = {}
    for key in ('avg_accuracy', 'avg_loss', 'total_anomalies', 'last_alerts', 'organization', 'org', 'subnet'):
        if key in data:
            extras[key] = data[key]

    if not client_id:
        logger.warning(f"push_update: Missing client_id in payload: {data}")
        return jsonify({'error': 'client_id required'}), 400

    logger.info(f"push_update: Received update from {client_id}: samples={samples}, rounds={rounds}, status={status}")

    try:
        from app.routes.federation_dashboard import update_client_status
        update_client_status(
            client_id,
            samples=int(samples),
            rounds=int(rounds),
            status=status,
            **extras
        )
        logger.info(f"✓ Client {client_id} status updated in dashboard")
        return jsonify({'status': 'ok', 'message': f'Client {client_id} updated'}), 200
    except Exception as e:
        logger.exception(f'✗ Failed to push update for client {client_id}')
        return jsonify({'error': str(e)}), 500
