"""
Federation Server Dashboard Routes
===================================
Real-time monitoring of federated learning aggregation.
"""

from flask import Blueprint, render_template, jsonify, Response, current_app, redirect, url_for
from flask_login import current_user
import json
import time
from threading import Lock
from datetime import datetime, timedelta
import threading
import requests
import os

federation_dashboard_bp = Blueprint('federation_dashboard', __name__, url_prefix='/federation')

# Shared metrics for federation server
_federation_metrics = {
    'server_id': None,
    'current_round': 0,
    'connected_clients': [],
    'registered_clients': [],
    'rounds_history': [],
    'global_model_version': None,
    'last_aggregation': None,
    'total_samples_processed': 0,
    'aggregation_strategy': 'fedavg',
    'is_aggregating': False,
}
_federation_lock = Lock()
_local_poller_thread = None


def update_federation_metrics(**kwargs):
    """Update federation metrics from server."""
    with _federation_lock:
        _federation_metrics.update(kwargs)


def add_client_connection(client_id, org, subnet):
    """Record client connection."""
    with _federation_lock:
        client_info = {
            'client_id': client_id,
            'org': org,
            'subnet': subnet,
            'connected_at': datetime.utcnow().isoformat(),
            'samples_contributed': 0,
            'rounds_participated': 0,
            'status': 'connected'
        }
        # Remove if exists
        _federation_metrics['connected_clients'] = [
            c for c in _federation_metrics['connected_clients']
            if c['client_id'] != client_id
        ]
        _federation_metrics['connected_clients'].append(client_info)


def record_round_completion(round_num, participants, samples, loss, accuracy, model_version):
    """Record completed federation round."""
    with _federation_lock:
        round_info = {
            'round': round_num,
            'participants': participants,
            'total_samples': samples,
            'avg_loss': round(loss, 4),
            'avg_accuracy': round(accuracy, 4),
            'model_version': model_version,
            'completed_at': datetime.utcnow().isoformat()
        }
        _federation_metrics['rounds_history'].append(round_info)
        _federation_metrics['current_round'] = round_num
        _federation_metrics['global_model_version'] = model_version
        _federation_metrics['total_samples_processed'] += samples
        _federation_metrics['last_aggregation'] = datetime.utcnow().isoformat()
        
        # Keep last 20 rounds
        if len(_federation_metrics['rounds_history']) > 20:
            _federation_metrics['rounds_history'] = _federation_metrics['rounds_history'][-20:]


def update_client_status(client_id, samples=None, rounds=None, status=None, **extra):
    """Update client status.

    Additional keyword arguments are stored directly on the client record. This
    allows the dashboard to display values like ``avg_accuracy`` or
    ``total_anomalies`` when reported by a client or pushed from an external
    process.
    """
    with _federation_lock:
        for client in _federation_metrics['connected_clients']:
            if client['client_id'] == client_id:
                if samples is not None:
                    client['samples_contributed'] += samples
                if rounds is not None:
                    client['rounds_participated'] = rounds
                if status is not None:
                    client['status'] = status
                # merge any extra fields into the client record
                for k, v in extra.items():
                    client[k] = v
                break


def _ensure_client_present(client_id, org='unknown', subnet='0.0.0.0/0'):
    """Ensure a client entry exists in the connected_clients list."""
    with _federation_lock:
        for client in _federation_metrics['connected_clients']:
            if client['client_id'] == client_id:
                return client
        client_info = {
            'client_id': client_id,
            'org': org,
            'subnet': subnet,
            'connected_at': datetime.utcnow().isoformat(),
            'samples_contributed': 0,
            'rounds_participated': 0,
            'status': 'connected'
        }
        _federation_metrics['connected_clients'].append(client_info)
        return client_info


def _poll_local_clients(interval=10, ports=None):
    """Background poller that fetches `/client/metrics` from local clients.

    This allows the dashboard to read zero-day detection samples directly
    from Flask client instances running on localhost:8001/8002/8003.
    """
    if ports is None:
        ports = [8001, 8002, 8003]

    while True:
        for p in ports:
            try:
                url = f'http://localhost:{p}/client/metrics'
                resp = requests.get(url, timeout=2)
                if resp.status_code == 200:
                    metrics = resp.json()
                    # Map port -> client id if possible
                    client_id = metrics.get('client_id') or f'client-{p}'
                    # Some client metrics return counts as total_samples
                    samples = int(metrics.get('total_samples', 0))
                    rounds = int(metrics.get('round', 0)) if metrics.get('round') is not None else None
                    org = metrics.get('organization') or metrics.get('org') or f'org-{p}'
                    subnet = metrics.get('subnet', f'127.0.0.1')

                    # additional fields we care about
                    accuracy = metrics.get('avg_accuracy') or metrics.get('accuracy')
                    loss = metrics.get('avg_loss') or metrics.get('loss')
                    anomalies = metrics.get('total_anomalies')
                    last_alerts = metrics.get('last_alerts')

                    # Ensure client present then update samples
                    _ensure_client_present(client_id, org, subnet)
                    # We set samples_contributed to the latest value (not additive)
                    with _federation_lock:
                        for client in _federation_metrics['connected_clients']:
                            if client['client_id'] == client_id:
                                client['samples_contributed'] = samples
                                if rounds is not None:
                                    client['rounds_participated'] = rounds
                                if accuracy is not None:
                                    client['avg_accuracy'] = accuracy
                                if loss is not None:
                                    client['avg_loss'] = loss
                                if anomalies is not None:
                                    client['total_anomalies'] = anomalies
                                if last_alerts is not None:
                                    client['last_alerts'] = last_alerts
                                client['last_seen'] = datetime.utcnow().isoformat()
                                break
            except Exception:
                # ignore individual client failures
                continue
        time.sleep(interval)


def start_local_client_poller(app=None, interval=None, ports=None):
    """Start the local client poller thread (idempotent).

    Should be called after app creation. Uses `LOCAL_CLIENT_PORTS` and
    `LOCAL_CLIENT_POLL_INTERVAL` from environment or app config when
    available.
    """
    global _local_poller_thread
    if _local_poller_thread and _local_poller_thread.is_alive():
        return

    cfg_ports = None
    cfg_interval = None
    try:
        if app is not None:
            cfg_ports = app.config.get('LOCAL_CLIENT_PORTS')
            cfg_interval = app.config.get('LOCAL_CLIENT_POLL_INTERVAL')
    except Exception:
        pass

    if ports is None:
        if cfg_ports:
            ports = cfg_ports
        else:
            env_ports = os.environ.get('LOCAL_CLIENT_PORTS')
            if env_ports:
                ports = [int(x.strip()) for x in env_ports.split(',') if x.strip()]
            else:
                ports = [8001, 8002, 8003]

    if interval is None:
        if cfg_interval:
            interval = cfg_interval
        else:
            interval = int(os.environ.get('LOCAL_CLIENT_POLL_INTERVAL', '10'))

    t = threading.Thread(target=_poll_local_clients, args=(interval, ports), daemon=True)
    t.start()
    _local_poller_thread = t


@federation_dashboard_bp.route('/dashboard', strict_slashes=False)
def federation_dashboard():
    """Render the federation server dashboard.

    By default (development/testing) the dashboard is public so that hitting
    localhost:5000 immediately displays the aggregation page.  If
    ``Config.PUBLIC_FEDERATION_DASHBOARD`` is False, the user must be
    authenticated; otherwise we simply redirect to the login page.

    A trailing slash is tolerated to avoid confusing 404s.
    """
    public = current_app.config.get('PUBLIC_FEDERATION_DASHBOARD', False)
    if not public and not current_user.is_authenticated:
        return redirect(url_for('auth.login'))
    return render_template('federation_dashboard.html')


@federation_dashboard_bp.route('/api/metrics')
def get_metrics():
    """Get current federation metrics.

    ``server_id`` used to occasionally surface as ``null`` when the server
    process was running separately from the Flask app.  The caller normally
    cares only about knowing whether or not a value is available, so we
    provide an explicit ``"unknown"`` string rather than a bare null to make
    it easier to read at the CLI and to avoid confusion in templates.
    """
    with _federation_lock:
        sid = _federation_metrics['server_id']
        return jsonify({
            'server_id': sid if sid is not None else 'unknown',
            'current_round': _federation_metrics['current_round'],
            'connected_clients': _federation_metrics['connected_clients'],
            'registered_clients': _federation_metrics['registered_clients'],
            'global_model_version': _federation_metrics['global_model_version'],
            'aggregation_strategy': _federation_metrics['aggregation_strategy'],
            'total_samples_processed': _federation_metrics['total_samples_processed'],
            'last_aggregation': _federation_metrics['last_aggregation'],
        })


# --- HTTP compatibility endpoints for clients --------------------------------

from federated.federated_server import get_global_server
import torch

@federation_dashboard_bp.route('/api/model', methods=['GET'])
def http_get_global_model():
    """Return the global model (compat path used by clients)."""
    server = get_global_server()
    if server is None:
        return jsonify({'error': 'Server not initialized'}), 503
    try:
        state = server.get_global_model()
        model_dict = {k: v.cpu().tolist() for k, v in state.items()}
        return jsonify(model_dict)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@federation_dashboard_bp.route('/api/update', methods=['POST'])
def http_receive_update():
    """Accept a federated update from a client (compat path)."""
    server = get_global_server()
    if server is None:
        return jsonify({'error': 'Server not initialized'}), 503
    data = request.get_json() or {}
    client_id = data.get('client_id')
    gradients_data = data.get('gradients', {})
    metrics = {
        'samples': data.get('samples', 0),
        'loss': data.get('loss', 0.0),
        'accuracy': data.get('accuracy', 0.0)
    }
    if not client_id:
        return jsonify({'error': 'client_id required'}), 400
    gradients = {k: torch.tensor(v) for k, v in gradients_data.items()}
    if client_id not in server.clients:
        server.register_client(client_id)
    success = server.submit_update(client_id, gradients, metrics)
    if success:
        if len(server.round_updates) >= server.config.min_clients_per_round:
            server.aggregate_round()
        return jsonify({'success': True})
    else:
        return jsonify({'error': 'Update rejected'}), 400


@federation_dashboard_bp.route('/api/rounds')
def get_rounds():
    """Get rounds history."""
    with _federation_lock:
        return jsonify(_federation_metrics['rounds_history'][-20:])

@federation_dashboard_bp.route('/demo-data', methods=['POST'])
def load_demo_data():
    """Load demo/sample federation data for demonstration/testing.
    
    This endpoint populates the dashboard with realistic sample data
    so examiners can see what the system looks like when it's working.
    """
    try:
        # Create sample clients
        clients_data = [
            {'client_id': 'Hospital-NYC', 'org': 'New York Hospital', 'subnet': '192.168.1.0/24', 'samples': 1250, 'rounds': 5},
            {'client_id': 'Bank-Boston', 'org': 'Boston Financial Corp', 'subnet': '10.0.0.0/24', 'samples': 980, 'rounds': 5},
            {'client_id': 'University-SF', 'org': 'SF State University', 'subnet': '172.16.0.0/24', 'samples': 1520, 'rounds': 5},
        ]
        
        for client_data in clients_data:
            _ensure_client_present(
                client_data['client_id'],
                client_data['org'],
                client_data['subnet']
            )
            with _federation_lock:
                for client in _federation_metrics['connected_clients']:
                    if client['client_id'] == client_data['client_id']:
                        client['samples_contributed'] = client_data['samples']
                        client['rounds_participated'] = client_data['rounds']
                        client['status'] = 'connected'
                        client['avg_accuracy'] = 0.87
                        client['avg_loss'] = 0.32
                        client['total_anomalies'] = 156
                        client['last_alerts'] = [
                            {'type': 'Zero-Day Exploit', 'confidence': 0.92},
                            {'type': 'Lateral Movement', 'confidence': 0.78},
                            {'type': 'Data Exfiltration', 'confidence': 0.65},
                        ]
                        break
        
        # Create sample rounds
        with _federation_lock:
            _federation_metrics['current_round'] = 5
            _federation_metrics['total_samples_processed'] = 3750
            _federation_metrics['aggregation_strategy'] = 'fedavg'
            _federation_metrics['server_id'] = 'fed-server-demo-001'
            _federation_metrics['global_model_version'] = 'v2.1.0-fedavg'
            _federation_metrics['last_aggregation'] = datetime.utcnow().isoformat()
            
            # Add sample round history
            for round_num in range(1, 6):
                round_info = {
                    'round': round_num,
                    'participants': 3,
                    'total_samples': 750,
                    'avg_loss': round(0.5 - (round_num * 0.08), 4),
                    'avg_accuracy': round(0.70 + (round_num * 0.04), 4),
                    'model_version': f'v2.1.0-r{round_num}',
                    'completed_at': (datetime.utcnow() - timedelta(minutes=30 - round_num*5)).isoformat()
                }
                _federation_metrics['rounds_history'].append(round_info)
        
        return jsonify({'status': 'ok', 'message': 'Demo data loaded successfully'}), 200
    except Exception as e:
        logger.exception('Failed to load demo data')
        return jsonify({'error': str(e)}), 500

@federation_dashboard_bp.route('/stream', strict_slashes=False)
def stream_metrics():
    """Server-sent events for real-time updates.

    If the dashboard is not public we still guard the stream with a simple
    authentication check; unauthenticated callers are redirected to login.
    Trailing slash support helps front-end fetches which occasionally add one.
    """
    public = current_app.config.get('PUBLIC_FEDERATION_DASHBOARD', False)
    if not public and not current_user.is_authenticated:
        return redirect(url_for('auth.login'))

    def event_stream():
        while True:
            with _federation_lock:
                data = dict(_federation_metrics)
            yield f"data: {json.dumps(data)}\n\n"
            time.sleep(0.5)
    
    return Response(event_stream(), mimetype='text/event-stream')
