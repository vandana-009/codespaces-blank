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
from datetime import datetime
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


def update_client_status(client_id, samples=None, rounds=None, status=None):
    """Update client status."""
    with _federation_lock:
        for client in _federation_metrics['connected_clients']:
            if client['client_id'] == client_id:
                if samples is not None:
                    client['samples_contributed'] += samples
                if rounds is not None:
                    client['rounds_participated'] = rounds
                if status is not None:
                    client['status'] = status
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

                    # Ensure client present then update samples
                    _ensure_client_present(client_id, org, subnet)
                    # We set samples_contributed to the latest value (not additive)
                    with _federation_lock:
                        for client in _federation_metrics['connected_clients']:
                            if client['client_id'] == client_id:
                                client['samples_contributed'] = samples
                                if rounds is not None:
                                    client['rounds_participated'] = rounds
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


@federation_dashboard_bp.route('/api/rounds')
def get_rounds():
    """Get rounds history."""
    with _federation_lock:
        return jsonify(_federation_metrics['rounds_history'][-20:])


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
