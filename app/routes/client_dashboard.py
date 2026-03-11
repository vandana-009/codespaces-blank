from flask import Blueprint, render_template, jsonify, Response
from flask_login import login_required
import json
import time
from threading import Lock

client_dashboard_bp = Blueprint('client_dashboard', __name__, url_prefix='/client')

# Shared metrics dictionary - updated by client processes
_client_metrics = {
    'alerts': [],
    'anomaly_scores': [],
    'model_version_local': None,
    'model_version_global': None,
    'update_latency': None,
    'mitigation_suggestions': []
}
_metrics_lock = Lock()


# helper functions for other modules to update the metrics

def update_metrics(**kwargs):
    with _metrics_lock:
        _client_metrics.update(kwargs)


def record_alert(alert):
    with _metrics_lock:
        entry = alert.to_dict() if hasattr(alert, 'to_dict') else alert
        _client_metrics['alerts'].append(entry)
        if len(_client_metrics['alerts']) > 20:
            _client_metrics['alerts'] = _client_metrics['alerts'][-20:]


def record_anomaly(score):
    with _metrics_lock:
        _client_metrics['anomaly_scores'].append(score)
        if len(_client_metrics['anomaly_scores']) > 100:
            _client_metrics['anomaly_scores'] = _client_metrics['anomaly_scores'][-100:]


def set_model_versions(local, global_):
    with _metrics_lock:
        _client_metrics['model_version_local'] = local
        _client_metrics['model_version_global'] = global_


def record_latency(lat):
    with _metrics_lock:
        _client_metrics['update_latency'] = lat


def add_mitigation_suggestion(sugg):
    with _metrics_lock:
        _client_metrics['mitigation_suggestions'].append(sugg)
        if len(_client_metrics['mitigation_suggestions']) > 10:
            _client_metrics['mitigation_suggestions'] = _client_metrics['mitigation_suggestions'][-10:]


@client_dashboard_bp.route('/dashboard')
@login_required
def client_dashboard():
    """Render the client-local dashboard page."""
    return render_template('client_dashboard.html')


@client_dashboard_bp.route('/dashboard/stream')
@login_required
def dashboard_stream():
    """Server-sent events endpoint streaming metrics."""
    def event_stream():
        while True:
            with _metrics_lock:
                data = dict(_client_metrics)
            yield f"data: {json.dumps(data)}\n\n"
            time.sleep(1)
    return Response(event_stream(), mimetype='text/event-stream')


@client_dashboard_bp.route('/metrics')
def get_metrics():
    """
    Get current client metrics as JSON.
    Used by client_metrics_reporter.py to report to federated server.
    """
    with _metrics_lock:
        data = dict(_client_metrics)
    
    # Calculate aggregate metrics based on in‑memory lists.
    # When the service has just started or only seeded a database the lists
    # will be empty; in that case we fall back to querying the local database
    # so that `curl /client/metrics` reflects the seeded alerts/flows rather
    # than appearing completely blank.
    alerts = data.get('alerts', [])
    anomaly_scores = data.get('anomaly_scores', [])

    # if there are no in-memory alerts, look at the database
    if not alerts:
        try:
            from flask import current_app
            from app.models.database import Alert, NetworkFlow

            with current_app.app_context():
                total_from_db = Alert.query.count()
                if total_from_db > 0:
                    alerts = [a.to_dict() for a in Alert.query.order_by(Alert.timestamp.desc()).limit(5).all()]
                # also update anomaly count from flows if available
                anomalies_db = NetworkFlow.query.filter_by(is_anomaly=True).count()
                if anomalies_db > 0 and not anomaly_scores:
                    anomaly_scores = [0.0] * anomalies_db  # placeholder list just for count
        except Exception:
            pass

    import statistics

    avg_loss = statistics.mean(anomaly_scores) if anomaly_scores else None
    avg_accuracy = (1.0 - avg_loss) if avg_loss is not None else None

    # ensure numeric metrics are never null
    metrics = {
        'total_samples': len(alerts),
        'total_anomalies': len(anomaly_scores),
        'avg_loss': avg_loss if avg_loss is not None else 0.0,
        'avg_accuracy': avg_accuracy if avg_accuracy is not None else 0.0,
        'model_version_local': data.get('model_version_local'),
        'model_version_global': data.get('model_version_global'),
        'update_latency': data.get('update_latency') if data.get('update_latency') is not None else 0.0,
        'last_alerts': alerts[:5]
    }

    return jsonify(metrics)
