"""Tests for client dashboard metrics endpoints."""

import os
# Ensure CLIENT_ID is set before importing the app so Config reads it
os.environ['CLIENT_ID'] = 'test-client'
os.environ['CLIENT_TYPE'] = 'unit'
from app import create_app, db
from app.models.database import User
import pytest


@pytest.fixture(autouse=True)
def setup_app(tmp_path, monkeypatch):
    # ensure the factory enables client-local routes by setting env var
    os.environ['CLIENT_ID'] = 'test-client'
    os.environ['CLIENT_TYPE'] = 'unit'
    app = create_app('testing')
    app.config['WTF_CSRF_ENABLED'] = False
    with app.app_context():
        db.drop_all()
        db.create_all()
        # ensure admin exists for login
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', email='admin@local', role='admin')
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
    return app


def login(client, username='admin', password='admin123'):
    return client.post(
        '/auth/login',
        data={'username': username, 'password': password},
        follow_redirects=True,
    )


def test_client_metrics_defaults(setup_app):
    """When no alerts/anomalies have been recorded the JSON fields should be
    null rather than misleading defaults.
    """
    app = setup_app
    with app.test_client() as c:
        resp = c.get('/client/metrics')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['total_samples'] == 0
        assert data['total_anomalies'] == 0
        # new behavior: numeric metrics are zero by default instead of null
        assert data['avg_loss'] == 0.0
        assert data['avg_accuracy'] == 0.0
        # versions remain None until set, latency is reported as 0.0
        assert data['model_version_local'] is None
        assert data['model_version_global'] is None
        assert data['update_latency'] == 0.0


def test_database_fallback_metrics(setup_app):
    """If the in-memory lists are empty but the database contains alerts/flows
    the `/client/metrics` endpoint should still return sensible numbers.
    This mirrors the behaviour after running the seeder and before any
    detection round has executed in the live client process."""
    from app.models.database import Alert, NetworkFlow, db

    with setup_app.app_context():
        # insert one alert and two anomaly flows
        a = Alert(source_ip='1.2.3.4', destination_ip='5.6.7.8',
                  source_port=1234, destination_port=80, protocol='TCP',
                  attack_type='Test', severity='low', confidence=0.5,
                  risk_score=0.5, timestamp=None, description='test')
        db.session.add(a)
        # create two flows marked anomalous
        nf1 = NetworkFlow(source_ip='10.0.0.1', destination_ip='10.0.0.2',
                          source_port=1000, destination_port=80, protocol='TCP',
                          duration=1.0, bytes_sent=100, bytes_recv=50,
                          packets_sent=1, packets_recv=1, total_bytes=150,
                          timestamp=None, is_anomaly=True)
        nf2 = NetworkFlow(source_ip='10.0.0.3', destination_ip='10.0.0.4',
                          source_port=1001, destination_port=443, protocol='TCP',
                          duration=2.0, bytes_sent=200, bytes_recv=100,
                          packets_sent=2, packets_recv=2, total_bytes=300,
                          timestamp=None, is_anomaly=True)
        db.session.add_all([nf1, nf2])
        db.session.commit()

    app = setup_app
    with app.test_client() as c:
        resp = c.get('/client/metrics')
        data = resp.get_json()
        # we expect at least one sample and two anomalies reported by count
        assert data['total_samples'] == 1
        assert data['total_anomalies'] == 2
        # averages still default to zero because we don't compute loss from DB
        assert data['avg_loss'] == 0.0
        assert data['avg_accuracy'] == 0.0


def test_recording_raises_metrics(setup_app):
    """Metrics reporter helper methods should populate the JSON output."""
    from app.routes.client_dashboard import record_anomaly, record_alert, update_metrics, set_model_versions, record_latency

    # simulate some activity
    record_alert({'foo': 'bar'})
    record_anomaly(0.2)
    record_anomaly(0.4)
    update_metrics(custom_field=123)
    set_model_versions('v1', 'v1-global')
    record_latency(5.5)

    app = setup_app
    with app.test_client() as c:
        resp = c.get('/client/metrics')
        data = resp.get_json()
        assert data['total_samples'] == 1  # one alert
        assert data['total_anomalies'] == 2
        assert abs(data['avg_loss'] - 0.3) < 1e-6
        assert abs(data['avg_accuracy'] - 0.7) < 1e-6
        assert data['model_version_local'] == 'v1'
        assert data['model_version_global'] == 'v1-global'
        assert data['update_latency'] == 5.5
