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
        assert data['avg_loss'] is None
        assert data['avg_accuracy'] is None
        # versions and latency are still None by default
        assert data['model_version_local'] is None
        assert data['model_version_global'] is None
        assert data['update_latency'] is None


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
