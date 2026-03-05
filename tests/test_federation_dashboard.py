"""Unit tests for the federation server dashboard blueprint."""

from app import create_app, db
from app.models.database import User
import pytest


@pytest.fixture(autouse=True)
def setup_app(tmp_path, monkeypatch):
    """Configure a fresh application and database for each test."""
    app = create_app('testing')
    app.config['WTF_CSRF_ENABLED'] = False  # simplify form posts
    with app.app_context():
        db.drop_all()
        db.create_all()
        # ensure admin user exists
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


def test_dashboard_redirects_to_login(setup_app):
    """When PUBLIC_FEDERATION_DASHBOARD is False the route should redirect."""
    app = setup_app
    app.config['PUBLIC_FEDERATION_DASHBOARD'] = False
    with app.test_client() as c:
        resp = c.get('/federation/dashboard')
        assert resp.status_code == 302
        assert '/auth/login' in resp.headers.get('Location', '')

def test_dashboard_open_when_public(setup_app):
    """When the flag is True anyone can access without logging in."""
    app = setup_app
    app.config['PUBLIC_FEDERATION_DASHBOARD'] = True
    with app.test_client() as c:
        resp = c.get('/federation/dashboard')
        assert resp.status_code == 200
        assert b'Federation' in resp.data


def test_dashboard_access_after_login(setup_app):
    """Logged‑in users can always view the dashboard regardless of flag."""
    app = setup_app
    app.config['PUBLIC_FEDERATION_DASHBOARD'] = False
    with app.test_client() as c:
        login(c)
        resp = c.get('/federation/dashboard')
        assert resp.status_code == 200
        assert b'Federation' in resp.data


def test_dashboard_trailing_slash(setup_app):
    app = setup_app
    with app.test_client() as c:
        login(c)
        # with trailing slash should also work now that strict_slashes=False
        resp = c.get('/federation/dashboard/')
        assert resp.status_code == 200
        assert b'Federation' in resp.data


def test_stream_endpoint_trailing_slash(setup_app):
    app = setup_app
    with app.test_client() as c:
        login(c)
        resp = c.get('/federation/stream/')
        # SSE response may stream forever; we only check that route exists
        assert resp.status_code == 200
        assert b'text/event-stream' in resp.headers.get('Content-Type', b'').encode()


def test_metrics_endpoint_defaults_and_push(setup_app):
    """The /federation/api/metrics endpoint should report a sensible default
    for server_id and accept updates via the ingest API.

    When the federation server runs externally it pushes round events to the
    dashboard; previously these messages lacked the server_id which resulted
    in ``null`` appearing in metrics output.  This test exercises the new
    behaviour.
    """
    app = setup_app
    app.config['PUBLIC_FEDERATION_DASHBOARD'] = True
    with app.test_client() as c:
        # initial state: no server_id set, should be 'unknown'
        resp = c.get('/federation/api/metrics')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['server_id'] == 'unknown'

        # push a round including a server_id
        payload = {
            'round': 1,
            'participants': 2,
            'samples': 100,
            'loss': 0.1,
            'accuracy': 0.9,
            'model_version': 'deadbeef',
            'server_id': 'test-server-42',
            'aggregation_strategy': 'fedavg'
        }
        resp2 = c.post('/api/federation/push-round', json=payload)
        assert resp2.status_code == 200

        resp = c.get('/federation/api/metrics')
        data = resp.get_json()
        assert data['server_id'] == 'test-server-42'
        assert data['aggregation_strategy'] == 'fedavg'
        assert data['current_round'] == 1
