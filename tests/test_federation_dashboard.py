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
        # raw JSON debug box should be present
        assert b'Raw Metrics JSON' in resp.data


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
        # initial state: server_id may already be populated by the
        # application startup; our concern is just that the endpoint returns a
        # string rather than a bare null.
        resp = c.get('/federation/api/metrics')
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data['server_id'], str)
        assert data['server_id'] != None

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


def test_submit_metrics_triggers_server_rounds(setup_app):
    """Posting to federated API should update internal state and advance rounds."""
    app = setup_app
    app.config['PUBLIC_FEDERATION_DASHBOARD'] = True
    from federated.federated_server import create_federated_server
    from federated.federated_client import LocalModel

    # create a fresh server instance; scheduler will auto-start but we'll
    # manage rounds manually via metrics submissions
    server = create_federated_server(LocalModel(), min_clients=2)
    server.register_client('a', 'org', '127.0.0.1/32')
    server.register_client('b', 'org', '127.0.0.1/32')

    with app.test_client() as c:
        # first client posts metrics (including extra fields that dashboard
        # should mirror)
        resp = c.post('/api/federated/submit-metrics', json={
            'client_id': 'a',
            'samples': 5,
            'loss': 1.0,
            'accuracy': 0.5,
            'avg_accuracy': 0.5,
            'avg_loss': 1.0
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['current_round'] >= 1

        # second client posts metrics – should bump round counter again
        resp2 = c.post('/api/federated/submit-metrics', json={
            'client_id': 'b',
            'samples': 7,
            'loss': 0.8,
            'accuracy': 0.6,
            'avg_accuracy': 0.6,
            'avg_loss': 0.8
        })
        assert resp2.status_code == 200
        data2 = resp2.get_json()
        assert data2['current_round'] >= data['current_round']

        # metrics endpoint should now report nonzero sample counts
        dmetrics = c.get('/federation/api/metrics').get_json()
        found = {c['client_id']: c for c in dmetrics['connected_clients']}
        assert found['a']['samples_contributed'] == 5
        assert found['b']['samples_contributed'] == 7
        # because we included accuracy/loss above the client record should
        # now include those fields as well (the dashboard poller/framework
        # will mirror whatever extras were sent)
        assert 'avg_accuracy' in found['a']
        assert 'avg_loss' in found['a']
        assert dmetrics['current_round'] >= 1

