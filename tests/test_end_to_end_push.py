"""End-to-end test: client reporter pushes to dashboard ingest endpoint.

This test starts the Flask app in testing mode and routes the reporter's
HTTP calls through the Flask `test_client` by monkeypatching `requests`.
"""

import os
from urllib.parse import urlparse
import requests
from app import create_app
from app.models.database import User
import pytest


@pytest.fixture(autouse=True)
def app_setup(tmp_path):
    # ensure dashboard URL used by reporter points at the test app base
    os.environ['DASHBOARD_PUSH_URL'] = 'http://localhost:5000'
    app = create_app('testing')
    with app.app_context():
        # ensure admin user exists but not necessary here
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', email='admin@local', role='admin')
            admin.set_password('admin123')
            from app import db
            db.session.add(admin)
            db.session.commit()
    return app


class FakeResp:
    def __init__(self, flask_resp):
        self._flask = flask_resp
        self.status_code = flask_resp.status_code

    def json(self):
        return self._flask.get_json()

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")


def test_reporter_pushes_to_ingest(app_setup, monkeypatch):
    app = app_setup
    client = app.test_client()

    # pre-register client via ingest endpoint so update_client_status can find it
    reg = client.post('/api/federation/push-client', json={'client_id': 'test-client', 'organization': 'test-org', 'subnet': '127.0.0.1/32'})
    assert reg.status_code == 200

    # monkeypatch requests.get (local client metrics) and requests.post (pushes)
    def fake_get(url, timeout=2, **kwargs):
        # if reporter asks local client metrics, return sample JSON
        p = urlparse(url)
        if p.path.endswith('/client/metrics'):
            class Local:
                def __init__(self):
                    self.status_code = 200
                def json(self):
                    return {
                        'total_samples': 123,
                        'total_anomalies': 2,
                        'avg_loss': 0.25,
                        'avg_accuracy': 0.75,
                        'model_version_local': 'v1',
                        'model_version_global': None,
                        'update_latency': 1.2,
                        'last_alerts': []
                    }
                def raise_for_status(self):
                    return None
            return Local()
        # default: call real requests.get
        return requests.get.__wrapped__(url, timeout=timeout, **kwargs)

    def fake_post(url, json=None, timeout=5, **kwargs):
        p = urlparse(url)
        # route to the test client's path
        resp = client.post(p.path, json=json)
        return FakeResp(resp)

    monkeypatch.setattr('requests.get', fake_get)
    monkeypatch.setattr('requests.post', fake_post)

    # import reporter and run a single collect+submit
    from scripts.client_metrics_reporter import ClientMetricsReporter

    reporter = ClientMetricsReporter('test-client', 8001, server_url='http://localhost:8765', organization='test-org')

    # collect (will use fake_get)
    ok = reporter.collect_local_metrics()
    assert ok is True
    assert reporter.total_samples == 123

    # submit (will use fake_post -> routes to /api/federation/push-update)
    ok2 = reporter.submit_metrics_to_server()
    assert ok2 is True

    # verify dashboard state updated
    resp = client.get('/federation/api/metrics')
    assert resp.status_code == 200
    data = resp.get_json()
    # find our client
    clients = [c for c in data['connected_clients'] if c['client_id'] == 'test-client']
    assert len(clients) == 1
    cinfo = clients[0]
    assert cinfo['samples_contributed'] == 123
    assert cinfo['rounds_participated'] >= 0
    # the fake local metrics included accuracy/loss/anomalies; ensure they
    # were copied through into the dashboard record
    assert cinfo.get('avg_accuracy') == 0.75
    assert cinfo.get('avg_loss') == 0.25
    assert cinfo.get('total_anomalies') == 2
