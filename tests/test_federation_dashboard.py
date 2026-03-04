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
