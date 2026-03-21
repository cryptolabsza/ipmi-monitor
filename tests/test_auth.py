"""
Tests for authentication and authorisation.

Covers:
  - POST /login (JSON mode)
  - GET  /logout
  - Auth decorators: @admin_required, @view_required, @login_required, @write_required
  - Proxy authentication via X-Fleet-Authenticated header
  - Rate limiting / brute-force protection
"""

import pytest


def _login(client, role='admin'):
    name_map = {'admin': 'testadmin', 'readwrite': 'testwriter', 'readonly': 'testreader'}
    with client.session_transaction() as sess:
        sess['logged_in'] = True
        sess['username'] = name_map[role]
        sess['user_role'] = role


def _logout(client):
    with client.session_transaction() as sess:
        sess.pop('logged_in', None)
        sess.pop('username', None)
        sess.pop('user_role', None)


# ===== Login =====

class TestLogin:

    def test_login_json_success(self, app_fixture):
        client, app, db, models = app_fixture
        with app.app_context():
            resp = client.post('/login', json={
                'username': 'testadmin', 'password': 'testpass',
            })
            assert resp.status_code == 200
            body = resp.get_json()
            assert body['status'] == 'success'
            assert body['role'] == 'admin'

    def test_login_invalid_credentials(self, app_fixture):
        client, app, db, models = app_fixture
        with app.app_context():
            resp = client.post('/login', json={
                'username': 'testadmin', 'password': 'wrongpass',
            })
            assert resp.status_code == 401
            assert 'error' in resp.get_json()

    def test_login_nonexistent_user(self, app_fixture):
        client, app, db, models = app_fixture
        with app.app_context():
            resp = client.post('/login', json={
                'username': 'nouser', 'password': 'anything',
            })
            assert resp.status_code == 401

    def test_login_sets_session(self, app_fixture):
        client, app, db, models = app_fixture
        with app.app_context():
            client.post('/login', json={
                'username': 'testwriter', 'password': 'writerpass',
            })
            with client.session_transaction() as sess:
                assert sess['logged_in'] is True
                assert sess['username'] == 'testwriter'
                assert sess['user_role'] == 'readwrite'


# ===== Logout =====

class TestLogout:

    def test_logout_clears_session(self, app_fixture):
        client, app, db, models = app_fixture
        _login(client, 'admin')
        with app.app_context():
            resp = client.get('/logout', follow_redirects=False)
            assert resp.status_code in (302, 301, 308)
            with client.session_transaction() as sess:
                assert 'logged_in' not in sess


# ===== Auth decorators =====

class TestAdminRequired:

    def test_admin_required_allows_admin(self, app_fixture):
        client, app, db, models = app_fixture
        _login(client, 'admin')
        with app.app_context():
            resp = client.post('/api/initial-setup/trigger')
            assert resp.status_code != 401

    def test_admin_required_rejects_readwrite(self, app_fixture):
        client, app, db, models = app_fixture
        _login(client, 'readwrite')
        with app.app_context():
            resp = client.post('/api/initial-setup/trigger',
                               headers={'Accept': 'application/json'})
            assert resp.status_code == 401

    def test_admin_required_rejects_anonymous(self, app_fixture):
        client, app, db, models = app_fixture
        with app.app_context():
            resp = client.post('/api/initial-setup/trigger',
                               headers={'Accept': 'application/json'})
            assert resp.status_code == 401


class TestWriteRequired:

    def test_write_required_allows_admin(self, app_fixture):
        client, app, db, models = app_fixture
        _login(client, 'admin')
        with app.app_context():
            resp = client.post('/api/servers/add', json={
                'bmc_ip': '10.50.50.50', 'server_name': 'wr-test',
            })
            assert resp.status_code == 200

    def test_write_required_allows_readwrite(self, app_fixture):
        client, app, db, models = app_fixture
        _login(client, 'readwrite')
        with app.app_context():
            resp = client.post('/api/servers/add', json={
                'bmc_ip': '10.50.50.51', 'server_name': 'wr-test2',
            })
            assert resp.status_code == 200

    def test_write_required_rejects_readonly(self, app_fixture):
        client, app, db, models = app_fixture
        _login(client, 'readonly')
        with app.app_context():
            resp = client.post('/api/servers/add', json={
                'bmc_ip': '10.50.50.52', 'server_name': 'wr-test3',
            })
            assert resp.status_code == 403

    def test_write_required_rejects_anonymous(self, app_fixture):
        client, app, db, models = app_fixture
        with app.app_context():
            resp = client.post('/api/servers/add',
                               json={'bmc_ip': '10.50.50.53', 'server_name': 'x'},
                               headers={'Accept': 'application/json'})
            assert resp.status_code == 401


class TestViewRequired:

    def test_view_required_allows_logged_in(self, app_fixture):
        client, app, db, models = app_fixture
        _login(client, 'readonly')
        with app.app_context():
            resp = client.get('/api/servers')
            assert resp.status_code == 200

    def test_view_required_rejects_anonymous_by_default(self, app_fixture):
        client, app, db, models = app_fixture
        with app.app_context():
            resp = client.get('/api/servers', headers={'Accept': 'application/json'})
            assert resp.status_code == 401

    def test_view_required_allows_anonymous_when_enabled(self, app_fixture):
        client, app, db, models = app_fixture
        with app.app_context():
            models['SystemSettings'].set('allow_anonymous_read', 'true')
        _logout(client)
        with app.app_context():
            resp = client.get('/api/servers')
            assert resp.status_code == 200


# ===== Proxy authentication =====

class TestProxyAuth:

    def test_proxy_auth_admin(self, app_fixture):
        client, app, db, models = app_fixture
        with app.app_context():
            resp = client.get('/api/servers', headers={
                'X-Fleet-Authenticated': 'true',
                'X-Fleet-Auth-User': 'proxyuser',
                'X-Fleet-Auth-Role': 'admin',
            })
            assert resp.status_code == 200

    def test_proxy_auth_readonly(self, app_fixture):
        client, app, db, models = app_fixture
        with app.app_context():
            resp = client.get('/api/servers', headers={
                'X-Fleet-Authenticated': 'true',
                'X-Fleet-Auth-User': 'proxyro',
                'X-Fleet-Auth-Role': 'readonly',
            })
            assert resp.status_code == 200

    def test_proxy_auth_write_denied_for_readonly(self, app_fixture):
        client, app, db, models = app_fixture
        with app.app_context():
            resp = client.post('/api/servers/add', json={
                'bmc_ip': '10.60.60.60', 'server_name': 'proxy-test',
            }, headers={
                'X-Fleet-Authenticated': 'true',
                'X-Fleet-Auth-User': 'proxyro',
                'X-Fleet-Auth-Role': 'readonly',
            })
            assert resp.status_code == 403

    def test_proxy_auth_without_username_ignored(self, app_fixture):
        client, app, db, models = app_fixture
        with app.app_context():
            resp = client.get('/api/servers', headers={
                'X-Fleet-Authenticated': 'true',
                'Accept': 'application/json',
            })
            assert resp.status_code == 401


# ===== Rate limiting =====

class TestRateLimiting:

    def test_rate_limit_after_max_attempts(self, app_fixture):
        client, app, db, models = app_fixture
        import ipmi_monitor.app as app_module
        orig = app_module.RATE_LIMIT_MAX_ATTEMPTS
        app_module.RATE_LIMIT_MAX_ATTEMPTS = 3
        try:
            with app.app_context():
                for _ in range(3):
                    client.post('/login', json={
                        'username': 'testadmin', 'password': 'wrong',
                    })
                resp = client.post('/login', json={
                    'username': 'testadmin', 'password': 'wrong',
                })
                assert resp.status_code == 429
                assert 'retry_after' in resp.get_json()
        finally:
            app_module.RATE_LIMIT_MAX_ATTEMPTS = orig

    def test_successful_login_resets_counter(self, app_fixture):
        client, app, db, models = app_fixture
        with app.app_context():
            client.post('/login', json={'username': 'testadmin', 'password': 'wrong'})
            client.post('/login', json={'username': 'testadmin', 'password': 'wrong'})
            resp = client.post('/login', json={
                'username': 'testadmin', 'password': 'testpass',
            })
            assert resp.status_code == 200
            resp2 = client.post('/login', json={
                'username': 'testadmin', 'password': 'wrong',
            })
            assert resp2.status_code == 401  # not 429
