"""
Tests for server CRUD API endpoints.

Covers:
  - GET  /api/servers          (list servers)
  - POST /api/servers/add      (add server)
  - GET  /api/servers/<bmc_ip> (single server detail)
  - DELETE /api/servers/<bmc_ip>
  - POST /api/servers/<bmc_ip>/deprecate
  - Auth required checks (401 without login)
"""

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _login(client, role='admin'):
    name_map = {'admin': 'testadmin', 'readwrite': 'testwriter', 'readonly': 'testreader'}
    with client.session_transaction() as sess:
        sess['logged_in'] = True
        sess['username'] = name_map[role]
        sess['user_role'] = role


def _seed_server(app, db, models, bmc_ip='10.0.0.1', name='test-server'):
    """Insert a Server + ServerStatus + ServerInventory."""
    with app.app_context():
        server = models['Server'](
            bmc_ip=bmc_ip, server_name=name, server_ip='10.0.0.2',
            enabled=True, status='active',
        )
        db.session.add(server)
        status = models['ServerStatus'](
            bmc_ip=bmc_ip, server_name=name, is_reachable=True, power_status='on',
        )
        db.session.add(status)
        inv = models['ServerInventory'](
            bmc_ip=bmc_ip, server_name=name, primary_ip_reachable=True,
        )
        db.session.add(inv)
        db.session.commit()
        return server


# ===== List servers =====

class TestListServers:

    def test_list_servers_requires_auth(self, app_fixture):
        client, app, db, models = app_fixture
        with app.app_context():
            resp = client.get('/api/servers', headers={'Accept': 'application/json'})
            assert resp.status_code == 401

    def test_list_servers_empty(self, app_fixture):
        client, app, db, models = app_fixture
        _login(client, 'admin')
        with app.app_context():
            resp = client.get('/api/servers')
            assert resp.status_code == 200
            assert resp.get_json() == []

    def test_list_servers_returns_seeded(self, app_fixture):
        client, app, db, models = app_fixture
        _login(client, 'admin')
        _seed_server(app, db, models)
        with app.app_context():
            resp = client.get('/api/servers')
            assert resp.status_code == 200
            data = resp.get_json()
            assert len(data) == 1
            assert data[0]['bmc_ip'] == '10.0.0.1'

    def test_list_servers_readonly_allowed(self, app_fixture):
        client, app, db, models = app_fixture
        _login(client, 'readonly')
        _seed_server(app, db, models)
        with app.app_context():
            resp = client.get('/api/servers')
            assert resp.status_code == 200


# ===== Add server =====

class TestAddServer:

    def test_add_server_success(self, app_fixture):
        client, app, db, models = app_fixture
        _login(client, 'admin')
        with app.app_context():
            resp = client.post('/api/servers/add', json={
                'bmc_ip': '10.1.1.1', 'server_name': 'new-server',
            })
            assert resp.status_code == 200
            body = resp.get_json()
            assert body['status'] == 'success'
            assert 'id' in body
            srv = models['Server'].query.filter_by(bmc_ip='10.1.1.1').first()
            assert srv is not None
            assert srv.server_name == 'new-server'

    def test_add_server_duplicate(self, app_fixture):
        client, app, db, models = app_fixture
        _login(client, 'admin')
        _seed_server(app, db, models, bmc_ip='10.1.1.1', name='existing')
        with app.app_context():
            resp = client.post('/api/servers/add', json={
                'bmc_ip': '10.1.1.1', 'server_name': 'dup',
            })
            assert resp.status_code == 409

    def test_add_server_missing_fields(self, app_fixture):
        client, app, db, models = app_fixture
        _login(client, 'admin')
        with app.app_context():
            resp = client.post('/api/servers/add', json={'bmc_ip': '10.0.0.5'})
            assert resp.status_code == 400

    def test_add_server_invalid_ip(self, app_fixture):
        client, app, db, models = app_fixture
        _login(client, 'admin')
        with app.app_context():
            resp = client.post('/api/servers/add', json={
                'bmc_ip': 'not-an-ip', 'server_name': 'bad-ip-srv',
            })
            assert resp.status_code == 400

    def test_add_server_readonly_forbidden(self, app_fixture):
        client, app, db, models = app_fixture
        _login(client, 'readonly')
        with app.app_context():
            resp = client.post('/api/servers/add', json={
                'bmc_ip': '10.2.2.2', 'server_name': 'ro-test',
            })
            assert resp.status_code == 403

    def test_add_server_unauthenticated(self, app_fixture):
        client, app, db, models = app_fixture
        with app.app_context():
            resp = client.post('/api/servers/add',
                               json={'bmc_ip': '10.2.2.2', 'server_name': 'unauth'},
                               headers={'Accept': 'application/json'})
            assert resp.status_code == 401

    def test_add_server_readwrite_allowed(self, app_fixture):
        client, app, db, models = app_fixture
        _login(client, 'readwrite')
        with app.app_context():
            resp = client.post('/api/servers/add', json={
                'bmc_ip': '10.3.3.3', 'server_name': 'rw-test',
            })
            assert resp.status_code == 200


# ===== Delete server =====

class TestDeleteServer:

    def test_delete_server_success(self, app_fixture):
        client, app, db, models = app_fixture
        _login(client, 'admin')
        _seed_server(app, db, models, bmc_ip='10.5.5.5', name='del-me')
        with app.app_context():
            resp = client.delete('/api/servers/10.5.5.5')
            assert resp.status_code == 200
            assert models['Server'].query.filter_by(bmc_ip='10.5.5.5').first() is None

    def test_delete_server_not_found(self, app_fixture):
        client, app, db, models = app_fixture
        _login(client, 'admin')
        with app.app_context():
            resp = client.delete('/api/servers/10.99.99.99')
            assert resp.status_code == 404

    def test_delete_server_requires_admin(self, app_fixture):
        client, app, db, models = app_fixture
        _login(client, 'readwrite')
        _seed_server(app, db, models, bmc_ip='10.5.5.5', name='del-me')
        with app.app_context():
            resp = client.delete('/api/servers/10.5.5.5')
            assert resp.status_code == 401


# ===== Deprecate server =====

class TestDeprecateServer:

    def test_deprecate_server_success(self, app_fixture):
        client, app, db, models = app_fixture
        _login(client, 'admin')
        _seed_server(app, db, models, bmc_ip='10.7.7.7', name='dep-me')
        with app.app_context():
            resp = client.post('/api/servers/10.7.7.7/deprecate',
                               json={'reason': 'End of life'})
            assert resp.status_code == 200
            body = resp.get_json()
            assert body['status'] == 'success'
            assert body['server']['status'] == 'deprecated'
            srv = models['Server'].query.filter_by(bmc_ip='10.7.7.7').first()
            assert srv.status == 'deprecated'
            assert srv.enabled is False

    def test_deprecate_server_not_found(self, app_fixture):
        client, app, db, models = app_fixture
        _login(client, 'admin')
        with app.app_context():
            resp = client.post('/api/servers/10.99.99.99/deprecate', json={})
            assert resp.status_code == 404

    def test_deprecate_server_readonly_forbidden(self, app_fixture):
        client, app, db, models = app_fixture
        _login(client, 'readonly')
        _seed_server(app, db, models, bmc_ip='10.7.7.7', name='dep-me')
        with app.app_context():
            resp = client.post('/api/servers/10.7.7.7/deprecate',
                               json={'reason': 'test'})
            assert resp.status_code == 403


# ===== Get single server =====

class TestGetServer:

    def test_get_server_detail(self, app_fixture):
        client, app, db, models = app_fixture
        _login(client, 'admin')
        _seed_server(app, db, models, bmc_ip='10.8.8.8', name='detail-srv')
        with app.app_context():
            resp = client.get('/api/servers/10.8.8.8')
            assert resp.status_code == 200
            body = resp.get_json()
            assert body['bmc_ip'] == '10.8.8.8'
            assert body['server_name'] == 'detail-srv'

    def test_get_server_not_found(self, app_fixture):
        client, app, db, models = app_fixture
        _login(client, 'admin')
        with app.app_context():
            resp = client.get('/api/servers/10.99.99.99')
            assert resp.status_code == 404
