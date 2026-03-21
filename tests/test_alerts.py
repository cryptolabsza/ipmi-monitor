"""
Tests for the alert rules API.

Covers:
  - GET  /api/alerts/rules          (list)
  - POST /api/alerts/rules          (create)
  - GET  /api/alerts/rules/<id>     (detail)
  - PUT  /api/alerts/rules/<id>     (update)
  - DELETE /api/alerts/rules/<id>   (delete)
  - Auth checks on create / update / delete
  - GET /api/alerts/history
"""

import pytest


def _login(client, role='admin'):
    name_map = {'admin': 'testadmin', 'readwrite': 'testwriter', 'readonly': 'testreader'}
    with client.session_transaction() as sess:
        sess['logged_in'] = True
        sess['username'] = name_map[role]
        sess['user_role'] = role


def _create_rule(client, app, **overrides):
    """POST a new alert rule and return (response, json_body)."""
    payload = {
        'name': 'Test Alert',
        'alert_type': 'temperature',
        'condition': 'gt',
        'threshold': 85.0,
        'severity': 'warning',
    }
    payload.update(overrides)
    with app.app_context():
        resp = client.post('/api/alerts/rules', json=payload)
    return resp, resp.get_json()


# ===== List rules =====

class TestListAlertRules:

    def test_list_rules_empty(self, app_fixture):
        client, app, db, models = app_fixture
        with app.app_context():
            resp = client.get('/api/alerts/rules')
            assert resp.status_code == 200
            assert resp.get_json() == []

    def test_list_rules_returns_created(self, app_fixture):
        client, app, db, models = app_fixture
        _login(client, 'admin')
        _create_rule(client, app, name='Rule A')
        _create_rule(client, app, name='Rule B')
        with app.app_context():
            resp = client.get('/api/alerts/rules')
            assert resp.status_code == 200
            names = [r['name'] for r in resp.get_json()]
            assert 'Rule A' in names
            assert 'Rule B' in names


# ===== Create rule =====

class TestCreateAlertRule:

    def test_create_rule_success(self, app_fixture):
        client, app, db, models = app_fixture
        _login(client, 'admin')
        resp, body = _create_rule(client, app)
        assert resp.status_code == 200
        assert body['status'] == 'success'
        assert 'id' in body

    def test_create_rule_missing_field(self, app_fixture):
        client, app, db, models = app_fixture
        _login(client, 'admin')
        with app.app_context():
            resp = client.post('/api/alerts/rules', json={
                'name': 'Incomplete',
            })
            assert resp.status_code == 400

    def test_create_rule_readonly_forbidden(self, app_fixture):
        client, app, db, models = app_fixture
        _login(client, 'readonly')
        resp, body = _create_rule(client, app)
        assert resp.status_code == 403

    def test_create_rule_readwrite_allowed(self, app_fixture):
        client, app, db, models = app_fixture
        _login(client, 'readwrite')
        resp, body = _create_rule(client, app)
        assert resp.status_code == 200

    def test_create_rule_unauthenticated(self, app_fixture):
        client, app, db, models = app_fixture
        with app.app_context():
            resp = client.post('/api/alerts/rules',
                               json={
                                   'name': 'Unauth',
                                   'alert_type': 'fan',
                                   'condition': 'lt',
                                   'severity': 'critical',
                               },
                               headers={'Accept': 'application/json'})
            assert resp.status_code == 401


# ===== Get / Update / Delete rule =====

class TestManageAlertRule:

    def _make_rule(self, client, app):
        _login(client, 'admin')
        _, body = _create_rule(client, app)
        return body['id']

    def test_get_rule_detail(self, app_fixture):
        client, app, db, models = app_fixture
        rule_id = self._make_rule(client, app)
        with app.app_context():
            resp = client.get(f'/api/alerts/rules/{rule_id}')
            assert resp.status_code == 200
            assert resp.get_json()['name'] == 'Test Alert'

    def test_get_rule_not_found(self, app_fixture):
        client, app, db, models = app_fixture
        with app.app_context():
            resp = client.get('/api/alerts/rules/9999')
            assert resp.status_code == 404

    def test_update_rule(self, app_fixture):
        client, app, db, models = app_fixture
        rule_id = self._make_rule(client, app)
        with app.app_context():
            resp = client.put(f'/api/alerts/rules/{rule_id}', json={
                'name': 'Updated Alert', 'threshold': 90.0,
            })
            assert resp.status_code == 200
            resp2 = client.get(f'/api/alerts/rules/{rule_id}')
            assert resp2.get_json()['name'] == 'Updated Alert'
            assert resp2.get_json()['threshold'] == 90.0

    def test_update_rule_requires_admin(self, app_fixture):
        client, app, db, models = app_fixture
        rule_id = self._make_rule(client, app)
        _login(client, 'readwrite')
        with app.app_context():
            resp = client.put(f'/api/alerts/rules/{rule_id}', json={'name': 'Nope'})
            assert resp.status_code == 401

    def test_delete_rule(self, app_fixture):
        client, app, db, models = app_fixture
        rule_id = self._make_rule(client, app)
        with app.app_context():
            resp = client.delete(f'/api/alerts/rules/{rule_id}')
            assert resp.status_code == 200
            resp2 = client.get(f'/api/alerts/rules/{rule_id}')
            assert resp2.status_code == 404

    def test_delete_rule_requires_admin(self, app_fixture):
        client, app, db, models = app_fixture
        rule_id = self._make_rule(client, app)
        _login(client, 'readwrite')
        with app.app_context():
            resp = client.delete(f'/api/alerts/rules/{rule_id}')
            assert resp.status_code == 401


# ===== Alert history =====

class TestAlertHistory:

    def test_alert_history_empty(self, app_fixture):
        client, app, db, models = app_fixture
        with app.app_context():
            resp = client.get('/api/alerts/history')
            assert resp.status_code == 200
            body = resp.get_json()
            assert 'alerts' in body or isinstance(body, list)

    def test_alert_history_with_data(self, app_fixture):
        client, app, db, models = app_fixture
        with app.app_context():
            ah = models['AlertHistory'](
                rule_name='Temp Alert',
                bmc_ip='10.0.0.1',
                server_name='test-srv',
                alert_type='temperature',
                severity='warning',
                message='Temperature exceeded threshold',
            )
            db.session.add(ah)
            db.session.commit()
            resp = client.get('/api/alerts/history')
            assert resp.status_code == 200
            body = resp.get_json()
            alerts = body if isinstance(body, list) else body.get('alerts', [])
            assert len(alerts) >= 1
            assert alerts[0]['rule_name'] == 'Temp Alert'
