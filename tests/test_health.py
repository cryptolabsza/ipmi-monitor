"""
Tests for health, version, and metrics endpoints.

Covers:
  - GET /health
  - GET /api/version
  - GET /metrics (Prometheus)
"""

import pytest
from unittest.mock import patch, MagicMock


class TestHealthEndpoint:

    def test_health_returns_json(self, app_fixture):
        client, app, db, models = app_fixture
        with app.app_context():
            with patch('ipmi_monitor.app.collector_thread', None, create=True):
                resp = client.get('/health')
                assert resp.status_code in (200, 503)
                body = resp.get_json()
                assert 'status' in body
                assert 'checks' in body
                assert 'database' in body['checks']

    def test_health_db_check(self, app_fixture):
        client, app, db, models = app_fixture
        with app.app_context():
            with patch('ipmi_monitor.app.collector_thread', None, create=True):
                resp = client.get('/health')
                body = resp.get_json()
                assert body['checks']['database'] == 'ok'

    def test_health_collector_not_running(self, app_fixture):
        client, app, db, models = app_fixture
        with app.app_context():
            with patch('ipmi_monitor.app.collector_thread', None, create=True):
                resp = client.get('/health')
                body = resp.get_json()
                assert body['status'] == 'degraded'
                assert body['checks']['collector_thread'] == 'not running'

    def test_health_collector_running(self, app_fixture):
        client, app, db, models = app_fixture
        mock_thread = MagicMock()
        mock_thread.is_alive.return_value = True
        with app.app_context():
            with patch('ipmi_monitor.app.collector_thread', mock_thread, create=True):
                resp = client.get('/health')
                body = resp.get_json()
                assert body['checks']['collector_thread'] == 'running'


class TestVersionEndpoint:

    def test_version_returns_json(self, app_fixture):
        client, app, db, models = app_fixture
        with app.app_context():
            resp = client.get('/api/version')
            assert resp.status_code == 200
            body = resp.get_json()
            assert 'version' in body
            assert 'version_string' in body
            assert 'git_branch' in body
            assert 'git_commit' in body

    def test_version_contains_version_number(self, app_fixture):
        client, app, db, models = app_fixture
        from ipmi_monitor import __version__
        with app.app_context():
            resp = client.get('/api/version')
            body = resp.get_json()
            assert body['version'] == __version__


class TestMetricsEndpoint:

    def test_metrics_returns_prometheus_format(self, app_fixture):
        client, app, db, models = app_fixture
        with app.app_context():
            resp = client.get('/metrics')
            assert resp.status_code == 200
            assert 'text/plain' in resp.content_type or 'openmetrics' in resp.content_type

    def test_metrics_no_auth_required(self, app_fixture):
        client, app, db, models = app_fixture
        with app.app_context():
            resp = client.get('/metrics')
            assert resp.status_code == 200
