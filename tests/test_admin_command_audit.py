"""
Tests for admin command audit logging (SSH & IPMI custom commands).

Verifies that multiple SSH/IPMI commands for the same BMC IP can be
logged without triggering UNIQUE constraint violations on ipmi_event.
"""

import os
import sys
import tempfile
import pytest
from datetime import datetime
from unittest.mock import patch, MagicMock

# Ensure the source package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))


@pytest.fixture
def app_client():
    """Create a test Flask app with an in-memory SQLite database."""
    # Set DATA_DIR to a temp directory before importing the app
    tmp_dir = tempfile.mkdtemp()
    os.environ['DATA_DIR'] = tmp_dir
    os.environ['SECRET_KEY'] = 'test-secret-key'

    from ipmi_monitor.app import app, db, Server, ServerConfig, IPMIEvent, User
    from werkzeug.security import generate_password_hash

    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'

    with app.app_context():
        db.create_all()

        # Create a test server
        server = Server(
            bmc_ip='10.0.0.1',
            server_name='test-server',
            server_ip='10.0.0.2',
            enabled=True,
        )
        db.session.add(server)

        # Create server config with SSH details
        config = ServerConfig(
            bmc_ip='10.0.0.1',
            server_name='test-server',
            server_ip='10.0.0.2',
            ssh_user='root',
        )
        db.session.add(config)

        # Create an admin user
        admin = User(
            username='testadmin',
            password_hash=generate_password_hash('testpass'),
            role='admin',
        )
        db.session.add(admin)
        db.session.commit()

    client = app.test_client()

    # Log in as admin
    with client.session_transaction() as sess:
        sess['logged_in'] = True
        sess['username'] = 'testadmin'
        sess['user_role'] = 'admin'

    yield client, app, db, IPMIEvent

    # Cleanup
    with app.app_context():
        db.drop_all()


class TestSSHCommandAuditUniqueness:
    """Multiple SSH commands for the same server must not cause UNIQUE violations."""

    @patch('ipmi_monitor.app.run_ssh_command', return_value='mock output\n')
    def test_two_ssh_commands_same_server_succeed(self, mock_ssh, app_client):
        """Executing two SSH commands on the same BMC IP must both succeed."""
        client, app, db, IPMIEvent = app_client

        with app.app_context():
            # First SSH command
            resp1 = client.post('/api/server/10.0.0.1/execute', json={
                'type': 'ssh',
                'command': 'pwd',
            })
            assert resp1.status_code == 200, f"First SSH command failed: {resp1.get_json()}"
            assert resp1.get_json()['status'] == 'success'

            # Second SSH command — this is the one that currently fails
            resp2 = client.post('/api/server/10.0.0.1/execute', json={
                'type': 'ssh',
                'command': 'uptime',
            })
            assert resp2.status_code == 200, f"Second SSH command failed: {resp2.get_json()}"
            assert resp2.get_json()['status'] == 'success'

            # Both audit events should exist in the database
            events = IPMIEvent.query.filter_by(bmc_ip='10.0.0.1', sensor_type='Admin Command').all()
            assert len(events) == 2, f"Expected 2 audit events, got {len(events)}"

            # Each event should have a unique sel_id
            sel_ids = [e.sel_id for e in events]
            assert len(set(sel_ids)) == 2, f"sel_ids must be unique, got: {sel_ids}"

    @patch('ipmi_monitor.app.run_ssh_command', return_value='mock output\n')
    def test_many_ssh_commands_same_server(self, mock_ssh, app_client):
        """Five rapid SSH commands on the same BMC IP must all succeed."""
        client, app, db, IPMIEvent = app_client

        with app.app_context():
            for i in range(5):
                resp = client.post('/api/server/10.0.0.1/execute', json={
                    'type': 'ssh',
                    'command': f'echo {i}',
                })
                assert resp.status_code == 200, f"SSH command #{i} failed: {resp.get_json()}"

            events = IPMIEvent.query.filter_by(bmc_ip='10.0.0.1', sensor_type='Admin Command').all()
            assert len(events) == 5

            sel_ids = [e.sel_id for e in events]
            assert len(set(sel_ids)) == 5, f"All sel_ids must be unique, got: {sel_ids}"


class TestIPMICommandAuditUniqueness:
    """Multiple IPMI commands for the same server must not cause UNIQUE violations."""

    @patch('subprocess.run')
    def test_two_ipmi_commands_same_server_succeed(self, mock_run, app_client):
        """Executing two IPMI commands on the same BMC IP must both succeed."""
        client, app, db, IPMIEvent = app_client

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = 'sensor data\n'
        mock_result.stderr = ''
        mock_run.return_value = mock_result

        with app.app_context():
            resp1 = client.post('/api/server/10.0.0.1/execute', json={
                'type': 'ipmi',
                'command': 'sensor list',
            })
            assert resp1.status_code == 200, f"First IPMI command failed: {resp1.get_json()}"

            resp2 = client.post('/api/server/10.0.0.1/execute', json={
                'type': 'ipmi',
                'command': 'sdr list',
            })
            assert resp2.status_code == 200, f"Second IPMI command failed: {resp2.get_json()}"

            events = IPMIEvent.query.filter_by(bmc_ip='10.0.0.1', sensor_type='Admin Command').all()
            assert len(events) == 2

            sel_ids = [e.sel_id for e in events]
            assert len(set(sel_ids)) == 2, f"sel_ids must be unique, got: {sel_ids}"
