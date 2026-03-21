"""
Shared fixtures for ipmi-monitor tests.

Provides a reusable app_fixture that initialises a Flask test client
backed by an in-memory SQLite database.
"""

import os
import sys
import tempfile
import pytest

# Ensure the source package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))


def _login_as(client, role='admin'):
    """Set session to an authenticated user with the given role."""
    name_map = {
        'admin': 'testadmin',
        'readwrite': 'testwriter',
        'readonly': 'testreader',
    }
    with client.session_transaction() as sess:
        sess['logged_in'] = True
        sess['username'] = name_map[role]
        sess['user_role'] = role


def _logout(client):
    """Clear the session so the next request is unauthenticated."""
    with client.session_transaction() as sess:
        sess.pop('logged_in', None)
        sess.pop('username', None)
        sess.pop('user_role', None)


@pytest.fixture()
def app_fixture():
    """
    Create a fully initialised Flask test client with an in-memory DB.

    Yields (client, app, db, models_dict) where *models_dict* contains
    every model class from ipmi_monitor.app that tests commonly need.
    """
    tmp_dir = tempfile.mkdtemp()
    os.environ['DATA_DIR'] = tmp_dir
    os.environ['SECRET_KEY'] = 'test-secret-key'
    os.environ['RATE_LIMIT_MAX_ATTEMPTS'] = '100'

    from ipmi_monitor.app import (
        app, db, Server, ServerConfig, ServerStatus, ServerInventory,
        IPMIEvent, User, AlertRule, AlertHistory, SystemSettings,
        SensorReading, PowerReading, ECCErrorTracker,
        _login_attempts, _login_attempts_lock,
    )
    from werkzeug.security import generate_password_hash

    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'

    with app.app_context():
        db.create_all()

        admin = User(
            username='testadmin',
            password_hash=generate_password_hash('testpass'),
            role='admin',
            password_changed=True,
        )
        db.session.add(admin)

        rw_user = User(
            username='testwriter',
            password_hash=generate_password_hash('writerpass'),
            role='readwrite',
            password_changed=True,
        )
        db.session.add(rw_user)

        ro_user = User(
            username='testreader',
            password_hash=generate_password_hash('readerpass'),
            role='readonly',
            password_changed=True,
        )
        db.session.add(ro_user)

        db.session.commit()

    client = app.test_client()

    models = {
        'Server': Server,
        'ServerConfig': ServerConfig,
        'ServerStatus': ServerStatus,
        'ServerInventory': ServerInventory,
        'IPMIEvent': IPMIEvent,
        'User': User,
        'AlertRule': AlertRule,
        'AlertHistory': AlertHistory,
        'SystemSettings': SystemSettings,
        'SensorReading': SensorReading,
        'PowerReading': PowerReading,
        'ECCErrorTracker': ECCErrorTracker,
    }

    yield client, app, db, models

    with app.app_context():
        db.drop_all()

    with _login_attempts_lock:
        _login_attempts.clear()


@pytest.fixture()
def login_as():
    """Fixture that returns the login_as helper function."""
    return _login_as


@pytest.fixture()
def logout_helper():
    """Fixture that returns the logout helper function."""
    return _logout
