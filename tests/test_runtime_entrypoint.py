# TRACEWEAVER: file-role=ipmi-monitor-verification; req=REQ-IPMI-MON-02; trace=TRACE-IPMI-MON-02; ver=VER-IPMI-MON-02
# TRACEWEAVER: verifies=VER-IPMI-MON-02; req=REQ-IPMI-MON-02; trace=TRACE-IPMI-MON-02
# TRACEWEAVER: file-role=ipmi-monitor-verification; req=REQ-IPMI-MON-01; trace=TRACE-IPMI-MON-01; ver=VER-IPMI-MON-01
# TRACEWEAVER: verifies=VER-IPMI-MON-01; req=REQ-IPMI-MON-01; trace=TRACE-IPMI-MON-01
"""Container startup coverage for the IPMI maintenance runtime."""

from pathlib import Path


def test_docker_entrypoint_calls_factory_and_factory_starts_collector_once(app_fixture, monkeypatch):
    """Gunicorn must construct the app through the one-time maintenance startup path."""
    _client, app, db, models = app_fixture
    import ipmi_monitor.app as runtime

    started_targets = []

    class CapturingThread:
        def __init__(self, target, daemon):
            self.target = target

        def start(self):
            started_targets.append(self.target)

    monkeypatch.setattr(runtime, "_background_started", False)
    monkeypatch.setattr(runtime, "auto_load_ssh_keys", lambda: None)
    monkeypatch.setattr(runtime, "auto_load_servers_config", lambda: None)
    monkeypatch.setattr(runtime.threading, "Thread", CapturingThread)

    assert runtime.create_app() is app
    assert runtime.create_app() is app
    assert started_targets.count(runtime.background_collector) == 1
    assert len(started_targets) == 2  # collector plus delayed initial check

    dockerfile = Path(__file__).parents[1] / "Dockerfile"
    assert '"ipmi_monitor.app:create_app()"' in dockerfile.read_text(encoding="utf-8")


def test_initial_collection_skips_an_empty_database_without_a_startup_exception(app_fixture, monkeypatch):
    """The delayed factory check must work when no BMCs or credentials are configured."""
    _client, app, db, models = app_fixture
    import ipmi_monitor.app as runtime

    updates = []
    monkeypatch.setattr(runtime, "update_initial_setup", updates.append)
    runtime.run_initial_collection()

    assert updates == [{"complete": True, "in_progress": False, "phase": "complete"}]


def test_existing_database_upgrade_creates_nonce_store_and_preserves_site(app_fixture):
    """Existing installations bypass create_all; the additive nonce table must still exist."""
    _client, app, db, models = app_fixture
    import ipmi_monitor.app as runtime
    with app.app_context():
        config = runtime.CloudSync.get_config()
        config.site_id = 'existing-site-do-not-reassign'
        db.session.commit()
        runtime.OAuthLinkState.__table__.drop(db.engine)
        runtime.init_db()
        assert runtime.OAuthLinkState.query.count() == 0
        assert runtime.CloudSync.get_config().site_id == 'existing-site-do-not-reassign'


def test_quickstart_activation_persists_verified_features_without_inventing_allowance(app_fixture, monkeypatch, capsys):
    """Execute the real generated activation program against SQLite; replace Docker/HTTP only."""
    import contextlib
    import io
    import subprocess
    from unittest.mock import Mock
    import ipmi_monitor.quickstart as setup
    from ipmi_monitor.app import CloudSync

    _client, app, db, models = app_fixture
    with app.app_context():
        database = str(db.engine.url.database)
    monkeypatch.setenv('DATA_DIR', str(Path(database).parent))
    monkeypatch.setattr('requests.post', Mock(return_value=Mock(ok=True, json=lambda: {
        'valid': True, 'tier': 'standard', 'max_servers': 125,
        'features': {'chat': True, 'summary': True, 'max_servers': 125},
        'email': 'verified@example.test', 'user_id': 71,
    })))

    def local_docker_transport(command, **kwargs):
        if command[-2:] == ['echo', 'ready']:
            return subprocess.CompletedProcess(command, 0, '', '')
        assert command[:5] == ['docker', 'exec', 'ipmi-monitor', 'python3', '-c']
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            exec(compile(command[-1], '<actual-quickstart-activation>', 'exec'), {})
        return subprocess.CompletedProcess(command, 0, output.getvalue(),
                                           'Runtime startup diagnostic\n' + errors.getvalue())

    monkeypatch.setattr(setup.subprocess, 'run', local_docker_transport)
    setup.activate_ai_license('isolated-activation-test-key')
    assert 'AI license activated' in capsys.readouterr().out
    with app.app_context():
        config = CloudSync.get_config()
        assert (config.subscription_valid, config.max_servers, config.get_features_list()) == (
            True, 125, ['chat', 'summary'])
