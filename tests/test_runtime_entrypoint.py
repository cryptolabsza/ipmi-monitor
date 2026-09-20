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
