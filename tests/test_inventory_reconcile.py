"""Tests for DC's authenticated, revisioned IPMI inventory reconciliation API."""

from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
import os
import sqlite3
import subprocess
import sys
import time
import pytest


def _headers(secret="inventory-secret"):
    return {"Authorization": f"Bearer {secret}"}


def _payload(revision=1, operation="upsert", **changes):
    payload = {
        "source_id": "11111111-1111-4111-8111-111111111111",
        "server_id": "22222222-2222-4222-8222-222222222222",
        "revision": revision,
        "operation": operation,
        "name": "ccc90",
        "server_ip": "10.10.0.90",
        "bmc_ip": "10.20.0.90",
    }
    payload.update(changes)
    return payload


def _configure_secret(monkeypatch, tmp_path):
    path = Path(tmp_path) / "inventory-secret"
    path.write_text("inventory-secret\n")
    monkeypatch.setenv("IPMI_INVENTORY_SECRET_FILE", str(path))
    credentials_path = Path(tmp_path) / "bmc-credentials.json"
    credentials_path.write_text('{"10.20.0.90": {"username": "operator", "password": "test-only"}}')
    monkeypatch.setenv("IPMI_BMC_CREDENTIALS_FILE", str(credentials_path))


def test_reconcile_requires_configured_bearer_secret(app_fixture, monkeypatch, tmp_path):
    client, app, db, models = app_fixture
    _configure_secret(monkeypatch, tmp_path)

    assert client.post("/api/internal/inventory/reconcile", json=_payload()).status_code == 401
    assert client.post(
        "/api/internal/inventory/reconcile",
        json=_payload(),
        headers={"X-Fleet-Authenticated": "true", "X-Fleet-Auth-Role": "admin"},
    ).status_code == 401
    assert client.post(
        "/api/internal/inventory/reconcile", json=_payload(), headers=_headers("wrong")
    ).status_code == 401


def test_internal_inventory_endpoints_reject_truthy_non_object_json_and_non_ascii_bearers(app_fixture, monkeypatch, tmp_path):
    """Malformed input fails before any reconciliation transaction starts."""
    client, app, db, models = app_fixture
    _configure_secret(monkeypatch, tmp_path)
    endpoints = [
        ("/api/internal/inventory/reconcile", _payload()),
        ("/api/internal/inventory/retire-preview", {"bmc_ips": ["10.20.0.90"]}),
    ]
    for path, valid_body in endpoints:
        assert client.post(path, json=["not-an-object"], headers=_headers()).status_code == 400
        assert client.post(path, json=valid_body, headers=_headers("inv\xffentory-secret")).status_code == 401


def test_reconcile_creates_renames_and_retires_only_bound_server(app_fixture, monkeypatch, tmp_path):
    client, app, db, models = app_fixture
    _configure_secret(monkeypatch, tmp_path)
    from ipmi_monitor.app import InventoryBinding

    created = client.post("/api/internal/inventory/reconcile", json=_payload(), headers=_headers())
    assert created.status_code == 200
    assert created.get_json()["accepted"] == {
        "source_id": "11111111-1111-4111-8111-111111111111", "server_id": "22222222-2222-4222-8222-222222222222", "revision": 1,
        "operation": "upsert", "name": "ccc90", "server_ip": "10.10.0.90",
        "bmc_ip": "10.20.0.90", "status": "active", "enabled": True,
    }

    with app.app_context():
        server = models["Server"].query.filter_by(bmc_ip="10.20.0.90").one()
        assert models["ServerStatus"].query.filter_by(bmc_ip=server.bmc_ip).one().server_name == "ccc90"
        assert models["ServerInventory"].query.filter_by(bmc_ip=server.bmc_ip).one().server_name == "ccc90"
        assert InventoryBinding.query.filter_by(source_id="11111111-1111-4111-8111-111111111111", source_server_id="22222222-2222-4222-8222-222222222222").one().revision == 1

    renamed = client.post(
        "/api/internal/inventory/reconcile",
        json=_payload(2, name="ccc90-renamed"),
        headers=_headers(),
    )
    assert renamed.status_code == 200
    with app.app_context():
        server = models["Server"].query.filter_by(bmc_ip="10.20.0.90").one()
        assert server.server_name == "ccc90-renamed"
        assert models["ServerStatus"].query.filter_by(bmc_ip=server.bmc_ip).one().server_name == "ccc90-renamed"
        assert models["ServerInventory"].query.filter_by(bmc_ip=server.bmc_ip).one().server_name == "ccc90-renamed"

    retired = client.post(
        "/api/internal/inventory/reconcile",
        json=_payload(3, operation="retire", name="ccc90-renamed"),
        headers=_headers(),
    )
    assert retired.status_code == 200
    with app.app_context():
        server = models["Server"].query.filter_by(bmc_ip="10.20.0.90").one()
        assert server.status == "deprecated"
        assert server.enabled is False


def test_reconcile_rejects_stale_revision_and_unmapped_bmc_takeover(app_fixture, monkeypatch, tmp_path):
    client, app, db, models = app_fixture
    _configure_secret(monkeypatch, tmp_path)
    assert client.post("/api/internal/inventory/reconcile", json=_payload(2), headers=_headers()).status_code == 200

    stale = client.post(
        "/api/internal/inventory/reconcile", json=_payload(1, name="stale"), headers=_headers()
    )
    assert stale.status_code == 409

    with app.app_context():
        unmanaged = models["Server"](bmc_ip="10.20.0.91", server_name="existing", server_ip="10.10.0.91")
        db.session.add(unmanaged)
        db.session.commit()

    conflict = client.post(
        "/api/internal/inventory/reconcile",
        json=_payload(1, server_id="33333333-3333-4333-8333-333333333333", name="different", server_ip="10.10.0.91", bmc_ip="10.20.0.91"),
        headers=_headers(),
    )
    assert conflict.status_code == 409


def test_exact_retire_preview_requires_service_secret_and_never_runs_implicitly(app_fixture, monkeypatch, tmp_path):
    """An operator can inspect an exact unmanaged list before applying a retained retirement."""
    client, app, db, models = app_fixture
    _configure_secret(monkeypatch, tmp_path)
    with app.app_context():
        server = models["Server"](bmc_ip="10.20.0.92", server_name="obsolete", enabled=True, status="active")
        db.session.add(server)
        db.session.commit()

    path = "/api/internal/inventory/retire-preview"
    body = {"bmc_ips": ["10.20.0.92"]}
    assert client.post(path, json=body).status_code == 401
    preview = client.post(path, json=body, headers=_headers())
    assert preview.status_code == 200
    assert preview.get_json()["apply"] is False
    with app.app_context():
        assert models["Server"].query.filter_by(bmc_ip="10.20.0.92").one().status == "active"

    applied = client.post(
        path,
        json={**body, "apply": True, "confirm_retire_count": 1},
        headers=_headers(),
    )
    assert applied.status_code == 200
    with app.app_context():
        server = models["Server"].query.filter_by(bmc_ip="10.20.0.92").one()
        assert (server.status, server.enabled) == ("deprecated", False)


def test_active_server_apis_hide_deprecated_records_but_keep_history(app_fixture, login_as):
    """Retiring an inventory record removes it from active views without deleting it."""
    client, app, db, models = app_fixture
    login_as(client)
    with app.app_context():
        active = models["Server"](bmc_ip="10.20.0.93", server_name="active", enabled=True, status="active")
        retired = models["Server"](bmc_ip="10.20.0.94", server_name="retired", enabled=False, status="deprecated")
        db.session.add_all([active, retired])
        db.session.add_all([
            models["ServerStatus"](bmc_ip="10.20.0.93", server_name="active"),
            models["ServerStatus"](bmc_ip="10.20.0.94", server_name="retired"),
        ])
        db.session.commit()

    visible = client.get("/api/servers")
    managed = client.get("/api/servers/managed")
    assert [item["bmc_ip"] for item in visible.get_json()] == ["10.20.0.93"]
    assert [item["bmc_ip"] for item in managed.get_json()] == ["10.20.0.93"]
    with app.app_context():
        assert models["Server"].query.filter_by(bmc_ip="10.20.0.94").one().status == "deprecated"


def test_file_backed_bmc_credentials_are_explicit_and_fail_closed(app_fixture, monkeypatch, tmp_path):
    """A malformed configured entry never falls through to a shared/default password."""
    client, app, db, models = app_fixture
    credentials_path = Path(tmp_path) / "bmc-credentials.json"
    credentials_path.write_text('{"10.20.0.95": {"username": "operator", "password": "test-only"}}')
    monkeypatch.setenv("IPMI_BMC_CREDENTIALS_FILE", str(credentials_path))
    from ipmi_monitor.app import get_ipmi_credentials

    assert get_ipmi_credentials("10.20.0.95") == ("operator", "test-only")
    credentials_path.write_text('{"10.20.0.95": {"username": "operator"}}')
    assert get_ipmi_credentials("10.20.0.95") == (None, None)


def test_receiver_requires_explicit_credentials_before_creating_new_active_server(app_fixture, monkeypatch, tmp_path):
    """A DC identity alone cannot enroll a new BMC into polling."""
    client, app, db, models = app_fixture
    _configure_secret(monkeypatch, tmp_path)
    no_credential = client.post(
        "/api/internal/inventory/reconcile",
        json=_payload(bmc_ip="10.20.0.96", server_ip="10.10.0.96"),
        headers=_headers(),
    )
    assert no_credential.status_code == 409
    with app.app_context():
        assert models["Server"].query.filter_by(bmc_ip="10.20.0.96").first() is None


def test_concurrent_independent_clients_leave_highest_revision_as_final_state(app_fixture, monkeypatch, tmp_path):
    """Two request connections cannot let an older revision commit after a newer one."""
    _client, app, db, models = app_fixture
    _configure_secret(monkeypatch, tmp_path)
    barrier = Barrier(2)

    def submit(payload):
        client = app.test_client()
        barrier.wait()
        return client.post("/api/internal/inventory/reconcile", json=payload, headers=_headers()).status_code

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(submit, [
            _payload(1, name="ccc90-old"),
            _payload(2, name="ccc90-current"),
        ]))

    assert 200 in results
    with app.app_context():
        binding = models["Server"].query.filter_by(bmc_ip="10.20.0.90").one()
        assert binding.server_name == "ccc90-current"


def test_equal_revision_rejects_a_mismatched_enabled_state(app_fixture, monkeypatch, tmp_path):
    """An idempotent acknowledgment must exactly represent the requested lifecycle."""
    client, app, db, models = app_fixture
    _configure_secret(monkeypatch, tmp_path)
    assert client.post("/api/internal/inventory/reconcile", json=_payload(), headers=_headers()).status_code == 200

    with app.app_context():
        server = models["Server"].query.filter_by(bmc_ip="10.20.0.90").one()
        server.enabled = False
        db.session.commit()

    repeated = client.post("/api/internal/inventory/reconcile", json=_payload(), headers=_headers())
    assert repeated.status_code == 409


def test_file_sqlite_serializes_preview_and_reconcile_across_processes(tmp_path):
    """An unmanaged retirement cannot commit after another worker binds that BMC."""
    data_dir = tmp_path / "ipmi-data"
    data_dir.mkdir()
    secret_path = tmp_path / "inventory-secret"
    secret_path.write_text("inventory-secret\n")
    environment = {
        **os.environ,
        "PYTHONPATH": str(Path(__file__).parents[1] / "src"),
        "DATA_DIR": str(data_dir),
        "SECRET_KEY": "test-secret",
        "IPMI_INVENTORY_SECRET_FILE": str(secret_path),
        "IPMI_BMC_CREDENTIALS_FILE": "",
    }
    setup = """
from ipmi_monitor.app import Server, app, db
with app.app_context():
    db.session.add(Server(bmc_ip='10.20.0.90', server_name='ccc90', server_ip='10.10.0.90', enabled=True, status='active'))
    db.session.commit()
"""
    subprocess.run([sys.executable, "-c", setup], check=True, env=environment, capture_output=True, text=True)

    preview_ready = tmp_path / "preview-ready"
    release_preview = tmp_path / "release-preview"
    preview_worker = """
import os
import time
from pathlib import Path
from ipmi_monitor.app import Server, app
original = Server.deprecate
def hold_after_preview(self, reason=None):
    Path(os.environ['PREVIEW_READY']).touch()
    while not Path(os.environ['PREVIEW_RELEASE']).exists():
        time.sleep(0.01)
    return original(self, reason)
Server.deprecate = hold_after_preview
with app.test_client() as client:
    response = client.post('/api/internal/inventory/retire-preview', json={
        'bmc_ips': ['10.20.0.90'], 'apply': True, 'confirm_retire_count': 1,
    }, headers={'Authorization': 'Bearer inventory-secret'})
    raise SystemExit(0 if response.status_code == 200 else response.status_code)
"""
    reconcile_worker = """
import os
from pathlib import Path
from ipmi_monitor.app import app
payload = {
    'source_id': '11111111-1111-4111-8111-111111111111',
    'server_id': '22222222-2222-4222-8222-222222222222',
    'revision': 1, 'operation': 'upsert', 'name': 'ccc90',
    'server_ip': '10.10.0.90', 'bmc_ip': '10.20.0.90',
}
Path(os.environ['RECONCILE_READY']).touch()
with app.test_client() as client:
    response = client.post('/api/internal/inventory/reconcile', json=payload,
                           headers={'Authorization': 'Bearer inventory-secret'})
    raise SystemExit(0 if response.status_code == 200 else response.status_code)
"""
    preview = subprocess.Popen(
        [sys.executable, "-c", preview_worker],
        env={**environment, "PREVIEW_READY": str(preview_ready), "PREVIEW_RELEASE": str(release_preview)},
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    deadline = time.monotonic() + 10
    while not preview_ready.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert preview_ready.exists(), preview.communicate(timeout=1)
    reconcile = subprocess.Popen(
        [sys.executable, "-c", reconcile_worker], env={**environment, "RECONCILE_READY": str(tmp_path / "reconcile-ready")},
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    reconcile_ready = tmp_path / "reconcile-ready"
    deadline = time.monotonic() + 10
    while not reconcile_ready.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert reconcile_ready.exists(), reconcile.communicate(timeout=1)
    time.sleep(0.2)
    release_preview.touch()
    preview_output = preview.communicate(timeout=10)
    reconcile_output = reconcile.communicate(timeout=10)
    assert preview.returncode == 0, preview_output
    assert reconcile.returncode == 0, reconcile_output

    with sqlite3.connect(data_dir / "ipmi_events.db") as connection:
        status, enabled = connection.execute(
            "SELECT status, enabled FROM server WHERE bmc_ip = '10.20.0.90'"
        ).fetchone()
        binding_count = connection.execute(
            "SELECT COUNT(*) FROM inventory_binding WHERE bmc_ip = '10.20.0.90'"
        ).fetchone()[0]
    assert (status, enabled, binding_count) == ("active", 1, 1)


@pytest.mark.parametrize("endpoint", ["reconcile", "retire-preview"])
@pytest.mark.parametrize("lock_kind", ["writer", "reader"])
def test_locked_receiver_returns_retryable_failure_before_sender_timeout(
    app_fixture, monkeypatch, tmp_path, endpoint, lock_kind
):
    """A busy database cannot occupy receiver threads beyond DC's five-second timeout."""
    _client, app, db, models = app_fixture
    _configure_secret(monkeypatch, tmp_path)
    with app.app_context():
        db.session.add(models["Server"](
            bmc_ip="10.20.0.90", server_name="ccc90", server_ip="10.10.0.90"
        ))
        db.session.commit()
        database_path = db.engine.url.database

    payload = _payload() if endpoint == "reconcile" else {
        "bmc_ips": ["10.20.0.90"], "apply": True, "confirm_retire_count": 1,
    }
    path = f"/api/internal/inventory/{endpoint}"

    def submit():
        started = time.monotonic()
        with app.test_client() as client:
            response = client.post(path, json=payload, headers=_headers())
            return response.status_code, response.headers.get("Retry-After"), time.monotonic() - started

    blocker = sqlite3.connect(database_path)
    blocker.execute("BEGIN IMMEDIATE" if lock_kind == "writer" else "BEGIN")
    if lock_kind == "reader":
        blocker.execute("SELECT * FROM server").fetchall()
    with ThreadPoolExecutor(max_workers=1) as executor:
        pending = executor.submit(submit)
        try:
            try:
                outcome = pending.result(timeout=3)
            except TimeoutError:
                outcome = None
        finally:
            blocker.rollback()
            blocker.close()
        if outcome is None:
            outcome = pending.result(timeout=3)

    assert outcome[0] == 503
    assert outcome[1] == "1"
    assert outcome[2] < 3
    with app.test_client() as client:
        assert client.post(path, json=payload, headers=_headers()).status_code == 200
    with app.app_context():
        assert db.session.execute(db.text("PRAGMA busy_timeout")).scalar() == 60000
