"""Tests for DC's authenticated, revisioned IPMI inventory reconciliation API."""

from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from base64 import urlsafe_b64encode
from hashlib import sha256
from io import StringIO
import hmac
import json
import os
import sqlite3
import subprocess
import sys
import time
import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import paramiko


def _headers(secret="inventory-secret"):
    return {"Authorization": f"Bearer {secret}"}


def _canonical_payload(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _hmac_headers(payload, secret="inventory-secret"):
    signature = hmac.new(secret.encode("utf-8"), _canonical_payload(payload), sha256).hexdigest()
    return {"Authorization": f"DC-HMAC {signature}"}


def _private_key():
    key = paramiko.RSAKey.generate(1024)
    output = StringIO()
    key.write_private_key(output)
    return output.getvalue()


def _credential_bundle(payload, *, ssh_password="ssh-secret", bmc_managed=True, bmc_password="bmc-secret"):
    derived_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None,
        info=b"dc-overview/ipmi-credentials/v1",
    ).derive(b"inventory-secret")
    plaintext = {
        "version": 1,
        "source_id": payload["source_id"],
        "server_id": payload["server_id"],
        "revision": payload["revision"],
        "operation": payload["operation"],
        "name": payload["name"],
        "server_ip": payload["server_ip"],
        "bmc_ip": payload["bmc_ip"],
        "credentials": {
            "ssh": {
                "username": "root", "port": 22, "private_key": _private_key(),
                "password": ssh_password,
            },
            "bmc_managed": bmc_managed,
            "bmc": {"username": "ADMIN", "password": bmc_password} if bmc_managed and bmc_password else None,
        },
    }
    return Fernet(urlsafe_b64encode(derived_key)).encrypt(
        json.dumps(plaintext, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")


def _bundled_payload(revision=1, **changes):
    payload = _payload(revision, **changes)
    payload["credential_bundle"] = _credential_bundle(payload)
    return payload


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


def _configure_local_secret(monkeypatch, tmp_path):
    _configure_secret(monkeypatch, tmp_path)
    monkeypatch.setenv("FLEET_CREDENTIAL_AUTHORITY", "local")


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


def test_local_signed_bundle_enrolls_credentials_and_acks_its_exact_digest(app_fixture, monkeypatch, tmp_path):
    """A signed encrypted bundle creates one bound server and its local credentials atomically."""
    client, app, db, models = app_fixture
    _configure_local_secret(monkeypatch, tmp_path)
    payload = _bundled_payload(bmc_ip="10.20.0.96", server_ip="10.10.0.96")

    response = client.post(
        "/api/internal/inventory/reconcile", json=payload, headers=_hmac_headers(payload)
    )

    assert response.status_code == 200
    body = response.get_json()
    assert body["credential_revision"] == 1
    assert body["credential_digest"] == sha256(payload["credential_bundle"].encode("utf-8")).hexdigest()
    expected_response_signature = hmac.new(
        b"inventory-secret", _canonical_payload(body), sha256
    ).hexdigest()
    assert response.headers["X-DC-Response-Signature"] == expected_response_signature
    with app.app_context():
        from ipmi_monitor.app import InventoryBinding, SSHKey

        binding = InventoryBinding.query.filter_by(bmc_ip="10.20.0.96").one()
        config = models["ServerConfig"].query.filter_by(bmc_ip="10.20.0.96").one()
        key = SSHKey.query.get(config.ssh_key_id)
        assert (binding.credential_revision, binding.credential_digest, binding.bmc_managed) == (
            1, body["credential_digest"], True,
        )
        assert (config.ssh_user, config.ssh_port, config.ssh_pass) == ("root", 22, "ssh-secret")
        assert (config.ipmi_user, config.ipmi_pass) == ("ADMIN", "bmc-secret")
        assert key is not None and key.key_content.startswith("-----BEGIN")


def test_bundle_requires_canonical_hmac_and_rejects_bearer_without_mutation(app_fixture, monkeypatch, tmp_path):
    """The shared encryption secret never travels as a bearer credential with ciphertext."""
    client, app, db, models = app_fixture
    _configure_local_secret(monkeypatch, tmp_path)
    payload = _bundled_payload(bmc_ip="10.20.0.96", server_ip="10.10.0.96")

    assert client.post(
        "/api/internal/inventory/reconcile", json=payload, headers=_headers()
    ).status_code == 401
    tampered = {**payload, "name": "tampered"}
    assert client.post(
        "/api/internal/inventory/reconcile", json=tampered, headers=_hmac_headers(payload)
    ).status_code == 401
    with app.app_context():
        assert models["Server"].query.filter_by(bmc_ip="10.20.0.96").first() is None


def test_bundle_rejects_tampering_and_metadata_substitution_without_mutation(app_fixture, monkeypatch, tmp_path):
    """Fernet authentication and encrypted metadata binding reject replay/substitution before writes."""
    client, app, db, models = app_fixture
    _configure_local_secret(monkeypatch, tmp_path)
    payload = _bundled_payload(bmc_ip="10.20.0.96", server_ip="10.10.0.96")
    payload["credential_bundle"] = payload["credential_bundle"][:-1] + "A"

    response = client.post(
        "/api/internal/inventory/reconcile", json=payload, headers=_hmac_headers(payload)
    )
    assert response.status_code == 400
    with app.app_context():
        assert models["Server"].query.filter_by(bmc_ip="10.20.0.96").first() is None


def test_bundled_replay_is_idempotent_but_same_revision_different_bundle_conflicts(app_fixture, monkeypatch, tmp_path):
    client, app, db, models = app_fixture
    _configure_local_secret(monkeypatch, tmp_path)
    payload = _bundled_payload(bmc_ip="10.20.0.96", server_ip="10.10.0.96")
    headers = _hmac_headers(payload)
    assert client.post("/api/internal/inventory/reconcile", json=payload, headers=headers).status_code == 200
    repeated = client.post("/api/internal/inventory/reconcile", json=payload, headers=headers)
    assert repeated.status_code == 200
    conflict = _bundled_payload(bmc_ip="10.20.0.96", server_ip="10.10.0.96")
    assert client.post(
        "/api/internal/inventory/reconcile", json=conflict, headers=_hmac_headers(conflict)
    ).status_code == 409


def test_upgrade_from_legacy_metadata_at_same_revision_applies_missing_bundle_once(app_fixture, monkeypatch, tmp_path):
    client, app, db, models = app_fixture
    _configure_local_secret(monkeypatch, tmp_path)
    legacy = _payload()
    # Existing receiver behavior remains available for old senders.
    assert client.post("/api/internal/inventory/reconcile", json=legacy, headers=_headers()).status_code == 200
    bundled = _bundled_payload()
    response = client.post(
        "/api/internal/inventory/reconcile", json=bundled, headers=_hmac_headers(bundled)
    )
    assert response.status_code == 200
    assert response.get_json()["credential_revision"] == 1


def test_bundle_explicit_bmc_clear_never_resurrects_old_per_server_or_file_password(app_fixture, monkeypatch, tmp_path):
    """A DC-managed clear takes precedence over stale config and shared file credentials."""
    client, app, db, models = app_fixture
    _configure_local_secret(monkeypatch, tmp_path)
    initial = _bundled_payload()
    assert client.post(
        "/api/internal/inventory/reconcile", json=initial, headers=_hmac_headers(initial)
    ).status_code == 200
    clear = _payload(2)
    clear["credential_bundle"] = _credential_bundle(
        clear, ssh_password=None, bmc_managed=True, bmc_password=None
    )
    assert client.post(
        "/api/internal/inventory/reconcile", json=clear, headers=_hmac_headers(clear)
    ).status_code == 200
    with app.app_context():
        from ipmi_monitor.app import get_ipmi_credentials

        config = models["ServerConfig"].query.filter_by(bmc_ip="10.20.0.90").one()
        assert (config.ipmi_user, config.ipmi_pass, config.ssh_pass) == (None, None, None)
        assert get_ipmi_credentials("10.20.0.90") == (None, None)


def test_vault_authority_rejects_bundle_before_inventory_or_credentials_change(app_fixture, monkeypatch, tmp_path):
    client, app, db, models = app_fixture
    _configure_secret(monkeypatch, tmp_path)
    payload = _bundled_payload(bmc_ip="10.20.0.96", server_ip="10.10.0.96")
    response = client.post(
        "/api/internal/inventory/reconcile", json=payload, headers=_hmac_headers(payload)
    )
    assert response.status_code == 409
    with app.app_context():
        assert models["Server"].query.filter_by(bmc_ip="10.20.0.96").first() is None


def test_signed_metadata_request_remains_supported_and_legacy_ack_is_not_signed(app_fixture, monkeypatch, tmp_path):
    client, app, db, models = app_fixture
    _configure_secret(monkeypatch, tmp_path)
    payload = _payload()
    response = client.post(
        "/api/internal/inventory/reconcile", json=payload, headers=_hmac_headers(payload)
    )
    assert response.status_code == 200
    assert set(response.get_json()) == {"accepted"}
    assert "X-DC-Response-Signature" not in response.headers


def test_invalid_explicit_credential_authority_fails_closed(app_fixture, monkeypatch, tmp_path):
    client, app, db, models = app_fixture
    _configure_local_secret(monkeypatch, tmp_path)
    monkeypatch.setenv("FLEET_CREDENTIAL_AUTHORITY", "untrusted")
    payload = _bundled_payload(bmc_ip="10.20.0.96", server_ip="10.10.0.96")
    assert client.post(
        "/api/internal/inventory/reconcile", json=payload, headers=_hmac_headers(payload)
    ).status_code == 409
    with app.app_context():
        assert models["Server"].query.filter_by(bmc_ip="10.20.0.96").first() is None


def test_retirement_clears_only_the_binding_owned_propagated_credentials(app_fixture, monkeypatch, tmp_path):
    client, app, db, models = app_fixture
    _configure_local_secret(monkeypatch, tmp_path)
    initial = _bundled_payload()
    assert client.post(
        "/api/internal/inventory/reconcile", json=initial, headers=_hmac_headers(initial)
    ).status_code == 200
    retire = _payload(2, operation="retire")
    response = client.post(
        "/api/internal/inventory/reconcile", json=retire, headers=_hmac_headers(retire)
    )
    assert response.status_code == 200
    with app.app_context():
        from ipmi_monitor.app import SSHKey

        config = models["ServerConfig"].query.filter_by(bmc_ip="10.20.0.90").one()
        assert (config.ssh_pass, config.ssh_key_id, config.ipmi_user, config.ipmi_pass) == (
            None, None, None, None,
        )
        assert SSHKey.query.count() == 0


def test_bundled_retirement_of_an_unknown_bmc_never_stores_supplied_credentials(app_fixture, monkeypatch, tmp_path):
    """A retirement records lifecycle history but must not enroll its credential pair."""
    client, app, db, models = app_fixture
    _configure_local_secret(monkeypatch, tmp_path)
    payload = _bundled_payload(1, operation="retire", bmc_ip="10.20.0.96", server_ip="10.10.0.96")

    response = client.post(
        "/api/internal/inventory/reconcile", json=payload, headers=_hmac_headers(payload)
    )

    assert response.status_code == 200
    with app.app_context():
        server = models["Server"].query.filter_by(bmc_ip="10.20.0.96").one()
        assert (server.status, server.enabled) == ("deprecated", False)
        assert models["ServerConfig"].query.filter_by(bmc_ip="10.20.0.96").first() is None
        from ipmi_monitor.app import SSHKey
        assert SSHKey.query.count() == 0


def test_metadata_only_retirement_preserves_credentials_not_installed_by_a_bundle(app_fixture, monkeypatch, tmp_path):
    client, app, db, models = app_fixture
    _configure_local_secret(monkeypatch, tmp_path)
    with app.app_context():
        db.session.add(models["ServerConfig"](
            bmc_ip="10.20.0.90", server_name="ccc90", ssh_user="root", ssh_pass="manual-secret"
        ))
        db.session.commit()
    initial = _payload()
    assert client.post(
        "/api/internal/inventory/reconcile", json=initial, headers=_headers()
    ).status_code == 200
    retire = _payload(2, operation="retire")
    assert client.post(
        "/api/internal/inventory/reconcile", json=retire, headers=_hmac_headers(retire)
    ).status_code == 200
    with app.app_context():
        assert models["ServerConfig"].query.filter_by(bmc_ip="10.20.0.90").one().ssh_pass == "manual-secret"


def test_shared_binding_key_causes_conflict_without_changing_either_server(app_fixture, monkeypatch, tmp_path):
    client, app, db, models = app_fixture
    _configure_local_secret(monkeypatch, tmp_path)
    initial = _bundled_payload()
    assert client.post(
        "/api/internal/inventory/reconcile", json=initial, headers=_hmac_headers(initial)
    ).status_code == 200
    with app.app_context():
        config = models["ServerConfig"].query.filter_by(bmc_ip="10.20.0.90").one()
        db.session.add(models["ServerConfig"](
            bmc_ip="10.20.0.97", server_name="unrelated", ssh_key_id=config.ssh_key_id
        ))
        db.session.commit()
    update = _payload(2)
    update["credential_bundle"] = _credential_bundle(update, ssh_password="changed")
    response = client.post(
        "/api/internal/inventory/reconcile", json=update, headers=_hmac_headers(update)
    )
    assert response.status_code == 409
    with app.app_context():
        config = models["ServerConfig"].query.filter_by(bmc_ip="10.20.0.90").one()
        assert config.ssh_pass == "ssh-secret"


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
