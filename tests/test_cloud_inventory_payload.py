"""Production cloud-sync payload coverage for DC inventory lifecycle metadata."""

from unittest.mock import Mock, patch


def test_sync_to_cloud_sends_bound_lifecycle_and_source_metadata(app_fixture):
    """The real producer carries a retired DC-bound BMC into the AI receiver payload."""
    client, app, db, models = app_fixture
    from ipmi_monitor.app import CloudSync, InventoryBinding, sync_to_cloud

    with app.app_context():
        db.session.add(CloudSync(license_key="test-license", sync_enabled=True, subscription_valid=True))
        db.session.add(models["Server"](
            bmc_ip="10.20.0.90", server_name="ccc90", server_ip="10.10.0.90",
            status="deprecated", enabled=False,
        ))
        db.session.add(InventoryBinding(
            source_id="11111111-1111-4111-8111-111111111111",
            source_server_id="22222222-2222-4222-8222-222222222222",
            bmc_ip="10.20.0.90", server_name="ccc90", server_ip="10.10.0.90",
            lifecycle="deprecated", revision=3,
        ))
        db.session.commit()

        response = Mock(ok=True, json=lambda: {})
        with patch("ipmi_monitor.app.sync_telemetry"), \
             patch("ipmi_monitor.app.fetch_ai_results"), \
             patch("ipmi_monitor.app.requests.post", return_value=response) as post:
            result = sync_to_cloud()

    assert result["success"] is True
    server = post.call_args.kwargs["json"]["servers"][0]
    assert server == {
        "name": "ccc90", "bmc_ip": "10.20.0.90", "server_ip": "10.10.0.90", "description": "",
        "source_id": "11111111-1111-4111-8111-111111111111",
        "source_server_id": "22222222-2222-4222-8222-222222222222",
        "lifecycle": "deprecated", "enabled": False,
    }
