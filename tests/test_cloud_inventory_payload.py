# TRACEWEAVER: file-role=ipmi-monitor-verification; req=REQ-IPMI-MON-03; trace=TRACE-IPMI-MON-03; ver=VER-IPMI-MON-03
# TRACEWEAVER: verifies=VER-IPMI-MON-03; req=REQ-IPMI-MON-03; trace=TRACE-IPMI-MON-03
"""Production cloud-sync payload coverage for DC inventory lifecycle metadata."""

from unittest.mock import Mock, patch

from datetime import datetime, timedelta


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


def test_cloud_payload_preserves_site_observation_and_retired_history(app_fixture, monkeypatch):
    """Step 4: current sensors exclude tombstones; history and source time survive."""
    client, app, db, models = app_fixture
    import ipmi_monitor.app as runtime
    observed = datetime.utcnow() - timedelta(hours=4)
    future = datetime.utcnow() + timedelta(days=365)
    monkeypatch.setattr(runtime, 'sync_telemetry', lambda: None)
    monkeypatch.setattr(runtime, 'fetch_ai_results', lambda: None)
    monkeypatch.setattr(runtime, 'get_public_ip', lambda: '192.0.2.1')
    monkeypatch.setattr(runtime, 'generate_instance_fingerprint', lambda: (
        'instance-unchanged', {'site_id': 'site-persisted', 'site_name': 'Site A'}))
    post = Mock(return_value=Mock(ok=True, json=lambda: {}))
    monkeypatch.setattr(runtime.requests, 'post', post)
    with app.app_context():
        db.session.add(runtime.CloudSync(license_key='test-license', sync_enabled=True,
                                       subscription_valid=True, site_id='site-persisted'))
        for name, address, enabled, status in [
            ('active', '192.0.2.10', True, 'active'),
            ('retired', '192.0.2.11', False, 'deprecated'),
        ]:
            db.session.add(models['Server'](bmc_ip=address, server_name=name,
                                           enabled=enabled, status=status))
            db.session.add(models['SensorReading'](bmc_ip=address, server_name=name,
                sensor_name='CPU Temp', sensor_type='temperature', value=40,
                collected_at=observed))
            db.session.add(models['IPMIEvent'](bmc_ip=address, server_name=name,
                sel_id='1', event_date=observed, sensor_type='temperature',
                event_description='Retained history', severity='info'))
        db.session.add(models['IPMIEvent'](bmc_ip='192.0.2.10', server_name='active',
            sel_id='2', event_date=future, sensor_type='temperature',
            event_description='Future clock evidence', severity='warning', raw_entry='original raw'))
        db.session.commit()
        assert runtime.sync_to_cloud()['success'] is True
        payload = post.call_args.kwargs['json']
        assert payload.get('site_id') == 'site-persisted'
        assert payload['instance_id'] == 'instance-unchanged'
        assert [s['server_name'] for s in payload['sensors']] == ['active']
        assert payload['sensors'][0]['collected_at'] == observed.isoformat()
        assert len(payload['servers']) == 2  # Existing tombstone contract remains additive.
        assert any(event['server_name'] == 'retired' for event in payload['events'])
        future_event = next(e for e in payload['events'] if e['description'] == 'Future clock evidence')
        assert future_event['timestamp'] == future.isoformat()
        assert future_event.get('raw_entry') == 'original raw'
        status = client.get('/api/ai/status').get_json()
        assert status['server_count'] == 1
