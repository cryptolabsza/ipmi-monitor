"""Current fleet metrics must not resurrect retained or renamed inventory."""

from datetime import datetime, timedelta

from prometheus_client.parser import text_string_to_metric_families


def _samples(client):
    response = client.get("/metrics")
    assert response.status_code == 200
    return [sample for metric in text_string_to_metric_families(response.text) for sample in metric.samples]


def _value(samples, name):
    return next(sample.value for sample in samples if sample.name == name)


def _seed(db, models, address, name):
    now = datetime.utcnow()
    db.session.add(models["Server"](bmc_ip=address, server_name=name, server_ip="10.10.0.90"))
    db.session.add(models["ServerStatus"](
        bmc_ip=address, server_name=name, is_reachable=True, power_status="on", total_events=1,
    ))
    db.session.add(models["SensorReading"](
        bmc_ip=address, server_name=name, sensor_name="CPU", sensor_type="temperature", value=45,
        collected_at=now,
    ))
    db.session.add(models["PowerReading"](
        bmc_ip=address, server_name=name, current_watts=450, collected_at=now,
    ))
    db.session.add(models["IPMIEvent"](
        bmc_ip=address, server_name=name, sel_id="event1", event_date=now,
        sensor_type="Temperature", event_description="Synthetic event", severity="critical",
    ))
    db.session.add(models["AlertHistory"](
        bmc_ip=address, server_name=name, severity="critical", fired_at=now,
    ))
    db.session.commit()


def test_retirement_removes_current_series_and_totals_without_deleting_history(app_fixture):
    client, app, db, models = app_fixture
    with app.app_context():
        _seed(db, models, "10.20.0.90", "current")
        _seed(db, models, "10.20.0.91", "obsolete")
    before = _samples(client)
    assert _value(before, "ipmi_total_servers") == 2
    assert any(sample.labels.get("server_name") == "obsolete" for sample in before)

    with app.app_context():
        models["Server"].query.filter_by(bmc_ip="10.20.0.91").one().deprecate("Retired")
        db.session.commit()

    after = _samples(client)
    assert not any(sample.labels.get("bmc_ip") == "10.20.0.91" for sample in after)
    for name in ("ipmi_total_servers", "ipmi_reachable_servers", "ipmi_total_critical_events_24h",
                 "ipmi_alerts_total", "ipmi_alerts_unacknowledged", "ipmi_alerts_critical_24h"):
        assert _value(after, name) == 1
    with app.app_context():
        for model in ("ServerStatus", "SensorReading", "PowerReading", "IPMIEvent", "AlertHistory"):
            assert models[model].query.filter_by(bmc_ip="10.20.0.91").count() == 1


def test_rename_relabels_current_readings_and_discards_old_metric_children(app_fixture):
    client, app, db, models = app_fixture
    with app.app_context():
        _seed(db, models, "10.20.0.90", "old-name")
    assert any(sample.labels.get("server_name") == "old-name" for sample in _samples(client))
    with app.app_context():
        models["Server"].query.filter_by(bmc_ip="10.20.0.90").one().server_name = "new-name"
        models["ServerStatus"].query.filter_by(bmc_ip="10.20.0.90").one().server_name = "new-name"
        db.session.commit()

    after = _samples(client)
    per_server = [sample for sample in after if sample.labels.get("bmc_ip") == "10.20.0.90"]
    assert per_server
    assert {sample.labels["server_name"] for sample in per_server} == {"new-name"}
    assert _value(after, "ipmi_temperature_celsius") == 45
    assert _value(after, "ipmi_power_watts") == 450
    with app.app_context():
        assert models["SensorReading"].query.one().server_name == "old-name"


def test_expired_readings_stop_being_exported_on_next_scrape(app_fixture):
    client, app, db, models = app_fixture
    with app.app_context():
        _seed(db, models, "10.20.0.90", "current")
    assert _value(_samples(client), "ipmi_temperature_celsius") == 45
    with app.app_context():
        for model in ("SensorReading", "PowerReading"):
            models[model].query.one().collected_at = datetime.utcnow() - timedelta(hours=2)
        db.session.commit()
    after = _samples(client)
    assert not any(sample.name in ("ipmi_temperature_celsius", "ipmi_power_watts") for sample in after)
