"""SQLite collector concurrency bounds."""


def test_collection_workers_caps_explicit_high_setting_for_sqlite(app_fixture):
    """A large host CPU count must not create an unbounded set of SQLite writers."""
    _client, app, db, models = app_fixture
    with app.app_context():
        setting = models["SystemSettings"].query.filter_by(key="collection_workers").first()
        if setting is None:
            setting = models["SystemSettings"](key="collection_workers")
            db.session.add(setting)
        setting.value = "128"
        db.session.commit()

        from ipmi_monitor.app import get_collection_workers

        assert get_collection_workers() == 8
