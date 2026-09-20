"""Regression coverage for bounded SQLite retention cleanup."""

from datetime import datetime, timedelta
from threading import Event, Thread

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import scoped_session, sessionmaker
import ipmi_monitor.app as app_module

from ipmi_monitor.app import (
    AIResult,
    AlertHistory,
    IPMIEvent,
    PowerReading,
    SensorReading,
    _cleanup_old_ssh_logs,
    _cleanup_has_more,
    _cleanup_wait_seconds,
    _delete_expired_rows_in_batches,
    cleanup_old_data,
    db,
)


@pytest.fixture()
def sqlite_sessions(tmp_path):
    """Use the production model metadata on a file-backed SQLite database."""
    engine = create_engine(f"sqlite:///{tmp_path / 'retention.db'}", connect_args={"timeout": 1})
    db.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine)
    yield sessions
    db.metadata.drop_all(engine)
    engine.dispose()


def _old_event(index, when):
    return IPMIEvent(
        bmc_ip="10.0.0.1",
        server_name="retention-test",
        sel_id=f"old-{index}",
        event_date=when,
        sensor_type="System Event",
        event_description="expired event",
        severity="info",
    )


def _current_event(sel_id, when):
    return IPMIEvent(
        bmc_ip="10.0.0.1",
        server_name="retention-test",
        sel_id=sel_id,
        event_date=when,
        sensor_type="System Event",
        event_description="current event",
        severity="info",
    )


def _release(session):
    session.close()


@pytest.fixture()
def entrypoint_sessions(tmp_path, monkeypatch):
    """Attach the real app models to an isolated file-backed SQLite session registry."""
    engine = create_engine(
        f"sqlite:///{tmp_path / 'entrypoint.db'}", connect_args={"timeout": 0.2, "check_same_thread": False}
    )
    sessions = scoped_session(sessionmaker(bind=engine))
    db.metadata.create_all(engine)
    monkeypatch.setattr(db, "session", sessions)
    yield engine, sessions
    sessions.remove()
    db.metadata.drop_all(engine)
    engine.dispose()


def test_committed_cleanup_batches_allow_independent_reader_and_writer(sqlite_sessions):
    """A reader and writer both progress after a real committed delete batch."""
    now = datetime.utcnow()
    cutoff = now - timedelta(days=30)
    seed = sqlite_sessions()
    seed.add_all(_old_event(index, cutoff - timedelta(minutes=index + 1)) for index in range(6))
    seed.commit()
    seed.close()

    observed = []

    def between_batches(result):
        if result["batches"] != 1:
            return
        reader = sqlite_sessions()
        try:
            observed.append(reader.query(IPMIEvent).count())
        finally:
            reader.close()

        writer = sqlite_sessions()
        try:
            writer.add(_current_event("written-between-batches", now))
            writer.commit()
        finally:
            writer.close()

    summary = _delete_expired_rows_in_batches(
        IPMIEvent,
        IPMIEvent.event_date,
        cutoff,
        label="events",
        batch_size=2,
        max_batches=10,
        session_factory=sqlite_sessions,
        release_session=_release,
        after_batch=between_batches,
    )

    verify = sqlite_sessions()
    try:
        assert summary == {"deleted": 6, "batches": 3, "complete": True, "failed": False}
        assert observed == [4]
        assert verify.query(IPMIEvent).filter(IPMIEvent.event_date < cutoff).count() == 0
        assert verify.query(IPMIEvent).filter_by(sel_id="written-between-batches").count() == 1
    finally:
        verify.close()


def test_cleanup_entrypoint_releases_event_batch_before_sensor_scan(entrypoint_sessions, monkeypatch):
    """The production entrypoint commits event cleanup before it queries sensor retention."""
    engine, sessions = entrypoint_sessions
    now = datetime.utcnow()
    seed = sessions()
    seed.add(_old_event(1, now - timedelta(days=31)))
    seed.commit()
    seed.close()
    monkeypatch.setattr(app_module, "_cleanup_target_cursor", 0)

    sensor_scan_started = Event()
    continue_cleanup = Event()

    def pause_before_sensor_scan(conn, cursor, statement, parameters, context, executemany):
        if "FROM sensor_reading" in statement and not sensor_scan_started.is_set():
            sensor_scan_started.set()
            assert continue_cleanup.wait(timeout=5)

    event.listen(engine, "before_cursor_execute", pause_before_sensor_scan)
    worker_errors = []

    def run_cleanup():
        try:
            cleanup_old_data()
        except Exception as exc:  # pragma: no cover - assertion below reports it
            worker_errors.append(exc)

    worker = Thread(target=run_cleanup)
    worker.start()
    assert sensor_scan_started.wait(timeout=5)

    writer = sessions()
    try:
        writer.add(_current_event("writer-during-cleanup", now))
        writer.commit()
    finally:
        writer.close()
        continue_cleanup.set()
        worker.join(timeout=5)
        event.remove(engine, "before_cursor_execute", pause_before_sensor_scan)

    assert not worker.is_alive()
    assert worker_errors == []


def test_cleanup_rotates_bounded_batches_across_all_retention_targets(sqlite_sessions):
    """A large event backlog cannot starve sensor, power, alert, or AI retention."""
    now = datetime.utcnow()
    old = now - timedelta(days=60)
    seed = sqlite_sessions()
    for index in range(3):
        seed.add(_old_event(index, old))
        seed.add(SensorReading(
            bmc_ip="10.0.0.1", server_name="retention-test", sensor_name=f"temp-{index}",
            sensor_type="temperature", collected_at=old,
        ))
        seed.add(PowerReading(bmc_ip="10.0.0.1", server_name="retention-test", collected_at=old))
        seed.add(AlertHistory(rule_name="expired", fired_at=old))
        seed.add(AIResult(result_type="summary", expires_at=old))
    seed.add(_current_event("current", now))
    seed.commit()
    seed.close()

    first_run = cleanup_old_data(
        now=now,
        batch_size=2,
        max_batches=5,
        session_factory=sqlite_sessions,
        release_session=_release,
    )
    second_run = cleanup_old_data(
        now=now,
        batch_size=2,
        max_batches=5,
        session_factory=sqlite_sessions,
        release_session=_release,
    )

    verify = sqlite_sessions()
    try:
        assert first_run["events"]["deleted"] == 2
        assert first_run["sensors"]["deleted"] == 2
        assert first_run["power"]["deleted"] == 2
        assert first_run["alerts"]["deleted"] == 2
        assert first_run["ai_results"]["deleted"] == 2
        assert first_run["events"]["complete"] is False
        assert _cleanup_has_more(first_run) is True
        assert second_run["events"]["deleted"] == 1
        assert all(result["complete"] for result in second_run.values())
        assert _cleanup_has_more(second_run) is False
        assert verify.query(IPMIEvent).filter(IPMIEvent.event_date < now - timedelta(days=30)).count() == 0
        assert verify.query(SensorReading).filter(SensorReading.collected_at < now - timedelta(days=7)).count() == 0
        assert verify.query(PowerReading).filter(PowerReading.collected_at < now - timedelta(days=7)).count() == 0
        assert verify.query(AlertHistory).filter(AlertHistory.fired_at < now - timedelta(days=30)).count() == 0
        assert verify.query(AIResult).filter(AIResult.expires_at < now).count() == 0
        assert verify.query(IPMIEvent).filter_by(sel_id="current").count() == 1
    finally:
        verify.close()


def test_failed_batch_rolls_back_only_that_batch(sqlite_sessions):
    """A failed second commit preserves its rows but not earlier committed batches."""
    now = datetime.utcnow()
    cutoff = now - timedelta(days=30)
    seed = sqlite_sessions()
    seed.add_all(_old_event(index, cutoff - timedelta(minutes=index + 1)) for index in range(5))
    seed.commit()
    seed.close()

    commit_attempts = 0

    def failing_session_factory():
        nonlocal commit_attempts
        session = sqlite_sessions()
        original_commit = session.commit

        def commit():
            nonlocal commit_attempts
            commit_attempts += 1
            if commit_attempts == 2:
                raise RuntimeError("simulated second-batch failure")
            return original_commit()

        session.commit = commit
        return session

    summary = _delete_expired_rows_in_batches(
        IPMIEvent,
        IPMIEvent.event_date,
        cutoff,
        label="events",
        batch_size=2,
        max_batches=10,
        session_factory=failing_session_factory,
        release_session=_release,
    )

    verify = sqlite_sessions()
    try:
        assert summary == {"deleted": 2, "batches": 1, "complete": False, "failed": True}
        assert verify.query(IPMIEvent).filter(IPMIEvent.event_date < cutoff).count() == 3
    finally:
        verify.close()


def test_cleanup_honours_shutdown_before_starting_another_batch(sqlite_sessions):
    """Timer shutdown stops retention work before it opens a new write transaction."""
    now = datetime.utcnow()
    cutoff = now - timedelta(days=30)
    seed = sqlite_sessions()
    seed.add(_old_event(1, cutoff - timedelta(minutes=1)))
    seed.commit()
    seed.close()
    stopped = Event()
    stopped.set()

    summary = _delete_expired_rows_in_batches(
        IPMIEvent,
        IPMIEvent.event_date,
        cutoff,
        label="events",
        session_factory=sqlite_sessions,
        release_session=_release,
        stop_event=stopped,
    )

    verify = sqlite_sessions()
    try:
        assert summary == {"deleted": 0, "batches": 0, "complete": False, "failed": False}
        assert verify.query(IPMIEvent).filter(IPMIEvent.event_date < cutoff).count() == 1
    finally:
        verify.close()


def test_cleanup_honours_an_expired_run_deadline(sqlite_sessions):
    """The scheduler deadline stops a cleanup run before it acquires a write lock."""
    now = datetime.utcnow()
    seed = sqlite_sessions()
    seed.add(_old_event(1, now - timedelta(days=31)))
    seed.commit()
    seed.close()

    summary = cleanup_old_data(
        now=now,
        deadline=0,
        session_factory=sqlite_sessions,
        release_session=_release,
    )

    verify = sqlite_sessions()
    try:
        assert summary["events"] == {"deleted": 0, "batches": 0, "complete": False, "failed": False}
        assert verify.query(IPMIEvent).count() == 1
    finally:
        verify.close()


def test_unfinished_retention_uses_short_continuation_not_the_six_hour_interval():
    unfinished = {"events": {"deleted": 500, "batches": 1, "complete": False, "failed": False}}
    complete = {"events": {"deleted": 0, "batches": 0, "complete": True, "failed": False}}

    assert _cleanup_wait_seconds(unfinished) < _cleanup_wait_seconds(complete)


def test_ssh_log_retention_uses_the_same_bounded_batch_contract(sqlite_sessions):
    """The raw ssh_logs table also releases its write transaction between batches."""
    now = datetime.utcnow()
    old = now - timedelta(days=10)
    seed = sqlite_sessions()
    seed.execute(db.text(
        "CREATE TABLE ssh_logs (id INTEGER PRIMARY KEY, collected_at DATETIME NOT NULL)"
    ))
    for index in range(5):
        seed.execute(
            db.text("INSERT INTO ssh_logs (id, collected_at) VALUES (:id, :collected_at)"),
            {"id": index + 1, "collected_at": old},
        )
    seed.execute(
        db.text("INSERT INTO ssh_logs (id, collected_at) VALUES (99, :collected_at)"),
        {"collected_at": now},
    )
    seed.commit()
    seed.close()

    first_run = _cleanup_old_ssh_logs(
        days=7,
        now=now,
        batch_size=2,
        max_batches=1,
        session_factory=sqlite_sessions,
        release_session=_release,
    )
    second_run = _cleanup_old_ssh_logs(
        days=7,
        now=now,
        batch_size=2,
        max_batches=2,
        session_factory=sqlite_sessions,
        release_session=_release,
    )

    verify = sqlite_sessions()
    try:
        assert first_run == {"deleted": 2, "batches": 1, "complete": False, "failed": False}
        assert second_run == {"deleted": 3, "batches": 2, "complete": True, "failed": False}
        assert verify.execute(db.text("SELECT COUNT(*) FROM ssh_logs WHERE id != 99")).scalar() == 0
        assert verify.execute(db.text("SELECT COUNT(*) FROM ssh_logs WHERE id = 99")).scalar() == 1
    finally:
        verify.close()
