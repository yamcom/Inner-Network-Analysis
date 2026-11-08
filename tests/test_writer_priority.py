import queue
import sqlite3

import pytest

from core.models import DhcpEvent, WriteBatch
from database.connection import connect_database
from database.migrations import migrate
from db_writer import DBWriter, PriorityScheduler, writer_process_main


def _db(tmp_path):
    path = str(tmp_path / "writer.db")
    connection = connect_database(path)
    migrate(connection)
    connection.close()
    return path


def _batch(job, priority, seq, mac="AA:BB:CC:DD:EE:01"):
    event = DhcpEvent(job_id=job, event_time="2026-11-07T00:00:00Z", message_type="NAK", client_mac=mac)
    return WriteBatch(job_id=job, events=(event,), stats={"NAK": 1}, batch_sequence=seq, priority=priority, batch_id=f"{job}-{priority}-{seq}")


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


def test_scheduler_serves_high_before_normal_before_low():
    clock = FakeClock()
    scheduler = PriorityScheduler(aging_seconds=30, clock=clock)
    for priority in ("LOW", "NORMAL", "HIGH", "NORMAL"):
        scheduler.push(_batch("j", priority, len(scheduler)))
    order = [scheduler.pop().priority for _ in range(4)]
    assert order == ["HIGH", "NORMAL", "NORMAL", "LOW"]


def test_scheduler_aging_prevents_low_starvation():
    clock = FakeClock()
    scheduler = PriorityScheduler(aging_seconds=10, clock=clock)
    scheduler.push(_batch("j", "LOW", 1))
    clock.now = 25.0  # LOW waited 2 aging periods -> effective HIGH
    scheduler.push(_batch("j", "HIGH", 2))
    # Equal effective rank: the original HIGH still wins the tie...
    assert scheduler.pop().priority == "HIGH"
    scheduler.push(_batch("j", "NORMAL", 3))
    # ...but the aged LOW now beats a fresh NORMAL batch.
    assert scheduler.pop().priority == "LOW"


def test_writer_process_commits_in_priority_order_and_persists_status(tmp_path):
    path = _db(tmp_path)
    inbox: queue.Queue = queue.Queue()
    errors: queue.Queue = queue.Queue()
    for seq, priority in enumerate(("LOW", "NORMAL", "HIGH"), start=1):
        inbox.put(_batch("job-p", priority, seq, mac=f"AA:BB:CC:DD:EE:0{seq}"))
    inbox.put(None)

    class NeverSet:
        def is_set(self):
            return False

    writer_process_main(path, inbox, errors, NeverSet())
    connection = connect_database(path)
    order = [row[0] for row in connection.execute("SELECT batch_id FROM write_batches ORDER BY rowid")]
    status = dict(connection.execute("SELECT key, value FROM system_status WHERE key LIKE 'writer_%'").fetchall())
    connection.close()
    assert order == ["job-p-HIGH-3", "job-p-NORMAL-2", "job-p-LOW-1"]
    assert errors.empty()
    assert status["writer_status"] == "offline"
    assert status["writer_committed_batches"] == "3"
    assert "writer_heartbeat" in status and "writer_queue_depth" in status


def test_apply_batch_retries_transient_lock_without_duplicates(tmp_path):
    path = _db(tmp_path)
    sleeps = []
    writer = DBWriter(path, retry_count=5, sleep=sleeps.append)
    real_apply = writer._apply_once
    failures = {"left": 2}

    def flaky(batch):
        if failures["left"]:
            failures["left"] -= 1
            raise sqlite3.OperationalError("database is locked")
        return real_apply(batch)

    writer._apply_once = flaky
    batch = _batch("job-r", "NORMAL", 1)
    assert writer.apply_batch(batch) is True
    assert writer.apply_batch(batch) is False  # replay is idempotent
    assert writer.total_retries == 2
    assert sleeps == [0.1, 0.2]
    connection = connect_database(path)
    assert connection.execute("SELECT COUNT(*) FROM dhcp_events").fetchone()[0] == 1
    assert connection.execute("SELECT total_events FROM analysis_stats WHERE job_id='job-r'").fetchone()[0] == 1
    connection.close()


def test_apply_batch_gives_up_and_never_marks_committed(tmp_path):
    path = _db(tmp_path)
    writer = DBWriter(path, retry_count=2, sleep=lambda _s: None)

    def always_locked(_batch):
        raise sqlite3.OperationalError("database is locked")

    writer._apply_once = always_locked
    with pytest.raises(sqlite3.OperationalError):
        writer.apply_batch(_batch("job-f", "HIGH", 1))
    assert writer.failed_batches == 1 and writer.total_retries == 2
    connection = connect_database(path)
    assert connection.execute("SELECT COUNT(*) FROM write_batches").fetchone()[0] == 0
    connection.close()


def test_non_retryable_error_is_not_retried(tmp_path):
    path = _db(tmp_path)
    writer = DBWriter(path, retry_count=5, sleep=lambda _s: pytest.fail("should not sleep"))

    def broken(_batch):
        raise sqlite3.OperationalError("no such table: dhcp_events")

    writer._apply_once = broken
    with pytest.raises(sqlite3.OperationalError):
        writer.apply_batch(_batch("job-n", "NORMAL", 1))
    assert writer.total_retries == 0
