from __future__ import annotations

import itertools
import json
import multiprocessing as mp
import queue
import sqlite3
import time
from typing import Any, Callable

from core.models import DhcpEvent, WriteBatch, priority_rank, utc_now
from database.connection import connect_database
from database.migrations import migrate


RETRYABLE_SQLITE_MARKERS = ("locked", "busy")


def is_retryable_sqlite_error(exc: BaseException) -> bool:
    return isinstance(exc, sqlite3.OperationalError) and any(
        marker in str(exc).lower() for marker in RETRYABLE_SQLITE_MARKERS
    )


class PriorityScheduler:
    """In-process HIGH/NORMAL/LOW ordering with aging (spec 2.3 items 9-10).

    A waiting batch is promoted one priority level for every
    ``aging_seconds`` it waits, so LOW work cannot starve forever while
    HIGH live-monitor batches are still served first under normal load.
    """

    def __init__(self, aging_seconds: float = 30.0, clock: Callable[[], float] = time.monotonic):
        if aging_seconds <= 0:
            raise ValueError("aging_seconds must be positive")
        self.aging_seconds = aging_seconds
        self.clock = clock
        self._items: list[tuple[int, float, int, WriteBatch]] = []
        self._counter = itertools.count()

    def __len__(self) -> int:
        return len(self._items)

    def push(self, batch: WriteBatch) -> None:
        self._items.append((priority_rank(batch.priority), self.clock(), next(self._counter), batch))

    def pop(self) -> WriteBatch:
        if not self._items:
            raise IndexError("pop from empty scheduler")
        now = self.clock()

        def key(item: tuple[int, float, int, WriteBatch]) -> tuple[int, int, int]:
            rank, enqueued, order, _ = item
            effective = max(0, rank - int((now - enqueued) // self.aging_seconds))
            return (effective, rank, order)

        index = min(range(len(self._items)), key=lambda i: key(self._items[i]))
        return self._items.pop(index)[3]


class DBWriter:
    """Single-owner SQLite writer with batch idempotency.

    Producers submit immutable WriteBatch objects. A batch is considered
    successful only after its SQLite transaction commits.
    """

    def __init__(self, database_path: str, retry_count: int = 5, retry_backoff_initial: float = 0.1, retry_backoff_max: float = 2.0, sleep: Callable[[float], None] = time.sleep):
        self.database_path = database_path
        self._connection: sqlite3.Connection | None = None
        self.retry_count = max(0, retry_count)
        self.retry_backoff_initial = retry_backoff_initial
        self.retry_backoff_max = retry_backoff_max
        self._sleep = sleep
        self.total_retries = 0
        self.failed_batches = 0
        self.committed_batches = 0
        self.last_error: str | None = None

    def open(self) -> None:
        if self._connection is None:
            self._connection = connect_database(self.database_path)
            migrate(self._connection)

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def apply_batch(self, batch: WriteBatch) -> bool:
        """Commit a batch with bounded retry on transient SQLite locks.

        Returns True when committed, False when the batch_id was already
        committed (idempotent replay). Raises after retries are exhausted;
        a failed batch is never recorded as committed.
        """
        delay = self.retry_backoff_initial
        attempt = 0
        while True:
            try:
                result = self._apply_once(batch)
                if result:
                    self.committed_batches += 1
                return result
            except sqlite3.OperationalError as exc:
                if not is_retryable_sqlite_error(exc) or attempt >= self.retry_count:
                    self.failed_batches += 1
                    self.last_error = repr(exc)
                    raise
                attempt += 1
                self.total_retries += 1
                self.last_error = repr(exc)
                self._sleep(delay)
                delay = min(self.retry_backoff_max, delay * 2)

    def write_status(self, updates: dict[str, Any]) -> None:
        """Persist writer health keys into system_status (spec 19.4)."""
        connection = self._connection or connect_database(self.database_path)
        try:
            with connection:
                now = utc_now()
                connection.executemany(
                    "INSERT INTO system_status(key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                    [(key, "" if value is None else str(value), now) for key, value in updates.items()],
                )
        finally:
            if connection is not self._connection:
                connection.close()

    def health(self, status: str, queue_depth: int) -> dict[str, Any]:
        return {
            "writer_status": status,
            "writer_heartbeat": utc_now(),
            "writer_queue_depth": queue_depth,
            "writer_retry_count": self.total_retries,
            "writer_failed_batches": self.failed_batches,
            "writer_committed_batches": self.committed_batches,
            "writer_last_error": self.last_error or "",
        }

    def _apply_once(self, batch: WriteBatch) -> bool:
        owns_connection = self._connection is None
        connection = self._connection or connect_database(self.database_path)
        try:
            if owns_connection:
                migrate(connection)
            with connection:
                inserted = connection.execute(
                    "INSERT OR IGNORE INTO write_batches(batch_id, job_id, batch_sequence, status, committed_at) VALUES (?, ?, ?, 'committed', ?)",
                    (batch.batch_id, batch.job_id, batch.batch_sequence, utc_now()),
                ).rowcount
                if inserted == 0:
                    return False
                self._ensure_job(connection, batch)
                self._insert_events_bulk(connection, batch.events)
                self._upsert_devices_bulk(connection, batch.events)
                self._upsert_job_device_mappings_bulk(connection, batch.events)
                self._update_stats(connection, batch)
                self._update_job(connection, batch)
                for key, value in batch.status_updates:
                    connection.execute(
                        "INSERT INTO system_status(key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                        (key, value, utc_now()),
                    )
            return True
        finally:
            if owns_connection:
                connection.close()

    @staticmethod
    def _ensure_job(connection: sqlite3.Connection, batch: WriteBatch) -> None:
        connection.execute(
            "INSERT OR IGNORE INTO analysis_jobs(job_id, source_type, source_name, status, created_at) VALUES (?, 'csv', 'worker', 'running', ?)",
            (batch.job_id, utc_now()),
        )

    @staticmethod
    def _insert_event(connection: sqlite3.Connection, event: DhcpEvent) -> None:
        connection.execute(
            """INSERT OR IGNORE INTO dhcp_events(
                event_uid, job_id, event_time, created_at, source_type, message_type,
                client_mac, source_ip, source_mac, server_ip, server_mac,
                requested_ip, assigned_ip, hostname, lease_time, transaction_id,
                relay_ip, vlan_id, source_packet_no, is_rogue, anomaly_type,
                anomaly_details, anomaly_score, detected_at, matched_watch, severity
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event.event_uid, event.job_id, event.event_time, event.created_at,
                event.source_type, event.message_type, event.client_mac,
                event.source_ip, event.source_mac, event.server_ip, event.server_mac,
                event.requested_ip, event.assigned_ip, event.hostname,
                event.lease_time, event.transaction_id, event.relay_ip, event.vlan_id,
                event.source_packet_no, int(event.is_rogue), event.anomaly_type,
                event.anomaly_details, None, utc_now() if event.anomaly_type != "NONE" else None,
                0, event.severity,
            ),
        )

    @staticmethod
    def _insert_events_bulk(connection: sqlite3.Connection, events: tuple[DhcpEvent, ...]) -> None:
        if not events:
            return
        sql = """INSERT OR IGNORE INTO dhcp_events(
            event_uid, job_id, event_time, created_at, source_type, message_type,
            client_mac, source_ip, source_mac, server_ip, server_mac,
            requested_ip, assigned_ip, hostname, lease_time, transaction_id,
            relay_ip, vlan_id, source_packet_no, is_rogue, anomaly_type,
            anomaly_details, anomaly_score, detected_at, matched_watch, severity
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"""
        rows = []
        for event in events:
            rows.append((
                event.event_uid, event.job_id, event.event_time, event.created_at,
                event.source_type, event.message_type, event.client_mac,
                event.source_ip, event.source_mac, event.server_ip, event.server_mac,
                event.requested_ip, event.assigned_ip, event.hostname, event.lease_time,
                event.transaction_id, event.relay_ip, event.vlan_id, event.source_packet_no,
                int(event.is_rogue), event.anomaly_type, event.anomaly_details, None,
                utc_now() if event.anomaly_type != "NONE" else None, 0, event.severity,
            ))
        connection.executemany(sql, rows)

    @staticmethod
    def _latest_by_mac(events: tuple[DhcpEvent, ...]) -> dict[str, tuple[DhcpEvent, DhcpEvent]]:
        grouped: dict[str, list[DhcpEvent]] = {}
        for event in events:
            if event.client_mac:
                grouped.setdefault(event.client_mac, []).append(event)
        result = {}
        for mac, items in grouped.items():
            first = items[0]
            latest = items[-1]
            for event in reversed(items):
                if event.hostname or event.assigned_ip or event.requested_ip:
                    latest = event
                    break
            result[mac] = (first, latest)
        return result

    @staticmethod
    def _upsert_devices_bulk(connection: sqlite3.Connection, events: tuple[DhcpEvent, ...]) -> None:
        grouped = DBWriter._latest_by_mac(events)
        if not grouped:
            return
        sql = """INSERT INTO devices(mac, hostname, last_ip, first_seen, last_seen, last_source_type, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(mac) DO UPDATE SET
            hostname=COALESCE(excluded.hostname, devices.hostname),
            last_ip=COALESCE(excluded.last_ip, devices.last_ip),
            last_seen=excluded.last_seen,
            last_source_type=excluded.last_source_type,
            updated_at=excluded.updated_at"""
        now = utc_now()
        rows = []
        for mac, (first, latest) in grouped.items():
            rows.append((mac, latest.hostname, latest.assigned_ip or latest.requested_ip,
                         first.event_time, latest.event_time, latest.source_type, now, now))
        connection.executemany(sql, rows)

    @staticmethod
    def _upsert_job_device_mappings_bulk(connection: sqlite3.Connection, events: tuple[DhcpEvent, ...]) -> None:
        grouped = DBWriter._latest_by_mac(events)
        if not grouped:
            return
        sql = """INSERT INTO job_device_mappings(job_id, mac, hostname, ip, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(job_id, mac) DO UPDATE SET
            hostname=COALESCE(excluded.hostname, job_device_mappings.hostname),
            ip=COALESCE(excluded.ip, job_device_mappings.ip),
            last_seen=excluded.last_seen"""
        rows = []
        for mac, (first, latest) in grouped.items():
            rows.append((latest.job_id, mac, latest.hostname,
                         latest.assigned_ip or latest.requested_ip,
                         first.event_time, latest.event_time))
        connection.executemany(sql, rows)

    @staticmethod
    def _upsert_device(connection: sqlite3.Connection, event: DhcpEvent) -> None:
        if not event.client_mac:
            return
        now = utc_now()
        connection.execute(
            """INSERT INTO devices(mac, hostname, last_ip, first_seen, last_seen, last_source_type, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(mac) DO UPDATE SET
                hostname=COALESCE(excluded.hostname, devices.hostname),
                last_ip=COALESCE(excluded.last_ip, devices.last_ip),
                last_seen=excluded.last_seen,
                last_source_type=excluded.last_source_type,
                updated_at=excluded.updated_at""",
            (event.client_mac, event.hostname, event.assigned_ip or event.requested_ip,
             event.event_time, event.event_time, event.source_type, now, now),
        )

    @staticmethod
    def _upsert_job_device_mapping(connection: sqlite3.Connection, event: DhcpEvent) -> None:
        if not event.client_mac:
            return
        connection.execute(
            """INSERT INTO job_device_mappings(job_id, mac, hostname, ip, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(job_id, mac) DO UPDATE SET
                hostname=COALESCE(excluded.hostname, job_device_mappings.hostname),
                ip=COALESCE(excluded.ip, job_device_mappings.ip),
                last_seen=excluded.last_seen""",
            (event.job_id, event.client_mac, event.hostname,
             event.assigned_ip or event.requested_ip, event.event_time, event.event_time),
        )

    @staticmethod
    def _update_stats(connection: sqlite3.Connection, batch: WriteBatch) -> None:
        counters = json.dumps(batch.stats, ensure_ascii=False, sort_keys=True)
        connection.execute(
            """INSERT INTO analysis_stats(job_id, snapshot_sequence, total_packets, total_events, counters_json, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(job_id) DO UPDATE SET
                snapshot_sequence=MAX(snapshot_sequence, excluded.snapshot_sequence),
                total_packets=MAX(total_packets, excluded.total_packets),
                total_events=analysis_stats.total_events + excluded.total_events,
                counters_json=excluded.counters_json,
                updated_at=excluded.updated_at""",
            (batch.job_id, batch.batch_sequence, batch.processed_packets or 0,
             len(batch.events), counters, utc_now()),
        )

    @staticmethod
    def _update_job(connection: sqlite3.Connection, batch: WriteBatch) -> None:
        fields: list[str] = ["status='running'", "last_progress_at=?", "total_events=total_events+?"]
        values: list[Any] = [utc_now(), len(batch.events)]
        if batch.progress is not None:
            fields.append("progress=?")
            values.append(max(0, min(100, batch.progress)))
        if batch.processed_packets is not None:
            fields.append("processed_packets=MAX(processed_packets, ?)")
            values.append(batch.processed_packets)
        values.append(batch.job_id)
        connection.execute(f"UPDATE analysis_jobs SET {', '.join(fields)} WHERE job_id=?", values)


def writer_process_main(database_path: str, input_queue: mp.Queue, error_queue: mp.Queue, stop_event: mp.Event, status_interval: float = 5.0, aging_seconds: float = 30.0) -> None:
    writer = DBWriter(database_path)
    writer.open()
    scheduler = PriorityScheduler(aging_seconds=aging_seconds)
    last_status = 0.0
    draining = False

    def persist_status(status: str) -> None:
        try:
            writer.write_status(writer.health(status, len(scheduler)))
        except Exception as exc:  # status is best-effort; never kill the writer
            writer.last_error = repr(exc)

    def pull(block: bool) -> bool:
        """Move queued batches into the scheduler; return False on sentinel."""
        nonlocal draining
        timeout = 0.2 if block else 0.0
        while True:
            try:
                item = input_queue.get(timeout=timeout) if timeout else input_queue.get_nowait()
            except queue.Empty:
                return True
            if item is None:
                draining = True
                return False
            scheduler.push(item)
            timeout = 0.0

    try:
        persist_status("running")
        last_status = time.monotonic()
        while True:
            try:
                pull(block=len(scheduler) == 0 and not draining)
                if stop_event.is_set():
                    draining = True
                if len(scheduler) == 0:
                    if draining:
                        break
                else:
                    batch = scheduler.pop()
                    try:
                        writer.apply_batch(batch)
                    except Exception as exc:
                        # The owning supervisor must record/retry the failed batch. The
                        # writer process never silently marks a failed batch as committed.
                        error_queue.put({"batch_id": batch.batch_id, "job_id": batch.job_id, "priority": batch.priority, "error": repr(exc)})
                if time.monotonic() - last_status >= status_interval:
                    persist_status("running")
                    last_status = time.monotonic()
            except KeyboardInterrupt:
                # Windows can deliver Ctrl-C to the writer child as well as the
                # console process. Keep draining; the supervisor owns shutdown.
                draining = True
        persist_status("offline")
    finally:
        writer.close()


class WriterClient:
    def __init__(self, database_path: str, max_pending_batches: int = 20):
        self.queue: mp.Queue = mp.Queue(maxsize=max_pending_batches)
        self.errors: mp.Queue = mp.Queue()
        self.stop_event = mp.Event()
        self.process = mp.Process(target=writer_process_main, args=(database_path, self.queue, self.errors, self.stop_event), daemon=True)

    def start(self) -> None:
        self.process.start()

    def submit(self, batch: WriteBatch, timeout: float = 1.0) -> None:
        self.queue.put(batch, timeout=timeout)

    def drain_errors(self) -> list[dict[str, Any]]:
        """Return batches the writer could not commit (never marked success)."""
        errors: list[dict[str, Any]] = []
        while True:
            try:
                errors.append(self.errors.get_nowait())
            except (queue.Empty, OSError, ValueError):
                return errors

    def stop(self, timeout: float = 60.0) -> None:
        self.stop_event.set()
        # A full queue must not make Ctrl-C wait forever.  stop_event causes
        # the writer to exit after its current queue has drained; the sentinel
        # is only an acceleration when there is room.
        try:
            self.queue.put(None, timeout=min(timeout, 1.0))
        except queue.Full:
            pass
        self.process.join(timeout)
        if self.process.is_alive():
            self.process.terminate()
            self.process.join(5.0)

