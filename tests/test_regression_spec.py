"""Spec 19.11 regression using the in-project dataset upload/dhcp_events.old.csv
(114,608 rows / 28,237 NAK). Run with: uv run pytest -m regression
"""
import threading
import time

import pytest
from fastapi.testclient import TestClient

from api_v2 import create_query_app
from core.config import PROJECT_ROOT
from core.models import DhcpEvent, WriteBatch
from database.connection import connect_database, connect_readonly_database
from database.migrations import migrate
from database.repositories import create_job
from db_writer import WriterClient
from workers.job_runner import run_csv_job

DATASET = PROJECT_ROOT / "upload" / "dhcp_events.old.csv"
EXPECTED_ROWS = 114_608
EXPECTED_NAK = 28_237

pytestmark = [
    pytest.mark.regression,
    pytest.mark.slow,
    pytest.mark.skipif(not DATASET.is_file(), reason="upload/dhcp_events.old.csv not present"),
]


@pytest.fixture(scope="module")
def analysed(tmp_path_factory):
    """Run the 114,608-row CSV through the background job path while a
    HIGH-priority live writer process and read-only API queries run
    concurrently (spec 20.3-A item 4)."""
    database_path = str(tmp_path_factory.mktemp("regression") / "regression.db")
    connection = connect_database(database_path)
    migrate(connection)
    job_id = create_job(connection, "csv", DATASET.name, str(DATASET))
    connection.execute(
        "INSERT INTO analysis_jobs(job_id, source_type, source_name, status, created_at) VALUES ('live-sim', 'live_monitor', 'sim', 'running', '2026-11-07T00:00:00Z')"
    )
    connection.commit()
    connection.close()

    live = WriterClient(database_path, max_pending_batches=20)
    live.start()
    stop = threading.Event()
    read_errors: list[BaseException] = []
    reads = {"count": 0}
    live_batches = {"submitted": 0}

    def live_producer():
        seq = 0
        while not stop.is_set():
            seq += 1
            event = DhcpEvent(job_id="live-sim", event_time="2026-11-07T00:00:00Z", message_type="DISCOVER", client_mac=f"02:00:00:00:{seq // 256 % 256:02X}:{seq % 256:02X}", source_type="scapy")
            live.submit(WriteBatch(job_id="live-sim", events=(event,), stats={"DISCOVER": seq}, batch_sequence=seq, priority="HIGH",
                                   status_updates=(("monitor_heartbeat", "2026-11-07T00:00:00Z"),)), timeout=5.0)
            live_batches["submitted"] += 1
            time.sleep(0.05)

    def reader():
        while not stop.is_set():
            try:
                ro = connect_readonly_database(database_path)
                try:
                    ro.execute("SELECT status, total_events FROM analysis_jobs WHERE job_id=?", (job_id,)).fetchone()
                    ro.execute("SELECT * FROM dhcp_events ORDER BY id DESC LIMIT 100").fetchall()
                finally:
                    ro.close()
                reads["count"] += 1
            except BaseException as exc:  # noqa: BLE001 - collected for assertion
                read_errors.append(exc)
            time.sleep(0.02)

    threads = [threading.Thread(target=live_producer), threading.Thread(target=reader)]
    for thread in threads:
        thread.start()
    started = time.monotonic()
    try:
        result = run_csv_job(database_path, str(DATASET), job_id)
    finally:
        elapsed = time.monotonic() - started
        stop.set()
        for thread in threads:
            thread.join(10)
        live.stop(timeout=30)
    writer_errors = live.drain_errors()
    return {
        "database_path": database_path, "job_id": job_id, "result": result, "elapsed": elapsed,
        "read_errors": read_errors, "reads": reads["count"], "writer_errors": writer_errors,
        "live_submitted": live_batches["submitted"],
    }


def test_background_worker_completes_114608_rows(analysed):
    connection = connect_database(analysed["database_path"])
    job = connection.execute("SELECT * FROM analysis_jobs WHERE job_id=?", (analysed["job_id"],)).fetchone()
    nak = connection.execute("SELECT COUNT(*) FROM dhcp_events WHERE job_id=? AND message_type='NAK'", (analysed["job_id"],)).fetchone()[0]
    connection.close()
    print(f"\n114,608-row job: {analysed['elapsed']:.1f}s result={analysed['result']}")
    assert job["status"] == "completed"
    assert analysed["result"]["processed_packets"] == EXPECTED_ROWS
    assert job["processed_packets"] == EXPECTED_ROWS
    assert job["total_events"] == EXPECTED_ROWS - analysed["result"]["parse_errors"]
    assert nak == EXPECTED_NAK


def test_concurrent_live_writer_and_readers_have_no_lock_errors(analysed):
    connection = connect_database(analysed["database_path"])
    live_events = connection.execute("SELECT COUNT(*) FROM dhcp_events WHERE job_id='live-sim'").fetchone()[0]
    connection.close()
    print(f"\nconcurrent reads={analysed['reads']} live_batches={analysed['live_submitted']}")
    assert analysed["read_errors"] == []
    assert analysed["writer_errors"] == []
    assert analysed["reads"] > 0
    assert live_events == analysed["live_submitted"] > 0


def test_28237_nak_are_paginated_by_backend_with_500_cap(analysed):
    app = create_query_app(analysed["database_path"], upload_root=PROJECT_ROOT / "tests" / ".tmp" / "regression-upload")
    seen: set[int] = set()
    after_id = None
    pages = 0
    with TestClient(app) as client:
        too_big = client.get("/api/v2/events", params={"job_id": analysed["job_id"], "message_type": "NAK", "limit": 501})
        assert too_big.status_code == 422  # response size cap enforced by the API
        started = time.monotonic()
        while True:
            params = {"job_id": analysed["job_id"], "message_type": "NAK", "limit": 500}
            if after_id is not None:
                params["after_id"] = after_id
            body = client.get("/api/v2/events", params=params).json()
            rows = body["data"]
            if not rows:
                break
            pages += 1
            assert len(rows) <= 500
            ids = [row["id"] for row in rows]
            assert ids == sorted(ids) and not seen.intersection(ids)
            seen.update(ids)
            after_id = body["next_after_id"]
        elapsed = time.monotonic() - started
    print(f"\nNAK keyset pagination: {pages} pages in {elapsed:.2f}s")
    assert len(seen) == EXPECTED_NAK
    assert pages == -(-EXPECTED_NAK // 500)
