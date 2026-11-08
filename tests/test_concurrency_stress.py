from __future__ import annotations

import concurrent.futures
import time
from pathlib import Path

from fastapi.testclient import TestClient

from api_v2 import create_query_app
from core.models import DhcpEvent, WriteBatch
from database.connection import connect_database
from database.migrations import migrate
from db_writer import DBWriter, WriterClient


def test_concurrent_monitor_worker_and_query_api_stress(tmp_path: Path):
    """Spec 20.3-A item 2: Concurrent live monitor (HIGH), offline worker (NORMAL), and Web Query API."""
    database_path = str(tmp_path / "concurrent_stress.db")
    connection = connect_database(database_path)
    migrate(connection)
    connection.close()

    writer_client = WriterClient(database_path)
    writer_client.start()

    app = create_query_app(database_path)
    client = TestClient(app)

    live_events_count = 50
    worker_events_count = 100

    def live_monitor_producer():
        for i in range(live_events_count):
            evt = DhcpEvent(
                job_id="job-live-stress",
                event_time="2026-11-07T12:00:00Z",
                message_type="ACK",
                client_mac=f"00:11:22:33:44:{i%50:02x}",
                assigned_ip=f"192.69.1.{i%50+10}",
                hostname=f"live-host-{i}",
            )
            writer_client.submit(WriteBatch(job_id="job-live-stress", events=(evt,), batch_sequence=i+1, priority="HIGH"))
            time.sleep(0.01)

    def offline_worker_producer():
        events = [
            DhcpEvent(
                job_id="job-offline-stress",
                event_time="2026-11-07T12:00:00Z",
                message_type="DISCOVER",
                client_mac=f"00:99:88:77:66:{i%50:02x}",
                hostname=f"worker-host-{i}",
            )
            for i in range(worker_events_count)
        ]
        # 分兩批 NORMAL 優先權提交
        writer_client.submit(WriteBatch(job_id="job-offline-stress", events=tuple(events[:50]), batch_sequence=1, priority="NORMAL"))
        time.sleep(0.05)
        writer_client.submit(WriteBatch(job_id="job-offline-stress", events=tuple(events[50:]), batch_sequence=2, priority="NORMAL"))

    def web_query_consumer():
        for _ in range(15):
            res = client.get("/api/v2/events/recent", params={"minutes": 60, "limit": 100})
            assert res.status_code in {200, 503}
            time.sleep(0.01)

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        f_live = executor.submit(live_monitor_producer)
        f_worker = executor.submit(offline_worker_producer)
        f_queries = [executor.submit(web_query_consumer) for _ in range(3)]

        concurrent.futures.wait([f_live, f_worker, *f_queries])

        f_live.result()
        f_worker.result()
        for f in f_queries:
            f.result()

    writer_client.stop(timeout=10.0)

    # 驗證資料庫最終一致性
    conn = connect_database(database_path)
    try:
        total_live = conn.execute("SELECT COUNT(*) FROM dhcp_events WHERE job_id='job-live-stress'").fetchone()[0]
        total_worker = conn.execute("SELECT COUNT(*) FROM dhcp_events WHERE job_id='job-offline-stress'").fetchone()[0]
        assert total_live == live_events_count
        assert total_worker == worker_events_count
    finally:
        conn.close()
