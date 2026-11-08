from fastapi.testclient import TestClient
import time

from api_v2 import create_query_app
from core.models import DhcpEvent, WriteBatch
from database.connection import connect_database
from database.migrations import migrate
from db_writer import DBWriter


def test_query_api_reads_database_with_keyset_cursor(tmp_path):
    database_path = str(tmp_path / "api.db")
    connection = connect_database(database_path)
    migrate(connection)
    connection.close()
    event = DhcpEvent(job_id="job-api", event_time="2026-11-07T00:00:00Z", message_type="NAK", client_mac="AA:BB:CC:DD:EE:FF")
    DBWriter(database_path).apply_batch(WriteBatch(job_id="job-api", events=(event,), stats={"NAK": 1}, batch_sequence=1))
    client = TestClient(create_query_app(database_path))
    response = client.get("/api/v2/events", params={"job_id": "job-api", "limit": 1})
    assert response.status_code == 200
    assert response.json()["data"][0]["message_type"] == "NAK"
    assert response.json()["next_after_id"] is not None
    devices = client.get("/api/v2/devices", params={"job_id": "job-api", "limit": 1})
    assert devices.status_code == 200
    assert devices.json()["data"][0]["mac"] == "AA:BB:CC:DD:EE:FF"


def test_job_api_accepts_csv_and_runs_in_background(tmp_path):
    database_path = str(tmp_path / "jobs-api.db")
    source = tmp_path / "events.csv"
    source.write_text(
        "Timestamp,Msg_Type,Client_MAC,Client_HostName,Server_IP,Server_MAC,Assigned/Req_IP,Lease_Time(sec)\n"
        "2026-11-07 00:00:00,ACK,aa:bb:cc:dd:ee:ff,pc-1,192.0.2.1,00:11:22:33:44:55,192.0.2.10,86400\n",
        encoding="utf-8",
    )
    with TestClient(create_query_app(database_path)) as client:
        response = client.post("/api/v2/jobs", json={"source_type": "csv", "source_path": str(source)})
        assert response.status_code == 202
        job_id = response.json()["data"]["job_id"]
        for _ in range(20):
            detail = client.get(f"/api/v2/jobs/{job_id}").json()["data"]
            if detail["status"] == "completed":
                break
            time.sleep(0.05)
        assert detail["status"] == "completed"


def test_recent_events_and_export_csv_with_time_windows(tmp_path):
    database_path = str(tmp_path / "recent.db")
    connection = connect_database(database_path)
    migrate(connection)
    connection.close()

    event = DhcpEvent(
        job_id="job-recent",
        event_time="2026-11-07T12:00:00Z",
        message_type="NAK",
        client_mac="11:22:33:44:55:66",
        relay_ip="192.69.1.254",
        hostname="test-host"
    )
    DBWriter(database_path).apply_batch(WriteBatch(job_id="job-recent", events=(event,), stats={"NAK": 1}, batch_sequence=1))

    client = TestClient(create_query_app(database_path))

    # 測試自訂時間區間包含該事件
    res = client.get("/api/v2/events/recent", params={
        "start_time": "2026-11-07T11:00:00Z",
        "end_time": "2026-11-07T13:00:00Z",
        "message_type": "NAK"
    })
    assert res.status_code == 200
    data = res.json()["data"]
    assert len(data) == 1
    assert data[0]["client_mac"] == "11:22:33:44:55:66"
    assert data[0]["relay_ip"] == "192.69.1.254"

    # 測試匯出 CSV 包含 relay_ip 與正確格式
    exp_res = client.get("/api/v2/events/export", params={
        "start_time": "2026-11-07T11:00:00Z",
        "end_time": "2026-11-07T13:00:00Z"
    })
    assert exp_res.status_code == 200
    assert "text/csv" in exp_res.headers["content-type"]
    csv_text = exp_res.content.decode("utf-8-sig")
    assert "relay_ip" in csv_text
    assert "192.69.1.254" in csv_text
    assert "11:22:33:44:55:66" in csv_text


