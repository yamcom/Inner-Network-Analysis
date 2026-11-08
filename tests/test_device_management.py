from __future__ import annotations

from pathlib import Path
from fastapi.testclient import TestClient

from api_v2 import create_query_app
from core.models import DhcpEvent, WriteBatch
from database.connection import connect_database
from database.migrations import migrate
from db_writer import DBWriter


def test_device_manual_metadata_persistence_and_no_dhcp_overwrite(tmp_path: Path):
    database_path = str(tmp_path / "test_devices.db")
    connection = connect_database(database_path)
    migrate(connection)
    connection.close()

    client = TestClient(create_query_app(database_path))

    mac = "00:11:22:33:44:55"

    # 1. 管理員手動設定設備名稱與位置
    res = client.patch(f"/api/v2/devices/{mac}", json={
        "device_name": "3F 會議室投影機",
        "location": "管理大樓 301"
    })
    assert res.status_code == 200
    data = res.json()["data"]
    assert data["mac"] == mac
    assert data["device_name"] == "3F 會議室投影機"
    assert data["location"] == "管理大樓 301"

    # 2. 模擬 DHCP 即時監控寫入封包事件 (自動更新 hostname 與 last_ip)
    writer = DBWriter(database_path)
    event = DhcpEvent(
        job_id="job-live-dhcp",
        event_time="2026-11-08T00:00:00Z",
        message_type="ACK",
        client_mac=mac,
        assigned_ip="192.69.1.50",
        hostname="projector-301",
    )
    writer.apply_batch(WriteBatch(job_id="job-live-dhcp", events=(event,), batch_sequence=1))

    # 3. 驗證資料庫中的人工維護欄位未被 DHCP 覆寫 (規格書 4.6 原則)
    conn = connect_database(database_path)
    try:
        row = conn.execute("SELECT * FROM devices WHERE mac=?", (mac,)).fetchone()
        assert row["hostname"] == "projector-301"
        assert row["last_ip"] == "192.69.1.50"
        assert row["device_name"] == "3F 會議室投影機"
        assert row["location"] == "管理大樓 301"
    finally:
        conn.close()

    # 4. 驗證 job_devices 查詢能成功 LEFT JOIN 出人工設定的名稱與位置
    job_dev_res = client.get("/api/v2/devices", params={"job_id": "job-live-dhcp"})
    assert job_dev_res.status_code == 200
    job_dev_data = job_dev_res.json()["data"]
    assert len(job_dev_data) == 1
    assert job_dev_data[0]["mac"] == mac
    assert job_dev_data[0]["hostname"] == "projector-301"
    assert job_dev_data[0]["device_name"] == "3F 會議室投影機"
    assert job_dev_data[0]["location"] == "管理大樓 301"
