import hashlib
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from api_v2 import create_query_app
from core.config import PROJECT_ROOT, load_config
from database.connection import connect_database
from database.migrations import migrate
from db_writer import DBWriter

CSV_BODY = (
    "Timestamp,Msg_Type,Client_MAC,Client_HostName,Server_IP,Server_MAC,Assigned/Req_IP,Lease_Time(sec)\n"
    "2026-11-07 00:00:00,ACK,aa:bb:cc:dd:ee:ff,pc-1,192.0.2.1,00:11:22:33:44:55,192.0.2.10,86400\n"
    "2026-11-07 00:00:01,NAK,aa:bb:cc:dd:ee:01,pc-2,192.0.2.1,00:11:22:33:44:55,192.0.2.11,\n"
).encode("utf-8")


def _app(tmp_path, **config_overrides):
    database_path = str(tmp_path / "upload.db")
    config = load_config()
    for section, values in config_overrides.items():
        config[section].update(values)
    app = create_query_app(database_path, upload_root=tmp_path / "upload", config=config)
    return app, database_path


def _wait_job(client, job_id, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        detail = client.get(f"/api/v2/jobs/{job_id}").json()["data"]
        if detail["status"] in {"completed", "failed"}:
            return detail
        time.sleep(0.05)
    return detail


def test_streaming_upload_stores_hash_and_runs_background_job(tmp_path):
    app, database_path = _app(tmp_path, upload={"chunk_size_kb": 1})
    with TestClient(app) as client:
        response = client.post("/api/v2/analysis/upload", params={"filename": "capture.csv"}, content=CSV_BODY)
        assert response.status_code == 202, response.text
        data = response.json()["data"]
        assert data["sha256"] == hashlib.sha256(CSV_BODY).hexdigest()
        assert data["file_size"] == len(CSV_BODY) and data["source_type"] == "csv"
        assert _wait_job(client, data["job_id"])["status"] == "completed"
    connection = connect_database(database_path)
    source = connection.execute("SELECT * FROM analysis_sources WHERE job_id=?", (data["job_id"],)).fetchone()
    events = connection.execute("SELECT COUNT(*) FROM dhcp_events WHERE job_id=?", (data["job_id"],)).fetchone()[0]
    connection.close()
    stored = Path(source["stored_path"])
    assert stored.parent == (tmp_path / "upload" / "stored").resolve()
    assert stored.name == f"{data['source_id']}.csv"  # UUID name, not the user filename
    assert source["upload_status"] == "completed" and source["file_hash"] == data["sha256"]
    assert events == 2
    assert not any((tmp_path / "upload" / "incoming").iterdir())


def test_path_traversal_filename_is_reduced_to_basename(tmp_path):
    app, _ = _app(tmp_path)
    with TestClient(app) as client:
        response = client.post("/api/v2/analysis/upload", params={"filename": "..\\..\\..\\Windows\\evil.csv"}, content=CSV_BODY)
    assert response.status_code == 202
    data = response.json()["data"]
    assert data["filename"] == "evil.csv"
    assert (tmp_path / "upload" / "stored" / f"{data['source_id']}.csv").is_file()


def test_rejects_bad_extension_disguised_content_and_oversize(tmp_path):
    app, _ = _app(tmp_path)
    with TestClient(app) as client:
        assert client.post("/api/v2/analysis/upload", params={"filename": "run.exe"}, content=b"MZ").status_code == 400
        disguised = client.post("/api/v2/analysis/upload", params={"filename": "fake.pcap"}, content=CSV_BODY)
        assert disguised.status_code == 400
        assert "does not match" in disguised.json()["detail"]
        assert client.post("/api/v2/analysis/upload", params={"filename": "empty.csv"}, content=b"").status_code == 400
    assert not any((tmp_path / "upload" / "incoming").iterdir())
    assert not any((tmp_path / "upload" / "stored").iterdir())

    small_app, _ = _app(tmp_path / "small", upload={"max_file_size_mb": 0})
    with TestClient(small_app) as client:
        assert client.post("/api/v2/analysis/upload", params={"filename": "big.csv"}, content=CSV_BODY).status_code == 413
    assert not any((tmp_path / "small" / "upload" / "incoming").iterdir())


def test_pcap_magic_is_accepted(tmp_path):
    from scapy.layers.dhcp import BOOTP, DHCP
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether
    from scapy.utils import wrpcap

    pcap = tmp_path / "one.pcap"
    wrpcap(str(pcap), [Ether() / IP(src="192.0.2.1") / UDP(sport=67, dport=68) / BOOTP(chaddr=b"\xaa\xbb\xcc\xdd\xee\xff") / DHCP(options=[("message-type", "ack"), "end"])])
    app, _ = _app(tmp_path)
    with TestClient(app) as client:
        response = client.post("/api/v2/analysis/upload", params={"filename": "one.pcap"}, content=pcap.read_bytes())
        assert response.status_code == 202, response.text
        assert response.json()["data"]["source_type"] == "pcap"
        assert _wait_job(client, response.json()["data"]["job_id"])["status"] == "completed"


def test_job_api_rejects_sources_outside_project(tmp_path):
    app, _ = _app(tmp_path)
    outside = PROJECT_ROOT.parent / "outside.csv"
    with TestClient(app) as client:
        response = client.post("/api/v2/jobs", json={"source_type": "csv", "source_path": str(outside)})
    assert response.status_code == 400
    assert "inside the project" in response.json()["detail"]


def test_queue_limit_returns_429(tmp_path):
    app, _ = _app(tmp_path, runtime={"max_queued_jobs": 0})
    with TestClient(app) as client:
        response = client.post("/api/v2/analysis/upload", params={"filename": "x.csv"}, content=CSV_BODY)
    assert response.status_code == 429


def test_monitor_status_reports_alive_and_timeout(tmp_path):
    app, database_path = _app(tmp_path)
    writer = DBWriter(database_path)
    fresh = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    writer.write_status({"monitor_status": "running", "monitor_heartbeat": fresh, "monitor_job_id": "j1", "writer_status": "running", "writer_queue_depth": 0})
    with TestClient(app) as client:
        data = client.get("/api/v2/monitor/status").json()["data"]
        assert data["is_alive"] is True and data["job_id"] == "j1"
        assert data["writer"]["status"] == "running"
        stale = (datetime.now(timezone.utc) - timedelta(seconds=30)).isoformat(timespec="seconds").replace("+00:00", "Z")
        writer.write_status({"monitor_heartbeat": stale})
        data = client.get("/api/v2/monitor/status").json()["data"]
        assert data["is_alive"] is False and data["message"] == "監控心跳逾時"
        assert client.get("/api/v2/monitor/summary").json() == {"status": "success", "data": None}


def test_database_unavailable_returns_503(tmp_path):
    app, database_path = _app(tmp_path)
    for suffix in ("", "-wal", "-shm"):
        if os.path.exists(database_path + suffix):
            os.remove(database_path + suffix)
    with TestClient(app) as client:
        response = client.get("/api/v2/monitor/status")
        assert response.status_code == 503
        assert response.headers["retry-after"] == "2"
        assert client.get("/api/v2/jobs").status_code == 503


def test_database_locked_returns_503(tmp_path):
    app, database_path = _app(tmp_path)
    import sqlite3

    import api_v2

    original = api_v2.connect_readonly_database

    def locked(_path):
        raise sqlite3.OperationalError("database is locked")

    api_v2.connect_readonly_database = locked
    try:
        with TestClient(app) as client:
            response = client.get("/api/v2/jobs")
    finally:
        api_v2.connect_readonly_database = original
    assert response.status_code == 503
    assert response.json()["error"] == "database_busy"
