from database.connection import connect_database
from database.migrations import migrate
from db_writer import DBWriter
from core.models import DhcpEvent, WriteBatch
from maintenance import online_backup, verify_database


def test_online_backup_and_restore_verification(tmp_path):
    database_path = str(tmp_path / "source.db")
    backup_path = str(tmp_path / "backup.db")
    connection = connect_database(database_path)
    migrate(connection)
    connection.close()
    event = DhcpEvent(job_id="maintenance", event_time="2026-11-07T00:00:00Z", message_type="ACK", client_mac="AA:BB:CC:DD:EE:FF")
    DBWriter(database_path).apply_batch(WriteBatch(job_id="maintenance", events=(event,), batch_sequence=1))
    online_backup(database_path, backup_path)
    result = verify_database(backup_path)
    assert result["integrity_check"] == "ok"
    assert result["foreign_key_errors"] == 0
    assert result["dhcp_events"] == 1


def test_maintenance_cycle_with_disk_check(tmp_path):
    from maintenance import run_all_maintenance, check_disk_space

    database_path = str(tmp_path / "source.db")
    backup_dir = str(tmp_path / "backups")

    connection = connect_database(database_path)
    migrate(connection)
    connection.close()

    disk_info = check_disk_space(tmp_path)
    assert disk_info["free_mb"] > 0
    assert disk_info["total_mb"] > 0

    res = run_all_maintenance(database_path, event_days=30, backup_dir=backup_dir)
    assert res["deleted_events"] == 0
    assert "dhcp_analyzer_backup_" in res["backup_path"]
    assert res["integrity_check"] == "ok"
    assert res["disk_free_mb"] > 0

    # 驗證當剩餘空間小於要求門檻（設定為極大值）時，主動拋出 RuntimeError 中斷
    import pytest
    with pytest.raises(RuntimeError, match="磁碟空間不足"):
        run_all_maintenance(database_path, event_days=30, backup_dir=backup_dir, min_free_mb=99999999)


