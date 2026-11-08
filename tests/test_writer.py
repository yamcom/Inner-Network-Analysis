from core.models import DhcpEvent, WriteBatch
from database.connection import connect_database
from database.migrations import migrate
from db_writer import DBWriter


def test_batch_is_idempotent(tmp_path):
    database_path = str(tmp_path / "test.db")
    connection = connect_database(database_path)
    migrate(connection)
    connection.close()
    event = DhcpEvent(job_id="job-1", event_time="2026-11-07T00:00:00Z", message_type="NAK", client_mac="AA:BB:CC:DD:EE:FF")
    batch = WriteBatch(job_id="job-1", events=(event,), stats={"NAK": 1}, batch_id="batch-1", batch_sequence=1)
    writer = DBWriter(database_path)
    assert writer.apply_batch(batch) is True
    assert writer.apply_batch(batch) is False
    connection = connect_database(database_path)
    assert connection.execute("SELECT COUNT(*) FROM dhcp_events").fetchone()[0] == 1
    assert connection.execute("SELECT COUNT(*) FROM write_batches").fetchone()[0] == 1
    connection.close()

