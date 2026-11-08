from database.connection import connect_database
from database.migrations import migrate
from database.repositories import create_job
from workers.job_runner import run_csv_job


def test_csv_job_runner_writes_and_completes(tmp_path):
    database_path = str(tmp_path / "jobs.db")
    source = tmp_path / "events.csv"
    source.write_text(
        "Timestamp,Msg_Type,Client_MAC,Client_HostName,Server_IP,Server_MAC,Assigned/Req_IP,Lease_Time(sec)\n"
        "2026-11-07 00:00:00,ACK,aa:bb:cc:dd:ee:ff,pc-1,192.0.2.1,00:11:22:33:44:55,192.0.2.10,86400\n",
        encoding="utf-8",
    )
    connection = connect_database(database_path)
    migrate(connection)
    job_id = create_job(connection, "csv", source.name, str(source))
    connection.close()
    result = run_csv_job(database_path, str(source), job_id, batch_size=1)
    assert result["processed_packets"] == 1
    connection = connect_database(database_path)
    assert connection.execute("SELECT status FROM analysis_jobs WHERE job_id=?", (job_id,)).fetchone()[0] == "completed"
    assert connection.execute("SELECT COUNT(*) FROM dhcp_events WHERE job_id=?", (job_id,)).fetchone()[0] == 1
    connection.close()

