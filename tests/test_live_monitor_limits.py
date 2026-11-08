from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

from core.models import utc_now
from database.connection import connect_database
from database.migrations import migrate
from dhcp_monitor import LiveMonitor


def _discover():
    return (
        Ether(src="aa:bb:cc:dd:ee:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=b"\xaa\xbb\xcc\xdd\xee\xff", xid=1)
        / DHCP(options=[("message-type", "discover"), "end"])
    )


def test_in_memory_event_buffer_is_bounded_and_counts_drops(tmp_path, capsys):
    monitor = LiveMonitor(database_path=str(tmp_path / "bounded.db"), max_in_memory_events=3)
    packet = _discover()
    for _ in range(10):
        monitor.process_packet(packet)
    assert len(monitor.events) == 3
    assert monitor.dropped_events == 7
    assert monitor.total_events == 10  # statistics stay correct
    assert monitor.counters["DROPPED_IN_MEMORY_EVENTS"] == 7
    assert "in_memory_events_dropped=7" in monitor._degradation_reason()


def test_startup_marks_unfinished_live_jobs_interrupted_and_records_degradation(tmp_path):
    database_path = str(tmp_path / "recover.db")
    connection = connect_database(database_path)
    migrate(connection)
    connection.execute(
        "INSERT INTO analysis_jobs(job_id, source_type, source_name, status, created_at) VALUES ('old-live', 'live_monitor', 'live', 'running', ?)",
        (utc_now(),),
    )
    connection.commit()
    connection.close()

    monitor = LiveMonitor(database_path=database_path, max_in_memory_events=2)
    monitor.initialize()
    for _ in range(5):
        monitor.process_packet(_discover())
    monitor.flush()
    monitor.stop()

    connection = connect_database(database_path)
    jobs = dict(connection.execute("SELECT job_id, status FROM analysis_jobs").fetchall())
    error = connection.execute("SELECT error_message FROM analysis_jobs WHERE job_id=?", (monitor.job_id,)).fetchone()[0]
    status = dict(connection.execute("SELECT key, value FROM system_status").fetchall())
    events = connection.execute("SELECT COUNT(*) FROM dhcp_events").fetchone()[0]
    connection.close()
    assert jobs["old-live"] == "interrupted"
    assert jobs[monitor.job_id] == "completed"
    assert events == 2
    assert error and "in_memory_events_dropped=3" in error
    assert status["monitor_status"] == "offline"
    assert status["monitor_dropped_events"] == "3"
    assert status["writer_status"] == "offline"
