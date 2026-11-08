from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

from database.connection import connect_database
from dhcp_monitor import LiveMonitor


def test_live_monitor_persists_events_and_heartbeat(tmp_path):
    database_path = str(tmp_path / "live.db")
    monitor = LiveMonitor(database_path=database_path, batch_interval=5)
    monitor.initialize()
    packet = (
        Ether(src="aa:bb:cc:dd:ee:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=b"\xaa\xbb\xcc\xdd\xee\xff", xid=1)
        / DHCP(options=[("message-type", "discover"), ("hostname", b"lab-pc"), "end"])
    )
    for _ in range(10):
        monitor.process_packet(packet)
    monitor.flush()
    monitor.stop()
    connection = connect_database(database_path)
    assert connection.execute("SELECT COUNT(*) FROM dhcp_events").fetchone()[0] == 10
    assert connection.execute("SELECT value FROM system_status WHERE key='monitor_heartbeat'").fetchone() is not None
    assert connection.execute("SELECT status FROM analysis_jobs").fetchone()[0] == "completed"
    connection.close()

