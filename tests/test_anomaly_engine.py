from core.anomaly_engine import DhcpAnomalyEngine
from core.models import DhcpEvent


def test_abnormal_lease_is_classified():
    event = DhcpEvent(job_id="j", event_time="2026-11-07T00:00:00Z", message_type="ACK", client_mac="AA:BB:CC:DD:EE:FF", lease_time=7_776_000)
    result = DhcpAnomalyEngine().classify(event)
    assert result.anomaly_type == "ABNORMAL_LEASE"
    assert result.severity == "WARNING"


def test_unauthorized_dhcp_server_is_classified():
    event = DhcpEvent(job_id="j", event_time="2026-11-07T00:00:00Z", message_type="OFFER", client_mac="AA:BB:CC:DD:EE:FF", server_ip="192.0.2.1")
    result = DhcpAnomalyEngine({"192.0.2.2"}).classify(event)
    assert result.anomaly_type == "ROGUE_DHCP"
    assert result.is_rogue is True

