from __future__ import annotations

import ipaddress

from core.dhcp_fields import extract_hostname
from core.models import DhcpEvent, normalize_mac, safe_optional


MESSAGE_TYPES = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE", 5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM"}


def _options_to_dict(options) -> dict:
    values = {}
    for option in options or []:
        if not isinstance(option, tuple) or len(option) != 2:
            continue
        key, value = option
        values[key] = value
        if isinstance(key, str):
            values[key.replace("-", "_")] = value
    return values


def parse_scapy_packet(packet, job_id: str, source_type: str = "scapy", source_packet_no: int | None = None, event_time: str | None = None) -> DhcpEvent | None:
    """Convert one Scapy DHCP packet into the shared event model."""
    from scapy.layers.dhcp import BOOTP, DHCP
    from scapy.layers.inet import IP
    from scapy.layers.l2 import Ether

    if not packet.haslayer(DHCP) or not packet.haslayer(BOOTP):
        return None
    bootp = packet[BOOTP]
    options = _options_to_dict(packet[DHCP].options)
    message_code = options.get("message-type", 0)
    if isinstance(message_code, bytes) and message_code:
        message_code = message_code[0]
    message_type = MESSAGE_TYPES.get(message_code, "UNKNOWN")
    raw_mac = bootp.chaddr[: bootp.hlen] if bootp.chaddr else (packet[Ether].src if packet.haslayer(Ether) else "")
    client_mac = normalize_mac(":".join(f"{byte:02x}" for byte in raw_mac) if isinstance(raw_mac, bytes) else raw_mac)
    hostname, _ = extract_hostname(options)
    server_ip = options.get("server_id") or (packet[IP].src if packet.haslayer(IP) else None)
    assigned_ip = str(bootp.yiaddr) if str(bootp.yiaddr) != "0.0.0.0" else None
    requested_ip = options.get("requested_addr")
    if isinstance(requested_ip, bytes):
        requested_ip = ".".join(str(x) for x in requested_ip)
    for value in (server_ip, assigned_ip, requested_ip):
        if value:
            ipaddress.ip_address(str(value))
    lease = options.get("lease_time")
    if isinstance(lease, bytes):
        lease = int.from_bytes(lease, "big") if lease else None
    return DhcpEvent(
        job_id=job_id,
        event_time=event_time or "unknown",
        source_type=source_type,
        message_type=message_type,
        client_mac=client_mac,
        source_ip=str(packet[IP].src) if packet.haslayer(IP) else None,
        source_mac=packet[Ether].src if packet.haslayer(Ether) else None,
        server_ip=safe_optional(server_ip),
        server_mac=packet[Ether].src if packet.haslayer(Ether) else None,
        requested_ip=safe_optional(requested_ip),
        assigned_ip=assigned_ip,
        hostname=hostname or None,
        lease_time=int(lease) if lease is not None else None,
        transaction_id=int(bootp.xid) if getattr(bootp, "xid", None) is not None else None,
        relay_ip=str(bootp.giaddr) if str(bootp.giaddr) != "0.0.0.0" else None,
        source_packet_no=source_packet_no,
    )


def parse_csv_row(row: dict[str, str], job_id: str, max_field_size: int = 4096) -> DhcpEvent:
    def field(name: str) -> str | None:
        value = safe_optional(row.get(name))
        if value and len(value) > max_field_size:
            raise ValueError(f"field too large: {name}")
        return value

    message_type = (field("Msg_Type") or "UNKNOWN").upper()
    client_mac = normalize_mac(field("Client_MAC"))
    if not client_mac:
        raise ValueError("missing client MAC")
    assigned_or_requested = field("Assigned/Req_IP")
    server_ip = field("Server_IP")
    lease_raw = field("Lease_Time(sec)")
    lease_time = int(lease_raw) if lease_raw and lease_raw.isdigit() else None
    for value in (server_ip, assigned_or_requested):
        if value:
            ipaddress.ip_address(value)
    is_response = message_type in {"OFFER", "ACK", "NAK"}
    return DhcpEvent(
        job_id=job_id,
        event_time=field("Timestamp") or "unknown",
        message_type=message_type,
        client_mac=client_mac,
        hostname=field("Client_HostName") or field("Client_FQDN"),
        server_ip=server_ip,
        server_mac=field("Server_MAC"),
        assigned_ip=assigned_or_requested if message_type == "ACK" else None,
        requested_ip=assigned_or_requested if not is_response or message_type == "NAK" else None,
        lease_time=lease_time,
        source_type="csv",
    )

