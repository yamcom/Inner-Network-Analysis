from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
import uuid


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class DhcpEvent:
    job_id: str
    event_time: str
    message_type: str
    client_mac: str
    event_uid: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(default_factory=utc_now)
    source_type: str = "csv"
    source_ip: str | None = None
    source_mac: str | None = None
    server_ip: str | None = None
    server_mac: str | None = None
    requested_ip: str | None = None
    assigned_ip: str | None = None
    hostname: str | None = None
    lease_time: int | None = None
    transaction_id: int | None = None
    relay_ip: str | None = None
    vlan_id: int | None = None
    source_packet_no: int | None = None
    severity: str = "INFO"
    anomaly_type: str = "NONE"
    anomaly_details: str | None = None
    is_rogue: bool = False


@dataclass(frozen=True)
class WriteBatch:
    job_id: str
    events: tuple[DhcpEvent, ...] = ()
    stats: dict[str, int] = field(default_factory=dict)
    progress: int | None = None
    processed_packets: int | None = None
    batch_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    batch_sequence: int = 0
    status_updates: tuple[tuple[str, str], ...] = ()
    priority: str = "NORMAL"
    created_at: str = field(default_factory=utc_now)
    retry_count: int = 0


# Lower rank is served first by the DB Writer (spec 2.3 / 1.2 principle five).
PRIORITY_RANK = {"HIGH": 0, "NORMAL": 1, "LOW": 2}


def priority_rank(priority: str | None) -> int:
    return PRIORITY_RANK.get((priority or "NORMAL").upper(), PRIORITY_RANK["NORMAL"])


def normalize_mac(value: str | None) -> str:
    if not value:
        return ""
    compact = "".join(ch for ch in value.strip().lower() if ch.isalnum())
    if len(compact) != 12:
        return value.strip().upper()
    return ":".join(compact[i : i + 2] for i in range(0, 12, 2)).upper()


def safe_optional(value: Any) -> str | None:
    text = "" if value is None else str(value).strip()
    return text or None

