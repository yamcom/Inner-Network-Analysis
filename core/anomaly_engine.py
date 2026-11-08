from __future__ import annotations

from dataclasses import replace
from collections import Counter, OrderedDict, deque
import time

from core.models import DhcpEvent


class DhcpAnomalyEngine:
    """Bounded, stateless first-pass DHCP anomaly classification."""

    def __init__(self, authorized_servers: set[str] | None = None, minimum_lease: int = 300, maximum_lease: int = 2_592_000, max_tracked_macs: int = 10000, window_seconds: int = 10, single_mac_threshold: int = 20, global_window_seconds: int = 1, global_mac_threshold: int = 100):
        self.authorized_servers = authorized_servers or set()
        self.minimum_lease = minimum_lease
        self.maximum_lease = maximum_lease
        self.max_tracked_macs = max_tracked_macs
        self.window_seconds = window_seconds
        self.single_mac_threshold = single_mac_threshold
        self.global_window_seconds = global_window_seconds
        self.global_mac_threshold = global_mac_threshold
        self._mac_windows: OrderedDict[str, deque[float]] = OrderedDict()
        self._global_window: deque[tuple[float, str]] = deque()
        self._last_alert: dict[tuple[str, str], float] = {}

    def _flooding(self, event: DhcpEvent) -> bool:
        now = time.monotonic()
        if event.message_type not in {"DISCOVER", "REQUEST"} or not event.client_mac:
            return False
        window = self._mac_windows.setdefault(event.client_mac, deque())
        self._mac_windows.move_to_end(event.client_mac)
        while window and now - window[0] > self.window_seconds:
            window.popleft()
        window.append(now)
        self._global_window.append((now, event.client_mac))
        while self._global_window and now - self._global_window[0][0] > self.global_window_seconds:
            self._global_window.popleft()
        while len(self._mac_windows) > self.max_tracked_macs:
            self._mac_windows.popitem(last=False)
        key = (event.client_mac, "FLOODING")
        if len(window) > self.single_mac_threshold or len(self._global_window) > self.global_mac_threshold:
            previous = self._last_alert.get(key, 0)
            if now - previous >= self.window_seconds:
                self._last_alert[key] = now
                return True
        return False

    def classify(self, event: DhcpEvent) -> DhcpEvent:
        anomaly_type = "NONE"
        severity = "INFO"
        is_rogue = False
        details: list[str] = []
        if self._flooding(event):
            anomaly_type = "FLOODING"
            severity = "HIGH"
            details.append("bounded_rate_window")
        if event.message_type == "DECLINE":
            anomaly_type = "DECLINE_DETECTED"
            severity = "WARNING"
        if event.lease_time is not None and (
            event.lease_time < self.minimum_lease or event.lease_time > self.maximum_lease
        ):
            anomaly_type = "ABNORMAL_LEASE"
            severity = "WARNING"
            details.append(f"lease_time={event.lease_time}")
        if event.message_type in {"OFFER", "ACK", "NAK"} and event.server_ip and event.server_ip != "0.0.0.0":
            if self.authorized_servers and event.server_ip not in self.authorized_servers:
                anomaly_type = "ROGUE_DHCP"
                severity = "HIGH"
                is_rogue = True
                details.append(f"server_ip={event.server_ip}")
        return replace(
            event,
            anomaly_type=anomaly_type,
            severity=severity,
            is_rogue=is_rogue,
            anomaly_details="; ".join(details) or None,
        )

