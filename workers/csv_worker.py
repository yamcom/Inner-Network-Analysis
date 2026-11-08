from __future__ import annotations

import csv
from collections import Counter
from core.anomaly_engine import DhcpAnomalyEngine
from itertools import chain
from pathlib import Path
from typing import Callable

from core.dhcp_parser import parse_csv_row
from core.models import DhcpEvent, WriteBatch


class CsvAnalysisWorker:
    """Bounded, row-streaming CSV worker.

    The worker emits bounded WriteBatch objects and never stores the complete
    source file or complete event list in memory.
    """

    def __init__(self, batch_size: int = 1000, max_field_size: int = 4096, authorized_servers: set[str] | None = None):
        if batch_size <= 0:
            raise ValueError("batch_size must be positive")
        self.batch_size = batch_size
        self.max_field_size = max_field_size
        self.anomaly_engine = DhcpAnomalyEngine(authorized_servers=authorized_servers or set())

    def run(self, path: str | Path, job_id: str, emit: Callable[[WriteBatch], None]) -> dict[str, int]:
        counters: Counter[str] = Counter()
        batch_events: list[DhcpEvent] = []
        sequence = 0
        processed = 0
        errors = 0
        csv.field_size_limit(self.max_field_size * 2)
        with Path(path).open("r", encoding="utf-8-sig", newline="") as source:
            reader = csv.reader(source)
            first_row = next(reader, None)
            if first_row is None:
                return {"processed_packets": 0, "parse_errors": 0}
            has_header = "Msg_Type" in first_row and "Client_MAC" in first_row
            headers = first_row if has_header else [
                "Timestamp", "Alert", "Msg_Type", "Client_MAC", "Client_HostName",
                "Server_IP", "Server_MAC", "Assigned/Req_IP", "Lease_Time(sec)",
                "Subnet_Mask", "Router",
            ]
            rows = reader if has_header else chain((first_row,), reader)
            try:
                for values in rows:
                    processed += 1
                    try:
                        row = dict(zip(headers, values))
                        event = self._event_from_row(row, job_id)
                    except (ValueError, TypeError, KeyError):
                        errors += 1
                        continue
                    event = self.anomaly_engine.classify(event)
                    counters[event.message_type] += 1
                    if event.anomaly_type != "NONE":
                        counters[event.anomaly_type] += 1
                    batch_events.append(event)
                    if len(batch_events) >= self.batch_size:
                        sequence += 1
                        emit(WriteBatch(job_id=job_id, events=tuple(batch_events), stats=dict(counters),
                                        processed_packets=processed, batch_sequence=sequence))
                        batch_events.clear()
            except csv.Error:
                errors += 1
        if batch_events:
            sequence += 1
            emit(WriteBatch(job_id=job_id, events=tuple(batch_events), stats=dict(counters),
                            processed_packets=processed, batch_sequence=sequence))
        return {"processed_packets": processed, "parse_errors": errors, **counters}

    def _event_from_row(self, row: dict[str, str], job_id: str) -> DhcpEvent:
        return parse_csv_row(row, job_id, self.max_field_size)

