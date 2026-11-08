import csv

import pytest

from workers.csv_worker import CsvAnalysisWorker


@pytest.mark.slow
def test_one_million_csv_events_streaming(tmp_path):
    source = tmp_path / "million.csv"
    with source.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["Timestamp", "Msg_Type", "Client_MAC", "Client_HostName", "Server_IP", "Server_MAC", "Assigned/Req_IP", "Lease_Time(sec)"])
        for index in range(1_000_000):
            writer.writerow(["2026-11-07 00:00:00", "DISCOVER", f"02:00:00:{index // 65536 % 256:02x}:{index // 256 % 256:02x}:{index % 256:02x}", "", "0.0.0.0", "", "", ""])
    batch_count = [0]
    event_count = [0]
    def emit(batch):
        batch_count[0] += 1
        event_count[0] += len(batch.events)
    result = CsvAnalysisWorker(batch_size=1000).run(str(source), "performance-job", emit)
    assert result["processed_packets"] == 1_000_000
    assert result["parse_errors"] == 0
    assert event_count[0] == 1_000_000
    assert batch_count[0] == 1_000

