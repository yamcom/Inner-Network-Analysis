from workers.csv_worker import CsvAnalysisWorker


def test_csv_worker_emits_bounded_batches(tmp_path):
    source = tmp_path / "events.csv"
    source.write_text(
        "Timestamp,Msg_Type,Client_MAC,Client_HostName,Server_IP,Server_MAC,Assigned/Req_IP,Lease_Time(sec)\n"
        "2026-11-07 00:00:00,DISCOVER,aa-bb-cc-dd-ee-ff,pc-1,0.0.0.0,,,,\n"
        "2026-11-07 00:00:01,ACK,aa:bb:cc:dd:ee:ff,pc-1,192.0.2.1,00:11:22:33:44:55,192.0.2.10,86400\n",
        encoding="utf-8",
    )
    batches = []
    result = CsvAnalysisWorker(batch_size=1).run(str(source), "job-1", batches.append)
    assert result["processed_packets"] == 2
    assert len(batches) == 2
    assert all(len(batch.events) <= 1 for batch in batches)

