from __future__ import annotations

import struct
from pathlib import Path
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet
from scapy.utils import PcapNgWriter

from workers.pcap_worker import PcapAnalysisWorker
from core.models import WriteBatch


def _build_dhcp_discover(mac: str = "00:11:22:33:44:55", xid: int = 0x12345678) -> Packet:
    mac_bytes = bytes.fromhex(mac.replace(":", ""))
    pkt = (
        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=mac_bytes + b"\x00" * 10, xid=xid)
        / DHCP(options=[("message-type", "discover"), ("hostname", "pcapng-test-host"), "end"])
    )
    return pkt


def test_pcapng_streaming_worker(tmp_path: Path):
    pcapng_file = tmp_path / "test_sample.pcapng"

    pkts = [_build_dhcp_discover(mac=f"00:11:22:33:44:{i:02x}", xid=0x1000 + i) for i in range(10)]
    writer = PcapNgWriter(str(pcapng_file))
    for p in pkts:
        writer.write(p)
    writer.close()

    worker = PcapAnalysisWorker(batch_size=5)
    batches = []

    def mock_emit(batch: WriteBatch):
        batches.append(batch)
        return True

    summary = worker.run(pcapng_file, job_id="job_pcapng_test", emit=mock_emit)

    assert summary["processed_packets"] == 10
    assert summary["DISCOVER"] == 10
    assert summary["parse_errors"] == 0
    assert len(batches) == 2
    assert batches[0].batch_sequence == 1
    assert len(batches[0].events) == 5
    assert batches[1].batch_sequence == 2
    assert len(batches[1].events) == 5
    assert batches[0].events[0].hostname == "pcapng-test-host"
