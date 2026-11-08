import csv
import datetime
import os
import threading
import time
import uuid
from collections import Counter
from scapy.all import sniff, DHCP, IP, Ether, BOOTP
from scapy.sendrecv import AsyncSniffer
from core.dhcp_fields import decode_client_fqdn, extract_hostname
from core.anomaly_engine import DhcpAnomalyEngine
from core.dhcp_parser import parse_scapy_packet
from core.models import WriteBatch, utc_now
from database.connection import connect_database
from database.migrations import migrate
from database.repositories import finish_job, recover_interrupted_live_jobs
from db_writer import WriterClient


def resolve_windows_interface(interface_name: str | None) -> str | None:
    """Resolve Windows friendly interface name (e.g. '乙太網路 2') to safe Npcap device (spec 3.2, 20.3-A)."""
    if not interface_name:
        return None
    try:
        from scapy.arch.windows import get_windows_if_list
        target = interface_name.strip()
        for iface in get_windows_if_list():
            name = iface.get("name") or ""
            desc = iface.get("description") or ""
            guid = iface.get("guid") or ""
            # Match against friendly name, description, or GUID
            if target.lower() in {name.lower(), desc.lower(), guid.lower()}:
                # Return the device name if available, else keep name
                return f"\\Device\\NPF_{guid}" if guid else name
    except Exception:
        pass
    return interface_name

# ==================== 設定區 ====================
# 合法的 DHCP 伺服器 IP 白名單（目前主要為 192.69.1.9，若 PA 也發可加進去）
AUTHORIZED_DHCP_SERVERS = ["192.69.1.9","192.69.1.254","192.69.6.41","192.69.6.101"]

# 輸出的記錄檔名
OUTPUT_CSV = "dhcp_events.csv"
# ===============================================

DHCP_MSG_TYPES = {
    1: "DISCOVER",
    2: "OFFER",
    3: "REQUEST",
    4: "DECLINE",
    5: "ACK",
    6: "NAK",
    7: "RELEASE",
    8: "INFORM"
}


def init_csv():
    """初始化 CSV 檔案標頭"""
    if not os.path.exists(OUTPUT_CSV):
        with open(OUTPUT_CSV, mode="w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Timestamp", "Alert", "Msg_Type", "Client_MAC", 
                "Client_HostName", "Server_IP", "Server_MAC", 
                "Assigned/Req_IP", "Lease_Time(sec)", "Subnet_Mask", "Router"
            ])

def log_to_csv(row_data):
    """寫入單筆 DHCP 記錄"""
    with open(OUTPUT_CSV, mode="a", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(row_data)

def process_dhcp_packet(packet):
    """回呼函式：處理每一個被捕獲的 DHCP 封包"""
    if not packet.haslayer(DHCP):
        return

    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    bootp = packet[BOOTP]
    dhcp_opts = {opt[0]: opt[1] for opt in packet[DHCP].options if isinstance(opt, tuple)}

    # 1. 取得訊息類型
    msg_type_code = dhcp_opts.get("message-type", 0)
    msg_type = DHCP_MSG_TYPES.get(msg_type_code, f"UNKNOWN({msg_type_code})")

    # 2. 用戶端資訊
    client_mac = packet[Ether].src if packet.haslayer(Ether) else ""
    if bootp.chaddr:
        # 將 BOOTP 的 chaddr 轉為標準 MAC 格式
        raw_chaddr = bootp.chaddr[:bootp.hlen]
        client_mac = ":".join(f"{b:02x}" for b in raw_chaddr)

    hostname, _hostname_source = extract_hostname(dhcp_opts)

    # 3. 伺服器與分配資訊
    server_ip = dhcp_opts.get("server_id", packet[IP].src if packet.haslayer(IP) else "")
    server_mac = packet[Ether].src if packet.haslayer(Ether) else ""
    assigned_ip = bootp.yiaddr if bootp.yiaddr != "0.0.0.0" else dhcp_opts.get("requested_addr", "")
    lease_time = dhcp_opts.get("lease_time", "")
    subnet_mask = dhcp_opts.get("subnet_mask", "")
    router = dhcp_opts.get("router", "")

    # 4. 偽冒 DHCP (Rogue DHCP) 檢測判定
    is_rogue = False
    alert_status = "NORMAL"

    if msg_type in ["OFFER", "ACK", "NAK"]:
        if server_ip and (server_ip not in AUTHORIZED_DHCP_SERVERS):
            is_rogue = True
            alert_status = f"[ROGUE DHCP DETECTED: {server_ip}]"

    # 5. 終端機即時輸出
    color_prefix = ""
    color_suffix = "\033[0m"
    if is_rogue:
        color_prefix = "\033[91m"  # 紅色警示
    elif msg_type == "NAK":
        color_prefix = "\033[93m"  # 黃色注意
    elif msg_type == "ACK":
        color_prefix = "\033[92m"  # 綠色正常

    print(f"{color_prefix}[{now_str}] {alert_status:<26} | Type: {msg_type:<8} | Server: {server_ip:<15} | Client MAC: {client_mac} | IP: {assigned_ip}{color_suffix}")

    # 6. 儲存至 CSV
    log_to_csv([
        now_str, alert_status, msg_type, client_mac, 
        hostname, server_ip, server_mac, 
        assigned_ip, lease_time, subnet_mask, router
    ])

class LiveMonitor:
    """Real-time DHCP monitor backed by the single DB Writer."""

    def __init__(self, database_path="data/dhcp_analyzer.db", interface=None, batch_interval=5, max_in_memory_events=5000, max_pending_write_batches=20):
        self.database_path = database_path
        self.interface = resolve_windows_interface(interface)
        self.raw_interface_name = interface or None
        self.batch_interval = batch_interval
        self.job_id = str(uuid.uuid4())
        self.monitor_instance_id = str(uuid.uuid4())
        self.writer = WriterClient(database_path, max_pending_batches=max_pending_write_batches)
        self.engine = DhcpAnomalyEngine()
        self.events = []
        self.max_in_memory_events = max(1, int(max_in_memory_events))
        self.dropped_events = 0
        self.writer_failed_batches = 0
        self.counters = Counter()
        self.total_events = 0
        self.processed_packets = 0
        self.batch_sequence = 0
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.sniffer = None
        self.dropped_batches = 0
        self._stopped = False

    def initialize(self):
        connection = connect_database(self.database_path)
        migrate(connection)
        recovered = recover_interrupted_live_jobs(connection)
        connection.execute(
            """INSERT INTO analysis_jobs(job_id, source_type, source_name, status, created_at, monitor_instance_id)
            VALUES (?, 'live_monitor', 'live DHCP monitor', 'running', ?, ?)""",
            (self.job_id, utc_now(), self.monitor_instance_id),
        )
        connection.commit()
        connection.close()
        self.writer.start()
        if recovered:
            print(f"[LIVE] marked {recovered} unfinished live_monitor job(s) as interrupted", flush=True)
        self._submit_heartbeat("starting")
        print(
            f"[LIVE] DHCP monitor started; job={self.job_id} "
            f"interface={self.interface or 'default'} filter=udp/67,68",
            flush=True,
        )

    def process_packet(self, packet):
        self.processed_packets += 1
        try:
            event = parse_scapy_packet(packet, self.job_id, source_type="scapy", source_packet_no=self.processed_packets, event_time=utc_now())
            if event is None:
                return
            event = self.engine.classify(event)
            with self.lock:
                self.total_events += 1
                self.counters[event.message_type] += 1
                if event.anomaly_type != "NONE":
                    self.counters[event.anomaly_type] += 1
                if len(self.events) >= self.max_in_memory_events:
                    # Bounded buffer (spec 14.1 / 19.7): count the loss
                    # explicitly instead of growing memory or dropping silently.
                    self.dropped_events += 1
                    self.counters["DROPPED_IN_MEMORY_EVENTS"] += 1
                else:
                    self.events.append(event)
            alert = event.anomaly_type if event.anomaly_type != "NONE" else "NORMAL"
            if event.anomaly_type != "NONE":
                color_prefix = "\033[91m"
            elif event.message_type == "NAK":
                color_prefix = "\033[93m"
            elif event.message_type == "ACK":
                color_prefix = "\033[92m"
            else:
                color_prefix = "\033[96m"
            color_suffix = "\033[0m"
            print(
                f"{color_prefix}[LIVE {event.event_time}] {alert:<16} | "
                f"Type: {event.message_type:<8} | "
                f"Client: {event.client_mac or '-':<17} | "
                f"Host: {event.hostname or '-':<24} | "
                f"Server: {event.server_ip or '-':<15} | "
                f"IP: {event.assigned_ip or event.requested_ip or '-'}{color_suffix}",
                flush=True,
            )
        except Exception as exc:
            with self.lock:
                self.counters["PARSER_ERROR"] += 1
            print(f"[WARN] DHCP packet parse failed: {exc}")

    def _collect_writer_errors(self):
        for error in self.writer.drain_errors():
            self.writer_failed_batches += 1
            with self.lock:
                self.counters["WRITER_FAILED_BATCHES"] += 1
            print(f"[WARN] DB writer failed batch {error.get('batch_id')}: {error.get('error')}", flush=True)

    def _degradation_reason(self):
        reasons = []
        if self.dropped_events:
            reasons.append(f"in_memory_events_dropped={self.dropped_events}")
        if self.dropped_batches:
            reasons.append(f"write_batches_dropped={self.dropped_batches}")
        if self.writer_failed_batches:
            reasons.append(f"writer_failed_batches={self.writer_failed_batches}")
        return "; ".join(reasons) or "none"

    def _status_updates(self, status):
        return (
            ("monitor_status", status),
            ("monitor_instance_id", self.monitor_instance_id),
            ("monitor_job_id", self.job_id),
            ("monitor_pid", str(os.getpid())),
            ("monitor_heartbeat", utc_now()),
            ("monitor_dropped_events", str(self.dropped_events)),
            ("monitor_dropped_batches", str(self.dropped_batches)),
            ("monitor_degradation_reason", self._degradation_reason()),
        )

    def _submit_heartbeat(self, status):
        self._collect_writer_errors()
        self.batch_sequence += 1
        try:
            self.writer.submit(WriteBatch(
                job_id=self.job_id,
                stats=dict(self.counters),
                processed_packets=self.processed_packets,
                batch_sequence=self.batch_sequence,
                status_updates=self._status_updates(status),
                priority="HIGH",
            ), timeout=1.0)
        except Exception:
            self.dropped_batches += 1
        print(
            f"[LIVE] heartbeat={status} packets={self.processed_packets} "
            f"events={self.total_events} dropped_batches={self.dropped_batches} "
            f"dropped_events={self.dropped_events}",
            flush=True,
        )

    def flush(self):
        self._collect_writer_errors()
        with self.lock:
            pending = tuple(self.events)
            self.events.clear()
            stats = dict(self.counters)
        if not pending:
            self._submit_heartbeat("running")
            return
        self.batch_sequence += 1
        try:
            self.writer.submit(WriteBatch(
                job_id=self.job_id,
                events=pending,
                stats=stats,
                processed_packets=self.processed_packets,
                batch_sequence=self.batch_sequence,
                status_updates=self._status_updates("running"),
                priority="HIGH",
            ), timeout=1.0)
            print(
                f"[LIVE] heartbeat=running packets={self.processed_packets} "
                f"events={self.total_events} pending_batch_events={len(pending)} "
                f"pending_batch={self.batch_sequence} "
                f"dropped_batches={self.dropped_batches} dropped_events={self.dropped_events}",
                flush=True,
            )
        except Exception:
            with self.lock:
                # Re-queue within the bounded buffer; overflow is counted.
                room = max(0, self.max_in_memory_events - len(self.events))
                keep = list(pending[:room])
                overflow = len(pending) - len(keep)
                self.events[0:0] = keep
                if overflow:
                    self.dropped_events += overflow
                    self.counters["DROPPED_IN_MEMORY_EVENTS"] += overflow
            self.dropped_batches += 1

    def run(self):
        self.initialize()
        self.sniffer = AsyncSniffer(
            iface=self.interface,
            filter="udp and (port 67 or port 68)",
            prn=self.process_packet,
            store=False,
        )
        self.sniffer.start()
        try:
            while not self.stop_event.wait(self.batch_interval):
                self.flush()
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self):
        if self._stopped:
            return
        self._stopped = True
        self.stop_event.set()
        if self.sniffer is not None:
            try:
                # Closing the capture socket wakes Scapy without making the
                # console wait indefinitely for its capture thread.
                self.sniffer.stop(join=False)
                self.sniffer.join(timeout=5.0)
            except Exception:
                pass
        print("[LIVE] stopping capture; flushing pending database batches...", flush=True)
        self.flush()
        self._submit_heartbeat("offline")
        self.writer.stop(timeout=15.0)
        self._collect_writer_errors()
        degradation = self._degradation_reason()
        connection = connect_database(self.database_path)
        try:
            migrate(connection)
            finish_job(connection, self.job_id, "completed", None if degradation == "none" else f"degraded: {degradation}")
        finally:
            connection.close()
        print(f"[LIVE] monitor stopped; job completed. degradation={degradation}", flush=True)


def main():
    database_path = os.getenv("DHCP_ANALYZER_DB", os.path.join("data", "dhcp_analyzer.db"))
    interface = os.getenv("DHCP_MONITOR_INTERFACE") or None
    max_events = int(os.getenv("DHCP_MAX_IN_MEMORY_EVENTS", "5000"))
    LiveMonitor(database_path=database_path, interface=interface, max_in_memory_events=max_events).run()


def legacy_csv_main():
    init_csv()
    print("=" * 80)
    print("啟動內網 DHCP 即時監控分析程序...")
    print(f"合法 DHCP 白名單: {AUTHORIZED_DHCP_SERVERS}")
    print(f"記錄檔儲存位置: {os.path.abspath(OUTPUT_CSV)}")
    print("過濾條件: UDP Port 67 & 68 (僅抓取 DHCP/BOOTP 廣播，不吃一般流量)")
    print("=" * 80)

    # 透過 BPF Filter 在核心層直接丟棄非 DHCP 流量，極低 CPU 與記憶體消耗
    # 若需指定網卡可加入參數 iface="eth0" 或 iface="乙太網路"
    sniff(filter="udp and (port 67 or port 68)", prn=process_dhcp_packet, store=False)

if __name__ == "__main__":
    main()
