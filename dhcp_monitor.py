import csv
import datetime
import os
from scapy.all import sniff, DHCP, IP, Ether, BOOTP

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

    hostname = dhcp_opts.get("hostname", "")
    if isinstance(hostname, bytes):
        hostname = hostname.decode("utf-8", errors="ignore")

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

def main():
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