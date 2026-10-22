import os
import subprocess
import struct
import socket
import csv
import datetime
import webbrowser
import threading
from collections import Counter, defaultdict
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

app = FastAPI(title="DHCP Packet & Log Analyzer")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

# 全域快取最近一次分析的裝置映射資料與分析時間
LATEST_ANALYSIS_DATA = {
    "analysis_time": "",
    "source_file": "",
    "device_mappings": []
}

class AnalyzeRequest(BaseModel):
    source_type: str = "pcap"  # "pcap" 或 "csv"
    wireshark_dir: str = ""
    source_pcap: str = ""
    output_pcap: str = ""
    source_csv: str = ""
    authorized_servers: str = "192.69.1.9"
    target_naks: str = ""

class BrowseRequest(BaseModel):
    dialog_type: str  # "file_open", "file_save", "dir"
    title: str = "請選擇路徑"
    filetypes: str = "all"

def decode_opt81_fqdn(val):
    """解析 RFC 4702 Option 81 (Client FQDN) 取得電腦名稱"""
    if len(val) <= 3:
        return ""
    flags = val[0]
    name_bytes = val[3:]
    if flags & 0x04:  # DNS Wire format
        parts = []
        i = 0
        while i < len(name_bytes):
            l = name_bytes[i]
            if l == 0:
                break
            parts.append(name_bytes[i+1 : i+1+l].decode('utf-8', errors='ignore'))
            i += 1 + l
        return ".".join(parts)
    else:
        return name_bytes.decode('utf-8', errors='ignore').rstrip('\x00')

@app.post("/api/browse")
def browse_system_dialog(req: BrowseRequest):
    """呼叫 Windows 原生視窗取得路徑"""
    try:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()
        root.attributes('-topmost', True)

        selected_path = ""
        if req.dialog_type == "dir":
            selected_path = filedialog.askdirectory(title=req.title)
        elif req.dialog_type == "file_save":
            types = [("PCAP/PCAPNG 封包檔", "*.pcapng;*.pcap"), ("所有檔案", "*.*")]
            selected_path = filedialog.asksaveasfilename(
                title=req.title, 
                defaultextension=".pcapng",
                filetypes=types
            )
        else:
            if req.filetypes == "pcap":
                types = [("Wireshark 封包檔 (*.pcapng, *.pcap)", "*.pcapng;*.pcap"), ("所有檔案", "*.*")]
            elif req.filetypes == "csv":
                types = [("CSV 記錄檔 (*.csv)", "*.csv"), ("所有檔案", "*.*")]
            else:
                types = [("所有檔案", "*.*")]
            selected_path = filedialog.askopenfilename(title=req.title, filetypes=types)

        root.destroy()
        if selected_path:
            selected_path = os.path.normpath(selected_path)
            return {"status": "success", "path": selected_path}
        return {"status": "cancelled", "path": ""}
    except Exception as e:
        return {"status": "error", "message": f"開啟對話框失敗: {str(e)}"}

def parse_filtered_pcap(filepath, authorized_list, target_nak_list):
    """解析精簡後的 pcapng，並彙整 MAC-電腦名稱總表"""
    stats = Counter()
    server_actions = defaultdict(lambda: Counter())
    rogue_servers = set()
    nak_events = []
    ack_events = []

    mac_to_host = {}
    mac_to_req_ip = {}
    mac_activity_map = {}  # mac -> {hostname, ip, last_seen}

    with open(filepath, 'rb') as f:
        file_bytes = f.read()

    offset = 0
    total_len = len(file_bytes)

    while offset < total_len:
        if offset + 8 > total_len:
            break
        block_type, block_len = struct.unpack('<II', file_bytes[offset:offset+8])
        if block_len == 0:
            break

        if block_type == 0x00000006:
            block_body = file_bytes[offset+8 : offset+block_len-4]
            if_id, ts_high, ts_low, cap_len, orig_len = struct.unpack('<IIIII', block_body[:20])
            pkt = block_body[20 : 20+cap_len]

            ts = (ts_high << 32) + ts_low
            try:
                pkt_time = datetime.datetime.fromtimestamp(ts / 1e6).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                pkt_time = "未知時間"

            if len(pkt) > 42:
                eth_type = struct.unpack('!H', pkt[12:14])[0]
                if eth_type == 0x0800:
                    ip_header = pkt[14:34]
                    proto = ip_header[9]
                    src_ip = socket.inet_ntoa(ip_header[12:16])
                    dst_ip = socket.inet_ntoa(ip_header[16:20])

                    if proto == 17:
                        udp_header = pkt[34:42]
                        src_port, dst_port = struct.unpack('!HH', udp_header[:4])

                        if src_port in (67, 68) or dst_port in (67, 68):
                            bootp = pkt[42:]
                            chaddr = ":".join(f"{b:02x}" for b in bootp[28:34])
                            yiaddr = socket.inet_ntoa(bootp[16:20])

                            opt_offset = 240
                            opts = {}
                            while opt_offset + 1 < len(bootp):
                                o_type = bootp[opt_offset]
                                if o_type == 255:
                                    break
                                if o_type == 0:
                                    opt_offset += 1
                                    continue
                                o_len = bootp[opt_offset+1]
                                opts[o_type] = bootp[opt_offset+2 : opt_offset+2+o_len]
                                opt_offset += 2 + o_len

                            msg_types = {
                                1: "DISCOVER", 2: "OFFER", 3: "REQUEST",
                                4: "DECLINE", 5: "ACK", 6: "NAK",
                                7: "RELEASE", 8: "INFORM"
                            }
                            msg_code = opts.get(53, b'\x00')[0]
                            m_type = msg_types.get(msg_code, f"TYPE_{msg_code}")

                            req_ip = socket.inet_ntoa(opts[50]) if 50 in opts else ""
                            srv_id = socket.inet_ntoa(opts[54]) if 54 in opts else src_ip

                            hostname = ""
                            if 12 in opts:
                                hostname = opts[12].decode('utf-8', errors='ignore').rstrip('\x00')
                            elif 81 in opts:
                                hostname = decode_opt81_fqdn(opts[81])

                            effective_ip = yiaddr if yiaddr != "0.0.0.0" else req_ip

                            if hostname:
                                mac_to_host[chaddr] = hostname
                            if req_ip:
                                mac_to_req_ip[chaddr] = req_ip

                            # 紀錄 MAC 裝置對照資料
                            if chaddr:
                                if chaddr not in mac_activity_map:
                                    mac_activity_map[chaddr] = {
                                        "mac": chaddr,
                                        "hostname": hostname or "未知",
                                        "ip": effective_ip,
                                        "last_seen": pkt_time
                                    }
                                else:
                                    if hostname:
                                        mac_activity_map[chaddr]["hostname"] = hostname
                                    if effective_ip and effective_ip != "0.0.0.0":
                                        mac_activity_map[chaddr]["ip"] = effective_ip
                                    mac_activity_map[chaddr]["last_seen"] = pkt_time

                            stats[m_type] += 1

                            if m_type in ("OFFER", "ACK", "NAK"):
                                server_actions[srv_id][m_type] += 1
                                if srv_id and srv_id != "0.0.0.0" and srv_id not in authorized_list:
                                    rogue_servers.add(srv_id)

                            if m_type == "NAK":
                                effective_host = hostname or mac_to_host.get(chaddr, "未知")
                                effective_req_ip = req_ip or mac_to_req_ip.get(chaddr, "-")

                                is_target = True if (not target_nak_list or effective_req_ip in target_nak_list or chaddr in target_nak_list or effective_host in target_nak_list) else False
                                nak_events.append({
                                    "timestamp": pkt_time,
                                    "server": srv_id,
                                    "client_mac": chaddr,
                                    "requested_ip": effective_req_ip,
                                    "hostname": effective_host,
                                    "matched_watch": is_target
                                })

                            if m_type == "ACK" and len(ack_events) < 50:
                                ack_events.append({
                                    "timestamp": pkt_time,
                                    "server": srv_id,
                                    "client_mac": chaddr,
                                    "assigned_ip": yiaddr,
                                    "hostname": hostname or mac_to_host.get(chaddr, "")
                                })

        offset += block_len

    # 封裝伺服器資訊（附帶主機名稱）
    server_details = {}
    for srv_ip, acts in server_actions.items():
        srv_name = "本機 / 官方 DHCP" if srv_ip in authorized_list else "未知設備 / 伺服器"
        server_details[srv_ip] = {
            "actions": dict(acts),
            "hostname": srv_name
        }

    return {
        "stats": dict(stats),
        "servers": server_details,
        "rogue_servers": list(rogue_servers),
        "nak_events": nak_events,
        "ack_events": ack_events,
        "device_mappings": list(mac_activity_map.values())
    }

def parse_csv_dhcp(filepath, authorized_list, target_nak_list):
    """解析本地 CSV，並彙整 MAC-電腦名稱總表"""
    stats = Counter()
    server_actions = defaultdict(lambda: Counter())
    rogue_servers = set()
    nak_events = []
    ack_events = []

    mac_to_host = {}
    mac_to_req_ip = {}
    mac_activity_map = {}

    with open(filepath, mode='r', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        for row in reader:
            m_type = row.get('Msg_Type', '').strip()
            server_ip = row.get('Server_IP', '').strip()
            client_mac = row.get('Client_MAC', '').strip()
            hostname = row.get('Client_HostName', '').strip()
            req_ip = row.get('Assigned/Req_IP', '').strip()
            timestamp = row.get('Timestamp', '').strip()

            if hostname:
                mac_to_host[client_mac] = hostname
            if req_ip:
                mac_to_req_ip[client_mac] = req_ip

            if client_mac:
                if client_mac not in mac_activity_map:
                    mac_activity_map[client_mac] = {
                        "mac": client_mac,
                        "hostname": hostname or "未知",
                        "ip": req_ip,
                        "last_seen": timestamp
                    }
                else:
                    if hostname:
                        mac_activity_map[client_mac]["hostname"] = hostname
                    if req_ip:
                        mac_activity_map[client_mac]["ip"] = req_ip
                    mac_activity_map[client_mac]["last_seen"] = timestamp

            stats[m_type] += 1

            if server_ip and server_ip != '0.0.0.0':
                server_actions[server_ip][m_type] += 1
                if m_type in ("OFFER", "ACK", "NAK"):
                    if server_ip not in authorized_list:
                        rogue_servers.add(server_ip)

            if m_type == "NAK":
                effective_host = hostname or mac_to_host.get(client_mac, "未知")
                effective_req_ip = req_ip or mac_to_req_ip.get(client_mac, "-")

                is_target = True if (not target_nak_list or effective_req_ip in target_nak_list or client_mac in target_nak_list or effective_host in target_nak_list) else False
                nak_events.append({
                    "timestamp": timestamp,
                    "server": server_ip,
                    "client_mac": client_mac,
                    "requested_ip": effective_req_ip,
                    "hostname": effective_host,
                    "matched_watch": is_target
                })

            if m_type == "ACK" and len(ack_events) < 50:
                ack_events.append({
                    "timestamp": timestamp,
                    "server": server_ip,
                    "client_mac": client_mac,
                    "assigned_ip": req_ip,
                    "hostname": hostname or mac_to_host.get(client_mac, "")
                })

    server_details = {}
    for srv_ip, acts in server_actions.items():
        srv_name = "本機 / 官方 DHCP" if srv_ip in authorized_list else "未知設備 / 伺服器"
        server_details[srv_ip] = {
            "actions": dict(acts),
            "hostname": srv_name
        }

    return {
        "stats": dict(stats),
        "servers": server_details,
        "rogue_servers": list(rogue_servers),
        "nak_events": nak_events,
        "ack_events": ack_events,
        "device_mappings": list(mac_activity_map.values())
    }

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")

# 獨立產出的 MAC 對應電腦名稱列表新頁面
@app.get("/device-mapping", response_class=HTMLResponse)
async def device_mapping_page(request: Request):
    return templates.TemplateResponse(
        request=request, 
        name="device_mapping.html",
        context={
            "analysis_time": LATEST_ANALYSIS_DATA["analysis_time"] or "尚未進行分析",
            "source_file": LATEST_ANALYSIS_DATA["source_file"] or "無",
            "device_mappings": LATEST_ANALYSIS_DATA["device_mappings"]
        }
    )

@app.post("/api/run")
async def run_analysis(req: AnalyzeRequest):
    auth_list = [x.strip() for x in req.authorized_servers.split(",") if x.strip()]
    nak_watch = [x.strip() for x in req.target_naks.split(",") if x.strip()]
    current_time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if req.source_type == "csv":
        if not os.path.exists(req.source_csv):
            return {"status": "error", "message": f"找不到 CSV 記錄檔: {req.source_csv}"}

        csv_size_kb = round(os.path.getsize(req.source_csv) / 1024, 2)
        analysis_res = parse_csv_dhcp(req.source_csv, auth_list, nak_watch)
        source_name = os.path.basename(req.source_csv)

        # 更新快取
        LATEST_ANALYSIS_DATA["analysis_time"] = current_time_str
        LATEST_ANALYSIS_DATA["source_file"] = source_name
        LATEST_ANALYSIS_DATA["device_mappings"] = analysis_res["device_mappings"]

        return {
            "status": "success",
            "source_type": "csv",
            "file_info": {
                "source_title": "本地 CSV 記錄檔",
                "orig_size": f"{csv_size_kb} KB",
                "filtered_size": "直讀解析 (免轉檔)",
                "output_path": req.source_csv
            },
            "data": analysis_res
        }
    else:
        tshark_path = os.path.join(req.wireshark_dir, "tshark.exe") if os.name == 'nt' else "tshark"
        if not os.path.exists(tshark_path) and os.name == 'nt':
            return {"status": "error", "message": f"找不到 tshark 執行檔: {tshark_path}"}

        if not os.path.exists(req.source_pcap):
            return {"status": "error", "message": f"找不到來源封包檔: {req.source_pcap}"}

        output_dir = os.path.dirname(req.output_pcap)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)

        cmd = [
            tshark_path,
            "-r", req.source_pcap,
            "-Y", "bootp || dhcp",
            "-w", req.output_pcap
        ]

        try:
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=180)
            if proc.returncode != 0:
                return {"status": "error", "message": f"tshark 萃取失敗: {proc.stderr}"}
        except Exception as e:
            return {"status": "error", "message": f"呼叫 tshark 錯誤: {str(e)}"}

        orig_size_mb = round(os.path.getsize(req.source_pcap) / (1024 * 1024), 2)
        filtered_size_kb = round(os.path.getsize(req.output_pcap) / 1024, 2)

        analysis_res = parse_filtered_pcap(req.output_pcap, auth_list, nak_watch)
        source_name = os.path.basename(req.source_pcap)

        # 更新快取
        LATEST_ANALYSIS_DATA["analysis_time"] = current_time_str
        LATEST_ANALYSIS_DATA["source_file"] = source_name
        LATEST_ANALYSIS_DATA["device_mappings"] = analysis_res["device_mappings"]

        return {
            "status": "success",
            "source_type": "pcap",
            "file_info": {
                "source_title": "原始大型封包檔",
                "orig_size": f"{orig_size_mb} MB",
                "filtered_size": f"{filtered_size_kb} KB",
                "output_path": req.output_pcap
            },
            "data": analysis_res
        }

if __name__ == "__main__":
    import uvicorn

    host = "0.0.0.0"
    port = 8000
    local_url = f"http://127.0.0.1:{port}"

    def get_lan_ip():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    lan_ip = get_lan_ip()
    lan_url = f"http://{lan_ip}:{port}"

    print("\n" + "=" * 65)
    print(" 🚀  內網 DHCP 封包精簡與健康診斷系統已成功啟動！")
    print("=" * 65)
    print(f" ▶ 本機開啟網址 : \033[96m{local_url}\033[0m")
    if lan_ip != "127.0.0.1":
        print(f" ▶ 區網開啟網址 : \033[92m{lan_url}\033[0m")
    print("-" * 65)
    print(" 提示：按 Ctrl + C 可隨時停止服務")
    print("=" * 65 + "\n")

    def auto_open_browser():
        webbrowser.open(local_url)

    threading.Timer(1.2, auto_open_browser).start()

    uvicorn.run(app, host=host, port=port, log_level="info")