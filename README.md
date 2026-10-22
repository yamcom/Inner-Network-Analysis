<<<<<<< HEAD
# 內網 DHCP 封包精簡與健康診斷系統

**DHCP Packet Analyzer & Network Endpoint Locator**

> 從 DHCP 封包分析、異常伺服器偵測，到 SNMP 交換器拓樸整合，協助網管人員快速定位內網異常設備。

## 1. 專案簡介

本專案是一套面向校園與企業內網的 DHCP 封包分析及網路健康診斷工具。

系統以 Python 為主要開發語言，結合 TShark、Scapy 與 FastAPI，支援大型 PCAP／PCAPNG 封包離線分析、DHCP 即時監聽、事件紀錄、裝置資訊彙整及網頁儀表板。

傳統網路異常調查往往需要人工開啟大型封包檔、逐筆篩選 DHCP 訊息，再比對 DHCP Server、用戶端 IP、MAC Address 與電腦名稱。本專案的目的，是將這些工作自動化，並逐步整合 SNMP 與交換器拓樸資料，讓網管人員能從異常事件追查到可能的交換器、連接埠、樓層及教室位置。

### 核心目標

1. **大型封包精簡：** 從數 GB 的歷史封包中萃取 DHCP 封包，降低儲存與後續分析成本。
2. **DHCP 健康診斷：** 統計 DHCP 訊息、租約分配及 NAK 拒絕事件。
3. **未授權 DHCP 偵測：** 比對核准的 DHCP Server 白名單，標示可疑的 DHCP 回應來源。
4. **裝置識別：** 建立 MAC、IP、電腦名稱及最後觀測時間的關聯資料。
5. **即時監控：** 使用 Python 監聽 DHCP 流量，持續累積事件紀錄。
6. **網路位置定位：** 後續透過 SNMP、MAC Address Table 及 LLDP 拓樸，縮小異常設備的實體查找範圍。

## 2. 系統功能與開發狀態

| 功能                   | 狀態   | 說明                                    |
| -------------------- | ---- | ------------------------------------- |
| PCAP／PCAPNG 離線匯入     | 已實作  | 由 Web API 接收來源檔案路徑                    |
| TShark DHCP 封包精簡     | 已實作  | 使用顯示過濾條件萃取 DHCP 封包                    |
| 精簡封包解析               | 已實作  | 解析部分 Ethernet、IPv4、UDP、BOOTP／DHCP 結構  |
| DHCP 訊息統計            | 已實作  | 統計 DISCOVER、OFFER、REQUEST、ACK、NAK 等訊息 |
| 未授權 DHCP Server 初步偵測 | 已實作  | 依伺服器 IP 白名單進行比對                       |
| NAK 事件追蹤             | 已實作  | 依 IP、MAC 或主機名稱篩選關注事件                  |
| MAC／IP／主機名稱彙整        | 已實作  | 顯示裝置最後觀測資訊                            |
| CSV 事件匯入             | 已實作  | 讀取指定欄位格式的 CSV                         |
| Python／Scapy 即時監聽    | 已有原型 | 將 DHCP 事件輸出至 CSV                      |
| SQLite 事件資料庫         | 規劃中  | 整合歷史紀錄與即時事件                           |
| 背景監聽服務管理             | 規劃中  | 啟停、狀態、輪替及健康檢查                         |
| SNMP 交換器 MAC 定位      | 規劃中  | 查詢交換器的 MAC 與介面對應                      |
| LLDP 網路拓樸追查          | 規劃中  | 沿上行介面追蹤下游交換器                          |
| 樓層、教室、資訊插座映射         | 規劃中  | 建立網路設備與實體位置對照                         |
| 跨事件關聯與調查紀錄           | 規劃中  | 整合告警、設備、位置及調查結果                       |

## 3. 系統架構

### 3.1 資料來源層

支援三種資料來源：

- **歷史封包：** PCAP、PCAPNG。
- **即時監聽：** Scapy 監聽指定網路介面的 DHCP 流量。
- **既有紀錄：** 匯入 CSV 格式的 DHCP 事件。

三種來源應逐步統一為相同的 DHCP 事件資料格式，以共用後續分析及告警邏輯。

### 3.2 封包擷取與精簡層

離線處理流程：

1. 指定原始封包檔案。
2. 使用 TShark 讀取封包。
3. 透過 DHCP／BOOTP 顯示過濾條件篩選封包。
4. 將符合條件的封包寫入新的 PCAPNG 檔案。
5. 解析精簡檔案，產生統計資料及裝置清單。
6. 顯示原始容量、精簡後容量及分析結果。

範例命令：

```
tshark -r input.pcapng \
  -Y "bootp || dhcp" \
  -w dhcp_filtered.pcapng
```

實際可使用的協定過濾欄位，應依部署的 TShark 版本確認。

### 3.3 即時監聽層

目前 `dhcp_monitor.py` 使用 Scapy 監聽 UDP 67／68 埠：

```
sniff(
    filter="udp and (port 67 or port 68)",
    prn=process_dhcp_packet,
    store=False
)
```

此方式透過 BPF 過濾條件減少傳入 Python 的非目標流量，並將 DHCP 事件輸出至 CSV。

正式版本應增加：

- 指定網路介面。
- 啟動、停止與服務狀態管理。
- 監聽權限及錯誤處理。
- CSV 或資料庫寫入緩衝。
- 記錄檔輪替、保留期限與磁碟容量檢查。
- 封包遺漏、程式中斷及重新啟動紀錄。

**注意：** 監聽程式只能分析網路介面實際收到的封包。若交換器沒有將相關流量送到監聽介面，系統就無法保證觀察到整個網路的 DHCP 事件。正式部署前，必須確認 SPAN／Mirror Port、網路 TAP 或其他合法的流量擷取方式。

### 3.4 分析與診斷層

主要分析項目：

- DHCP 訊息類型與數量。
- DHCP Server 回應來源及白名單比對。
- ACK 租約分配紀錄。
- NAK 拒絕事件與關注對象篩選。
- 用戶端 MAC、IP、主機名稱及最後觀測時間。
- 不同來源的事件關聯與歷史查詢。

目前 Rogue DHCP 偵測主要依 DHCP Server IP 白名單判斷，屬於初步告警機制。未列入白名單不必然代表設備為惡意設備，仍須由網管人員確認。

### 3.5 Web 管理層

目前 `app.py` 使用 FastAPI 提供以下介面：

| 路由                    | 功能                  |
| --------------------- | ------------------- |
| `GET /`               | 主要分析頁面              |
| `GET /device-mapping` | 裝置對應資料頁面            |
| `POST /api/run`       | 執行封包或 CSV 分析        |
| `POST /api/browse`    | 呼叫 Windows 原生檔案選擇視窗 |

前端模板位於 `templates/` 目錄，使用 Jinja2 產生網頁。

正式版本建議將檔案操作、封包分析、事件儲存與前端顯示分離，避免所有分析資料只能存放在程式記憶體中的全域變數。

## 4. 下一階段：SNMP 網路位置定位

本專案的重要發展方向，是將 DHCP 異常事件與交換器實體拓樸串接。

### 4.1 預期定位流程

1. 偵測異常 DHCP 回應，取得相關 IP、MAC 與事件時間。
2. 查詢受管理交換器的 MAC Address Table。
3. 找出該 MAC 所在的交換器、VLAN 及介面。
4. 若介面為上行 Trunk，利用 LLDP 鄰接資訊追查下游設備。
5. 若介面連接無線 AP 或下游交換器，繼續追查相關設備。
6. 將最終可能的接入埠對應到樓層、機櫃、教室及資訊插座。
7. 將定位結果、查詢時間與判斷依據呈現在事件詳情頁。

### 4.2 SNMP 查詢資料

建議蒐集：

- 交換器設備識別資訊與管理 IP。
- `sysName`、`sysObjectID` 等設備資訊。
- `ifName`、`ifDescr`、`ifAlias`、`ifOperStatus` 等介面資訊。
- Bridge／Q-Bridge MAC Address Table。
- MAC 所屬 VLAN 與介面索引。
- LLDP 鄰接設備、連接埠及管理位址。
- 設備最後查詢時間及資料新鮮度。

SNMP 的實際 OID 與回傳格式須依交換器型號、作業系統及支援的 MIB 驗證。

### 4.3 定位結果的限制

- MAC 表可能只顯示最後學習到的來源位置，且會因老化而消失。
- Trunk 介面可能代表下游交換器，而非終端電腦。
- 無線用戶端可能先對應到 AP，再透過無線控制器或 AP 管理資訊定位。
- 虛擬機、橋接介面、MAC 隨機化及設備移動，都可能影響定位結果。
- 不同 VLAN、路由邊界與網路設備可能造成 MAC 可見範圍不同。
- DHCP Relay 可能使伺服器 IP 與實際發送封包的設備位置不同。

因此，系統應區分「已觀測到的 MAC 位置」與「推測的終端實體位置」，並保留查詢時間及證據來源。

## 5. 建議的資料模型

正式版建議使用 SQLite 作為初期資料庫；若未來需要多台分析節點、多使用者同時操作或大量長期事件，再評估 PostgreSQL。

### 5.1 `dhcp_events`

保存標準化 DHCP 事件。

| 欄位             | 說明                 |
| -------------- | ------------------ |
| `id`           | 事件識別碼              |
| `event_time`   | 封包事件時間             |
| `ingest_time`  | 系統接收時間             |
| `source_type`  | PCAP、SCAPY、CSV 等來源 |
| `message_type` | DHCP 訊息類型          |
| `client_mac`   | 用戶端 MAC            |
| `client_ip`    | 用戶端相關 IP           |
| `requested_ip` | 要求的 IP             |
| `assigned_ip`  | DHCP 指派的 IP        |
| `hostname`     | 用戶端主機名稱            |
| `server_ip`    | DHCP Server 識別資訊   |
| `server_mac`   | 觀測到的乙太網路來源 MAC     |
| `vlan_id`      | 可取得時記錄 VLAN        |
| `alert_type`   | 告警類型               |
| `raw_source`   | 來源檔案或擷取工作識別碼       |

### 5.2 `devices`

保存裝置的識別資訊及歷史觀測。

- `device_id`
- `mac_address`
- `hostname`
- `last_ipv4`
- `first_seen`
- `last_seen`
- `identity_source`
- `notes`

MAC、IP 與主機名稱不應假設為永久的一對一關係。系統應保留歷史關聯，避免同一 IP 重新分配後造成錯誤的設備識別。

### 5.3 `switches` 與 `switch_ports`

保存網路設備與實體介面資訊。

- 交換器管理 IP、名稱、廠牌、型號及位置。
- 介面索引、名稱、描述、狀態及 VLAN。
- 機櫃、樓層、教室、資訊插座及上行介面資訊。

### 5.4 `mac_locations`

保存每次 SNMP 定位結果。

- `mac_address`
- `switch_id`
- `port_id`
- `vlan_id`
- `observed_at`
- `query_time`
- `location_source`
- `confidence`
- `is_uplink`

### 5.5 `alerts` 與 `investigations`

保存告警、調查歷程與處理結果，讓管理人員能追蹤異常首次發生時間、設備位置變化、處理人員及結案原因。

## 6. 專案目錄建議

```
dhcp-packet-analyzer/
├── app.py
├── dhcp_monitor.py
├── requirements.txt
├── README.md
├── .gitignore
├── config/
│   ├── authorized_servers.json
│   └── network_inventory.json
├── templates/
│   ├── index.html
│   └── device_mapping.html
├── static/
│   ├── css/
│   └── js/
├── src/
│   ├── capture/
│   │   ├── tshark_reader.py
│   │   └── scapy_listener.py
│   ├── parsers/
│   │   ├── dhcp_parser.py
│   │   └── csv_parser.py
│   ├── analyzers/
│   │   ├── rogue_dhcp.py
│   │   └── lease_diagnostics.py
│   ├── storage/
│   │   ├── database.py
│   │   └── repositories.py
│   ├── snmp/
│   │   ├── client.py
│   │   ├── mac_table.py
│   │   └── lldp_topology.py
│   └── services/
│       ├── analysis_service.py
│       └── location_service.py
├── data/
│   ├── captures/
│   ├── filtered/
│   ├── exports/
│   └── dhcp_analyzer.db
├── logs/
└── tests/
    ├── test_dhcp_parser.py
    ├── test_rogue_dhcp.py
    └── test_mac_location.py
```

以上為目標目錄規劃，不代表所有模組目前均已建立。應分階段將既有程式移入模組，並維持原有功能可測試、可回復。

## 7. 安裝與執行

### 7.1 環境需求

- Windows 10／11 或其他支援的作業系統。
- Python 3。
- FastAPI、Uvicorn、Jinja2、Pydantic。
- Scapy。
- 離線分析模式所需的 TShark。(安裝Wireshark可取得)
- 即時監聽所需的網路擷取權限與相容驅動程式。
- 後續 SNMP 整合所需的 SNMP 套件與交換器唯讀查詢權限。

### 7.2 建立 Python 環境

```
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install fastapi uvicorn jinja2 pydantic scapy
```

以上是依目前兩個程式整理的基本套件安裝方式。正式部署應建立並維護經測試的 `requirements.txt`，鎖定實際相容的版本。

### 7.3 啟動 Web 分析系統

```
python app.py
```

目前程式預設使用：

- 本機網址：`http://127.0.0.1:8000`
- 服務監聽位址：`0.0.0.0:8000`

因為服務目前監聽所有網路介面，正式部署前必須限制可存取的網段，並補上身分驗證、授權及安全的檔案存取控制。

### 7.4 啟動即時監聽

```
python dhcp_monitor.py
```

目前監聽程式會將事件輸出至 `dhcp_events.csv`。執行前須確認網路介面、封包擷取權限及輸出檔案位置。

## 8. 目前程式的改善重點

### 8.1 封包解析正確性

目前離線解析器以固定偏移量解析部分 PCAPNG、Ethernet、IPv4、UDP 與 BOOTP 結構。正式版應改用經驗證的封包解析器或標準化匯出格式，處理不同封包格式與擷取條件，避免錯誤判讀。

需特別驗證：

- PCAPNG 的 Section Header、Byte Order、Interface Description 及封包區塊。
- 不同介面的時間戳精度與時區。
- VLAN 標籤、IPv4 Options、IPv6、DHCP Relay 及截斷封包。
- DHCP Option 12、Option 81、Option 50、Option 54 與其他選項的正確解析。
- BOOTP 用戶端硬體位址長度與無效封包。
- TShark 與 Python 解析結果的一致性。

### 8.2 事件時間與資料一致性

目前即時監聽程式使用程式處理時間作為時間戳，並非精確的封包擷取時間。正式版應保留封包時間、接收時間及時區資訊。

同時，離線分析與即時監聽應共用事件模型，避免欄位定義與白名單判斷不一致。

### 8.3 大型檔案處理

目前離線解析器會將精簡後的檔案整份讀入記憶體。建議改為串流處理或分批處理，並加入：

- 工作進度與取消機制。
- 執行時間及處理封包數統計。
- 輸入、輸出容量與縮減比例。
- 逾時、錯誤與中斷恢復處理。
- 原始檔與精簡檔的完整性驗證。

### 8.4 Web API 安全性

目前 API 可接收本機檔案路徑，並透過檔案選擇端點操作檔案系統。正式版必須：

- 加入身分驗證及角色權限。
- 限制允許讀取與寫入的目錄。
- 禁止未授權使用者透過 API 任意指定檔案路徑。
- 限制可執行的分析工作及同時執行數量。
- 保護 DHCP、MAC、IP 與網路拓樸等敏感資料。
- 記錄管理操作與調查存取紀錄。
- 避免將未經驗證的使用者輸入直接組成系統命令。

### 8.5 監聽與分析分離

即時監聽不應因為 Web 使用者開啟或關閉頁面而停止。正式版應將監聽器設計為獨立工作程序或服務，並由 Web 管理介面查詢狀態及讀取事件。

## 9. 分階段開發計畫

### Phase 1：穩定現有功能

- 整理 PCAP／PCAPNG、CSV 及即時監聽的共用資料格式。
- 驗證 DHCP 解析正確性。
- 改善大型封包處理效能。
- 建立單元測試及分析結果比對工具。
- 補強 API 安全性。

### Phase 2：資料庫與事件管理

- 導入 SQLite。
- 儲存 DHCP 事件、裝置資訊、告警與分析工作。
- 提供時間區間、MAC、IP、主機名稱及事件類型查詢。
- 建立歷史趨勢與事件時間軸。

### Phase 3：SNMP 交換器定位

- 建立交換器清冊與 SNMP 唯讀連線設定。
- 查詢 MAC Address Table、VLAN 與介面資訊。
- 解析 LLDP 鄰接資訊。
- 建立 MAC 到交換器、介面及拓樸的對應。
- 加入查詢時間、資料過期及定位可信度。

### Phase 4：校園網路實體位置整合

- 匯入樓層、機櫃、交換器、教室及資訊插座清冊。
- 建立交換器上行介面與下游設備關係。
- 將定位結果呈現在事件詳情頁。
- 支援從異常事件追蹤到可能的終端接入位置。

### Phase 5：資安調查與維運自動化

- 設計可調整的告警規則。
- 建立事件指派、處理紀錄與結案流程。
- 整合 DHCP、SNMP 及其他授權的網管資料來源。
- 加入告警通知、報表匯出及資料保留政策。

## 10. 驗收指標

| 項目         | 建議驗收方式                      |
| ---------- | --------------------------- |
| 封包精簡       | 以固定測試封包比較精簡前後容量及封包數         |
| 解析正確性      | 與 Wireshark／TShark 解碼結果逐筆比對 |
| Rogue DHCP | 使用核准與未核准的測試來源驗證告警           |
| NAK 追蹤     | 驗證 MAC、IP、主機名稱與時間範圍篩選       |
| 即時監聽       | 比對監聽紀錄與測試流量，確認漏包與錯誤處理       |
| SNMP 定位    | 以已知接入埠的測試 MAC 驗證交換器與介面對應    |
| 拓樸追查       | 驗證跨交換器、Trunk 及下游設備的追查結果     |
| 安全性        | 驗證未授權存取、任意路徑操作及權限限制         |

正式驗收前，應建立固定測試資料集，並將解析正確率、分析時間、記憶體用量與定位成功率量化。

## 11. 安全與使用原則

本系統應部署於經授權的校園或企業網路環境，僅用於網路維運、DHCP 異常診斷及資安事件調查。

SNMP 優先使用唯讀權限；不應將社群字串、密碼或其他憑證直接寫入程式碼或提交至版本控制。

封包、MAC、IP、主機名稱及設備位置可能涉及敏感資訊，應依組織政策限制存取、設定保留期限並保護備份。

告警結果是調查線索，不應單憑一筆 DHCP 訊息或單一 MAC 位置就直接認定設備遭入侵或具有惡意。

## 12. 官方參考文件

- Wireshark User’s Guide：[https://www.wireshark.org/docs/wsug_html/](https://www.wireshark.org/docs/wsug_html/)
- TShark 命令列工具說明：[https://www.wireshark.org/docs/man-pages/tshark.html](https://www.wireshark.org/docs/man-pages/tshark.html)
- Scapy 官方文件：[https://scapy.readthedocs.io/](https://scapy.readthedocs.io/)
- FastAPI 官方文件：[https://fastapi.tiangolo.com/](https://fastapi.tiangolo.com/)

---

**專案定位總結：**

本專案以 DHCP 封包為切入點，結合歷史封包分析與即時監聽，建立內網設備識別與異常診斷能力；下一階段透過 SNMP、MAC Address Table、LLDP 及實體網路清冊，逐步建立從 DHCP 異常事件到交換器接入位置的調查鏈，降低網管人員人工比對與現場查找的時間成本。