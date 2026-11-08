# ==============================================================================
# DHCP Analyzer - Windows 11 實體網卡即時監控啟動工具 (規格書第 7 章, 20.3-A)
# ==============================================================================
# 預設綁定使用中實體網卡: 乙太網路 2 (Intel I219-LM, IP: 192.69.1.42)
# 具備啟動前 5GB 磁碟剩餘空間安全檢查與 CSV 雙寫輸出路徑
# ==============================================================================

param(
    [string]$Interface = "乙太網路 2",
    [string]$Database = "data\dhcp_analyzer.db",
    [string]$CsvPath = "dhcp_events.csv"
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ScriptDir

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "DHCP Analyzer 即時監控啟動環境檢測" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# 1. 檢測磁碟剩餘空間 (必須 >= 5GB)
$drive = (Get-Item $ScriptDir).PSDrive
$freeGB = [math]::Round($drive.Free / 1GB, 2)
Write-Host "磁碟剩餘空間: $freeGB GB (門檻: 5.00 GB)"

if ($freeGB -lt 5.0) {
    Write-Error "磁碟剩餘空間不足 5GB ($freeGB GB)，系統主動中斷啟動以確保資料庫安全！"
    exit 1
}

# 2. 檢測 Python 虛擬環境
$PythonExe = Join-Path $ScriptDir ".venv\Scripts\python.exe"
if (-not (Test-Path $PythonExe)) {
    Write-Error "找不到虛擬環境 Python: $PythonExe"
    exit 1
}

Write-Host "監聽網卡: $Interface"
Write-Host "資料庫路徑: $Database"
Write-Host "CSV 雙寫路徑: $CsvPath"
Write-Host "--------------------------------------------------"
Write-Host "正在啟動即時監控程序 (按 Ctrl+C 可安全 Flush 並停止)..." -ForegroundColor Green

$env:DHCP_MONITOR_INTERFACE = $Interface
$env:DHCP_ANALYZER_DB = $Database
$env:DHCP_ANALYZER_CSV = $CsvPath

& $PythonExe dhcp_monitor.py
