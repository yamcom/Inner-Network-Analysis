# ==============================================================================
# DHCP Analyzer - Web API 與儀表板啟動腳本 (規格書第 10 章, 20.4)
# ==============================================================================
# 說明：以 FastAPI + Uvicorn 啟動唯讀查詢與離線分析工作 Web 服務
# 網址：http://127.0.0.1:8000
# 原則：僅供查詢與離線分析，無啟停即時監控按鈕 (完全解耦架構)
# ==============================================================================

param(
    [string]$HostIP = "127.0.0.1",
    [int]$Port = 8000
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ScriptDir

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "DHCP Analyzer Web 服務啟動程序" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# 檢測虛擬環境 Python
$PythonExe = Join-Path $ScriptDir ".venv\Scripts\python.exe"
if (-not (Test-Path $PythonExe)) {
    Write-Error "找不到虛擬環境 Python: $PythonExe"
    exit 1
}

Write-Host "綁定位置: http://${HostIP}:${Port}"
Write-Host "架構原則: Web 僅提供唯讀查詢與離線檔案分析，不控制即時監控 (完全解耦)"
Write-Host "--------------------------------------------------"
Write-Host "正在啟動 Web 服務 (按 Ctrl+C 可停止伺服器)..." -ForegroundColor Green

& $PythonExe app.py
