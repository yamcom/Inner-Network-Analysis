# ==============================================================================
# DHCP Analyzer - Windows 工作排程器註冊腳本 (規格書 13.1, 13.3, 13.4, 20.3-B)
# ==============================================================================
# 用途：向 Windows Task Scheduler 註冊/解除註冊每日凌晨 03:00 自動維護排程
# 執行：以系統管理員身分開啟 PowerShell 執行本腳本
#       .\register_task_scheduler.ps1            (註冊排程)
#       .\register_task_scheduler.ps1 -Uninstall (移除排程)
# ==============================================================================

param(
    [switch]$Uninstall,
    [string]$TaskName = "DHCP_Analyzer_Daily_Maintenance",
    [string]$ScheduleTime = "03:00"
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$BatchFile = Join-Path $ScriptDir "run_maintenance.bat"

if (-not (Test-Path $BatchFile)) {
    Write-Error "找不到維護批次檔: $BatchFile"
    exit 1
}

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "DHCP Analyzer 自動維運排程管理器" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

if ($Uninstall) {
    Write-Host "正在移除 Windows 工作排程: $TaskName ..." -ForegroundColor Yellow
    try {
        & schtasks.exe /Delete /TN $TaskName /F
        Write-Host "✅ 排程 $TaskName 已成功移除。" -ForegroundColor Green
    } catch {
        Write-Warning "移除失敗或排程不存在。"
    }
    exit 0
}

Write-Host "排程名稱: $TaskName"
Write-Host "執行時機: 每日 $ScheduleTime"
Write-Host "目標腳本: $BatchFile"
Write-Host "工作目錄: $ScriptDir"
Write-Host "--------------------------------------------------"

try {
    # 建立每日 03:00 執行的工作排程
    $Action = "cmd.exe /c `"`"$BatchFile`"`""
    & schtasks.exe /Create /TN $TaskName /TR $Action /SC DAILY /ST $ScheduleTime /RL HIGHEST /F

    Write-Host ""
    Write-Host "✅ 工作排程 [$TaskName] 註冊成功！" -ForegroundColor Green
    Write-Host "系統將於每日凌晨 $ScheduleTime 自動執行 30 天清理、WAL Checkpoint 與資料庫備份。" -ForegroundColor Green
} catch {
    Write-Error "註冊失敗，請確認是否以『系統管理員身分』執行 PowerShell。"
}
