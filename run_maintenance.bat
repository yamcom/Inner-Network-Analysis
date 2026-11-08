@echo off
REM DHCP Analyzer Scheduled Maintenance Script (spec 13.1, 13.3, 13.4)
REM Recommended schedule: Daily at 03:00 AM via Windows Task Scheduler.

cd /d "%~dp0"

echo [%DATE% %TIME%] Starting DHCP Analyzer maintenance...
uv run python -c "from maintenance import run_all_maintenance; import os; db=os.getenv('DHCP_ANALYZER_DB', 'data/dhcp_analyzer.db'); res=run_all_maintenance(db); print(res)"

if %ERRORLEVEL% equ 0 (
    echo [%DATE% %TIME%] Maintenance completed successfully.
) else (
    echo [%DATE% %TIME%] Maintenance failed with error code %ERRORLEVEL%.
)
