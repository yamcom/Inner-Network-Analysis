@echo off
setlocal EnableExtensions

rem Rebuild/reset helper for the DHCP Analyzer project.
rem Supports:
rem   1. Full Rebuild (Cleans caches, temp files, resets SQLite database, syncs uv env)
rem   2. Clean Caches Only (Cleans caches, pycache, temp files, keeps SQLite DB intact)
rem
rem Usage:
rem   rebuild_project.bat               (Interactive mode)
rem   rebuild_project.bat --clean-cache (Clean caches only, non-interactive)
rem   rebuild_project.bat --full -y     (Full rebuild, non-interactive)

set "ROOT=%~dp0"
set "DB=%ROOT%data\dhcp_analyzer.db"
set "UV_CACHE=%ROOT%.uv-cache"
set "PYTEST_CACHE=%ROOT%.pytest_cache"
set "TESTS_TMP=%ROOT%tests\.tmp"
set "UPLOAD_INCOMING=%ROOT%upload\incoming"
set "UPLOAD_FAILED=%ROOT%upload\failed"
set "OLD_VENV=%ROOT%.venv-v2"
set "UV_CACHE_DIR=%UV_CACHE%"
set "UV_PROJECT_ENVIRONMENT=%ROOT%.venv"

set "MODE="
set "ASSUME_YES=0"

:parse_args
if "%~1"=="" goto check_mode
if /i "%~1"=="--clean-cache" (
    set "MODE=CACHE_ONLY"
    shift
    goto parse_args
)
if /i "%~1"=="--full" (
    set "MODE=FULL"
    shift
    goto parse_args
)
if /i "%~1"=="-y" (
    set "ASSUME_YES=1"
    shift
    goto parse_args
)
if /i "%~1"=="--yes" (
    set "ASSUME_YES=1"
    shift
    goto parse_args
)
shift
goto parse_args

:check_mode
if not "%MODE%"=="" goto confirm_action

echo ========================================================
echo         DHCP Analyzer Project Cleanup ^& Rebuild
echo ========================================================
echo Project Directory: %ROOT%
echo.
echo Select an option:
echo   [1] Full Rebuild (Clean temp/caches + RESET SQLite Database + uv sync)
echo   [2] Clean Temp ^& Caches Only (Keep SQLite Database intact)
echo   [3] Cancel
echo.

choice /C 123 /N /M "Enter your choice [1, 2, or 3]: "
if errorlevel 3 (
    echo Cancelled.
    exit /b 0
)
if errorlevel 2 (
    set "MODE=CACHE_ONLY"
    goto do_cleanup
)
if errorlevel 1 (
    set "MODE=FULL"
    goto confirm_action
)

:confirm_action
if "%MODE%"=="FULL" (
    echo.
    echo [WARNING] Full Rebuild will remove the SQLite database and all local analysis jobs!
    echo Target DB: %DB%*
    if "%ASSUME_YES%"=="0" (
        choice /C YN /N /M "Are you sure you want to proceed with Full Rebuild? (Y/N): "
        if errorlevel 2 (
            echo Cancelled.
            exit /b 0
        )
    )
)

:do_cleanup
echo.
echo [1/4] Cleaning Python bytecode caches (__pycache__, *.pyc, *.pyo)...
for /d /r "%ROOT%" %%D in (__pycache__) do (
    if exist "%%~fD" (
        rmdir /s /q "%%~fD" 2>nul
    )
)
del /s /f /q "%ROOT%*.pyc" 2>nul
del /s /f /q "%ROOT%*.pyo" 2>nul

echo [2/4] Cleaning test caches and temp folders (.pytest_cache, tests\.tmp)...
if exist "%PYTEST_CACHE%" rmdir /s /q "%PYTEST_CACHE%" 2>nul
if exist "%TESTS_TMP%" rmdir /s /q "%TESTS_TMP%" 2>nul
for /d %%D in ("%ROOT%.pytest-tmp*") do (
    if exist "%%~fD" rmdir /s /q "%%~fD" 2>nul
)

echo [3/4] Cleaning upload temporary files and uv cache...
if exist "%UV_CACHE%" rmdir /s /q "%UV_CACHE%" 2>nul

if not exist "%UPLOAD_INCOMING%" mkdir "%UPLOAD_INCOMING%" 2>nul
del /f /q "%UPLOAD_INCOMING%\*.*" 2>nul

if not exist "%UPLOAD_FAILED%" mkdir "%UPLOAD_FAILED%" 2>nul
del /f /q "%UPLOAD_FAILED%\*.*" 2>nul

if exist "%ROOT%dhcp_events.old.csv" del /f /q "%ROOT%dhcp_events.old.csv" 2>nul

if "%MODE%"=="FULL" goto do_full_rebuild

echo [4/4] SQLite database preserved.
goto cleanup_done

:do_full_rebuild
echo [4/4] Removing SQLite database and syncing uv environment...
if exist "%DB%" del /f /q "%DB%" 2>nul
if exist "%DB%-wal" del /f /q "%DB%-wal" 2>nul
if exist "%DB%-shm" del /f /q "%DB%-shm" 2>nul
if exist "%ROOT%dhcp_events.csv" del /f /q "%ROOT%dhcp_events.csv" 2>nul
if exist "%OLD_VENV%" rmdir /s /q "%OLD_VENV%" 2>nul

echo.
echo Synchronizing uv environment (%UV_PROJECT_ENVIRONMENT%)...
uv sync --dev
if errorlevel 1 (
    echo [ERROR] uv sync failed. Please review the output above.
    exit /b 1
)

:cleanup_done
echo.
echo ========================================================
echo Cleanup completed successfully! Mode: %MODE%
echo ========================================================
if "%MODE%"=="FULL" (
    echo Start the web application with:
    echo   uv run python app.py
)
exit /b 0
