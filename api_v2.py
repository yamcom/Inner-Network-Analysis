from __future__ import annotations

import os
import csv
import io
import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from core.config import PROJECT_ROOT, load_config, project_path
from database.connection import connect_database, connect_readonly_database
from database.migrations import migrate
from database.repositories import create_job, create_upload_job, get_job, get_status_values, latest_completed_job, list_device_locations, list_events, list_job_devices, list_jobs, list_recent_events, update_device_metadata
from services.upload_service import UploadError, UploadService
from workers.job_runner import run_csv_job, run_pcap_job


MONITOR_STATUS_KEYS = ("monitor_status", "monitor_instance_id", "monitor_job_id", "monitor_heartbeat", "monitor_degradation_reason")
WRITER_STATUS_KEYS = ("writer_status", "writer_heartbeat", "writer_queue_depth", "writer_retry_count", "writer_failed_batches", "writer_last_error")


class CreateJobRequest(BaseModel):
    source_type: str = Field(default="csv")
    source_path: str = Field(min_length=1, max_length=1024)


class UpdateDeviceRequest(BaseModel):
    device_name: str | None = Field(default=None, max_length=255)
    location: str | None = Field(default=None, max_length=255)


def _validate_source(source_path: str, source_type: str, allowed_root: Path = PROJECT_ROOT) -> Path:
    path = Path(source_path).expanduser().resolve()
    if not path.is_relative_to(Path(allowed_root).resolve()):
        # Spec 6.2 item 12: browsers must not make the server read arbitrary host files.
        raise HTTPException(status_code=400, detail="source must be inside the project directory")
    allowed = {"csv": {".csv"}, "pcap": {".pcap", ".pcapng"}, "pcapng": {".pcapng"}}
    if path.suffix.lower() not in allowed.get(source_type, set()):
        raise HTTPException(status_code=400, detail="source extension does not match source_type")
    if not path.is_file():
        raise HTTPException(status_code=400, detail="source CSV does not exist")
    max_size = int(os.getenv("DHCP_ANALYZER_MAX_SOURCE_BYTES", str(2 * 1024 * 1024 * 1024)))
    if path.stat().st_size > max_size:
        raise HTTPException(status_code=413, detail="source CSV exceeds configured size limit")
    return path


def _time_window(minutes: int, start_time: str | None, end_time: str | None) -> tuple[str, str]:
    if (start_time is None) != (end_time is None):
        raise HTTPException(status_code=400, detail="start_time and end_time must be provided together")
    if start_time and end_time:
        try:
            start = datetime.fromisoformat(start_time.replace("Z", "+00:00")).astimezone(timezone.utc)
            end = datetime.fromisoformat(end_time.replace("Z", "+00:00")).astimezone(timezone.utc)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="invalid ISO-8601 time range") from exc
        if end <= start:
            raise HTTPException(status_code=400, detail="end_time must be after start_time")
        if end - start > timedelta(days=7):
            raise HTTPException(status_code=400, detail="custom time range cannot exceed 7 days")
    else:
        end = datetime.now(timezone.utc)
        start = end - timedelta(minutes=minutes)
    return (
        start.isoformat(timespec="seconds").replace("+00:00", "Z"),
        end.isoformat(timespec="seconds").replace("+00:00", "Z"),
    )


def _seconds_since(timestamp: str | None) -> int | None:
    if not timestamp:
        return None
    try:
        moment = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return max(0, int((datetime.now(timezone.utc) - moment).total_seconds()))


def create_query_app(database_path: str = "data/dhcp_analyzer.db", route_prefix: str = "/api/v2", upload_root: str | Path | None = None, allowed_source_root: str | Path | None = None, config: dict | None = None) -> FastAPI:
    app = FastAPI(title="DHCP Analyzer Query API", version="2.0")
    settings = config or load_config()
    runtime = settings["runtime"]
    upload_cfg = settings["upload"]
    heartbeat_timeout = int(settings.get("monitor", {}).get("heartbeat_timeout", 15))
    max_queued_jobs = int(runtime.get("max_queued_jobs", 10))
    chunk_size = int(upload_cfg.get("chunk_size_kb", 1024)) * 1024
    executor = ThreadPoolExecutor(max_workers=max(1, int(runtime.get("max_workers", 1))), thread_name_prefix="dhcp-analysis")
    route_prefix = route_prefix.rstrip("/")
    source_root = Path(allowed_source_root).resolve() if allowed_source_root else PROJECT_ROOT
    uploads = UploadService(
        Path(upload_root) if upload_root else project_path(upload_cfg.get("root", "upload")),
        max_bytes=int(upload_cfg.get("max_file_size_mb", 2048)) * 1024 * 1024,
    )
    pending_jobs = {"count": 0}
    pending_lock = threading.Lock()

    # Initialize only a brand-new database. Existing databases are migrated
    # by deployment/monitor startup; GET requests must never migrate or change
    # WAL state while the live writer is committing batches.
    if not Path(database_path).exists():
        bootstrap = connect_database(database_path)
        try:
            migrate(bootstrap)
        finally:
            bootstrap.close()

    @app.exception_handler(sqlite3.OperationalError)
    async def sqlite_unavailable(_request: Request, exc: sqlite3.OperationalError):
        # Spec 20.3-C: busy/locked/unavailable DB is reported as 503, never as
        # a healthy or generic 500 response.
        busy = any(marker in str(exc).lower() for marker in ("locked", "busy"))
        return JSONResponse(
            status_code=503,
            headers={"Retry-After": "2"},
            content={"status": "error", "error": "database_busy" if busy else "database_unavailable", "message": "資料庫暫時無法服務，請稍後重試"},
        )

    def rows_to_dict(rows):
        return [dict(row) for row in rows]

    def submit_job(source_type: str, source_path: str, job_id: str) -> None:
        runner = run_csv_job if source_type == "csv" else run_pcap_job

        def run() -> None:
            try:
                runner(database_path, source_path, job_id)
            finally:
                with pending_lock:
                    pending_jobs["count"] -= 1

        with pending_lock:
            pending_jobs["count"] += 1
        executor.submit(run)

    def ensure_queue_capacity() -> None:
        with pending_lock:
            if pending_jobs["count"] >= max_queued_jobs:
                raise HTTPException(status_code=429, detail="analysis queue is full; retry later")

    @app.post(f"{route_prefix}/jobs", status_code=202)
    def create_analysis_job(request: CreateJobRequest):
        source_type = request.source_type.lower()
        if source_type not in {"csv", "pcap", "pcapng"}:
            raise HTTPException(status_code=400, detail="V2 supports CSV, PCAP, and PCAPNG jobs")
        source = _validate_source(request.source_path, source_type, source_root)
        ensure_queue_capacity()
        connection = connect_database(database_path)
        try:
            migrate(connection)
            job_id = create_job(connection, source_type, source.name, str(source))
        finally:
            connection.close()
        submit_job(source_type, str(source), job_id)
        return {"status": "accepted", "data": {"job_id": job_id, "status": "queued", "source_name": source.name}}

    @app.post(f"{route_prefix}/analysis/upload", status_code=202)
    async def upload_analysis_source(request: Request, filename: str = Query(min_length=1, max_length=255)):
        """Stream a raw request body (application/octet-stream) to disk.

        The HTTP request only stores the file and queues a job; parsing is
        done by the background worker (spec 10.8).
        """
        ensure_queue_capacity()

        async def chunks():
            buffer = bytearray()
            async for piece in request.stream():
                buffer.extend(piece)
                while len(buffer) >= chunk_size:
                    yield bytes(buffer[:chunk_size])
                    del buffer[:chunk_size]
            if buffer:
                yield bytes(buffer)

        try:
            stored = await uploads.store(filename, chunks())
        except UploadError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
        connection = connect_database(database_path)
        try:
            migrate(connection)
            job_id = create_upload_job(connection, stored.source_id, stored.source_type, stored.original_filename, str(stored.stored_path), stored.file_size, stored.file_hash)
        finally:
            connection.close()
        submit_job(stored.source_type, str(stored.stored_path), job_id)
        return {"status": "success", "data": {
            "job_id": job_id, "source_id": stored.source_id, "filename": stored.original_filename,
            "file_size": stored.file_size, "sha256": stored.file_hash, "source_type": stored.source_type, "status": "queued",
        }}

    @app.get(f"{route_prefix}/monitor/status")
    def monitor_status():
        connection = connect_readonly_database(database_path)
        try:
            values = get_status_values(connection, MONITOR_STATUS_KEYS + WRITER_STATUS_KEYS)
        finally:
            connection.close()

        def value(key):
            return values[key]["value"] if key in values else None

        heartbeat = value("monitor_heartbeat")
        seconds_ago = _seconds_since(heartbeat)
        reported = value("monitor_status")
        is_alive = seconds_ago is not None and seconds_ago < heartbeat_timeout and reported not in {"offline", "error"}
        if heartbeat is None:
            message = "尚無監控心跳紀錄"
        elif is_alive:
            message = "監控程序正常運作中"
        elif reported == "offline":
            message = "監控程序已正常停止"
        else:
            message = "監控心跳逾時"
        writer_heartbeat = value("writer_heartbeat")
        return {"status": "success", "data": {
            "is_alive": is_alive,
            "monitor_status": reported,
            "monitor_instance_id": value("monitor_instance_id"),
            "job_id": value("monitor_job_id"),
            "last_heartbeat": heartbeat,
            "seconds_ago": seconds_ago,
            "degradation_reason": value("monitor_degradation_reason"),
            "message": message,
            "writer": {
                "status": value("writer_status"),
                "last_heartbeat": writer_heartbeat,
                "seconds_ago": _seconds_since(writer_heartbeat),
                "queue_depth": value("writer_queue_depth"),
                "retry_count": value("writer_retry_count"),
                "failed_batches": value("writer_failed_batches"),
                "last_error": value("writer_last_error"),
            },
        }}

    @app.get(f"{route_prefix}/monitor/summary")
    def monitor_summary():
        connection = connect_readonly_database(database_path)
        try:
            job = connection.execute(
                "SELECT * FROM analysis_jobs WHERE source_type='live_monitor' ORDER BY created_at DESC, job_id DESC LIMIT 1"
            ).fetchone()
            if job is None:
                return {"status": "success", "data": None}
            stats = connection.execute("SELECT * FROM analysis_stats WHERE job_id=?", (job["job_id"],)).fetchone()
            today = datetime.now(timezone.utc).strftime("%Y-%m-%dT00:00:00Z")
            today_nak = connection.execute(
                "SELECT COUNT(*) FROM dhcp_events WHERE message_type='NAK' AND event_time >= ?", (today,)
            ).fetchone()[0]
        finally:
            connection.close()
        counters = json.loads(stats["counters_json"]) if stats and stats["counters_json"] else {}
        anomaly_keys = ("FLOODING", "DECLINE_DETECTED", "POSSIBLE_IP_CONFLICT", "CONFIRMED_IP_CONFLICT", "ABNORMAL_LEASE", "ROGUE_DHCP")
        return {"status": "success", "data": {
            "job_id": job["job_id"],
            "job_status": job["status"],
            "total_packets": stats["total_packets"] if stats else 0,
            "total_events": stats["total_events"] if stats else 0,
            "message_counts": {key: counters.get(key, 0) for key in ("DISCOVER", "OFFER", "REQUEST", "ACK", "NAK", "DECLINE", "INFORM", "RELEASE")},
            "today_nak": today_nak,
            "rogue_dhcp": counters.get("ROGUE_DHCP", 0),
            "anomaly_count": sum(counters.get(key, 0) for key in anomaly_keys),
            "silent_count": stats["silent_count"] if stats else 0,
            "dropped_in_memory_events": counters.get("DROPPED_IN_MEMORY_EVENTS", 0),
            "updated_at": stats["updated_at"] if stats else job["last_progress_at"],
        }}

    @app.get(f"{route_prefix}/jobs")
    def jobs(limit: int = Query(default=100, ge=1, le=500)):
        connection = connect_readonly_database(database_path)
        try:
            return {"status": "success", "data": rows_to_dict(list_jobs(connection, limit))}
        finally:
            connection.close()

    @app.get(f"{route_prefix}/jobs/{{job_id}}")
    def job_detail(job_id: str):
        connection = connect_readonly_database(database_path)
        try:
            row = get_job(connection, job_id)
            if row is None:
                raise HTTPException(status_code=404, detail="job not found")
            stats = connection.execute("SELECT * FROM analysis_stats WHERE job_id=?", (job_id,)).fetchone()
            data = dict(row)
            data["stats"] = dict(stats) if stats else None
            return {"status": "success", "data": data}
        finally:
            connection.close()

    @app.get(f"{route_prefix}/events")
    def events(job_id: str, limit: int = Query(default=100, ge=1, le=500), after_id: int | None = Query(default=None, ge=0), message_type: str | None = None):
        connection = connect_readonly_database(database_path)
        try:
            if get_job(connection, job_id) is None:
                raise HTTPException(status_code=404, detail="job not found")
            data = rows_to_dict(list_events(connection, job_id, limit, after_id, message_type))
            next_after_id = data[-1]["id"] if data else after_id
            return {"status": "success", "data": data, "next_after_id": next_after_id}
        finally:
            connection.close()

    @app.get(f"{route_prefix}/events/recent")
    def recent_events(
        minutes: int = Query(default=5, ge=1, le=1440),
        start_time: str | None = None,
        end_time: str | None = None,
        limit: int = Query(default=1000, ge=1, le=2000),
        message_type: str | None = None,
    ):
        window_start, window_end = _time_window(minutes, start_time, end_time)
        connection = connect_readonly_database(database_path)
        try:
            data = rows_to_dict(connection_rows := list_recent_events(
                connection, window_start, window_end, limit, message_type
            ))
            return {
                "status": "success",
                "data": data,
                "window": {"start_time": window_start, "end_time": window_end},
                "truncated": len(connection_rows) >= limit,
            }
        finally:
            connection.close()

    @app.get(f"{route_prefix}/events/export")
    def export_events(
        minutes: int = Query(default=5, ge=1, le=1440),
        start_time: str | None = None,
        end_time: str | None = None,
        limit: int = Query(default=10000, ge=1, le=10000),
        message_type: str | None = None,
    ):
        window_start, window_end = _time_window(minutes, start_time, end_time)
        connection = connect_readonly_database(database_path)
        try:
            rows = list_recent_events(connection, window_start, window_end, limit, message_type)
        finally:
            connection.close()
        output = io.StringIO(newline="")
        fields = [
            "id", "job_id", "event_time", "source_type", "message_type", 
            "client_mac", "server_ip", "requested_ip", "assigned_ip", 
            "hostname", "relay_ip", "anomaly_type", "severity", "is_rogue"
        ]
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        writer.writerows({field: row[field] for field in fields} for row in rows)
        filename = f"dhcp_events_{window_start.replace(':', '').replace('-', '')}_{window_end.replace(':', '').replace('-', '')}.csv"
        return StreamingResponse(
            iter([output.getvalue().encode("utf-8-sig")]),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.get(f"{route_prefix}/devices")
    def devices(job_id: str | None = None, limit: int = Query(default=500, ge=1, le=500)):
        connection = connect_readonly_database(database_path)
        try:
            selected_job_id = job_id
            if selected_job_id is None:
                latest = latest_completed_job(connection)
                selected_job_id = latest["job_id"] if latest else None
            if selected_job_id is None:
                return {"status": "success", "job_id": None, "data": []}
            if get_job(connection, selected_job_id) is None:
                raise HTTPException(status_code=404, detail="job not found")
            return {"status": "success", "job_id": selected_job_id, "data": rows_to_dict(list_job_devices(connection, selected_job_id, limit))}
        finally:
            connection.close()

    @app.patch(f"{route_prefix}/devices/{{mac}}")
    def update_device(mac: str, req: UpdateDeviceRequest):
        """Manually update device_name and location (spec 4.6)."""
        connection = connect_database(database_path)
        try:
            res = update_device_metadata(connection, mac, device_name=req.device_name, location=req.location)
            return {"status": "success", "data": res}
        finally:
            connection.close()

    @app.get(f"{route_prefix}/locations")
    def locations(mac_address: str, limit: int = Query(default=100, ge=1, le=500)):
        connection = connect_readonly_database(database_path)
        try:
            return {"status": "success", "data": rows_to_dict(list_device_locations(connection, mac_address, limit))}
        finally:
            connection.close()

    return app


app = create_query_app()

