from __future__ import annotations

import sqlite3
import uuid

from core.models import utc_now


def create_job(connection: sqlite3.Connection, source_type: str, source_name: str, source_path: str | None = None) -> str:
    job_id = str(uuid.uuid4())
    connection.execute(
        """INSERT INTO analysis_jobs(job_id, source_type, source_name, source_path, status, created_at)
        VALUES (?, ?, ?, ?, 'queued', ?)""",
        (job_id, source_type, source_name, source_path, utc_now()),
    )
    connection.commit()
    return job_id


def create_upload_job(connection: sqlite3.Connection, source_id: str, source_type: str, original_filename: str, stored_path: str, file_size: int, file_hash: str) -> str:
    """Create analysis_jobs + analysis_sources atomically for an upload."""
    job_id = str(uuid.uuid4())
    now = utc_now()
    with connection:
        connection.execute(
            """INSERT INTO analysis_jobs(job_id, source_type, source_name, source_path, status, created_at)
            VALUES (?, ?, ?, ?, 'queued', ?)""",
            (job_id, source_type, original_filename, stored_path, now),
        )
        connection.execute(
            """INSERT INTO analysis_sources(source_id, job_id, original_filename, stored_path, file_size,
                file_hash, source_type, upload_status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'queued', ?)""",
            (source_id, job_id, original_filename, stored_path, file_size, file_hash, source_type, now),
        )
    return job_id


def get_status_values(connection: sqlite3.Connection, keys: tuple[str, ...]) -> dict[str, sqlite3.Row]:
    placeholders = ",".join("?" for _ in keys)
    rows = connection.execute(
        f"SELECT key, value, updated_at FROM system_status WHERE key IN ({placeholders})", keys
    ).fetchall()
    return {row["key"]: row for row in rows}


def mark_job_running(connection: sqlite3.Connection, job_id: str, worker_id: str) -> None:
    connection.execute(
        """UPDATE analysis_jobs
        SET status='running', worker_id=?, started_at=COALESCE(started_at, ?), last_progress_at=?
        WHERE job_id=? AND status='queued'""",
        (worker_id, utc_now(), utc_now(), job_id),
    )
    connection.execute("UPDATE analysis_sources SET upload_status='processing' WHERE job_id=?", (job_id,))
    connection.commit()


def finish_job(connection: sqlite3.Connection, job_id: str, status: str, error_message: str | None = None) -> None:
    if status not in {"completed", "failed", "interrupted"}:
        raise ValueError("invalid terminal job status")
    connection.execute(
        """UPDATE analysis_jobs
        SET status=?, completed_at=?, last_progress_at=?, progress=CASE WHEN ?='completed' THEN 100 ELSE progress END,
            error_message=?
        WHERE job_id=?""",
        (status, utc_now(), utc_now(), status, error_message, job_id),
    )
    connection.execute(
        "UPDATE analysis_sources SET upload_status=? WHERE job_id=?",
        ("completed" if status == "completed" else "failed", job_id),
    )
    connection.commit()


def recover_interrupted_live_jobs(connection: sqlite3.Connection) -> int:
    """Mark live-monitor jobs left 'running' by a killed process as interrupted.

    Spec 14.3: never auto-rerun; only record the interruption honestly.
    """
    now = utc_now()
    cursor = connection.execute(
        """UPDATE analysis_jobs
        SET status='interrupted', completed_at=?, last_progress_at=COALESCE(last_progress_at, ?),
            error_message=COALESCE(error_message, 'process ended without graceful shutdown')
        WHERE source_type='live_monitor' AND status IN ('queued','running')""",
        (now, now),
    )
    connection.commit()
    return cursor.rowcount


def get_job(connection: sqlite3.Connection, job_id: str) -> sqlite3.Row | None:
    return connection.execute("SELECT * FROM analysis_jobs WHERE job_id=?", (job_id,)).fetchone()


def list_jobs(connection: sqlite3.Connection, limit: int = 100) -> list[sqlite3.Row]:
    limit = max(1, min(limit, 500))
    return connection.execute(
        "SELECT * FROM analysis_jobs ORDER BY created_at DESC, job_id DESC LIMIT ?", (limit,)
    ).fetchall()


def list_events(connection: sqlite3.Connection, job_id: str, limit: int = 100, after_id: int | None = None, message_type: str | None = None) -> list[sqlite3.Row]:
    limit = max(1, min(limit, 500))
    type_filter = " AND message_type=?" if message_type else ""
    type_value = (message_type.upper(),) if message_type else ()
    if after_id is None:
        return connection.execute(
            f"""SELECT * FROM dhcp_events WHERE job_id=?{type_filter}
            ORDER BY id ASC LIMIT ?""", (job_id, *type_value, limit)
        ).fetchall()
    return connection.execute(
        f"""SELECT * FROM dhcp_events WHERE job_id=? AND id>?{type_filter}
        ORDER BY id ASC LIMIT ?""", (job_id, after_id, *type_value, limit)
    ).fetchall()


def list_recent_events(
    connection: sqlite3.Connection,
    start_time: str,
    end_time: str,
    limit: int = 1000,
    message_type: str | None = None,
) -> list[sqlite3.Row]:
    """Read a bounded time window using the global event-time index."""
    limit = max(1, min(limit, 10000))
    type_filter = " AND message_type=?" if message_type else ""
    values: list[object] = [start_time, end_time]
    if message_type:
        values.append(message_type.upper())
    values.append(limit)
    return connection.execute(
        f"""SELECT id, job_id, event_time, source_type, message_type,
                   client_mac, server_ip, requested_ip, assigned_ip,
                   hostname, relay_ip, anomaly_type, severity, is_rogue
            FROM dhcp_events
            WHERE event_time >= ? AND event_time <= ?{type_filter}
            ORDER BY event_time DESC, id DESC LIMIT ?""",
        values,
    ).fetchall()


def latest_completed_job(connection: sqlite3.Connection) -> sqlite3.Row | None:
    return connection.execute(
        """SELECT * FROM analysis_jobs
        WHERE status='completed' ORDER BY completed_at DESC, created_at DESC LIMIT 1"""
    ).fetchone()


def update_device_metadata(
    connection: sqlite3.Connection,
    mac: str,
    device_name: str | None = None,
    location: str | None = None,
) -> dict[str, str | None]:
    """Manually update or initialize device_name and location (spec 4.6)."""
    norm_mac = mac.strip().upper()
    now = utc_now()
    with connection:
        # 確保該 MAC 在 devices 表存在
        connection.execute(
            """INSERT INTO devices(mac, first_seen, last_seen, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(mac) DO NOTHING""",
            (norm_mac, now, now, now, now),
        )
        # 更新人工維護欄位
        connection.execute(
            """UPDATE devices
            SET device_name = COALESCE(?, device_name),
                location = COALESCE(?, location),
                updated_at = ?
            WHERE mac = ?""",
            (device_name, location, now, norm_mac),
        )
        row = connection.execute(
            "SELECT mac, hostname, last_ip, device_name, location, updated_at FROM devices WHERE mac = ?",
            (norm_mac,),
        ).fetchone()
        return dict(row) if row else {"mac": norm_mac, "device_name": device_name, "location": location}


def list_job_devices(connection: sqlite3.Connection, job_id: str, limit: int = 500) -> list[sqlite3.Row]:
    limit = max(1, min(limit, 500))
    return connection.execute(
        """SELECT j.mac, j.hostname, j.ip, j.first_seen, j.last_seen,
                  d.device_name, d.location
        FROM job_device_mappings j
        LEFT JOIN devices d ON UPPER(j.mac) = UPPER(d.mac)
        WHERE j.job_id=?
        ORDER BY j.hostname COLLATE NOCASE ASC, j.mac ASC LIMIT ?""",
        (job_id, limit),
    ).fetchall()


def list_device_locations(connection: sqlite3.Connection, mac_address: str, limit: int = 100) -> list[sqlite3.Row]:
    limit = max(1, min(limit, 500))
    return connection.execute(
        """SELECT * FROM device_locations
        WHERE mac_address=? ORDER BY observed_at DESC, id DESC LIMIT ?""",
        (mac_address.upper(), limit),
    ).fetchall()

