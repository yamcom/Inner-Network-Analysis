from __future__ import annotations

import os
import shutil
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from database.connection import connect_database
from database.migrations import migrate


def check_disk_space(path: str | Path, min_free_mb: int = 5120) -> dict[str, float | bool]:
    """Check remaining disk space (spec 14.1; min 5GB default)."""
    target = Path(path).resolve()
    # Find existing ancestor directory to check disk usage
    while not target.exists() and target.parent != target:
        target = target.parent
    usage = shutil.disk_usage(str(target))
    free_mb = usage.free / (1024 * 1024)
    return {
        "free_mb": round(free_mb, 2),
        "total_mb": round(usage.total / (1024 * 1024), 2),
        "is_sufficient": free_mb >= min_free_mb,
    }


def purge_old_events(database_path: str, event_days: int = 30, batch_size: int = 5000) -> int:
    if event_days < 1 or batch_size < 1:
        raise ValueError("event_days and batch_size must be positive")
    cutoff = (datetime.now(timezone.utc) - timedelta(days=event_days)).isoformat(timespec="seconds").replace("+00:00", "Z")
    connection = connect_database(database_path)
    deleted = 0
    try:
        migrate(connection)
        while True:
            with connection:
                cursor = connection.execute(
                    """DELETE FROM dhcp_events WHERE id IN (
                        SELECT id FROM dhcp_events WHERE created_at < ? LIMIT ?
                    )""",
                    (cutoff, batch_size),
                )
                count = cursor.rowcount
            deleted += count
            if count == 0:
                return deleted
    finally:
        connection.close()


def online_backup(database_path: str, backup_path: str) -> Path:
    source = connect_database(database_path)
    target_path = Path(backup_path)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    target = sqlite3.connect(target_path)
    try:
        source.backup(target)
        target.commit()
    finally:
        target.close()
        source.close()
    return target_path


def wal_checkpoint(database_path: str) -> None:
    """Execute WAL truncation checkpoint (spec 13.3)."""
    connection = connect_database(database_path)
    try:
        migrate(connection)
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        connection.close()


def run_all_maintenance(database_path: str, event_days: int = 30, backup_dir: str = "backups", min_free_mb: int = 5120) -> dict[str, str | int | float | bool]:
    """Execute retention purge, WAL checkpoint, and online backup in sequence."""
    disk_info = check_disk_space(backup_dir, min_free_mb=min_free_mb)
    if not disk_info["is_sufficient"]:
        raise RuntimeError(f"磁碟空間不足 (剩餘 {disk_info['free_mb']} MB < {min_free_mb} MB (約 {round(min_free_mb / 1024, 1)}GB))，停止執行維護作業以防損壞")

    deleted = purge_old_events(database_path, event_days=event_days)
    wal_checkpoint(database_path)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_file = Path(backup_dir) / f"dhcp_analyzer_backup_{timestamp}.db"
    online_backup(database_path, str(backup_file))
    health = verify_database(database_path)
    return {
        "deleted_events": deleted,
        "backup_path": str(backup_file),
        "disk_free_mb": disk_info["free_mb"],
        **health,
    }


def verify_database(database_path: str) -> dict[str, str | int]:
    connection = connect_database(database_path)
    try:
        migrate(connection)
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
        return {
            "integrity_check": integrity,
            "foreign_key_errors": len(foreign_keys),
            "dhcp_events": connection.execute("SELECT COUNT(*) FROM dhcp_events").fetchone()[0],
            "devices": connection.execute("SELECT COUNT(*) FROM devices").fetchone()[0],
        }
    finally:
        connection.close()

