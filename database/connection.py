from __future__ import annotations

import sqlite3
from pathlib import Path


def connect_database(path: str | Path) -> sqlite3.Connection:
    db_path = Path(path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path, timeout=10.0)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=NORMAL")
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=10000")
    connection.execute("PRAGMA cache_size=-32768")
    connection.execute("PRAGMA temp_store=MEMORY")
    return connection


def connect_readonly_database(path: str | Path) -> sqlite3.Connection:
    """Open a WAL-safe read-only connection for web/API queries."""
    db_path = Path(path).resolve()
    connection = sqlite3.connect(
        f"file:{db_path.as_posix()}?mode=ro", uri=True, timeout=2.0
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    connection.execute("PRAGMA busy_timeout=2000")
    connection.execute("PRAGMA cache_size=-16384")
    connection.execute("PRAGMA temp_store=MEMORY")
    return connection

