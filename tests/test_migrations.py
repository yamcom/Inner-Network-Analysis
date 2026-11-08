import sqlite3

from database.migrations import migrate


def test_migration_is_repeatable():
    connection = sqlite3.connect(":memory:")
    migrate(connection)
    migrate(connection)
    tables = {
        row[0]
        for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    assert {"analysis_jobs", "dhcp_events", "analysis_stats", "write_batches"} <= tables

