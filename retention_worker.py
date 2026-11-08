from __future__ import annotations

import os

from maintenance import purge_old_events


def main() -> None:
    database_path = os.getenv("DHCP_ANALYZER_DB", os.path.join("data", "dhcp_analyzer.db"))
    event_days = int(os.getenv("DHCP_EVENT_RETENTION_DAYS", "30"))
    deleted = purge_old_events(database_path, event_days=event_days)
    print(f"Deleted {deleted} expired DHCP events")


if __name__ == "__main__":
    main()

