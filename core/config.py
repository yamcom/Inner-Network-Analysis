from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DEFAULTS: dict[str, Any] = {
    "database": {"path": "data/dhcp_analyzer.db"},
    "writer": {"retry_count": 5, "retry_backoff_initial": 0.1, "retry_backoff_max": 2.0, "aging_seconds": 30},
    "upload": {"root": "upload", "max_file_size_mb": 2048, "chunk_size_kb": 1024, "allowed_extensions": ["pcap", "pcapng", "csv"]},
    "runtime": {"max_workers": 1, "max_queued_jobs": 10, "max_in_memory_events": 5000, "max_pending_write_batches": 20, "max_events_per_response": 500},
    "monitor": {"heartbeat_timeout": 15},
}


def _merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    """Load config.yaml merged over safe defaults; missing file -> defaults."""
    config_path = Path(path) if path else PROJECT_ROOT / "config.yaml"
    if not config_path.is_file():
        return copy.deepcopy(DEFAULTS)
    try:
        import yaml
    except ImportError:  # pragma: no cover - yaml ships with uvicorn[standard]
        return copy.deepcopy(DEFAULTS)
    with config_path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValueError("config.yaml must contain a mapping")
    return _merge(DEFAULTS, data)


def project_path(value: str | Path) -> Path:
    """Resolve a configured path and require it to stay inside the project."""
    path = Path(value)
    resolved = (path if path.is_absolute() else PROJECT_ROOT / path).resolve()
    if not resolved.is_relative_to(PROJECT_ROOT):
        raise ValueError(f"path escapes project directory: {value}")
    return resolved
