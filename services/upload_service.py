"""Safe streaming upload handling (spec 6.1 / 6.2 / 10.8).

Uploads are written chunk-by-chunk into ``<root>/incoming`` while the
SHA-256 and size are computed; the file is then content-sniffed and moved
to ``<root>/stored`` under a UUID name. User-supplied filenames are never
used as filesystem paths.
"""
from __future__ import annotations

import hashlib
import os
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePath
from typing import AsyncIterator

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",  # microsecond
    b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",  # nanosecond
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
EXTENSION_TYPES = {".csv": {"csv"}, ".pcap": {"pcap", "pcapng"}, ".pcapng": {"pcapng"}}


class UploadError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


@dataclass(frozen=True)
class StoredUpload:
    source_id: str
    original_filename: str
    stored_path: Path
    file_size: int
    file_hash: str
    source_type: str


def safe_display_name(filename: str | None) -> str:
    """Keep only the basename for display/logging; never used as a path."""
    name = PurePath((filename or "").replace("\\", "/")).name.strip()
    name = "".join(ch for ch in name if ch.isprintable())[:255]
    if not name or name in {".", ".."}:
        raise UploadError(400, "missing or invalid filename")
    return name


def sniff_source_type(head: bytes) -> str | None:
    if len(head) >= 4 and head[:4] == PCAPNG_MAGIC:
        return "pcapng"
    if len(head) >= 4 and head[:4] in PCAP_MAGICS:
        return "pcap"
    if b"\x00" in head:
        return None
    try:
        text = head.decode("utf-8-sig")
    except UnicodeDecodeError:
        # A chunk boundary may split a multi-byte character.
        try:
            text = head[:-3].decode("utf-8-sig")
        except UnicodeDecodeError:
            return None
    first_line = text.splitlines()[0] if text.splitlines() else ""
    if "Msg_Type" in first_line and "Client_MAC" in first_line:
        return "csv"
    if first_line.count(",") >= 7:  # headerless legacy monitor CSV
        return "csv"
    return None


class UploadService:
    def __init__(self, root: Path, max_bytes: int):
        self.root = Path(root).resolve()
        self.incoming = self.root / "incoming"
        self.stored = self.root / "stored"
        self.failed = self.root / "failed"
        for directory in (self.incoming, self.stored, self.failed):
            directory.mkdir(parents=True, exist_ok=True)
        self.max_bytes = max_bytes

    async def store(self, filename: str | None, chunks: AsyncIterator[bytes]) -> StoredUpload:
        display = safe_display_name(filename)
        extension = PurePath(display).suffix.lower()
        if extension not in EXTENSION_TYPES:
            raise UploadError(400, "only .pcap, .pcapng and .csv files are accepted")
        source_id = str(uuid.uuid4())
        temp_path = self.incoming / f"{source_id}.part"
        digest = hashlib.sha256()
        size = 0
        head = b""
        try:
            with temp_path.open("xb") as handle:
                async for chunk in chunks:
                    if not chunk:
                        continue
                    size += len(chunk)
                    if size > self.max_bytes:
                        raise UploadError(413, "file exceeds configured size limit")
                    if len(head) < 4096:
                        head += chunk[: 4096 - len(head)]
                    digest.update(chunk)
                    handle.write(chunk)
            if size == 0:
                raise UploadError(400, "empty upload")
            detected = sniff_source_type(head)
            if detected is None or detected not in EXTENSION_TYPES[extension]:
                self._quarantine(temp_path, source_id)
                raise UploadError(400, "file content does not match its extension")
            final_path = self.stored / f"{source_id}{'.pcapng' if detected == 'pcapng' else extension}"
            os.replace(temp_path, final_path)
            return StoredUpload(source_id, display, final_path, size, digest.hexdigest(), detected)
        except BaseException:
            # Interrupted or rejected uploads never leave partial files behind.
            if temp_path.exists():
                temp_path.unlink(missing_ok=True)
            raise

    def _quarantine(self, temp_path: Path, source_id: str) -> None:
        try:
            os.replace(temp_path, self.failed / f"{source_id}.rejected")
        except OSError:
            temp_path.unlink(missing_ok=True)
