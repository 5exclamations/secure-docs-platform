"""Upload validation: size cap enforced while streaming, content-type allowlist plus magic-byte
sniffing, filename sanitisation."""

from __future__ import annotations

import hashlib
import re
import tempfile
import unicodedata
from dataclasses import dataclass
from typing import IO

from fastapi import HTTPException, UploadFile

OOXML = {
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
}
TEXTUAL = {"text/plain", "text/csv", "application/json", "text/markdown"}
ALLOWED_CONTENT_TYPES = {"application/pdf", "image/png", "image/jpeg"} | OOXML | TEXTUAL

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._ \-()]")


def sanitize_filename(name: str | None) -> str:
    name = unicodedata.normalize("NFKD", name or "").encode("ascii", "ignore").decode()
    name = name.replace("\\", "/").rsplit("/", 1)[-1]  # drop any path component
    name = _SAFE_NAME.sub("_", name).strip(" .")
    name = re.sub(r"\.{2,}", ".", name)
    return (name or "file")[:200]


def _matches_magic(content_type: str, head: bytes) -> bool:
    if content_type == "application/pdf":
        return head.startswith(b"%PDF-")
    if content_type == "image/png":
        return head.startswith(b"\x89PNG\r\n\x1a\n")
    if content_type == "image/jpeg":
        return head.startswith(b"\xff\xd8\xff")
    if content_type in OOXML:
        return head.startswith(b"PK\x03\x04")
    if content_type in TEXTUAL:
        if b"\x00" in head:
            return False
        try:
            head.decode("utf-8")
        except UnicodeDecodeError as exc:
            # a multi-byte char may be cut at the sniff boundary; only tolerate that case
            if exc.start < len(head) - 4:
                return False
        return True
    return False


@dataclass
class StoredUpload:
    file: IO[bytes]
    size: int
    sha256: str
    content_type: str
    filename: str


async def read_upload(upload: UploadFile, max_bytes: int) -> StoredUpload:
    content_type = (upload.content_type or "").split(";")[0].strip().lower()
    if content_type not in ALLOWED_CONTENT_TYPES:
        raise HTTPException(415, f"Content type '{content_type or 'unknown'}' is not allowed")
    spool = tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024)  # noqa: SIM115 - closed by caller
    digest = hashlib.sha256()
    size = 0
    head = b""
    try:
        while chunk := await upload.read(64 * 1024):
            size += len(chunk)
            if size > max_bytes:
                raise HTTPException(413, f"File exceeds the {max_bytes // (1024 * 1024)} MB limit")
            if len(head) < 8192:
                head += chunk[: 8192 - len(head)]
            digest.update(chunk)
            spool.write(chunk)
        if size == 0:
            raise HTTPException(400, "Empty file")
        if not _matches_magic(content_type, head):
            raise HTTPException(415, "File content does not match the declared content type")
    except BaseException:
        spool.close()
        raise
    spool.seek(0)
    return StoredUpload(spool, size, digest.hexdigest(), content_type, sanitize_filename(upload.filename))
