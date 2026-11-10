"""Append-only audit hash chain.

Each line is metadata. The chain detects edits and truncation if the tip file
is still the one this process wrote. It does not detect a full rewrite of both
the log and the tip. There is no external witness.
"""

import errno
import fcntl
import hashlib
import hmac
import json
import os
import re
from pathlib import Path

from agentlab.codec import canonical_json
from agentlab.errors import BoundaryDenied

GENESIS = "0" * 64
AUDIT_FIELDS = (
    "ts",
    "outcome",
    "reason",
    "detail",
    "capability",
    "path",
    "content_sha256",
    "content_len",
)
_HASH = re.compile(r"[0-9a-f]{64}")
_STRING_FIELDS = ("outcome", "reason", "detail", "capability", "path", "content_sha256")


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.tip_path = Path(str(path) + ".tip")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        for candidate in (self.path, self.tip_path):
            if candidate.is_symlink():
                raise BoundaryDenied("layout", "audit path must not be a symlink")
        if not self.path.exists():
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
        if not self.tip_path.exists():
            _write_tip(self.tip_path, GENESIS)
        os.chmod(self.path, 0o600)
        os.chmod(self.tip_path, 0o600)

    def append(self, event: dict) -> str:
        _validate_event(event)
        fd = os.open(self.path, os.O_RDWR | os.O_NOFOLLOW)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            previous = _read_tip(self.tip_path)
            body = {**event, "prev": previous}
            record_hash = hashlib.sha256(canonical_json(body)).hexdigest()
            line = canonical_json({**body, "hash": record_hash}) + b"\n"
            os.lseek(fd, 0, os.SEEK_END)
            _write_full(fd, line)
            os.fsync(fd)
            _write_tip(self.tip_path, record_hash)
            return record_hash
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)


def verify(path: Path, tip_path: Path | None = None) -> tuple[bool, str]:
    path = Path(path)
    tip_path = Path(str(path) + ".tip") if tip_path is None else Path(tip_path)
    try:
        raw = path.read_bytes()
        tip = tip_path.read_text(encoding="ascii").strip()
    except OSError:
        return False, "unreadable"
    if not _HASH.fullmatch(tip):
        return False, "bad tip"
    if b"\r" in raw:
        return False, "carriage return"
    previous = GENESIS
    if raw == b"":
        if hmac.compare_digest(tip, GENESIS):
            return True, "ok"
        return False, "tip mismatch"
    if not raw.endswith(b"\n"):
        return False, "missing newline"
    lines = raw.split(b"\n")[:-1]
    for index, line in enumerate(lines, start=1):
        if line == b"":
            return False, f"bad line {index}"
        try:
            parsed = json.loads(line.decode("ascii"))
        except (UnicodeError, json.JSONDecodeError):
            return False, f"bad line {index}"
        if type(parsed) is not dict or "hash" not in parsed or "prev" not in parsed:
            return False, f"bad line {index}"
        declared = parsed.pop("hash")
        if type(declared) is not str or not _HASH.fullmatch(declared):
            return False, f"bad hash {index}"
        if parsed.get("prev") != previous:
            return False, f"chain break {index}"
        calculated = hashlib.sha256(canonical_json(parsed)).hexdigest()
        if not hmac.compare_digest(calculated, declared):
            return False, f"hash mismatch {index}"
        previous = declared
    if not hmac.compare_digest(previous, tip):
        return False, "tip mismatch"
    return True, "ok"


def _validate_event(event: dict) -> None:
    if type(event) is not dict or set(event) != set(AUDIT_FIELDS):
        raise RuntimeError("audit event fields are not exact")
    if type(event["ts"]) is not int or type(event["content_len"]) is not int:
        raise RuntimeError("audit integers are wrong")
    if event["ts"] < 0 or event["content_len"] < 0:
        raise RuntimeError("audit integers are wrong")
    for key in _STRING_FIELDS:
        value = event[key]
        if type(value) is not str or len(value) > 300 or "\n" in value or "\r" in value:
            raise RuntimeError("audit strings are wrong")
    if len(event["detail"]) > 200:
        raise RuntimeError("audit detail is too long")


def _read_tip(path: Path) -> str:
    text = path.read_text(encoding="ascii").strip()
    if not _HASH.fullmatch(text):
        raise RuntimeError("audit tip is unusable")
    return text


def _write_tip(path: Path, digest: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        _write_full(fd, (digest + "\n").encode("ascii"))
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_full(fd: int, data: bytes) -> None:
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        written = os.write(fd, view[offset:])
        if written <= 0:
            raise OSError(errno.EIO, "EIO")
        offset += written
