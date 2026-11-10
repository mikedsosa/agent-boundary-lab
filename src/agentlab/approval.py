"""Operator approval tokens.

A token is an HMAC over a canonical body. The body names the digest of one
exact action, a nonce, and an expiry. The planner cannot produce a valid
token unless it has the operator key. The key is not a sandbox file.

`verify_token` does not record use. `authorize` is the function the executor
calls: it verifies, then consumes the nonce so the token cannot be replayed.
"""

import base64
import errno
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
from pathlib import Path

from agentlab.actions import Action
from agentlab.codec import canonical_json
from agentlab.errors import BoundaryDenied

MAX_TTL_SECONDS = 3600
MAX_TOKEN_CHARS = 4096
_NONCE = re.compile(r"[0-9a-f]{32}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_TOKEN_KEYS = frozenset({"v", "digest", "nonce", "iat", "exp"})


def load_key(path: Path, *, create: bool) -> bytes:
    path = Path(path)
    if path.is_symlink():
        raise BoundaryDenied("key_permissions", "approval key path must not be a symlink")
    if path.exists():
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            raise BoundaryDenied(
                "key_permissions",
                "approval key must not be group or world accessible",
            )
        data = path.read_bytes()
        if len(data) != 32:
            raise BoundaryDenied("key_invalid", "approval key must be 32 bytes")
        return data
    if not create:
        raise BoundaryDenied("key_invalid", "approval key is missing")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink():
        raise BoundaryDenied("key_permissions", "approval key directory must not be a symlink")
    os.chmod(path.parent, 0o700)
    data = secrets.token_bytes(32)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(str(path), flags, 0o600)
    try:
        _write_full(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(path, 0o600)
    return data


def issue_token(key: bytes, action: Action, *, now: int, ttl: int) -> str:
    _require_key(key)
    _require_int(now, "iat")
    if type(ttl) is not int or ttl < 1 or ttl > MAX_TTL_SECONDS:
        raise BoundaryDenied("approval_ttl", "ttl is not allowed")
    body = {
        "v": 1,
        "digest": action.digest(),
        "nonce": secrets.token_hex(16),
        "iat": now,
        "exp": now + ttl,
    }
    raw = canonical_json(body)
    signature = hmac.new(key, raw, hashlib.sha256).digest()
    return _b64(raw) + "." + _b64(signature)


def verify_token(key: bytes, token: object, action: Action, now: int) -> str:
    """Return the nonce if the token is authentic for this exact action.

    Does not consume the nonce. Callers that perform a side effect must use
    `authorize` so replay protection cannot be skipped.
    """
    _require_key(key)
    _require_int(now, "now")
    raw = _authenticated_body(key, token)
    try:
        parsed = json.loads(raw.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError):
        raise BoundaryDenied("approval_malformed", "approval body is not JSON") from None
    if type(parsed) is not dict or canonical_json(parsed) != raw:
        raise BoundaryDenied("approval_malformed", "approval body is not canonical")
    if set(parsed) != _TOKEN_KEYS:
        raise BoundaryDenied("approval_malformed", "approval fields are not exact")
    if parsed["v"] != 1:
        raise BoundaryDenied("approval_malformed", "approval version is not allowed")
    digest = parsed["digest"]
    nonce = parsed["nonce"]
    iat = parsed["iat"]
    exp = parsed["exp"]
    if type(digest) is not str or _DIGEST.fullmatch(digest) is None:
        raise BoundaryDenied("approval_malformed", "approval digest is not allowed")
    if type(nonce) is not str or _NONCE.fullmatch(nonce) is None:
        raise BoundaryDenied("approval_malformed", "approval nonce is not allowed")
    _require_int(iat, "iat")
    _require_int(exp, "exp")
    if not hmac.compare_digest(digest, action.digest()):
        raise BoundaryDenied("approval_mismatch", "approval is not for this exact action")
    if exp <= iat or exp - iat > MAX_TTL_SECONDS:
        raise BoundaryDenied("approval_ttl", "approval window is not allowed")
    if iat > now:
        raise BoundaryDenied("approval_not_yet_valid", "approval is not yet valid")
    if now >= exp:
        raise BoundaryDenied("approval_expired", "approval has expired")
    return nonce


def authorize(key: bytes, store: "NonceStore", token: object, action: Action, now: int) -> None:
    nonce = verify_token(key, token, action, now)
    store.consume(nonce)


class NonceStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        if self.path.is_symlink():
            raise BoundaryDenied("layout", "nonce store must not be a symlink")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
        os.chmod(self.path, 0o600)

    def consume(self, nonce: str) -> None:
        if _NONCE.fullmatch(nonce) is None:
            raise BoundaryDenied("approval_malformed", "approval nonce is not allowed")
        fd = os.open(self.path, os.O_RDWR | os.O_NOFOLLOW)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            os.fchmod(fd, 0o600)
            raw = _read_capped(fd, 10_000_000)
            existing = raw.decode("ascii").split()
            if nonce in existing:
                raise BoundaryDenied("approval_replay", "approval nonce was already used")
            if len(existing) > 100_000:
                raise BoundaryDenied("nonce_store_full", "nonce store is full")
            os.lseek(fd, 0, os.SEEK_END)
            _write_full(fd, (nonce + "\n").encode("ascii"))
            os.fsync(fd)
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)


def _authenticated_body(key: bytes, token: object) -> bytes:
    if type(token) is not str or token == "" or len(token) > MAX_TOKEN_CHARS:
        raise BoundaryDenied("approval_malformed", "approval token is not usable")
    parts = token.split(".")
    if len(parts) != 2 or parts[0] == "" or parts[1] == "":
        raise BoundaryDenied("approval_malformed", "approval token is not usable")
    try:
        raw = _unb64(parts[0])
        signature = _unb64(parts[1])
    except (ValueError, UnicodeError):
        raise BoundaryDenied("approval_malformed", "approval token is not usable") from None
    if len(raw) > MAX_TOKEN_CHARS or len(signature) != 32:
        raise BoundaryDenied("approval_malformed", "approval token is not usable")
    expected = hmac.new(key, raw, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, signature):
        raise BoundaryDenied("approval_bad_signature", "approval signature is not valid")
    return raw


def _require_key(key: bytes) -> None:
    if type(key) is not bytes or len(key) != 32:
        raise BoundaryDenied("key_invalid", "approval key must be 32 bytes")


def _require_int(value: object, name: str) -> None:
    if type(value) is not int:
        raise BoundaryDenied("approval_malformed", f"{name} is not an integer")


def _read_capped(fd: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        size += len(chunk)
        if size > limit:
            raise BoundaryDenied("nonce_store_full", "nonce store is full")
        chunks.append(chunk)
    return b"".join(chunks)


def _write_full(fd: int, data: bytes) -> None:
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        written = os.write(fd, view[offset:])
        if written <= 0:
            raise OSError(errno.EIO, "EIO")
        offset += written


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    # urlsafe_b64decode does not accept validate=. Check the alphabet, then
    # decode the standard alphabet with validate=True.
    if re.fullmatch(r"[A-Za-z0-9_\-]+=*", text) is None:
        raise ValueError("bad alphabet")
    standard = text.replace("-", "+").replace("_", "/")
    return base64.b64decode(standard.encode("ascii"), validate=True)
