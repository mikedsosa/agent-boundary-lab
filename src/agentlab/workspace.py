"""Create a local workspace and open the trusted boundary around it.

Layout (all under the workspace directory the operator chose):

    sandbox/     tool-visible tree, including untrusted fixtures
    outside/     not inside the sandbox; symlink and hard-link target
    operator/    approval key and nonce store (mode 0700 directory)
    audit/       hash-chained log

Agent capabilities are not given paths in operator/ or audit/. That is an
API choice enforced by scope checks and by which functions exist. It is not
a separate OS user.
"""

import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from agentlab.approval import NonceStore, load_key
from agentlab.audit import AuditLog
from agentlab.errors import BoundaryDenied
from agentlab.executor import Executor
from agentlab.fs import Sandbox

FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures"
FIXTURE_FILES = (
    "inbox/status.txt",
    "inbox/message.txt",
    "inbox/nested/readme.txt",
    "notes/schedule.txt",
    "private/token.txt",
)
OUTSIDE_TEXT = "synthetic-outside-marker-4b1d\n"


@dataclass
class Lab:
    base: Path
    executor: Executor
    key: bytes

    def close(self) -> None:
        self.executor.close()

    def __enter__(self) -> "Lab":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def assert_safe_workspace(base: Path) -> None:
    if base.is_symlink():
        raise BoundaryDenied("layout", "workspace path must not be a symlink")
    resolved = base.resolve()
    if resolved == Path("/") or resolved.parent == Path("/"):
        raise BoundaryDenied("layout", "refusing to prepare this workspace path")


def prepare_workspace(base: Path) -> None:
    base = Path(base)
    assert_safe_workspace(base)
    if base.exists():
        shutil.rmtree(base)
    sandbox = base / "sandbox"
    sandbox.mkdir(parents=True)
    for relative in FIXTURE_FILES:
        source = FIXTURE_ROOT / relative
        if source.is_symlink() or not source.is_file():
            raise BoundaryDenied("layout", "fixture must be a regular file")
        data = source.read_bytes()
        if b"\x00" in data or len(data) > 4096:
            raise BoundaryDenied("layout", "fixture is not usable")
        destination = sandbox / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        _write_new(destination, data)
    outside = base / "outside"
    outside.mkdir()
    outside_note = outside / "note.txt"
    _write_new(outside_note, OUTSIDE_TEXT.encode("ascii"))
    os.symlink("../../outside/note.txt", sandbox / "inbox" / "escape-link")
    os.symlink("../../outside", sandbox / "inbox" / "dir-link")
    os.link(outside_note, sandbox / "inbox" / "hardlinked.txt")
    (sandbox / "out").mkdir()
    operator = base / "operator"
    operator.mkdir()
    os.chmod(operator, 0o700)
    (base / "audit").mkdir()


def open_lab(base: Path) -> Lab:
    base = Path(base)
    sandbox = base / "sandbox"
    operator = base / "operator"
    audit_path = base / "audit" / "audit.jsonl"
    if sandbox.is_symlink() or operator.is_symlink() or audit_path.is_symlink():
        raise BoundaryDenied("layout", "workspace control paths must not be symlinks")
    if _inside(sandbox, operator) or _inside(sandbox, audit_path.parent):
        raise BoundaryDenied("layout", "control files must sit outside the sandbox")
    key = load_key(operator / "approval.key", create=True)
    executor = Executor(
        Sandbox(sandbox),
        AuditLog(audit_path),
        NonceStore(operator / "nonces.txt"),
        key,
    )
    return Lab(base, executor, key)


def _inside(parent: Path, child: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True


def _write_new(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
