"""Application-level filesystem confinement.

The walk uses the sandbox directory file descriptor, openat (dir_fd), and
O_NOFOLLOW. It also compares the Linux mount id in /proc/self/fdinfo with the
id captured for the sandbox root, so a bind mount is not treated as the same
directory just because the device id matches. It is still not a strong OS
sandbox: there is no separate user, mount namespace, or seccomp filter. See
THREAT_MODEL.md.
"""

import errno
import os
import stat

from agentlab.errors import BoundaryDenied
from agentlab.paths import MAX_BYTES, assert_safe_parts

MAX_LIST = 200


def _map_oserror(exc: OSError) -> BoundaryDenied:
    if isinstance(exc, FileNotFoundError):
        return BoundaryDenied("not_found", "path does not exist")
    if isinstance(exc, NotADirectoryError):
        return BoundaryDenied("not_a_directory", "expected a directory")
    if exc.errno == errno.ELOOP:
        return BoundaryDenied("symlink_denied", "symlink is not followed")
    if exc.errno == errno.EEXIST or isinstance(exc, FileExistsError):
        return BoundaryDenied("already_exists", "destination already exists")
    if isinstance(exc, PermissionError):
        return BoundaryDenied("io_error", "EACCES")
    code = errno.errorcode.get(exc.errno or 0, "EUNKNOWN")
    return BoundaryDenied("io_error", code)


class Sandbox:
    def __init__(self, root: os.PathLike[str] | str) -> None:
        self.root_fd = -1
        if os.path.islink(root):
            raise BoundaryDenied("layout", "sandbox root must not be a symlink")
        try:
            self.root_fd = os.open(
                root,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
        except OSError:
            raise BoundaryDenied("layout", "sandbox root is not a directory") from None
        info = os.fstat(self.root_fd)
        self.root_dev = info.st_dev
        self.root_ino = info.st_ino
        self.root_mount = _mount_id(self.root_fd)

    def close(self) -> None:
        fd = self.root_fd
        self.root_fd = -1
        if fd >= 0:
            os.close(fd)

    def read_file(self, parts: tuple[str, ...]) -> bytes:
        parent, name, owns = self._parent(parts)
        try:
            # Reject special files before open. Opening a FIFO would unblock
            # a waiting writer even though the read is then denied.
            _reject_not_regular(parent, name)
            try:
                fd = os.open(
                    name,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                    dir_fd=parent,
                )
            except OSError as exc:
                raise _map_oserror(exc) from None
            try:
                self._check_file_fd(fd)
                return _read_bounded(fd)
            finally:
                os.close(fd)
        finally:
            _close_owned(parent, owns)

    def delete_if_regular(self, parts: tuple[str, ...]) -> None:
        """Remove a regular file created by this sandbox. Do not follow links.

        The file descriptor's own mount id is compared with the sandbox root.
        The parent directory's mount id is not enough: a file bind mount can
        sit in a directory that is still on the sandbox mount.
        """
        parent, name, owns = self._parent(parts)
        fd = -1
        try:
            try:
                info = os.lstat(name, dir_fd=parent)
            except FileNotFoundError:
                return
            except OSError as exc:
                raise _map_oserror(exc) from None
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                return
            try:
                fd = os.open(
                    name,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=parent,
                )
            except OSError as exc:
                raise _map_oserror(exc) from None
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode):
                return
            self._check_mount(fd)
            os.close(fd)
            fd = -1
            os.unlink(name, dir_fd=parent)
        finally:
            if fd >= 0:
                os.close(fd)
            _close_owned(parent, owns)

    def list_dir(self, parts: tuple[str, ...]) -> list[dict[str, str]]:
        parent, name, owns = self._parent(parts)
        try:
            try:
                fd = self._open_dir(parent, name)
            except BoundaryDenied:
                raise
            try:
                return _list_fd(fd)
            finally:
                os.close(fd)
        finally:
            _close_owned(parent, owns)

    def create_file(self, parts: tuple[str, ...], content: bytes) -> None:
        if type(content) is not bytes or len(content) > MAX_BYTES:
            raise BoundaryDenied("too_large", "content exceeds the write limit")
        parent, name, owns = self._parent(parts)
        fd = -1
        try:
            _reject_existing(parent, name)
            try:
                fd = os.open(
                    name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o644,
                    dir_fd=parent,
                )
            except OSError as exc:
                raise _map_oserror(exc) from None
            try:
                info = os.fstat(fd)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_dev != self.root_dev
                    or info.st_nlink != 1
                ):
                    raise BoundaryDenied("not_a_file", "created object failed confinement checks")
                self._check_mount(fd)
                if stat.S_IMODE(info.st_mode) & 0o111:
                    os.fchmod(fd, stat.S_IMODE(info.st_mode) & ~0o111)
                _write_all(fd, content)
                os.fsync(fd)
            except Exception:
                os.close(fd)
                fd = -1
                try:
                    os.unlink(name, dir_fd=parent)
                except OSError:
                    pass
                raise
            os.close(fd)
            fd = -1
            os.fsync(parent)
        finally:
            if fd >= 0:
                os.close(fd)
            _close_owned(parent, owns)

    def _parent(self, parts: tuple[str, ...]) -> tuple[int, str, bool]:
        assert_safe_parts(parts)
        parent = self.root_fd
        owns = False
        try:
            for name in parts[:-1]:
                opened = self._open_dir(parent, name)
                if owns:
                    os.close(parent)
                parent = opened
                owns = True
            return parent, parts[-1], owns
        except Exception:
            if owns:
                os.close(parent)
            raise

    def _open_dir(self, parent: int, name: str) -> int:
        # A symlink is not a directory. Linux can return ENOTDIR for
        # O_DIRECTORY|O_NOFOLLOW before ELOOP, which would hide the symlink.
        # lstat first so the denial stays symlink_denied. The open below still
        # uses O_NOFOLLOW and does not follow a link planted after the lstat.
        try:
            info = os.lstat(name, dir_fd=parent)
        except OSError as exc:
            raise _map_oserror(exc) from None
        if stat.S_ISLNK(info.st_mode):
            raise BoundaryDenied("symlink_denied", "symlink is not followed")
        if not stat.S_ISDIR(info.st_mode):
            raise BoundaryDenied("not_a_directory", "expected a directory")
        try:
            fd = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=parent,
            )
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise BoundaryDenied("symlink_denied", "symlink is not followed") from None
            raise _map_oserror(exc) from None
        opened = os.fstat(fd)
        if opened.st_dev != self.root_dev:
            os.close(fd)
            raise BoundaryDenied("device_mismatch", "path is on a different device")
        try:
            self._check_mount(fd)
        except BoundaryDenied:
            os.close(fd)
            raise
        if not stat.S_ISDIR(opened.st_mode):
            os.close(fd)
            raise BoundaryDenied("not_a_directory", "expected a directory")
        return fd

    def _check_file_fd(self, fd: int) -> None:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise BoundaryDenied("not_a_file", "only regular files can be read")
        if info.st_dev != self.root_dev:
            raise BoundaryDenied("device_mismatch", "path is on a different device")
        if info.st_nlink != 1:
            raise BoundaryDenied("hardlink_denied", "hard-linked files are denied")
        self._check_mount(fd)
        if info.st_size > MAX_BYTES:
            raise BoundaryDenied("too_large", "file exceeds the read limit")

    def _check_mount(self, fd: int) -> None:
        if _mount_id(fd) != self.root_mount:
            raise BoundaryDenied("mount_mismatch", "path is on a different mount")


def _close_owned(fd: int, owns: bool) -> None:
    if owns and fd >= 0:
        os.close(fd)


def _reject_not_regular(parent: int, name: str) -> None:
    try:
        info = os.lstat(name, dir_fd=parent)
    except OSError as exc:
        raise _map_oserror(exc) from None
    if stat.S_ISLNK(info.st_mode):
        raise BoundaryDenied("symlink_denied", "symlink is not followed")
    if not stat.S_ISREG(info.st_mode):
        raise BoundaryDenied("not_a_file", "only regular files can be read")
    if info.st_nlink != 1:
        raise BoundaryDenied("hardlink_denied", "hard-linked files are denied")


def _read_bounded(fd: int) -> bytes:
    chunks: list[bytes] = []
    remaining = MAX_BYTES + 1
    while remaining > 0:
        chunk = os.read(fd, remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    data = b"".join(chunks)
    if len(data) > MAX_BYTES:
        raise BoundaryDenied("too_large", "file exceeds the read limit")
    return data


def _mount_id(fd: int) -> str:
    """Return the Linux mount id for an open fd, or deny if it cannot be read."""
    if type(fd) is not int or fd < 0:
        raise BoundaryDenied("mount_unknown", "mount id is not available")
    path = f"/proc/self/fdinfo/{fd}"
    try:
        with open(path, encoding="ascii") as handle:
            raw = handle.read()
    except OSError:
        raise BoundaryDenied("mount_unknown", "mount id is not available") from None
    for line in raw.splitlines():
        if line.startswith("mnt_id:"):
            value = line.split(":", 1)[1].strip()
            if value.isdigit():
                return value
    raise BoundaryDenied("mount_unknown", "mount id is not available")


def _list_fd(fd: int) -> list[dict[str, str]]:
    try:
        names = os.listdir(fd)
    except OSError as exc:
        raise _map_oserror(exc) from None
    if len(names) > MAX_LIST:
        raise BoundaryDenied("too_many_entries", "directory listing is too large")
    entries: list[dict[str, str]] = []
    for name in names:
        if type(name) is not str or name in {".", ".."}:
            continue
        try:
            info = os.lstat(name, dir_fd=fd)
        except OSError as exc:
            raise _map_oserror(exc) from None
        if stat.S_ISLNK(info.st_mode):
            kind = "symlink"
        elif stat.S_ISDIR(info.st_mode):
            kind = "dir"
        elif stat.S_ISREG(info.st_mode):
            kind = "file"
        else:
            kind = "other"
        entries.append({"name": name, "kind": kind})
    entries.sort(key=lambda item: item["name"])
    return entries


def _reject_existing(parent: int, name: str) -> None:
    try:
        info = os.lstat(name, dir_fd=parent)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise _map_oserror(exc) from None
    if stat.S_ISLNK(info.st_mode):
        raise BoundaryDenied("symlink_denied", "refusing to replace a symlink")
    raise BoundaryDenied("already_exists", "destination already exists")


def _write_all(fd: int, content: bytes) -> None:
    view = memoryview(content)
    offset = 0
    while offset < len(view):
        written = os.write(fd, view[offset:])
        if written <= 0:
            raise OSError(errno.EIO, "EIO")
        offset += written
