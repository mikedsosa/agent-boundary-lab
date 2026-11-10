"""Path syntax for tool arguments.

This is string policy. It does not open files and it is not a sandbox.
"""

import re

from agentlab.errors import BoundaryDenied

MAX_PATH_CHARS = 256
MAX_DEPTH = 8
MAX_COMPONENT = 64
MAX_BYTES = 4096

# Alphanumeric first character, then a short safe set. No dotfiles, no "..".
COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")

READ_ROOTS = frozenset({"inbox", "notes"})
LIST_ROOTS = frozenset({"inbox", "notes", "out"})
WRITE_ROOT = "out"


def split_relative(path: object) -> tuple[str, ...]:
    """Return canonical components or deny the path.

    Traversal, absolute paths, empty components, and odd characters are
    rejected here so later code never joins them onto a root.
    """
    if type(path) is not str:
        raise BoundaryDenied("bad_path", "path must be text")
    if path == "" or len(path) > MAX_PATH_CHARS:
        raise BoundaryDenied("bad_path", "path length is not allowed")
    if "\x00" in path or "\\" in path or path.startswith("/"):
        raise BoundaryDenied("bad_path", "path is not a relative sandbox path")
    parts = path.split("/")
    if len(parts) > MAX_DEPTH:
        raise BoundaryDenied("bad_path", "path depth is not allowed")
    for part in parts:
        if part in (".", ".."):
            raise BoundaryDenied("path_traversal", "path traversal is denied")
        if part == "" or len(part) > MAX_COMPONENT or COMPONENT.fullmatch(part) is None:
            raise BoundaryDenied("bad_path", "path component is not allowed")
    return tuple(parts)


def assert_safe_parts(parts: tuple[str, ...]) -> None:
    """Second check used by the filesystem walk, independent of the caller."""
    if type(parts) is not tuple or not parts or len(parts) > MAX_DEPTH:
        raise BoundaryDenied("bad_path", "path depth is not allowed")
    for part in parts:
        if type(part) is not str or part in (".", ".."):
            raise BoundaryDenied("path_traversal", "path traversal is denied")
        if COMPONENT.fullmatch(part) is None:
            raise BoundaryDenied("bad_path", "path component is not allowed")
