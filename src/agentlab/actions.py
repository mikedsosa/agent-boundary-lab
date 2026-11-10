"""Parse an untrusted action dict into a value the rest of the boundary can hold.

Parsing checks shape and types. It does not decide scope and it does not open files.
"""

import hashlib
from dataclasses import dataclass

from agentlab.codec import canonical_json
from agentlab.errors import BoundaryDenied
from agentlab.paths import MAX_BYTES, split_relative

CAPABILITIES = {
    "list_dir": frozenset({"path"}),
    "read_file": frozenset({"path"}),
    "write_file": frozenset({"path", "content"}),
}


@dataclass(frozen=True)
class Action:
    capability: str
    path: str
    parts: tuple[str, ...]
    content: str | None
    content_bytes: bytes | None

    def binding(self) -> dict:
        content = self.content_bytes
        return {
            "v": 1,
            "capability": self.capability,
            "path": self.path,
            "content_sha256": "" if content is None else hashlib.sha256(content).hexdigest(),
            "content_len": 0 if content is None else len(content),
        }

    def digest(self) -> str:
        return hashlib.sha256(canonical_json(self.binding())).hexdigest()


def parse_action(raw: object) -> Action:
    if type(raw) is not dict:
        raise BoundaryDenied("malformed", "action must be an object")
    if set(raw) != {"capability", "args"}:
        raise BoundaryDenied("malformed", "action fields are not exact")
    capability = raw["capability"]
    args = raw["args"]
    if type(capability) is not str or type(args) is not dict:
        raise BoundaryDenied("malformed", "action fields have the wrong type")
    expected = CAPABILITIES.get(capability)
    if expected is None:
        raise BoundaryDenied("unknown_capability", "capability is not allowed")
    if set(args) != expected:
        raise BoundaryDenied("bad_args", "arguments do not match the capability")
    parts = split_relative(args["path"])
    path = "/".join(parts)
    content: str | None = None
    content_bytes: bytes | None = None
    if capability == "write_file":
        content = args["content"]
        if type(content) is not str:
            raise BoundaryDenied("bad_args", "content must be text")
        if "\x00" in content:
            raise BoundaryDenied("bad_args", "content contains NUL")
        content_bytes = content.encode("utf-8")
        if len(content_bytes) > MAX_BYTES:
            raise BoundaryDenied("too_large", "content exceeds the write limit")
    return Action(capability, path, parts, content, content_bytes)
