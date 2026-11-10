"""Deny-by-default capability and argument policy.

This module does not import the filesystem walker or the planner. A path can
be inside the sandbox directory and still be out of scope.
"""

from agentlab.actions import Action, parse_action
from agentlab.errors import BoundaryDenied
from agentlab.paths import LIST_ROOTS, READ_ROOTS, WRITE_ROOT


def enforce_scope(action: Action) -> None:
    root = action.parts[0]
    if action.capability == "read_file":
        if root not in READ_ROOTS:
            raise BoundaryDenied("scope_denied", "read is outside the allowed roots")
        return
    if action.capability == "list_dir":
        if root not in LIST_ROOTS:
            raise BoundaryDenied("scope_denied", "list is outside the allowed roots")
        return
    if action.capability == "write_file":
        if len(action.parts) != 2 or root != WRITE_ROOT:
            raise BoundaryDenied("scope_denied", "writes are limited to out/<name>")
        return
    raise BoundaryDenied("unknown_capability", "capability is not allowed")


def vet(raw: object) -> Action:
    """Validate an untrusted action. Does not touch the sandbox."""
    action = parse_action(raw)
    enforce_scope(action)
    return action
