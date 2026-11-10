"""Sequence policy, approval, confinement, and audit.

The planner is not imported here. Approval text inside an action or a fixture
is not an approval. `approval_token` is a separate operator input.
"""

import hashlib
import time
from dataclasses import dataclass

from agentlab.actions import Action, parse_action
from agentlab.approval import NonceStore, authorize
from agentlab.audit import AuditLog
from agentlab.errors import BoundaryDenied
from agentlab.fs import Sandbox
from agentlab.policy import enforce_scope

OUTCOMES = frozenset({"allow", "deny", "needs_approval", "error"})


@dataclass(frozen=True)
class Result:
    outcome: str
    reason: str
    detail: str
    data: dict | None = None


class Executor:
    def __init__(self, sandbox: Sandbox, audit: AuditLog, nonces: NonceStore, key: bytes) -> None:
        self.sandbox = sandbox
        self.audit = audit
        self.nonces = nonces
        self.key = key

    def close(self) -> None:
        self.sandbox.close()

    def execute(
        self,
        raw: object,
        *,
        approval_token: str | None = None,
        now: int | None = None,
    ) -> Result:
        if now is None:
            now = int(time.time())
        if type(now) is not int or now < 0:
            return self._commit(
                "deny",
                "malformed",
                "clock must be a positive integer",
                None,
                None,
                0,
            )
        action: Action | None = None
        try:
            if approval_token is not None and type(approval_token) is not str:
                return self._commit(
                    "deny",
                    "approval_malformed",
                    "approval token must be text",
                    None,
                    None,
                    now,
                )
            action = parse_action(raw)
            enforce_scope(action)
            if action.capability == "write_file":
                return self._execute_write(action, approval_token, now)
            if approval_token is not None:
                return self._commit(
                    "deny",
                    "approval_not_applicable",
                    "this capability does not accept an approval token",
                    action,
                    None,
                    now,
                )
            if action.capability == "read_file":
                return self._execute_read(action, now)
            if action.capability == "list_dir":
                return self._execute_list(action, now)
            return self._commit(
                "deny",
                "unknown_capability",
                "capability is not allowed",
                action,
                None,
                now,
            )
        except BoundaryDenied as exc:
            return self._commit("deny", exc.reason, exc.detail, action, None, now)
        except Exception as exc:
            return self._commit("error", "internal_error", type(exc).__name__, action, None, now)

    def _execute_read(self, action: Action, now: int) -> Result:
        data = self.sandbox.read_file(action.parts)
        if b"\x00" in data:
            raise BoundaryDenied("not_text", "file contains NUL")
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            raise BoundaryDenied("not_text", "file is not utf-8 text") from None
        return self._commit(
            "allow",
            "ok",
            "read completed",
            action,
            {"text": text, "content_len": len(data)},
            now,
            content_sha256=hashlib.sha256(data).hexdigest(),
            content_len=len(data),
        )

    def _execute_list(self, action: Action, now: int) -> Result:
        entries = self.sandbox.list_dir(action.parts)
        return self._commit(
            "allow",
            "ok",
            "list completed",
            action,
            {"entries": entries},
            now,
        )

    def _execute_write(self, action: Action, token: str | None, now: int) -> Result:
        if token is None:
            return self._commit(
                "needs_approval",
                "approval_required",
                "write is staged until this exact action is approved",
                action,
                {"digest": action.digest()},
                now,
            )
        # Consume the nonce before the create so a failed write cannot be retried
        # with the same token. This does not create or modify the destination.
        authorize(self.key, self.nonces, token, action, now)
        if action.content_bytes is None:
            raise BoundaryDenied("bad_args", "content must be text")
        self.sandbox.create_file(action.parts, action.content_bytes)
        committed = self._commit(
            "allow",
            "ok",
            "write created",
            action,
            {"path": action.path, "content_len": len(action.content_bytes)},
            now,
        )
        if committed.reason == "audit_failed":
            # The allow record was not written. Remove the file so a failed
            # audit does not leave an unlogged side effect. A failed removal
            # is a different result: the file may still be there.
            try:
                self.sandbox.delete_if_regular(action.parts)
            except Exception as exc:
                return Result(
                    "error",
                    "audit_failed_rollback_failed",
                    type(exc).__name__,
                    None,
                )
        return committed

    def _commit(
        self,
        outcome: str,
        reason: str,
        detail: str,
        action: Action | None,
        data: dict | None,
        now: int,
        *,
        content_sha256: str | None = None,
        content_len: int | None = None,
    ) -> Result:
        if outcome not in OUTCOMES:
            return Result("error", "audit_failed", "audit log was not updated", None)
        try:
            if action is None:
                capability = ""
                path = ""
                bound_hash = ""
                bound_len = 0
            else:
                binding = action.binding()
                capability = action.capability
                path = action.path
                bound_hash = binding["content_sha256"]
                bound_len = binding["content_len"]
            event = {
                "ts": now,
                "outcome": outcome,
                "reason": reason,
                "detail": detail,
                "capability": capability,
                "path": path,
                "content_sha256": bound_hash if content_sha256 is None else content_sha256,
                "content_len": bound_len if content_len is None else content_len,
            }
            self.audit.append(event)
        except Exception:
            return Result("error", "audit_failed", "audit log was not updated", None)
        return Result(outcome, reason, detail, data)
