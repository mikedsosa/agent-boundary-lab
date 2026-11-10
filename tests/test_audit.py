import json
from pathlib import Path

from agentlab.audit import GENESIS, AuditLog, verify
from agentlab.demo_runner import run_demo


def _event(outcome: str = "deny") -> dict:
    return {
        "ts": 10,
        "outcome": outcome,
        "reason": "ok" if outcome == "allow" else "scope_denied",
        "detail": "recorded",
        "capability": "read_file",
        "path": "private/token.txt",
        "content_sha256": "",
        "content_len": 0,
    }


def test_chain_detects_edits_and_truncation(tmp_path: Path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append(_event("deny"))
    log.append(_event("allow"))
    assert verify(log.path) == (True, "ok")
    raw = log.path.read_bytes()
    flipped = bytearray(raw)
    flipped[20] = flipped[20] ^ 1
    log.path.write_bytes(bytes(flipped))
    ok, reason = verify(log.path)
    assert ok is False
    assert reason != "ok"
    log.path.write_bytes(raw)
    assert verify(log.path)[0] is True
    lines = raw.splitlines()
    log.path.write_bytes(lines[0] + b"\n")
    assert verify(log.path)[0] is False
    log.path.write_bytes(raw)
    log.tip_path.write_text(GENESIS + "\n", encoding="ascii")
    assert verify(log.path) == (False, "tip mismatch")


def test_rewritten_chain_and_tip_verify_locally(tmp_path: Path):
    """Local verify has no external witness.

    A caller who can replace both the log and the tip can build a new chain
    that verifies. This test records that limit. It is not a claim that the
    agent tools can write the audit files.
    """
    forged = AuditLog(tmp_path / "forged.jsonl")
    forged.append(
        {
            "ts": 1,
            "outcome": "allow",
            "reason": "ok",
            "detail": "rewritten",
            "capability": "write_file",
            "path": "out/summary.txt",
            "content_sha256": "ab" * 32,
            "content_len": 1,
        }
    )
    assert verify(forged.path) == (True, "ok")


def test_audit_failure_does_not_leave_the_new_file(tmp_path: Path):
    from agentlab.approval import issue_token
    from agentlab.policy import vet
    from agentlab.workspace import open_lab, prepare_workspace

    base = tmp_path / "ws"
    prepare_workspace(base)
    lab = open_lab(base)
    try:
        action = {
            "capability": "write_file",
            "args": {"path": "out/summary.txt", "content": "kept\n"},
        }
        token = issue_token(lab.key, vet(action), now=1_700_000_000, ttl=30)

        def fail(event: dict) -> str:
            raise OSError("audit append failed")

        lab.executor.audit.append = fail
        result = lab.executor.execute(action, approval_token=token, now=1_700_000_000)
        dest = base / "sandbox" / "out" / "summary.txt"
        assert result.outcome == "error"
        assert result.reason == "audit_failed"
        assert dest.exists() is False
    finally:
        lab.close()


def test_audit_rollback_failure_is_reported(tmp_path: Path, monkeypatch):
    import errno
    import os

    from agentlab.approval import issue_token
    from agentlab.policy import vet
    from agentlab.workspace import open_lab, prepare_workspace

    base = tmp_path / "ws"
    prepare_workspace(base)
    lab = open_lab(base)
    try:
        action = {
            "capability": "write_file",
            "args": {"path": "out/summary.txt", "content": "kept\n"},
        }
        token = issue_token(lab.key, vet(action), now=1_700_000_000, ttl=30)

        def fail_append(event: dict) -> str:
            raise OSError("audit append failed")

        def fail_unlink(*args, **kwargs):
            raise OSError(errno.EPERM, "EPERM")

        monkeypatch.setattr(lab.executor.audit, "append", fail_append)
        monkeypatch.setattr(os, "unlink", fail_unlink)
        result = lab.executor.execute(action, approval_token=token, now=1_700_000_000)
        dest = base / "sandbox" / "out" / "summary.txt"
        assert result.outcome == "error"
        assert result.reason == "audit_failed_rollback_failed"
        assert result.detail == "PermissionError"
        assert dest.is_file()
        assert dest.read_text(encoding="utf-8") == "kept\n"
    finally:
        lab.close()


def test_demo_audit_verifies_and_omits_fixture_bodies(tmp_path: Path):
    base = tmp_path / "ws"
    text, code = run_demo(base)
    assert code == 0
    assert verify(base / "audit" / "audit.jsonl") == (True, "ok")
    audit = (base / "audit" / "audit.jsonl").read_text(encoding="utf-8")
    assert "INJECTION-MARKER-do-not-log-9c2e" not in audit
    assert "synthetic-example-token-not-a-real-credential-7f3a" not in audit
    assert "Synthetic schedule" not in audit
    assert "synthetic-outside-marker-4b1d" not in audit
    assert json.loads(audit.splitlines()[0])["prev"] == "0" * 64
    assert "Synthetic schedule" in text
    assert "INJECTION-MARKER-do-not-log-9c2e" not in text
