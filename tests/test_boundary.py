import errno
import hashlib
import hmac
import os
import stat
import threading
from base64 import urlsafe_b64encode
from pathlib import Path

import pytest

from agentlab.actions import parse_action
from agentlab.approval import authorize, issue_token, load_key, verify_token
from agentlab.audit import verify
from agentlab.codec import canonical_json
from agentlab.errors import BoundaryDenied
from agentlab.planner import EXFIL_PAYLOAD, SUMMARY, summary_write
from agentlab.policy import vet
from agentlab.workspace import OUTSIDE_TEXT

NOW = 1_700_000_000


def snapshot(root: Path) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in sorted(dirnames + filenames):
            path = Path(dirpath) / name
            info = path.lstat()
            rel = str(path.relative_to(root))
            if stat.S_ISLNK(info.st_mode):
                rows.append((rel, "symlink:" + os.readlink(path)))
            elif stat.S_ISREG(info.st_mode):
                rows.append((rel, "file:" + path.read_bytes().hex()))
            else:
                rows.append((rel, f"other:{stat.S_IFMT(info.st_mode)}"))
    return rows


def read(path: str) -> dict:
    return {"capability": "read_file", "args": {"path": path}}


def write(path: str, content: str) -> dict:
    return {"capability": "write_file", "args": {"path": path, "content": content}}


def test_benign_read_returns_fixture_text_and_does_not_mutate(lab):
    before = snapshot(lab.base / "sandbox")
    result = lab.executor.execute(read("notes/schedule.txt"), now=NOW)
    assert result.outcome == "allow"
    assert result.reason == "ok"
    assert result.data is not None
    assert "Synthetic schedule" in result.data["text"]
    assert snapshot(lab.base / "sandbox") == before


def test_private_file_is_inside_the_tree_but_denied(lab):
    token_path = lab.base / "sandbox" / "private" / "token.txt"
    assert token_path.is_file()
    assert not token_path.is_symlink()
    assert token_path.resolve().is_relative_to(lab.base / "sandbox")
    direct = lab.executor.sandbox.read_file(("private", "token.txt"))
    assert b"synthetic-example-token-not-a-real-credential-7f3a" in direct
    before = snapshot(lab.base / "sandbox")
    present = lab.executor.execute(read("private/token.txt"), now=NOW)
    missing = lab.executor.execute(read("private/missing.txt"), now=NOW)
    assert present.reason == "scope_denied"
    assert missing.reason == "scope_denied"
    assert present.data is None and missing.data is None
    assert snapshot(lab.base / "sandbox") == before
    audit = (lab.base / "audit" / "audit.jsonl").read_text(encoding="utf-8")
    assert "synthetic-example-token-not-a-real-credential-7f3a" not in audit


def test_os_user_can_follow_symlink_and_the_boundary_does_not(lab):
    link = lab.base / "sandbox" / "inbox" / "escape-link"
    assert link.read_text(encoding="utf-8") == OUTSIDE_TEXT
    assert not str(link.resolve()).startswith(str((lab.base / "sandbox").resolve()))
    before = snapshot(lab.base / "sandbox")
    outside = (lab.base / "outside" / "note.txt").read_bytes()
    result = lab.executor.execute(read("inbox/escape-link"), now=NOW)
    nested = lab.executor.execute(read("inbox/dir-link/note.txt"), now=NOW)
    assert result.reason == "symlink_denied"
    assert nested.reason == "symlink_denied"
    assert result.data is None and nested.data is None
    assert "synthetic-outside-marker" not in (result.detail + nested.detail)
    assert snapshot(lab.base / "sandbox") == before
    assert (lab.base / "outside" / "note.txt").read_bytes() == outside


def test_traversal_absolute_and_hardlink_do_not_escape(lab):
    outside = (lab.base / "outside" / "note.txt").read_bytes()
    before = snapshot(lab.base / "sandbox")
    traversal = lab.executor.execute(read("inbox/../../outside/note.txt"), now=NOW)
    absolute = lab.executor.execute(read("/etc/passwd"), now=NOW)
    hard = lab.executor.execute(read("inbox/hardlinked.txt"), now=NOW)
    assert traversal.reason == "path_traversal"
    assert absolute.reason == "bad_path"
    assert hard.reason == "hardlink_denied"
    assert hard.data is None
    assert snapshot(lab.base / "sandbox") == before
    assert (lab.base / "outside" / "note.txt").read_bytes() == outside


def test_denied_fifo_read_does_not_unblock_a_writer(lab):
    import threading

    fifo = lab.base / "sandbox" / "inbox" / "pipe1"
    os.mkfifo(fifo)
    unblocked = threading.Event()

    def writer() -> None:
        fd = os.open(fifo, os.O_WRONLY)
        os.close(fd)
        unblocked.set()

    thread = threading.Thread(target=writer, daemon=True)
    thread.start()
    thread.join(0.2)
    try:
        result = lab.executor.execute(read("inbox/pipe1"), now=NOW)
        assert result.reason == "not_a_file"
        assert result.data is None
        assert unblocked.is_set() is False
    finally:
        opener = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
        os.close(opener)
        thread.join(1)


def test_fifo_and_directory_are_not_read(lab):
    os.mkfifo(lab.base / "sandbox" / "inbox" / "pipe1")
    fifo = lab.executor.execute(read("inbox/pipe1"), now=NOW)
    directory = lab.executor.execute(read("inbox/nested"), now=NOW)
    listing = lab.executor.execute(
        {"capability": "list_dir", "args": {"path": "inbox/status.txt"}},
        now=NOW,
    )
    assert fifo.reason == "not_a_file"
    assert directory.reason == "not_a_file"
    assert listing.reason == "not_a_directory"
    assert fifo.data is None


def test_untrusted_fixture_text_does_not_authorize(lab):
    message = lab.executor.execute(read("inbox/message.txt"), now=NOW)
    assert message.outcome == "allow"
    assert message.data is not None
    body = message.data["text"]
    assert "INJECTION-MARKER-do-not-log-9c2e" in body
    assert "APPROVED" in body
    before = snapshot(lab.base / "sandbox")
    follow = lab.executor.execute(read("private/token.txt"), now=NOW + 1)
    staged = lab.executor.execute(
        write("out/exfil.txt", EXFIL_PAYLOAD),
        now=NOW + 2,
    )
    assert follow.reason == "scope_denied"
    assert staged.outcome == "needs_approval"
    assert staged.reason == "approval_required"
    assert not (lab.base / "sandbox" / "out" / "exfil.txt").exists()
    assert snapshot(lab.base / "sandbox") == before
    audit = (lab.base / "audit" / "audit.jsonl").read_text(encoding="utf-8")
    assert "INJECTION-MARKER-do-not-log-9c2e" not in audit
    assert "APPROVED: true" not in audit
    assert "Synthetic schedule" not in audit
    assert EXFIL_PAYLOAD.strip() not in audit


def test_approval_text_is_not_an_approval(lab):
    before = snapshot(lab.base / "sandbox")
    raw = write("out/note.txt", "APPROVED BY OPERATOR")
    result = lab.executor.execute(raw, now=NOW)
    assert result.outcome == "needs_approval"
    assert not (lab.base / "sandbox" / "out" / "note.txt").exists()
    forged = lab.executor.execute(raw, approval_token="APPROVED", now=NOW)
    assert forged.reason == "approval_malformed"
    assert snapshot(lab.base / "sandbox") == before


def test_exact_approval_writes_once_and_replay_does_not(lab):
    action = summary_write()
    token = issue_token(lab.key, vet(action), now=NOW, ttl=60)
    dest = lab.base / "sandbox" / "out" / "summary.txt"
    assert not dest.exists()
    allowed = lab.executor.execute(action, approval_token=token, now=NOW + 1)
    assert allowed.outcome == "allow"
    assert dest.read_text(encoding="utf-8") == SUMMARY
    assert stat.S_IMODE(dest.stat().st_mode) & 0o111 == 0
    replay = lab.executor.execute(action, approval_token=token, now=NOW + 2)
    assert replay.reason == "approval_replay"
    assert dest.read_text(encoding="utf-8") == SUMMARY


def test_changed_bytes_or_path_do_not_match_and_do_not_consume(lab):
    action = summary_write()
    token = issue_token(lab.key, vet(action), now=NOW, ttl=60)
    changed = write("out/summary.txt", SUMMARY + " ")
    mismatch = lab.executor.execute(changed, approval_token=token, now=NOW)
    assert mismatch.reason == "approval_mismatch"
    other = write("out/other.txt", SUMMARY)
    path_mismatch = lab.executor.execute(other, approval_token=token, now=NOW)
    assert path_mismatch.reason == "approval_mismatch"
    assert not (lab.base / "sandbox" / "out" / "summary.txt").exists()
    assert not (lab.base / "sandbox" / "out" / "other.txt").exists()
    allowed = lab.executor.execute(action, approval_token=token, now=NOW + 1)
    assert allowed.outcome == "allow"


def test_unicode_lookalikes_are_different_actions(lab):
    first = write("out/note.txt", "cafe\u0301")
    second = write("out/note.txt", "caf\u00e9")
    assert parse_action(first).digest() != parse_action(second).digest()
    token = issue_token(lab.key, vet(first), now=NOW, ttl=30)
    result = lab.executor.execute(second, approval_token=token, now=NOW)
    assert result.reason == "approval_mismatch"
    assert not (lab.base / "sandbox" / "out" / "note.txt").exists()


def test_expired_future_and_long_ttl_tokens_are_denied(lab):
    action = summary_write()
    expired = issue_token(lab.key, vet(action), now=NOW, ttl=5)
    result = lab.executor.execute(action, approval_token=expired, now=NOW + 5)
    assert result.reason == "approval_expired"
    early = issue_token(lab.key, vet(action), now=NOW + 10, ttl=5)
    future = lab.executor.execute(action, approval_token=early, now=NOW)
    assert future.reason == "approval_not_yet_valid"
    long_token = _sign(
        lab.key,
        {
            "v": 1,
            "digest": vet(action).digest(),
            "nonce": "cd" * 16,
            "iat": NOW,
            "exp": NOW + 3601,
        },
    )
    too_long = lab.executor.execute(action, approval_token=long_token, now=NOW)
    assert too_long.reason == "approval_ttl"
    assert not (lab.base / "sandbox" / "out" / "summary.txt").exists()
    nonces = (lab.base / "operator" / "nonces.txt").read_text(encoding="utf-8")
    assert nonces.strip() == ""


def test_bad_signature_and_extra_fields_are_rejected(lab):
    action = summary_write()
    forged = _sign(b"k" * 32, _body(vet(action), NOW))
    result = lab.executor.execute(action, approval_token=forged, now=NOW)
    assert result.reason == "approval_bad_signature"
    extra = _body(vet(action), NOW)
    extra["alg"] = "none"
    signed = _sign(lab.key, extra)
    malformed = lab.executor.execute(action, approval_token=signed, now=NOW)
    assert malformed.reason == "approval_malformed"
    assert not (lab.base / "sandbox" / "out" / "summary.txt").exists()


def test_approval_does_not_override_scope(lab):
    raw = write("private/token.txt", "x")
    token = issue_token(lab.key, parse_action(raw), now=NOW, ttl=30)
    original = (lab.base / "sandbox" / "private" / "token.txt").read_bytes()
    result = lab.executor.execute(raw, approval_token=token, now=NOW)
    assert result.reason == "scope_denied"
    assert (lab.base / "sandbox" / "private" / "token.txt").read_bytes() == original
    read_token = issue_token(lab.key, parse_action(read("notes/schedule.txt")), now=NOW, ttl=30)
    tagged = lab.executor.execute(read("notes/schedule.txt"), approval_token=read_token, now=NOW)
    assert tagged.reason == "approval_not_applicable"
    assert tagged.data is None


def test_symlink_destination_is_not_replaced(lab):
    outside = lab.base / "outside" / "note.txt"
    dest = lab.base / "sandbox" / "out" / "summary.txt"
    os.symlink(outside, dest)
    action = summary_write()
    token = issue_token(lab.key, vet(action), now=NOW, ttl=30)
    result = lab.executor.execute(action, approval_token=token, now=NOW)
    assert result.reason == "symlink_denied"
    assert dest.is_symlink()
    assert outside.read_text(encoding="utf-8") == OUTSIDE_TEXT
    replay = lab.executor.execute(action, approval_token=token, now=NOW + 1)
    assert replay.reason == "approval_replay"


def test_symlinked_out_directory_is_not_followed(lab):
    out = lab.base / "sandbox" / "out"
    out.rmdir()
    os.symlink(lab.base / "outside", out)
    action = summary_write()
    token = issue_token(lab.key, vet(action), now=NOW, ttl=30)
    result = lab.executor.execute(action, approval_token=token, now=NOW)
    assert result.reason == "symlink_denied"
    assert not (lab.base / "outside" / "summary.txt").exists()


def test_existing_file_is_not_clobbered(lab):
    action = summary_write()
    token = issue_token(lab.key, vet(action), now=NOW, ttl=30)
    lab.executor.execute(action, approval_token=token, now=NOW)
    other = write("out/summary.txt", "replacement\n")
    second = issue_token(lab.key, vet(other), now=NOW + 1, ttl=30)
    result = lab.executor.execute(other, approval_token=second, now=NOW + 1)
    assert result.reason == "already_exists"
    assert (lab.base / "sandbox" / "out" / "summary.txt").read_text(encoding="utf-8") == SUMMARY


def test_failed_write_unlinks_the_new_file(lab, monkeypatch):
    def fail(fd: int, content: bytes) -> None:
        raise OSError(errno.ENOSPC, "ENOSPC")

    monkeypatch.setattr("agentlab.fs._write_all", fail)
    action = summary_write()
    token = issue_token(lab.key, vet(action), now=NOW, ttl=30)
    result = lab.executor.execute(action, approval_token=token, now=NOW)
    assert result.outcome == "error"
    assert result.reason == "internal_error"
    assert result.detail == "OSError"
    assert not (lab.base / "sandbox" / "out" / "summary.txt").exists()
    audit = (lab.base / "audit" / "audit.jsonl").read_text(encoding="utf-8")
    assert "ENOSPC" not in audit
    assert SUMMARY not in audit
    replay = lab.executor.execute(action, approval_token=token, now=NOW + 1)
    assert replay.reason == "approval_replay"


def test_parallel_use_of_one_token_allows_one_write(lab):
    action = summary_write()
    token = issue_token(lab.key, vet(action), now=NOW, ttl=30)
    barrier = threading.Barrier(8)
    results = []
    lock = threading.Lock()

    def worker() -> None:
        barrier.wait()
        result = lab.executor.execute(action, approval_token=token, now=NOW)
        with lock:
            results.append(result)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sum(item.outcome == "allow" for item in results) == 1
    assert sum(item.reason == "approval_replay" for item in results) == 7
    assert (lab.base / "sandbox" / "out" / "summary.txt").read_text(encoding="utf-8") == SUMMARY
    assert verify(lab.base / "audit" / "audit.jsonl")[0] is True


def test_verify_does_not_consume_until_authorize(lab):
    action = vet(summary_write())
    token = issue_token(lab.key, action, now=NOW, ttl=30)
    assert verify_token(lab.key, token, action, NOW) == verify_token(lab.key, token, action, NOW)
    authorize(lab.key, lab.executor.nonces, token, action, NOW)
    with pytest.raises(BoundaryDenied) as caught:
        authorize(lab.key, lab.executor.nonces, token, action, NOW)
    assert caught.value.reason == "approval_replay"


def test_loose_or_symlinked_key_is_refused(tmp_path):
    key_path = tmp_path / "approval.key"
    load_key(key_path, create=True)
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
    key_path.chmod(0o644)
    with pytest.raises(BoundaryDenied) as loose:
        load_key(key_path, create=False)
    assert loose.value.reason == "key_permissions"
    link = tmp_path / "link.key"
    link.symlink_to(key_path)
    with pytest.raises(BoundaryDenied) as linked:
        load_key(link, create=False)
    assert linked.value.reason == "key_permissions"


def test_sandbox_root_symlink_is_refused(lab):
    lab.close()
    sandbox = lab.base / "sandbox"
    import shutil

    shutil.rmtree(sandbox)
    os.symlink("/", sandbox)
    with pytest.raises(BoundaryDenied) as caught:
        from agentlab.workspace import open_lab

        open_lab(lab.base)
    assert caught.value.reason == "layout"


def test_prepare_does_not_follow_a_symlink_out_of_the_tree(tmp_path):
    precious = tmp_path / "precious"
    precious.mkdir()
    (precious / "keep.txt").write_text("keep", encoding="utf-8")
    base = tmp_path / "ws"
    base.mkdir()
    os.symlink(precious, base / "link")
    from agentlab.workspace import prepare_workspace

    prepare_workspace(base)
    assert (precious / "keep.txt").read_text(encoding="utf-8") == "keep"


def test_workspace_path_guard(tmp_path):
    from agentlab.errors import BoundaryDenied as Denied
    from agentlab.workspace import assert_safe_workspace

    with pytest.raises(Denied):
        assert_safe_workspace(Path("/tmp"))
    link = tmp_path / "link"
    real = tmp_path / "real"
    real.mkdir()
    link.symlink_to(real)
    with pytest.raises(Denied):
        assert_safe_workspace(link)


def test_write_error_audit_has_no_secret_marker(lab):
    token_text = (lab.base / "sandbox" / "private" / "token.txt").read_text(encoding="utf-8")
    result = lab.executor.execute(write("out/copied.txt", token_text), now=NOW)
    assert result.outcome == "needs_approval"
    audit = (lab.base / "audit" / "audit.jsonl").read_text(encoding="utf-8")
    assert token_text.strip() not in audit
    assert hashlib.sha256(token_text.encode("utf-8")).hexdigest() in audit


def test_list_hides_symlink_targets(lab):
    result = lab.executor.execute({"capability": "list_dir", "args": {"path": "inbox"}}, now=NOW)
    assert result.outcome == "allow"
    assert result.data is not None
    rendered = str(result.data["entries"])
    assert "outside" not in rendered
    kinds = {item["name"]: item["kind"] for item in result.data["entries"]}
    assert kinds["escape-link"] == "symlink"
    assert kinds["hardlinked.txt"] == "file"


def test_too_large_and_nul_files_return_nothing(lab):
    inbox = lab.base / "sandbox" / "inbox"
    (inbox / "big.txt").write_bytes(b"a" * 4097)
    (inbox / "nul.txt").write_bytes(b"a\x00b")
    assert lab.executor.execute(read("inbox/big.txt"), now=NOW).reason == "too_large"
    nul = lab.executor.execute(read("inbox/nul.txt"), now=NOW)
    assert nul.reason == "not_text"
    assert nul.data is None


def test_control_paths_are_not_tool_targets(lab):
    key = (lab.base / "operator" / "approval.key").read_bytes()
    for path in (
        "../operator/approval.key",
        "../operator/nonces.txt",
        "../audit/audit.jsonl",
    ):
        result = lab.executor.execute(read(path), now=NOW)
        assert result.reason == "path_traversal"
        assert result.data is None
    audit = (lab.base / "audit" / "audit.jsonl").read_bytes()
    sandbox_bytes = b"".join(
        path.read_bytes()
        for path in (lab.base / "sandbox").rglob("*")
        if path.is_file() and not path.is_symlink()
    )
    assert key not in audit
    assert key not in sandbox_bytes


def _body(action, now: int) -> dict:
    return {"v": 1, "digest": action.digest(), "nonce": "ab" * 16, "iat": now, "exp": now + 30}


def _sign(key: bytes, body: dict) -> str:
    raw = canonical_json(body)
    signature = hmac.new(key, raw, hashlib.sha256).digest()
    body_b64 = urlsafe_b64encode(raw).decode("ascii")
    sig_b64 = urlsafe_b64encode(signature).decode("ascii")
    return body_b64 + "." + sig_b64
