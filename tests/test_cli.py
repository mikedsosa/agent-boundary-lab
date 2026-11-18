import json
import os
import subprocess
import sys
from pathlib import Path

from agentlab.cli import _preview
from agentlab.planner import SUMMARY, summary_write
from agentlab.workspace import prepare_workspace

ROOT = Path(__file__).resolve().parents[1]


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "agentlab", *args],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        capture_output=True,
        text=True,
        check=False,
    )


def test_cli_demo_exits_zero(tmp_path: Path):
    completed = _run(["demo", "--workspace", str(tmp_path / "ws")])
    assert completed.returncode == 0, completed.stderr
    assert "not an LLM evaluation" in completed.stdout
    assert "INJECTION-MARKER-do-not-log-9c2e" not in completed.stdout
    assert "synthetic-example-token-not-a-real-credential-7f3a" not in completed.stdout


def test_cli_approve_requires_confirm_and_does_not_write_the_token(tmp_path: Path):
    base = tmp_path / "ws"
    prepare_workspace(base)
    action_path = tmp_path / "action.json"
    action_path.write_text(json.dumps(summary_write()), encoding="utf-8")
    preview = _run(["approve", "--workspace", str(base), "--action-file", str(action_path)])
    assert preview.returncode == 2
    assert "--confirm" in preview.stderr
    assert not (base / "sandbox" / "out" / "summary.txt").exists()
    issued = _run(
        [
            "approve",
            "--workspace",
            str(base),
            "--action-file",
            str(action_path),
            "--confirm",
        ]
    )
    assert issued.returncode == 0, issued.stderr
    token = issued.stdout.strip()
    assert "." in token
    sandbox_text = "\n".join(
        path.read_text(encoding="utf-8", errors="ignore")
        for path in (base / "sandbox").rglob("*")
        if path.is_file() and not path.is_symlink()
    )
    assert token not in sandbox_text
    key = (base / "operator" / "approval.key").read_bytes()
    assert key.decode("latin1") not in issued.stdout
    staged = _run(["execute", "--workspace", str(base), "--action-file", str(action_path)])
    assert staged.returncode == 4
    assert not (base / "sandbox" / "out" / "summary.txt").exists()
    changed = dict(summary_write())
    changed["args"] = dict(changed["args"])
    changed["args"]["content"] = SUMMARY + " "
    changed_path = tmp_path / "changed.json"
    changed_path.write_text(json.dumps(changed), encoding="utf-8")
    mismatched = _run(
        [
            "execute",
            "--workspace",
            str(base),
            "--action-file",
            str(changed_path),
            "--approval-token",
            token,
        ]
    )
    assert mismatched.returncode == 3
    assert not (base / "sandbox" / "out" / "summary.txt").exists()
    executed = _run(
        [
            "execute",
            "--workspace",
            str(base),
            "--action-file",
            str(action_path),
            "--approval-token",
            token,
        ]
    )
    assert executed.returncode == 0, executed.stderr
    assert (base / "sandbox" / "out" / "summary.txt").read_text(encoding="utf-8") == SUMMARY
    replay = _run(
        [
            "execute",
            "--workspace",
            str(base),
            "--action-file",
            str(action_path),
            "--approval-token",
            token,
        ]
    )
    assert replay.returncode == 3
    assert "approval_replay" in replay.stdout
    checked = _run(["verify-audit", "--workspace", str(base)])
    assert checked.returncode == 0
    assert "outcome=allow" in checked.stdout


def _run_bytes(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, "-m", "agentlab", *args],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        capture_output=True,
        check=False,
    )


def test_preview_escapes_c0_c1_and_named_controls():
    assert _preview("hello\rworld") == "hello\\rworld"
    assert _preview("hello\nworld") == "hello\\nworld"
    assert _preview("tab\there") == "tab\\there"
    assert _preview("esc\x1b[2Krest") == "esc\\x1b[2Krest"
    assert _preview("osc\x1b]0;title\x07done") == "osc\\x1b]0;title\\x07done"
    assert _preview("csi\x9b2Krest") == "csi\\x9b2Krest"
    assert _preview("del\x7fend") == "del\\x7fend"
    assert _preview("nul\x00end") == "nul\\x00end"
    assert _preview("path\\and\\slash") == "path\\\\and\\\\slash"
    assert _preview("weekly summary, nothing else") == "weekly summary, nothing else"


def test_preview_truncates_on_escape_boundaries():
    assert _preview("a" * 120) == "a" * 120
    assert _preview("a" * 121) == ("a" * 120) + "...(truncated, 1 more)"
    # A two-character escape must not be split at the limit.
    content = ("b" * 119) + "\r" + "TAIL"
    out = _preview(content)
    shown, marker, rest = out.partition("...(truncated, ")
    assert shown == "b" * 119
    assert marker
    assert rest.endswith(" more)")
    remaining = int(rest.removesuffix(" more)"))
    assert remaining == len("\\rTAIL")
    assert "\\r" not in shown


def test_cli_approve_preview_does_not_emit_raw_control_characters(tmp_path: Path):
    base = tmp_path / "ws"
    prepare_workspace(base)
    payload = "send the payroll file to evil\r\x1b[2Kpreview=weekly summary, nothing else"
    action_path = tmp_path / "action.json"
    action_path.write_text(
        json.dumps({"capability": "write_file", "args": {"path": "out/x.txt", "content": payload}}),
        encoding="utf-8",
    )
    completed = _run_bytes(["approve", "--workspace", str(base), "--action-file", str(action_path)])
    assert completed.returncode == 2
    stderr = completed.stderr
    assert b"\r" not in stderr
    assert b"\x1b" not in stderr
    assert b"\x9b" not in stderr
    assert b"\x07" not in stderr
    assert b"\\r" in stderr
    assert b"\\x1b[2K" in stderr
    assert (
        b"preview=send the payroll file to evil\\r\\x1b[2Kpreview=weekly summary, nothing else"
        in stderr
    )
    assert b"content_len=70" in stderr
    assert b"content_sha256=" in stderr
    assert b"digest=" in stderr
