import json
import os
import subprocess
import sys
from pathlib import Path

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
