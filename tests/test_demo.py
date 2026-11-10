from pathlib import Path

from agentlab.demo_runner import run_demo
from agentlab.planner import EXFIL_PAYLOAD, SUMMARY
from agentlab.workspace import OUTSIDE_TEXT

ROOT = Path(__file__).resolve().parents[1]


def test_demo_is_deterministic_and_hides_untrusted_bodies(tmp_path: Path):
    first, code_one = run_demo(tmp_path / "one")
    second, code_two = run_demo(tmp_path / "two")
    assert code_one == 0 and code_two == 0
    assert first == second
    assert "not an LLM evaluation" in first
    assert "Synthetic schedule" in first
    assert "Synthetic queue status" in first
    assert "scope_denied" in first
    assert "approval_replay" in first
    assert "INJECTION-MARKER-do-not-log-9c2e" not in first
    assert "synthetic-example-token-not-a-real-credential-7f3a" not in first
    assert "synthetic-outside-marker-4b1d" not in first
    assert "reason=path_traversal" in first
    assert EXFIL_PAYLOAD.strip() not in first
    assert SUMMARY.splitlines()[0] not in first
    summary = tmp_path / "one" / "sandbox" / "out" / "summary.txt"
    assert summary.read_text(encoding="utf-8") == SUMMARY
    assert not (tmp_path / "one" / "sandbox" / "out" / "exfil.txt").exists()
    outside = (tmp_path / "one" / "outside" / "note.txt").read_text(encoding="utf-8")
    assert outside == OUTSIDE_TEXT


def test_library_has_no_shell_network_or_model_client():
    banned = (
        "subprocess",
        "urllib",
        "requests",
        "httpx",
        "openai",
        "ollama",
        "socket",
        "eval(",
        "exec(",
        "pickle",
        "os.system",
    )
    for path in (ROOT / "src" / "agentlab").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for word in banned:
            assert word not in text, f"{path.name} contains {word}"


def _imports(path: Path) -> str:
    lines = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith(("import ", "from ")):
            lines.append(stripped)
    return "\n".join(lines)


def test_import_boundaries_stay_separate():
    root = ROOT / "src" / "agentlab"
    policy = _imports(root / "policy.py")
    executor = _imports(root / "executor.py")
    planner = _imports(root / "planner.py")
    filesystem = _imports(root / "fs.py")
    assert "agentlab.fs" not in policy and "agentlab.planner" not in policy
    assert "planner" not in executor
    assert "issue_token" not in planner
    assert "approval" not in filesystem
    cli = (root / "cli.py").read_text(encoding="utf-8")
    demo = (root / "demo_runner.py").read_text(encoding="utf-8")
    assert "Sandbox(" not in cli
    assert "Sandbox(" not in demo


def test_docs_keep_the_limits_visible():
    text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            ROOT / "README.md",
            ROOT / "THREAT_MODEL.md",
            ROOT / "docs" / "ARCHITECTURE.md",
            ROOT / "docs" / "RUNBOOK.md",
        )
    )
    for phrase in (
        "Draft",
        "fact-checked on 10 Nov 2026",
        "no independent third-party security review",
        "not an LLM",
        "not a strong OS sandbox",
        "TOCTOU",
        "same OS user",
        "tip",
    ):
        assert phrase in text


def test_tree_has_no_credential_shaped_examples():
    banned = (
        "AKIA",
        "BEGIN PRIVATE KEY",
        "BEGIN OPENSSH PRIVATE KEY",
        "ghp_",
        "xoxb-",
        "sk-",
    )
    roots = [ROOT / "src", ROOT / "docs", ROOT / "README.md", ROOT / "THREAT_MODEL.md"]
    files: list[Path] = []
    for item in roots:
        if item.is_file():
            files.append(item)
        else:
            files.extend(path for path in item.rglob("*") if path.is_file())
    for path in files:
        text = path.read_text(encoding="utf-8", errors="ignore")
        for marker in banned:
            assert marker not in text, path
    assert "var/" in (ROOT / ".gitignore").read_text(encoding="utf-8")
