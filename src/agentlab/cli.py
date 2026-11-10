"""Operator CLI. Tokens are printed to stdout and are not written into the sandbox."""

import argparse
import json
import sys
from pathlib import Path

from agentlab.approval import issue_token
from agentlab.audit import verify
from agentlab.demo_runner import run_demo
from agentlab.errors import BoundaryDenied
from agentlab.policy import vet
from agentlab.workspace import open_lab

MAX_ACTION_BYTES = 65536


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agentlab")
    sub = parser.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo", help="run the offline scripted demo")
    demo.add_argument("--workspace", default="var/demo")

    approve = sub.add_parser("approve", help="issue an approval token for one write")
    approve.add_argument("--workspace", required=True)
    approve.add_argument("--action-file", required=True)
    approve.add_argument("--ttl", type=int, default=300)
    approve.add_argument("--confirm", action="store_true")

    execute = sub.add_parser("execute", help="execute one action through the boundary")
    execute.add_argument("--workspace", required=True)
    execute.add_argument("--action-file", required=True)
    execute.add_argument("--approval-token", default=None)

    check = sub.add_parser("verify-audit", help="verify the workspace audit chain")
    check.add_argument("--workspace", required=True)

    args = parser.parse_args(argv)
    try:
        if args.command == "demo":
            text, code = run_demo(Path(args.workspace))
            sys.stdout.write(text)
            return code
        if args.command == "verify-audit":
            path = Path(args.workspace) / "audit" / "audit.jsonl"
            ok, detail = verify(path)
            print(f"outcome={'allow' if ok else 'deny'} reason={detail}")
            return 0 if ok else 1
        raw = _load_action(Path(args.action_file))
        if raw is None:
            print("action JSON could not be parsed", file=sys.stderr)
            return 1
        if args.command == "approve":
            return _approve(args, raw)
        return _execute(args, raw)
    except BoundaryDenied as exc:
        print(f"{exc.reason}: {exc.detail}", file=sys.stderr)
        return 1


def _approve(args: argparse.Namespace, raw: object) -> int:
    action = vet(raw)
    if action.capability != "write_file" or action.content is None:
        print("only a write_file action can be approved", file=sys.stderr)
        return 1
    binding = action.binding()
    review = "\n".join(
        [
            f"path={action.path}",
            f"content_len={binding['content_len']}",
            f"content_sha256={binding['content_sha256']}",
            f"digest={action.digest()}",
            f"preview={_preview(action.content)}",
        ]
    )
    print(
        "This signs the parsed action below. Text inside the sandbox is not an approval.",
        file=sys.stderr,
    )
    print(review, file=sys.stderr)
    if not args.confirm:
        print(
            "re-run with --confirm to issue a token for this exact action",
            file=sys.stderr,
        )
        return 2
    with open_lab(Path(args.workspace)) as lab:
        token = issue_token(lab.key, action, now=_now(), ttl=args.ttl)
    print(token)
    return 0


def _execute(args: argparse.Namespace, raw: object) -> int:
    with open_lab(Path(args.workspace)) as lab:
        result = lab.executor.execute(raw, approval_token=args.approval_token, now=_now())
    path = ""
    if type(raw) is dict and type(raw.get("args")) is dict:
        candidate = raw["args"].get("path")
        if type(candidate) is str:
            path = candidate
    print(f"outcome={result.outcome} reason={result.reason} path={path}")
    if result.outcome == "allow":
        return 0
    if result.outcome == "needs_approval":
        return 4
    if result.outcome == "deny":
        return 3
    return 1


def _load_action(path: Path) -> object | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if len(data) > MAX_ACTION_BYTES:
        return None
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return None


def _preview(content: str) -> str:
    flat = content.replace("\n", "\\n")
    if len(flat) > 120:
        return flat[:120] + "...(truncated)"
    return flat


def _now() -> int:
    import time

    return int(time.time())
