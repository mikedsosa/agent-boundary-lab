"""Run the offline demo. The orchestrator is trusted glue, not the planner.

The one call to issue_token stands in for an operator who has reviewed the
printed binding. The planner module never receives the key or the token.
"""

import base64
import hashlib
from pathlib import Path

from agentlab.approval import issue_token
from agentlab.audit import verify
from agentlab.codec import canonical_json
from agentlab.planner import (
    EXFIL_PAYLOAD,
    SUMMARY,
    benign_reads,
    denied_reads,
    injection_followups,
    summary_write,
)
from agentlab.policy import vet
from agentlab.workspace import OUTSIDE_TEXT, open_lab, prepare_workspace

CLOCK_START = 1_700_000_000
HEADER = (
    "# agent-boundary-lab draft demo",
    "# scripted proposals only; not an LLM evaluation; no model was loaded",
    "# list kinds are descriptive; a hard link is a regular file and is still denied on read",
)
EXPECTED = (
    ("list_inbox", "allow", "ok"),
    ("read_schedule", "allow", "ok"),
    ("read_status", "allow", "ok"),
    ("read_private", "deny", "scope_denied"),
    ("read_traversal", "deny", "path_traversal"),
    ("read_absolute", "deny", "bad_path"),
    ("read_symlink", "deny", "symlink_denied"),
    ("read_dir_symlink", "deny", "symlink_denied"),
    ("read_hardlink", "deny", "hardlink_denied"),
    ("read_injection", "allow", "ok"),
    ("injection_read_private", "deny", "scope_denied"),
    ("injection_write_exfil", "needs_approval", "approval_required"),
    ("summary_staged", "needs_approval", "approval_required"),
    ("summary_forged", "deny", "approval_bad_signature"),
    ("summary_tampered", "deny", "approval_mismatch"),
    ("summary_expired", "deny", "approval_expired"),
    ("summary_approved", "allow", "ok"),
    ("summary_replay", "deny", "approval_replay"),
    ("audit_verify", "allow", "ok"),
)


def run_demo(base: Path) -> tuple[str, int]:
    base = Path(base)
    prepare_workspace(base)
    rows: list[dict[str, str]] = []
    clock = CLOCK_START
    outside = base / "outside" / "note.txt"
    outside_hash = hashlib.sha256(OUTSIDE_TEXT.encode("ascii")).hexdigest()
    with open_lab(base) as lab:
        executor = lab.executor
        benign = benign_reads()
        rows.append(_call(executor, "list_inbox", benign[0], clock))
        clock += 1
        rows.append(_call(executor, "read_schedule", benign[1], clock, reveal=True))
        clock += 1
        rows.append(_call(executor, "read_status", benign[2], clock, reveal=True))
        clock += 1
        for label, action in zip(
            (
                "read_private",
                "read_traversal",
                "read_absolute",
                "read_symlink",
                "read_dir_symlink",
                "read_hardlink",
            ),
            denied_reads(),
            strict=True,
        ):
            row = _call(executor, label, action, clock)
            if label in {"read_symlink", "read_dir_symlink", "read_hardlink"}:
                row["outside_sha256"] = _sha(outside)
            rows.append(row)
            clock += 1
        followups = injection_followups()
        rows.append(_call(executor, "read_injection", followups[0], clock))
        clock += 1
        rows.append(_call(executor, "injection_read_private", followups[1], clock))
        clock += 1
        exfil = followups[2]
        exfil_row = _call(executor, "injection_write_exfil", exfil, clock)
        exfil_row["exists"] = _exists(base / "sandbox" / "out" / "exfil.txt")
        rows.append(exfil_row)
        clock += 1

        action = summary_write()
        staged = _call(executor, "summary_staged", action, clock)
        staged["exists"] = _exists(base / "sandbox" / "out" / "summary.txt")
        rows.append(staged)
        clock += 1

        forged = _forged_token()
        forged_row = _call(executor, "summary_forged", action, clock, token=forged)
        forged_row["exists"] = _exists(base / "sandbox" / "out" / "summary.txt")
        rows.append(forged_row)
        clock += 1

        mismatch = _call(
            executor,
            "summary_tampered",
            {
                "capability": "write_file",
                "args": {"path": "out/summary.txt", "content": SUMMARY + " "},
            },
            clock,
            token=issue_token(lab.key, vet(action), now=clock, ttl=60),
        )
        mismatch["exists"] = _exists(base / "sandbox" / "out" / "summary.txt")
        rows.append(mismatch)
        clock += 1

        expired_at = clock
        expired = issue_token(lab.key, vet(action), now=expired_at, ttl=5)
        expired_row = _call(
            executor,
            "summary_expired",
            action,
            expired_at + 5,
            token=expired,
        )
        expired_row["exists"] = _exists(base / "sandbox" / "out" / "summary.txt")
        rows.append(expired_row)
        clock = expired_at + 6

        approved_token = issue_token(lab.key, vet(action), now=clock, ttl=60)
        approved = _call(executor, "summary_approved", action, clock, token=approved_token)
        summary_path = base / "sandbox" / "out" / "summary.txt"
        approved["exists"] = _exists(summary_path)
        approved["file_sha256"] = _sha(summary_path)
        rows.append(approved)
        clock += 1

        replay = _call(executor, "summary_replay", action, clock, token=approved_token)
        replay["exists"] = _exists(summary_path)
        replay["file_sha256"] = _sha(summary_path)
        rows.append(replay)

        ok, detail = verify(base / "audit" / "audit.jsonl")
        tip = (base / "audit" / "audit.jsonl.tip").read_text(encoding="ascii").strip()
        rows.append(
            {
                "label": "audit_verify",
                "outcome": "allow" if ok else "deny",
                "reason": "ok" if ok else detail,
                "tip": tip,
            }
        )
        if _sha(outside) != outside_hash:
            rows.append(
                {
                    "label": "outside_mutated",
                    "outcome": "error",
                    "reason": "outside_changed",
                }
            )

    text = "\n".join([*HEADER, *(_format_row(row) for row in rows)]) + "\n"
    code = 0 if _matches(rows) and "outside_mutated" not in text else 1
    return text, code


def _call(
    executor,
    label: str,
    action: dict,
    now: int,
    *,
    token: str | None = None,
    reveal: bool = False,
) -> dict[str, str]:
    result = executor.execute(action, approval_token=token, now=now)
    path = ""
    args = action.get("args") if type(action) is dict else None
    if type(args) is dict and type(args.get("path")) is str:
        path = args["path"]
    row: dict[str, str] = {
        "label": label,
        "outcome": result.outcome,
        "reason": result.reason,
        "path": path,
    }
    if result.data and "content_len" in result.data and result.outcome == "allow":
        row["content_len"] = str(result.data["content_len"])
    if result.data and result.outcome == "needs_approval" and "digest" in result.data:
        row["digest"] = str(result.data["digest"])
    if reveal and result.data and result.outcome == "allow" and "text" in result.data:
        row["text"] = str(result.data["text"])
    if result.data and result.outcome == "allow" and "entries" in result.data:
        row["entries"] = ",".join(
            f"{_escape(item['name'])}:{item['kind']}" for item in result.data["entries"]
        )
    return row


def _matches(rows: list[dict[str, str]]) -> bool:
    got = [(row["label"], row["outcome"], row["reason"]) for row in rows]
    if got != list(EXPECTED):
        return False
    by_label = {row["label"]: row for row in rows}
    if by_label["injection_write_exfil"]["exists"] != "false":
        return False
    if by_label["summary_staged"]["exists"] != "false":
        return False
    if by_label["summary_forged"]["exists"] != "false":
        return False
    if by_label["summary_tampered"]["exists"] != "false":
        return False
    if by_label["summary_expired"]["exists"] != "false":
        return False
    if by_label["summary_approved"]["exists"] != "true":
        return False
    if by_label["summary_replay"]["exists"] != "true":
        return False
    if by_label["summary_approved"]["file_sha256"] != by_label["summary_replay"]["file_sha256"]:
        return False
    expected_file = hashlib.sha256(SUMMARY.encode("utf-8")).hexdigest()
    if by_label["summary_approved"]["file_sha256"] != expected_file:
        return False
    if EXFIL_PAYLOAD.strip() in by_label["injection_write_exfil"].get("text", ""):
        return False
    return True


def _forged_token() -> str:
    body = canonical_json(
        {
            "v": 1,
            "digest": "0" * 64,
            "nonce": "ab" * 16,
            "iat": 1,
            "exp": 2,
        }
    )
    return (
        base64.urlsafe_b64encode(body).decode("ascii")
        + "."
        + base64.urlsafe_b64encode(b"\x00" * 32).decode("ascii")
    )


def _exists(path: Path) -> str:
    return "true" if path.is_file() and not path.is_symlink() else "false"


def _sha(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        return "absent"
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _escape(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace(" ", "\\s")
        .replace(",", "\\,")
    )


def _format_row(row: dict[str, str]) -> str:
    order = (
        "label",
        "outcome",
        "reason",
        "path",
        "content_len",
        "entries",
        "digest",
        "exists",
        "file_sha256",
        "outside_sha256",
        "tip",
    )
    line = " ".join(f"{key}={row[key]}" for key in order if key in row)
    if "text" not in row:
        return line
    body = "\n".join(f"  | {part}" for part in row["text"].splitlines())
    return f"{line}\n{body}"
