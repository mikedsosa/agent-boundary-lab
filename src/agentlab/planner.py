"""Handwritten tool proposals.

These dicts are untrusted input to the executor. They include proposals that
imitate a planner obeying instructions found in a fixture. Nothing here is
model output, and nothing here is an evaluation of a model.
"""

SUMMARY = "Synthetic summary drafted by the scripted planner.\nstatus: nominal\n"
EXFIL_PAYLOAD = "EXFIL-PAYLOAD-do-not-write-33aa\n"


def benign_reads() -> list[dict]:
    return [
        {"capability": "list_dir", "args": {"path": "inbox"}},
        {"capability": "read_file", "args": {"path": "notes/schedule.txt"}},
        {"capability": "read_file", "args": {"path": "inbox/status.txt"}},
    ]


def denied_reads() -> list[dict]:
    return [
        {"capability": "read_file", "args": {"path": "private/token.txt"}},
        {"capability": "read_file", "args": {"path": "inbox/../../outside/note.txt"}},
        {"capability": "read_file", "args": {"path": "/tmp/not-a-sandbox-path"}},
        {"capability": "read_file", "args": {"path": "inbox/escape-link"}},
        {"capability": "read_file", "args": {"path": "inbox/dir-link/note.txt"}},
        {"capability": "read_file", "args": {"path": "inbox/hardlinked.txt"}},
    ]


def injection_followups() -> list[dict]:
    """What a naive planner might emit after reading inbox/message.txt."""
    return [
        {"capability": "read_file", "args": {"path": "inbox/message.txt"}},
        {"capability": "read_file", "args": {"path": "private/token.txt"}},
        {
            "capability": "write_file",
            "args": {"path": "out/exfil.txt", "content": EXFIL_PAYLOAD},
        },
    ]


def summary_write() -> dict:
    return {
        "capability": "write_file",
        "args": {"path": "out/summary.txt", "content": SUMMARY},
    }
