import pytest

from agentlab.errors import BoundaryDenied
from agentlab.paths import split_relative
from agentlab.policy import vet


def test_unknown_capability_is_denied():
    with pytest.raises(BoundaryDenied) as caught:
        vet({"capability": "run_shell", "args": {"path": "inbox"}})
    assert caught.value.reason == "unknown_capability"


def test_scope_is_narrower_than_a_path_that_parses():
    with pytest.raises(BoundaryDenied) as caught:
        vet({"capability": "read_file", "args": {"path": "private/token.txt"}})
    assert caught.value.reason == "scope_denied"
    missing = vet({"capability": "read_file", "args": {"path": "inbox/does-not-exist.txt"}})
    assert missing.path == "inbox/does-not-exist.txt"
    with pytest.raises(BoundaryDenied) as missing_private:
        vet({"capability": "read_file", "args": {"path": "private/missing.txt"}})
    assert missing_private.value.reason == "scope_denied"


def test_writes_only_under_out_name():
    for path in ("notes/schedule.txt", "out/nested/file.txt", "private/token.txt"):
        with pytest.raises(BoundaryDenied) as caught:
            vet({"capability": "write_file", "args": {"path": path, "content": "x"}})
        assert caught.value.reason == "scope_denied"
    allowed = vet({"capability": "write_file", "args": {"path": "out/summary.txt", "content": "x"}})
    assert allowed.parts == ("out", "summary.txt")


def test_traversal_and_absolute_paths_fail_closed():
    samples = {
        "inbox/../../outside/note.txt": "path_traversal",
        "inbox/../notes/schedule.txt": "path_traversal",
        "../operator/approval.key": "path_traversal",
        "notes/./schedule.txt": "path_traversal",
        "/tmp/not-a-sandbox-path": "bad_path",
        "inbox/%2e%2e/secret": "bad_path",
        "inbox/status.txt\x00": "bad_path",
        "": "bad_path",
        "inbox//status.txt": "bad_path",
        "inbox/\u2024\u2024/secret": "bad_path",
    }
    for path, reason in samples.items():
        with pytest.raises(BoundaryDenied) as caught:
            split_relative(path)
        assert caught.value.reason == reason


def test_malformed_actions_are_rejected():
    samples = (
        None,
        [],
        "read",
        {},
        {"capability": "read_file"},
        {"capability": "read_file", "args": {"path": "inbox/status.txt"}, "approved": True},
        {"capability": "read_file", "args": {"path": "inbox/status.txt", "approved": True}},
        {"capability": "write_file", "args": {"path": "out/a.txt", "content": 1}},
        {"capability": "write_file", "args": {"path": "out/a.txt", "content": "a\x00b"}},
        {"capability": "read_file", "args": {"path": 12}},
        {"capability": True, "args": {}},
    )
    for raw in samples:
        with pytest.raises(BoundaryDenied) as caught:
            vet(raw)
        assert caught.value.reason in {"malformed", "bad_args", "bad_path", "unknown_capability"}


def test_oversized_write_is_denied_before_any_approval_object():
    with pytest.raises(BoundaryDenied) as caught:
        vet({"capability": "write_file", "args": {"path": "out/a.txt", "content": "a" * 4097}})
    assert caught.value.reason == "too_large"
    action = vet({"capability": "write_file", "args": {"path": "out/a.txt", "content": "a" * 4096}})
    assert action.content_bytes is not None
    assert len(action.content_bytes) == 4096
