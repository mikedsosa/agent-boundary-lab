"""Mount checks that need a user namespace.

A different device is denied. A same-filesystem bind mount is also denied:
the path can stay inside the sandbox string while the directory or file is
another mount. That is a confinement failure, not an accepted limitation.
"""

import shutil
import subprocess
import sys

import pytest


def test_cross_device_and_bind_mounts_are_denied(tmp_path):
    if shutil.which("unshare") is None:
        pytest.skip("unshare is not available")
    script = r"""
import os, sys
from pathlib import Path
from agentlab.workspace import open_lab, prepare_workspace

base = Path(sys.argv[1])
prepare_workspace(base)
notes = base / "sandbox" / "notes"
if os.system(f"mount -t tmpfs tmpfs {notes}") != 0:
    raise SystemExit(2)
(notes / "x.txt").write_text("from-tmpfs\n", encoding="utf-8")
lab = open_lab(base)
tmpfs = lab.executor.execute(
    {"capability": "read_file", "args": {"path": "notes/x.txt"}},
    now=1_700_000_000,
)
print(f"tmpfs {tmpfs.outcome} {tmpfs.reason} data={tmpfs.data is not None}")
lab.close()
if os.system(f"umount {notes}") != 0:
    raise SystemExit(3)
other = base / "otherdir"
other.mkdir()
(other / "y.txt").write_text("from-bind\n", encoding="utf-8")
if os.system(f"mount --bind {other} {notes}") != 0:
    raise SystemExit(4)
lab = open_lab(base)
bound = lab.executor.execute(
    {"capability": "read_file", "args": {"path": "notes/y.txt"}},
    now=1_700_000_000,
)
text = "" if bound.data is None else bound.data.get("text", "")
print(f"bind {bound.outcome} {bound.reason} text={text!r}")
from agentlab.approval import issue_token
from agentlab.policy import vet

target = base / "write-target"
target.mkdir()
out = base / "sandbox" / "out"
if os.system(f"mount --bind {target} {out}") != 0:
    raise SystemExit(5)
action = {"capability": "write_file", "args": {"path": "out/summary.txt", "content": "escaped\\n"}}
token = issue_token(lab.key, vet(action), now=1_700_000_000, ttl=30)
wrote = lab.executor.execute(action, approval_token=token, now=1_700_000_000)
print(
    f"bind_write {wrote.outcome} {wrote.reason} "
    f"outside={ (target / 'summary.txt').exists() }"
)
lab.close()
if os.system(f"umount {notes}") != 0:
    raise SystemExit(6)
secret = base / "file-secret.txt"
secret.write_text("file-bind-secret\\n", encoding="utf-8")
schedule = base / "sandbox" / "notes" / "schedule.txt"
if os.system(f"mount --bind {secret} {schedule}") != 0:
    raise SystemExit(7)
lab = open_lab(base)
filed = lab.executor.execute(
    {"capability": "read_file", "args": {"path": "notes/schedule.txt"}},
    now=1_700_000_000,
)
body = "" if filed.data is None else filed.data.get("text", "")
print(f"file_bind {filed.outcome} {filed.reason} text={body!r}")
lab.close()
"""
    completed = subprocess.run(
        [
            "unshare",
            "--user",
            "--map-root-user",
            "--mount",
            sys.executable,
            "-c",
            script,
            str(tmp_path / "ws"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode == 2:
        pytest.skip("tmpfs mount is not permitted")
    assert completed.returncode == 0, completed.stderr + completed.stdout
    assert "tmpfs deny device_mismatch data=False" in completed.stdout
    assert "from-tmpfs" not in completed.stdout
    assert "from-bind" not in completed.stdout
    assert "file-bind-secret" not in completed.stdout
    assert "bind deny mount_mismatch text=''" in completed.stdout
    assert "bind_write deny mount_mismatch outside=False" in completed.stdout
    assert "file_bind deny mount_mismatch text=''" in completed.stdout


def test_delete_checks_the_file_mount_id(tmp_path):
    if shutil.which("unshare") is None:
        pytest.skip("unshare is not available")
    script = r"""
import os, sys
from pathlib import Path
from agentlab.approval import issue_token
from agentlab.errors import BoundaryDenied
from agentlab.policy import vet
from agentlab.workspace import open_lab, prepare_workspace

base = Path(sys.argv[1])
prepare_workspace(base)
lab = open_lab(base)
action = {"capability": "write_file", "args": {"path": "out/summary.txt", "content": "ours\n"}}
token = issue_token(lab.key, vet(action), now=1_700_000_000, ttl=30)
created = lab.executor.execute(action, approval_token=token, now=1_700_000_000)
if created.outcome != "allow":
    raise SystemExit(2)
other = base / "other-file.txt"
other.write_text("do-not-unlink\n", encoding="utf-8")
mounted = base / "sandbox" / "out" / "summary.txt"
if os.system(f"mount --bind {other} {mounted}") != 0:
    raise SystemExit(3)
try:
    lab.executor.sandbox.delete_if_regular(("out", "summary.txt"))
    print("delete allowed")
except BoundaryDenied as exc:
    print(f"delete {exc.reason}")
print("other=" + other.read_text(encoding="utf-8").strip())
print("mounted=" + mounted.read_text(encoding="utf-8").strip())
lab.close()
"""
    completed = subprocess.run(
        [
            "unshare",
            "--user",
            "--map-root-user",
            "--mount",
            sys.executable,
            "-c",
            script,
            str(tmp_path / "ws"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode == 3:
        pytest.skip("file bind mount is not permitted")
    assert completed.returncode == 0, completed.stderr + completed.stdout
    assert "delete mount_mismatch" in completed.stdout
    assert "other=do-not-unlink" in completed.stdout
    assert "mounted=do-not-unlink" in completed.stdout
