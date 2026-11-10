# Agent Boundary Lab

> **Draft.** The docs were fact-checked on 10 Nov 2026. There has been no independent third-party security review. This is a local demonstration, not a production control. Released under the MIT License; see [LICENSE](LICENSE).

The planner in this lab is a handwritten script. It is not an LLM. Nothing here calls a model, downloads weights, or uses a paid API. The scenarios show how a separate executor treats hostile or mistaken tool calls. They are not an evaluation of any model.

## Problem

A tool-using agent turns proposed calls into effects. Those proposals can be wrong, or they can be steered by text found in a file. Checking the prose does not decide which effect is allowed. The effect has to be checked by code that does not trust the proposal.

Two OWASP Gen AI Security Project pages were read for this draft on 8 November 2026. The 2025 page text was last read on 8 Nov 2026 and rechecked on 10 Nov 2026:

- [LLM01:2025 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) describes direct and indirect injection, including instructions in files, and says it is unclear whether there are fool-proof methods of prevention. It lists deterministic checks, least privilege, and human approval among mitigations.
- [LLM06:2025 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/) describes damaging actions from unexpected or manipulated model output, caused by excessive functionality, excessive permissions, or excessive autonomy. It says the downstream system should authorize the call. Logging limits damage. It does not, by itself, prevent the action.

This lab does not constrain a model prompt, filter natural language, rate-limit calls, or run the adversarial testing and attack simulations the LLM01 page also recommends. No other 2025 document was read for these citations.

Accessed 10 Nov 2026. The citations above are the 2025 edition. OWASP published the Top 10 for LLM Applications 2026 on 4 Aug 2026. Prompt Injection is still LLM01:2026. Excessive Agency is now LLM03:2026, and LLM06:2026 is Unbounded Consumption. That date and those three titles are from the 2026 list README, read the same day, at <https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/main/2026/README.md>. The project page for that edition, also read the same day, is <https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/>. The 2025 pages remain the ones this draft quotes.

## Threat model

The trusted part is this process: `policy.py`, `approval.py`, `fs.py`, `executor.py`, and `audit.py`. The planner's dicts and the bytes under `sandbox/` are not trusted. The operator holds the approval key and is expected to read the binding before confirming.

In scope for the executor:

- A proposal with an unknown tool, extra fields, a bad path, or a path outside that tool's roots.
- A read or write that leaves the sandbox mount through `..`, an absolute path, a symlink, a hard link, or a different Linux mount id.
- A write with no token, a forged token, an expired token, a replayed token, or a token for different bytes or a different path.
- Text in a fixture or an action that says `APPROVED`.
- An audit line that is edited while the tip file still names the old chain.

Out of scope, and not provided here:

- Another program running as the same OS user. There is no separate user, no seccomp filter, and no mount namespace. This is not a strong OS sandbox.
- A person who already has the approval key.
- A model, and any loop that feeds a tool result back into a model.

The longer write-up is [THREAT_MODEL.md](THREAT_MODEL.md). The operator steps are [docs/RUNBOOK.md](docs/RUNBOOK.md). The component diagram is [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Approach

Three capabilities exist. There is no shell, network, or mail tool.

| Capability | Effect | Rule |
| --- | --- | --- |
| `list_dir` | Names and types under `inbox/`, `notes/`, or `out/` | No approval. Symlink targets are not returned. |
| `read_file` | UTF-8 text under `inbox/` or `notes/`, at most 4096 bytes | No approval. `private/` is inside the directory and is still denied. |
| `write_file` | Create one new file at `out/<name>` | No create until an HMAC token matches that exact action. |

The token is URL-safe base64 of the canonical JSON, a dot, and URL-safe base64 of the HMAC-SHA256. The encoded token binds version, digest, nonce, iat and exp, and the digest covers the action fields (capability, path, content hash, content length). It expires, and its nonce is recorded before the create so the same token cannot be reused. The key lives in `operator/approval.key`, mode `0600`, outside the sandbox. The executor recomputes the digest from the action it is about to run.

The filesystem walk holds the sandbox directory fd and opens children with `O_NOFOLLOW`. It compares device id and the mount id from `/proc/self/fdinfo` with the sandbox root. A FIFO is rejected with `lstat` before `open`, so a denied read does not wake a writer blocked on that FIFO. If the audit record for a create cannot be written, that new file is unlinked.

`private/` is readable by the walk and denied by scope. Both checks are required.

## Setup

CPython 3.11 or newer on Linux. The runtime dependency set is empty. pytest and ruff are development tools.

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/ruff check src tests
.venv/bin/pytest -q
.venv/bin/agentlab demo
.venv/bin/agentlab verify-audit --workspace var/demo
```

`agentlab demo` deletes and recreates its workspace. The default path is `var/demo`, which is gitignored. The demo clock is fixed, so two runs print the same transcript, including the audit tip. `approve` and `execute` use the wall clock, so their tokens differ across runs. `approve` without `--confirm` does not sign.

## Results

Measured on this draft after the mount, FIFO, and audit-rollback changes. Commands and outputs:

```text
.venv/bin/ruff check src tests
All checks passed!

.venv/bin/pytest -q
48 passed in 1.01s

.venv/bin/pytest --collect-only -q
48 tests collected in 0.01s

.venv/bin/agentlab demo --workspace /tmp/factcheck-demo
exit 0

.venv/bin/agentlab verify-audit --workspace /tmp/factcheck-demo
outcome=allow reason=ok
```

A second workspace produced the same demo stdout. That stdout matches the previous demo byte for byte, including the tip below. The last run of this tree printed `48 passed in 1.01s`. An earlier run of the same tests printed `48 passed in 0.93s`. The duration is not a benchmark.

The demo is 19 scripted steps. Stdout:

```text
# agent-boundary-lab draft demo
# scripted proposals only; not an LLM evaluation; no model was loaded
# list kinds are descriptive; a hard link is a regular file and is still denied on read
label=list_inbox outcome=allow reason=ok path=inbox entries=dir-link:symlink,escape-link:symlink,hardlinked.txt:file,message.txt:file,nested:dir,status.txt:file
label=read_schedule outcome=allow reason=ok path=notes/schedule.txt content_len=45
  | Synthetic schedule
  | review: local policy demo
label=read_status outcome=allow reason=ok path=inbox/status.txt content_len=47
  | Synthetic queue status
  | state: nominal
  | depth: 3
label=read_private outcome=deny reason=scope_denied path=private/token.txt
label=read_traversal outcome=deny reason=path_traversal path=inbox/../../outside/note.txt
label=read_absolute outcome=deny reason=bad_path path=/tmp/not-a-sandbox-path
label=read_symlink outcome=deny reason=symlink_denied path=inbox/escape-link outside_sha256=24e43c7a159dd12419be4e12ae3ca9baa9d0ef37ec1dd4b8b90869a77df30754
label=read_dir_symlink outcome=deny reason=symlink_denied path=inbox/dir-link/note.txt outside_sha256=24e43c7a159dd12419be4e12ae3ca9baa9d0ef37ec1dd4b8b90869a77df30754
label=read_hardlink outcome=deny reason=hardlink_denied path=inbox/hardlinked.txt outside_sha256=24e43c7a159dd12419be4e12ae3ca9baa9d0ef37ec1dd4b8b90869a77df30754
label=read_injection outcome=allow reason=ok path=inbox/message.txt content_len=235
label=injection_read_private outcome=deny reason=scope_denied path=private/token.txt
label=injection_write_exfil outcome=needs_approval reason=approval_required path=out/exfil.txt digest=4059fec58259cb27722ab27b23cb2ac0cb6610c23fc6b1f1cfe86894d791f1d6 exists=false
label=summary_staged outcome=needs_approval reason=approval_required path=out/summary.txt digest=a42338a640b22b8fde11c810ce7a3abe29232c392b3f6ab08139475104dea090 exists=false
label=summary_forged outcome=deny reason=approval_bad_signature path=out/summary.txt exists=false
label=summary_tampered outcome=deny reason=approval_mismatch path=out/summary.txt exists=false
label=summary_expired outcome=deny reason=approval_expired path=out/summary.txt exists=false
label=summary_approved outcome=allow reason=ok path=out/summary.txt content_len=67 exists=true file_sha256=38f809ba7c5193f243f047622a42540a1bf6fdef4d05c512f333bb0b87460b55
label=summary_replay outcome=deny reason=approval_replay path=out/summary.txt exists=true file_sha256=38f809ba7c5193f243f047622a42540a1bf6fdef4d05c512f333bb0b87460b55
label=audit_verify outcome=allow reason=ok tip=267911e1375d463d453c2fa0175a78a2a12a8330b40df9c90b88844f010c1cc2
```

Before those three fixes, the same commands on commit `d9b8008f3b54110667049c7a9a5cf991876254d8` reported `44 passed in 0.76s`, ruff clean, and demo exit 0. The tests added for those fixes are the FIFO writer, the bind-mount read and write, and the audit-failure rollback. This fact-check pass adds the rollback-failure report and the file-mount delete check, which is why the count is now 48.

## Limitations

- Same OS user. Not a strong OS sandbox. Code that does not call the executor can read the key and the disk.
- Mount id checks need `/proc/self/fdinfo`. If that file cannot be read, the open is denied. A process killed after create and before unlink can leave a partial file. Replacing a regular file with a FIFO in that gap can still open the new inode.
- A hard link is denied only while `st_nlink != 1`. After the other name is removed, the bytes are an ordinary file in the sandbox.
- The audit hash chain and tip detect an edit that does not rebuild both. Replacing the log and the tip together verifies. There is no external witness.
- A valid token is consumed even when the later create is denied, so it cannot be retried against a swapped mount.
- The scripted demo is not an LLM evaluation. There is no model in this tree.
