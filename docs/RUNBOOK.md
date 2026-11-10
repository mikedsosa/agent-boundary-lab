# Operator runbook

> **Draft.** The docs were fact-checked on 10 Nov 2026. There has been no independent third-party security review. Use this for the local lab only. It is not an incident-response procedure for a deployed agent.

## Run the offline demo

From the project directory:

```bash
PYTHONPATH=src python3 -m agentlab demo --workspace var/demo
echo $?
PYTHONPATH=src python3 -m agentlab verify-audit --workspace var/demo
```

Exit 0 means the scripted outcomes matched the expectations in `demo_runner.py`. The first lines say the run is not an LLM evaluation. If those lines are missing, stop and treat the tree as modified.

Read the transcript as outcomes, not as a model score. `needs_approval` with `exists=false` means the write was staged and `out/` was not changed. `allow` on `summary_approved` is the one create. `approval_replay` must leave the same `file_sha256`.

## Approve a write by hand

1. Put the action JSON outside the sandbox, or, if it is inside, treat the file as untrusted until you read the printed binding.
2. Run `approve` without `--confirm`. Read `path`, `content_len`, `content_sha256`, `digest`, and the truncated preview on stderr.
3. If any field is not the action you intend, do not confirm. A changed file will not match a token you already issued, but a token you confirm now will match the parsed action, including a hostile one.
4. Re-run with `--confirm`. The token is printed to stdout. It is not written under `sandbox/`.
5. Run `execute` with that token and the same action file.
6. If you edit the action after signing, expect `approval_mismatch` and no file.
7. A second `execute` with the same token returns `approval_replay`. Issue a new token only if you still want the effect. An existing `out/<name>` is not replaced; delete it yourself if a different create is actually what you want.

`--confirm` is the human step. The scripted demo calls the same signer in-process after the staged denial. Do not point that function at planner output in new code unless a person has reviewed the binding.

## When a call is denied

| Reason | What it means | What to do |
| --- | --- | --- |
| `scope_denied` | The path is not in that capability's roots. `private/` is inside the directory and still denied. | Do not "fix" this by widening scope to make a demo pass. |
| `path_traversal`, `bad_path` | The string is not a canonical relative path. | Inspect the proposal. The walk was not used to interpret `..`. |
| `symlink_denied` | A component or the destination is a symlink, or `out/` itself is. | The target was not followed. Leave the link in place unless you put it there as the operator. |
| `hardlink_denied` | The inode has another name. | Listing may still say `file`. That label is not a permission. |
| `approval_required` | The write is valid and not done. | Review and sign, or discard it. |
| `approval_bad_signature` | The token was not signed by this workspace key. | Do not copy a token out of fixture text. There is not one. |
| `approval_mismatch` | The token is real and the action differs. | Sign the action you are executing, not an earlier draft. |
| `approval_expired` | `now >= exp`. | Issue a new token. The clock is this machine's clock. |
| `approval_replay` | The nonce was consumed, including if an earlier create failed after a valid token. | Issue a new token if the effect is still wanted. |
| `already_exists` | `out/<name>` is already a non-symlink. | The bytes were not replaced. |
| `audit_failed` | The decision was not recorded. | Stop and inspect the log before another write. |

Denials are written to the audit log. That is a control-plane write, not a sandbox write.

## Hostile text in a fixture

`inbox/message.txt` contains an instruction to ignore policy and the marker `INJECTION-MARKER-do-not-log-9c2e`. A read of it is allowed because it lives under `inbox/`. The following proposals are not.

If you are investigating a surprise proposal:

1. Stop using the token you were about to confirm.
2. Search the audit for the marker and for `synthetic-example-token-not-a-real-credential-7f3a`. Neither should appear. A hit means a body was copied into the log.
3. Check `sandbox/out/` for files you did not approve. `exfil.txt` should not exist after the demo.
4. Compare `outside/note.txt` with `synthetic-outside-marker-4b1d`. A change means something followed or replaced the escape link.
5. Run `verify-audit`. A failure means the chain or the tip moved. A success does not prove the original history is intact. See below.

Do not delete the workspace as a cleanup step until you have copied out whatever you need. `agentlab demo` wipes its workspace path on purpose.

## Audit verify failed

`verify-audit` recomputes each line and compares the last hash to `audit.jsonl.tip`.

- `hash mismatch` or `chain break`: a line changed or disappeared and the tip was not rebuilt to match.
- `tip mismatch`: the log and the tip disagree, including after a crash between the line sync and the tip sync.
- `outcome=allow`: the files you have form a chain. It does not prove they are the chain this process first wrote. Replacing both files produces a new chain that verifies. The lab does not keep an external copy of the tip.

On failure, stop the demo, keep the directory, and do not truncate the log to "repair" it. If you stored a tip somewhere else, compare it. This runbook does not do that copy for you.

## Key and tokens

The key is created at `operator/approval.key` on first open, 32 random bytes, mode `0600`. The directory is mode `0700`. A group- or world-readable key is refused. A symlink at the key path is refused.

If the key file is copied, replaced, or left world-readable, treat every outstanding token as untrusted. Remove the key file. Tokens already used cannot be unused. Files already created under `out/` stay until you delete them. Creating a new key does not roll those files back.

Do not put the token, the key, or the nonce file inside `sandbox/`, and do not paste a token into a fixture or a planner prompt. The executor will honor a real, unexpired, unused token no matter who hands it to `execute`.

## What this runbook does not cover

It does not respond to compromise of the OS user, the interpreter, or this source tree. Those are the same trust domain as the executor. It does not rotate anything in an external system. The lab does not talk to one.
