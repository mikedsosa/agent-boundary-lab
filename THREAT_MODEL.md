# Threat model

> **Draft.** The docs were fact-checked on 10 Nov 2026. There has been no independent third-party security review. This document describes the lab as implemented. It is not a claim that the lab meets OWASP, NIST, or any other standard, and it is not an audit report.

## System

The lab is one Linux process. A scripted planner proposes tool calls. `Executor.execute` is the only path that turns a proposal into a read, a directory listing, or a new file. The sandbox is a directory of synthetic fixtures. The operator key, nonce store, and audit log are sibling directories, not tools.

No model is called. Handwritten scenarios are a way to drive the boundary. They are not an LLM evaluation and they are not a measurement of prompt injection against a model.

## Assets

- Confidentiality of bytes outside the capability scope, including `private/` inside the sandbox directory and files outside it.
- Integrity of `out/`: a new file appears only for the exact approved bytes, once.
- Integrity of the operator key and of the single-use property of an approval.
- An audit trail that records the decision without copying file bodies or tokens, and that detects some classes of later edits.

## Assumptions

- The operator runs this on a machine they control and reviews the printed binding before `--confirm`.
- This Python code and the interpreter are trusted. The planner's dicts and the bytes in `sandbox/` are not.
- The operator clock is the executor's clock. There is no network time.
- The workspace layout stays the one `prepare_workspace` writes: `operator/` and `audit/` are not inside `sandbox/`, and the sandbox root is not a symlink.

## Adversaries the code is aimed at

- A planner that emits the wrong capability or the wrong arguments, including because fixture text said to.
- Fixture text that contains instructions, the word `APPROVED`, or a copy of a secret-shaped synthetic token.
- A proposal that names `..`, an absolute path, a symlink, a hard link, a FIFO, or a path outside the scope roots.
- A second use of a captured approval token, a token past its expiry, a token signed with the wrong key, or a token whose action was edited by one byte or one path segment.
- An editor of the audit log who does not also publish a new tip that matches a rebuilt chain.

## Out of scope

- Another program running as the same OS user, or a bug that never calls `Executor`.
- Kernel exploits, container escapes, and a hostile operator who already holds the approval key.
- A model, a prompt, retrieval, or tool-result re-injection into a model. The executor returns read text to its caller. This demo does not feed that text back into a planner. A real integration that does would face indirect prompt injection again on the next decision; the boundary only sees the next call.
- Resource exhaustion beyond the fixed size, depth, and listing caps. There is no rate limit.
- Confining a process that never calls `Executor`. Mount id checks apply only to descriptors this walk opens.

## What is enforced

**Deny by default, independent of the planner.** `policy.py` does not import the planner or the filesystem walker. Unknown capabilities, extra fields, wrong types, NUL, and over-long writes are rejected. `private/` parses as a path and is still `scope_denied`, whether or not the file exists, so the denial does not reveal existence. `fs.py` will read `private/` if called directly. The executor does not do that. Both layers are required.

**Filesystem confinement.** The walk holds the sandbox directory fd and opens each component with `O_NOFOLLOW`. Checks use `fstat` on that fd and the Linux mount id from `/proc/self/fdinfo`, compared with the sandbox root. Reads require a regular file on the same device and the same mount, with link count 1, and they refuse files larger than 4096 bytes without returning a prefix. A FIFO or other non-regular file is rejected with `lstat` before `open`. Listings do not include symlink targets. Writes use `O_CREAT|O_EXCL|O_NOFOLLOW` and do not follow or replace a symlink. A symlinked `out/` directory is not entered. The sandbox root itself is refused if it is a symlink.

This is not a strong OS sandbox. It is a disciplined open in one process. The same OS user can open the symlink target, the hard-linked inode, or the approval key without calling the executor. Tests show the OS user can read the escape symlink and the executor cannot.

**Approval is not agent text.** The token is URL-safe base64 of the canonical JSON, a dot, and URL-safe base64 of the HMAC-SHA256. The JSON binds version, the digest of the action, a 16-byte nonce, `iat`, and `exp`. The digest covers capability, canonical relative path, SHA-256 of the UTF-8 content, and the content length. The signature is checked before the digest comparison. Extra fields, a non-canonical body, a bad signature, a lifetime over 3600 seconds, `now < iat`, and `now >= exp` are denials. The nonce is consumed under a lock only after those checks pass. Tools cannot write the key: they have no such capability, the key is outside the sandbox, the path is not a symlink, and the file mode must be `0600`.

A token does not widen scope. A signed write to `private/token.txt` is still `scope_denied` and does not change the file. A token attached to a read is `approval_not_applicable` and the read is not performed.

**No tool side effect on deny or error.** Denied reads do not return bytes. A write that fails policy or approval does not create the destination. If the new file is created and the subsequent write raises, the executor unlinks it. A test forces that error. A crash after create and before unlink can leave a partial file; that window is not closed. A valid token whose create then fails is still consumed, so the same token cannot be aimed at a name that changed. That updates the nonce store and the audit log. It does not update the destination. Recording a denial in the audit log is intentional.

**Audit contents.** Each record has a fixed field set: time, outcome, reason, a short fixed detail, capability, relative path, content hash, and length. There is no field for file text, tokens, or the key. A hash chain links each record to the previous hash. A tip file stores the last hash. In-place edits, dropped lines, and a tip that no longer matches are detected. A full rewrite of the log and the tip verifies locally. There is no external witness and no separate audit MAC. Anyone who can write both files can produce a chain that `verify` accepts. The agent tools are not given those paths. The same OS user can write them.

## TOCTOU

Enforced in this process:

- `..`, absolute paths, and empty or odd components are rejected as strings before any open.
- `O_NOFOLLOW` on the opened component means a symlink fails the open instead of being followed. `fstat` then applies to the inode behind that fd.
- `O_EXCL` fails if the destination name exists, including when it is a symlink, so the write does not follow a link planted at the final name. An `lstat` just before the open only selects the error string.

Not enforced:

- A bind mount has a different mount id even when `st_dev` matches. The walk compares `/proc/self/fdinfo` `mnt_id` with the sandbox root captured at open. A tmpfs, a directory bind mount, and a file bind mount were denied under a user namespace, including a write approved before `out/` was bind-mounted. If the mount id cannot be read, the open is denied.
- Replacing a regular file with a FIFO between `lstat` and `open` can still open the new inode. The static FIFO case is rejected before `open`. Symlink replacement is rejected by `O_NOFOLLOW`.
- A hard link is denied only while `st_nlink != 1`. If the other name is removed, the count can return to 1 and the bytes live at the sandbox path. That is an ordinary in-sandbox file, and it is also a way to place bytes there outside the fixture copy.
- A privileged writer that can replace parent directories the process has already passed is outside this model. Holding a directory fd pins the directory inode that was opened; it does not freeze the rest of the machine.
- The scope allowlist is policy. It does not confine code that never calls the executor. Do not describe it as a sandbox.

## Relation to the two OWASP pages that were read

Read on 8 November 2026:

- OWASP Gen AI Security Project, "LLM01:2025 Prompt Injection", <https://genai.owasp.org/llmrisk/llm01-prompt-injection/>
- OWASP Gen AI Security Project, "LLM06:2025 Excessive Agency", <https://genai.owasp.org/llmrisk/llm062025-excessive-agency/>

LLM01 describes direct and indirect prompt injection, including instructions in external files, and says it is unclear whether there are fool-proof methods of prevention. Mitigations it lists include deterministic format checks, least privilege, human approval for high-risk actions, and separating untrusted content. This lab checks action shape, limits the three tools, and requires approval for writes. It does not constrain a model system prompt, run semantic filters, or perform the adversarial testing and attack simulations the page also recommends. The fixture that says "ignore previous instructions" is data. The script that "obeys" it is handwritten.

LLM06 describes damaging actions from unexpected or manipulated model output, caused by excessive functionality, excessive permissions, or excessive autonomy. It recommends few tools, no open-ended shell or URL tool, authorization in the downstream system, human approval, and logging as a way to limit damage rather than as the prevention. This lab follows that shape for local files. It does not implement the per-user OAuth or the rate limits that page discusses. A separate OS identity is also not implemented here. That is a lab limitation, not an item on the LLM06 page. The audit is a damage-investigation aid with the rewrite limit above. It is not a preventative control.

Accessed 10 Nov 2026. The citations above are the 2025 edition. OWASP published the Top 10 for LLM Applications 2026 on 4 Aug 2026. Prompt Injection is still LLM01:2026. Excessive Agency is now LLM03:2026, and LLM06:2026 is Unbounded Consumption. That date and those three titles are from the 2026 list README, read the same day: <https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/main/2026/README.md>. The project page for that edition, also read the same day, is <https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/>. The 2025 pages remain the ones this draft quotes.

No other 2025 document was read for these citations. The reference lists on those pages are not sources for this draft.

## Review questions

- Is the executor the only caller of `Sandbox.read_file` and `Sandbox.create_file` on every path that can be reached from the CLI?
- Does any audit or demo path copy fixture bodies, the synthetic token, the approval key, or the approval token?
- Does any test still pass if a symlink starts being followed?
- Which residual items above are acceptable for a later revision, and which would make the lab misleading if left undocumented?
