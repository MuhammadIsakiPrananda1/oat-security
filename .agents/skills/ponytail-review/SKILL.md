---
name: ponytail-review
description: >
  Quality review of a change: is the logic right, is it safe, does it hold under real load, is risky code tested, is it fast enough, and is every line needed. Reads the connected code, not only the diff. Each finding is explained in plain English. Use for "review this", "code review", "review the last commit", "review my PR", "is this over-engineered", /ponytail-review.
---

# ponytail-review

Review a change like the senior developer who will be paged when it breaks.

Order of importance: **correct, safe, holds under load, tested, fast, lean.**
Lean still matters: every extra line must be read, tested, and fixed later. This is a report the user asked for, so give it in full.

## 1. Understand first

- Review what the user names: uncommitted or staged changes, a branch, a PR link, or files. Nothing named: the uncommitted changes, or the last commit if there are none.
- Read the diff, then the code it touches: callers of every changed function, the functions it calls, the tests, the README.
- Trace the real flow: where data comes in, what is stored, what goes out.
- A change can break code it does not touch. When a signature, return value, or behavior changes, grep every caller.
- Find the expected load in the repo (README, deploy config): one person running a script, or many users and processes at once. Judge scale against that, and say which load you assumed.

## 2. Look for

- **Bug:** wrong result, crash, missed edge case (empty, zero, last item, rounding, time zones), a caller broken by the change, a fix applied in one caller while the shared function stays broken.
- **Risk:** security holes (injection, weak randomness, secrets, missing checks on input from users), data loss (errors swallowed, writes in the wrong order, no transaction).
- **Scale:** fine for one user, wrong for many: check-then-write races, the same work done by every process, memory or lists that only grow, a query per item, O(n²) on big input, per-process state that must be shared.
- **Missing test:** risky new logic (a branch, a parser, money, security, data writes, a bug fix) with no test that fails when it breaks. One good test, not coverage.
- **Speed:** big slowdowns are problems. Small wins (work repeated in a hot loop) are suggestions; some software counts every millisecond.
- **Lean:** code that should not exist or should be smaller (`delete`: dead code, unused options, speculative features; `reuse`: the repo already has this helper; `stdlib` / `native`: standard library or platform features; `yagni`: abstraction with one implementation; `merge`: near-copies; `split`: one function doing several unrelated jobs).

## 3. Check before you report

- Every finding needs a concrete case: *"this input or situation leads to this wrong result"*. No case, no finding.
- Re-read the lines and confirm: the caller exists, the value can really be empty, the code really is unused.
- Propose the smallest fix that works, preferring deletions.
- No style taste, no "consider", no vague worries.

## 4. Output

Very simple English: short sentences, everyday words. Start with **What this change does:** in two or three sentences, followed by findings grouped into:

- **Must fix:** bug, security, data loss, breaks at the expected load.
- **Should fix:** risky code without a test, real slowness, duplication, a function that mixes jobs, code that should not exist.
- **Nice to have:** small speed-ups, shorter forms.

