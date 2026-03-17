---
name: review-pr
description: Review a GitHub pull request against QuestDB client library coding standards
argument-hint: [PR number or URL]
allowed-tools: Bash(gh *), Read, Grep, Glob, Agent
---

Review the pull request `$ARGUMENTS`.

## Review mindset

You are a senior QuestDB engineer performing a blocking code review. The QuestDB client library is mission-critical software — bugs can cause data loss, silent data corruption, or crashes in customer applications. There is zero tolerance for correctness issues, resource leaks, undefined behavior, or unsound FFI. Be critical, thorough, and opinionated. Your job is to catch problems before they ship, not to be nice.

- **Assume nothing is correct until you've verified it.** Read surrounding code to understand context — don't just look at the diff in isolation.
- **Flag every issue you find**, no matter how small. Do not soften language or hedge. Say "this is wrong" not "this might be an issue".
- **Do not praise the code.** Skip "looks good", "nice work", "clever approach". Focus entirely on problems and risks.
- **Think adversarially.** For each change, ask: what inputs break this? What happens under concurrent access? What if the buffer is empty? What if the string contains invalid UTF-8? What if the connection drops mid-flush? What if the caller passes NULL?
- **Check what's missing**, not just what's there. Missing tests, missing error handling, missing edge cases, missing documentation for public API changes.
- **Verify every claim.** If the PR title says "fix", verify the bug actually existed and the fix is correct. If it says "improve performance", look for benchmarks or reason about the algorithmic change. If it says "simplify", verify the new code is actually simpler and doesn't drop behavior. Treat the PR description as an unverified hypothesis, not a statement of fact.
- **Read the full context of changed files** when the diff alone is ambiguous. Use Read/Grep/Glob to inspect the surrounding code, callers, and related tests.

## Step 1: Gather PR context

Fetch PR metadata, diff, and any review comments:

```bash
gh pr view $ARGUMENTS --json number,title,body,labels,state
gh pr diff $ARGUMENTS
gh pr view $ARGUMENTS --comments
```

## Step 2: PR title and description

Check:
- Title is clear and describes the change
- Description speaks to end-user impact, not just implementation internals
- If fixing an issue, `Fixes #NNN` or a link to the issue is present
- Tone is level-headed and analytical

## Step 3: Parallel review

Launch the following agents in parallel. Each agent receives the full PR diff and should read surrounding source files as needed for context.

**Agent 1 — Correctness & bugs:** NULL/None handling, edge cases, logic errors, off-by-one, operator precedence, error paths, integer overflow/truncation.

**Agent 2 — Rust safety & soundness:** Check for any code that can panic at runtime — `unwrap()`, `expect()`, array indexing without bounds checks, `panic!()`, `unreachable!()`, `todo!()`, integer overflow in release mode, `slice::from_raw_parts` with invalid inputs. In a client library, panics in Rust code called via FFI will abort the caller's process with no recovery. Every fallible operation must use `Result`/`Option` with proper error propagation. Flag every potential panic site. Also check for unsound `unsafe` blocks: verify all safety invariants are documented and upheld, check pointer validity, aliasing rules, and lifetime correctness.

**Agent 3 — FFI boundary safety:** Check every `#[no_mangle]` / `extern "C"` function. Verify: NULL pointer checks on all pointer arguments, proper error propagation across the FFI boundary (no panics escaping into C), correct ownership transfer semantics (who allocates, who frees), buffer length validation, string encoding correctness (UTF-8 ↔ C strings), and that the C header (`line_sender.h`) and C++ wrapper (`line_sender.hpp`) accurately reflect the Rust implementation.

**Agent 4 — Concurrency & thread safety:** Race conditions, `Send`/`Sync` bounds, shared mutable state, lock ordering, correct use of `Arc`/`Mutex`/`RwLock`, thread-safety of data structures. For C/C++ API: verify documented thread-safety guarantees match the implementation.

**Agent 5 — Resource management & memory:** Leaks on all code paths (especially errors), `Drop` implementations, native memory management, buffer lifecycle, socket/connection cleanup on error paths. For C API: verify every allocation has a documented deallocation path, and error paths don't leak.

**Agent 6 — Performance & allocations:** Unnecessary allocations on hot paths (buffer building, flushing), excessive copying, inefficient serialization, unnecessary syscalls, buffer growth strategy.

**Agent 7 — Test review & coverage:** Coverage gaps, error path tests, NULL/edge-case tests, boundary conditions, regression tests, test quality. Check Rust unit tests, C++ doctest tests in `cpp_test/`, and Python system tests in `system_test/`.

**Agent 8 — Code quality & API design:** Public API ergonomics and consistency, backward compatibility of C/C++ headers, naming conventions, dead code, documentation for public items, `clippy` compliance.

Combine all agent findings into a single deduplicated **draft** report. Do NOT present this draft to the user yet — it goes straight into verification.

## Step 3b: Verify every finding against source code

The parallel review agents work from the diff alone and frequently produce false positives — especially around memory ownership, unsafe blocks, FFI lifecycle conventions, and Rust control-flow guarantees. Every finding MUST be verified before it is reported.

For each finding in the draft report:

1. **Read the actual source code** at the exact lines cited. Do not rely on the agent's description alone.
2. **Trace the full code path**: follow callers, trait implementations, and generic instantiations. A method called on a trait object may dispatch to a specific impl.
3. **Check both sides of FFI boundaries**: if a finding involves Rust↔C interaction, read both the Rust FFI function and the C/C++ header/caller. Verify ownership transfer, error propagation, and cleanup on both sides.
4. **For resource leak claims**: trace every allocation to its corresponding free/drop on ALL code paths (happy path, error path, `?` operator early returns). Check for `Drop` impls.
5. **For Rust panic claims**: verify whether the panic site is actually reachable. Trace control flow backwards — a preceding guard, match arm, or early return may make it unreachable.
6. **For unsafe soundness claims**: verify whether the safety invariants are actually violated. Check preconditions established by callers.
7. **Classify each finding** as:
   - **CONFIRMED** — the bug is real and reproducible via the traced code path
   - **FALSE POSITIVE** — the code is actually correct (explain why)
   - **CONFIRMED with nuance** — the issue exists but is less severe than stated (explain)

**Move false positives to a separate "Downgraded" section** at the end of the report. For each, give a one-line explanation of why it was dismissed. This lets the PR author verify the reasoning and catch verification mistakes.

Launch verification agents in parallel where findings are independent. Each verification agent should read surrounding source files, not just the diff.

## Review checklists

Review the diff for:

### Correctness & bugs
- NULL/None handling at API boundaries
- Edge cases and error paths
- Logic errors, off-by-one, incorrect bounds, wrong operator precedence
- Integer overflow and truncation (especially in buffer size calculations)
- Correct protocol serialization (ILP v1/v2 wire format)

### Rust safety
- No `unwrap()`/`expect()` in library code (only in tests)
- All `unsafe` blocks have documented safety invariants
- No undefined behavior: dangling pointers, use-after-free, double-free, data races
- Proper `Send`/`Sync` bounds on public types
- No panics that can escape FFI boundaries (use `catch_unwind` or avoid panic paths)

### FFI boundary
- All pointer arguments validated for NULL before dereference
- Error codes and error messages propagated correctly across FFI
- Ownership semantics clear and correct (caller-owned vs callee-owned)
- C header and C++ wrapper match Rust implementation signatures
- String handling: UTF-8 validation, null termination, length parameters

### Performance
- Performance regressions: changes that make hot paths slower
- Unnecessary allocations in buffer building or flushing paths
- Excessive copying of data that could be passed by reference
- Buffer growth strategy (exponential vs linear)
- Syscall overhead (batching, buffering)

### Resource management
- Resources properly cleaned up on all code paths (especially error paths)
- `Drop` implementations correct and complete
- Socket/connection cleanup on error
- Buffer memory freed correctly
- No leaks through FFI boundary

### Code quality
- Public API is consistent and ergonomic
- Backward-compatible changes to C/C++ headers (or breaking changes are intentional and documented)
- Naming conventions consistent with existing codebase
- No dead code or unused imports
- `clippy` clean

### Test review
- **Coverage gaps:** For every new or changed code path, verify a corresponding test exists. If not, flag it explicitly as "missing test for X".
- **Error path coverage:** Are failure cases, exceptions, and edge conditions tested — not just the happy path?
- **NULL/edge-case tests:** Are NULL inputs, empty buffers, zero-length strings, and boundary values tested?
- **FFI tests:** Are C/C++ API changes covered by tests in `cpp_test/`?
- **Integration tests:** Are protocol-level changes covered by system tests in `system_test/`?
- **Test quality:** Are tests actually asserting the right thing? Watch for tests that pass trivially or assert on wrong values.
- **Regression tests:** If this PR fixes a bug, is there a test that reproduces the original bug and would fail without the fix?

### Commit messages
- Plain English titles, under 50 chars
- Active voice, naming the acting subject

## Step 4: Output

Present ONLY verified findings (false positives are excluded). Structure as:

### Critical
Issues that must be fixed before merge. Each must include:
- Exact file path and line numbers
- Code path trace showing why the bug is real
- Suggested fix

### Moderate
Issues worth addressing but not blocking.

### Minor
Style nits and suggestions.

### Downgraded (false positives)
Findings from the initial review that were dismissed after source code verification. For each, state:
- The original claim (one line)
- Why it was dismissed (one line, citing the specific code that disproves it)

### Summary
- One-line verdict: approve, request changes, or needs discussion
- Highlight any regressions or tradeoffs
- State how many draft findings were verified vs dropped as false positives (e.g., "8 findings verified, 4 false positives removed")