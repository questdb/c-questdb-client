---
name: approve-pr
description: Approve a QuestDB client pull request by posting the most recent approving review verbatim and adding READY. Use only after review-pr clears both gates and the user explicitly asks to approve.
argument-hint: "[optional PR number or URL to override auto-detection]"
disable-model-invocation: true
allowed-tools: Bash, Read, Write
---

# Approve a QuestDB client pull request

Approve the pull request for the currently checked-out branch. This skill is
meant to run **right after `review-pr`** in the same conversation: it takes the
review just produced and posts it as an approving review. Do not re-review or
rewrite the report here.

Actions performed, in order:
1. Post the existing review as the PR review body.
2. Approve the PR (or post the documented self-review fallback).
3. Add the `READY` label.

`c-questdb-client` uses `READY` as its merge-readiness label; it does not have
the main QuestDB repository's `QUEUED FOR MERGE` label.

## Step 0: Confirm the review clears the gate

Use the **most recent `review-pr` report in this conversation**. Approve only
when its verdict is **approve** or **approve with comments**, with:

- zero open Critical findings;
- correctness gate `PASS`;
- test gate `PASS`.

These are the hard gates defined by this repository's `review-pr` skill. Do not
reinterpret admitted Moderate or Minor comments as blocking when that report's
verdict explicitly approves.

- If no review report exists in this conversation, STOP and tell the user to
  run `/review-pr` first. Never approve unreviewed code.
- If the verdict is `request changes`, STOP and suggest `/reject-pr`.
- If the verdict is `needs discussion`, STOP and explain that an architecture,
  product, or compatibility decision is still required.
- Preserve the report verbatim. Do not shorten, summarize, or rewrite it.

## Step 1: Detect and validate the PR

An explicit PR number/URL in the arguments overrides branch auto-detection.
Normalize either form to the numeric PR number before constructing file paths.

```bash
TARGET='<explicit PR number/URL from arguments, else empty>'
if [ -z "$TARGET" ]; then
  TARGET=$(gh pr view --json number --jq .number 2>/dev/null)
fi
if [ -z "$TARGET" ]; then
  echo "No PR found for the current branch. Run 'gh pr checkout <n>' or pass a PR number."
  exit 1
fi
PR=$(gh pr view "$TARGET" --json number --jq .number 2>/dev/null)
if [ -z "$PR" ]; then
  echo "Could not resolve PR target: $TARGET"
  exit 1
fi
gh pr view "$PR" --json number,title,author,headRefName,url,state,isDraft,labels
```

Before posting anything, verify all of the following:

- the PR is open;
- it is the same PR reviewed by the most recent `review-pr` report;
- if it is a draft, STOP rather than marking it ready;
- if it has `DO NOT MERGE`, STOP and ask the user to resolve that label — do
  not silently remove or override it.

A target mismatch is a hard stop: never post one PR's review onto another PR.
State one line to the user: `Approving PR #<number> — <title>`, then proceed.

## Step 2: Write the review body to a file

Write the complete, verbatim `review-pr` report to
`/tmp/approve-pr-$PR.md` using the `Write` tool. Never interpolate the report
into a shell command — reviews contain backticks, quotes, and `$` characters
that break shell quoting.

## Step 3: Post the approval and mark it ready

Determine whether GitHub will allow a formal approval before posting:

```bash
if ! AUTHOR=$(gh pr view "$PR" --json author --jq .author.login) || [ -z "$AUTHOR" ]; then
  echo "Could not resolve the author of PR #$PR."
  exit 1
fi
if ! CURRENT_USER=$(gh api user --jq .login) || [ -z "$CURRENT_USER" ]; then
  echo "Could not resolve the current GitHub user."
  exit 1
fi

if [ "$CURRENT_USER" = "$AUTHOR" ]; then
  # GitHub forbids approving your own PR. Preserve the review as a normal
  # comment and make the limitation explicit in the final response.
  if ! gh pr comment "$PR" --body-file "/tmp/approve-pr-$PR.md"; then
    echo "Failed to post the self-review comment on PR #$PR."
    exit 1
  fi
  REVIEW_RESULT=self-comment
else
  if ! gh pr review "$PR" --approve --body-file "/tmp/approve-pr-$PR.md"; then
    echo "Failed to approve PR #$PR."
    exit 1
  fi
  REVIEW_RESULT=approved
fi

# Add READY only after the review/comment command succeeds.
if ! LABELS=$(gh pr view "$PR" --json labels --jq '.labels[].name'); then
  echo "Approval succeeded, but reading labels on PR #$PR failed."
  exit 1
fi
if printf '%s\n' "$LABELS" | grep -qx "READY"; then
  LABEL_RESULT=already-present
else
  if ! gh pr edit "$PR" --add-label "READY"; then
    echo "Approval succeeded, but adding READY to PR #$PR failed."
    exit 1
  fi
  LABEL_RESULT=added
fi
```

Safety rule: if formal approval fails for any reason other than the
pre-detected self-review case, STOP. Do not convert an arbitrary permissions,
network, or API failure into a comment, and do not add `READY` after a failed
review command.

## Step 4: Confirm

Read back the final state:

```bash
gh pr view "$PR" --json number,title,url,state,isDraft,reviewDecision,labels
```

Report in one or two lines:
- PR number + title;
- formal approval posted, or the self-authored comment fallback used;
- whether `READY` was added or already present;
- PR URL.
