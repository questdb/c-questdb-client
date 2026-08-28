---
name: reject-pr
description: Reject a QuestDB client pull request by posting the most recent request-changes review verbatim, tagging the author, requesting changes, and removing READY. Use only after review-pr requests changes and the user explicitly asks to reject.
allowed-tools: bash read write
disable-model-invocation: true
metadata:
  argument-hint: "[optional PR number or URL to override auto-detection]"
---

# Reject a QuestDB client pull request

Reject the pull request for the currently checked-out branch. This skill is
meant to run **right after `review-pr`** in the same conversation: it takes the
review just produced and turns it into a blocking change-request on the PR. Do
not re-review or rewrite the report here.

Actions performed, in order:
1. Post the existing review as the PR review body, tagging the PR author.
2. Request changes (sets the PR to the `changes requested` state).
3. Remove the `READY` label when present.

## Step 0: Locate and validate the review

Use the **most recent `review-pr` report in this conversation** (its Critical /
Moderate / Minor / Coverage map / Summary output).

- If no review report exists in this conversation, STOP and tell the user to
  run `/skill:review-pr` first. Never fabricate a review.
- Its verdict must be **request changes**. If it is `approve` or
  `approve with comments`, STOP and suggest `/skill:approve-pr`. If it is
  `needs discussion`, STOP: a reviewer decision is still required before a
  blocking GitHub review is appropriate.
- Preserve the report verbatim. Do not shorten, summarize, or rewrite it. The
  only addition is the author mention required below.

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
if ! AUTHOR=$(gh pr view "$PR" --json author --jq .author.login) || [ -z "$AUTHOR" ]; then
  echo "Could not resolve the author of PR #$PR."
  exit 1
fi
```

Before posting anything, verify:

- the PR is open;
- it is the same PR reviewed by the most recent `review-pr` report.

A target mismatch is a hard stop: never post one PR's review onto another PR.
State one line to the user:
`Rejecting PR #<number> — <title> by @<author>`, then proceed.

## Step 2: Write the review body to a file

Write `/tmp/reject-pr-$PR.md` using the `write` tool. Never interpolate the
review into a shell command — reviews contain backticks, quotes, and `$`
characters that break shell quoting.

The file must contain exactly:

```text
@<AUTHOR>

<the complete, verbatim review-pr report>
```

## Step 3: Post the rejection and clear readiness

Determine whether GitHub will allow a formal change request before posting:

```bash
if ! CURRENT_USER=$(gh api user --jq .login) || [ -z "$CURRENT_USER" ]; then
  echo "Could not resolve the current GitHub user."
  exit 1
fi

if [ "$CURRENT_USER" = "$AUTHOR" ]; then
  # GitHub forbids requesting changes on your own PR. Preserve the tagged
  # review as a normal comment and make the limitation explicit later.
  if ! gh pr comment "$PR" --body-file "/tmp/reject-pr-$PR.md"; then
    echo "Failed to post the self-review comment on PR #$PR."
    exit 1
  fi
  REVIEW_RESULT=self-comment
else
  if ! gh pr review "$PR" --request-changes --body-file "/tmp/reject-pr-$PR.md"; then
    echo "Failed to request changes on PR #$PR."
    exit 1
  fi
  REVIEW_RESULT=changes-requested
fi

# Clear READY only after the review/comment command succeeds.
if ! LABELS=$(gh pr view "$PR" --json labels --jq '.labels[].name'); then
  echo "Change request succeeded, but reading labels on PR #$PR failed."
  exit 1
fi
if printf '%s\n' "$LABELS" | grep -qx "READY"; then
  if ! gh pr edit "$PR" --remove-label "READY"; then
    echo "Change request succeeded, but removing READY from PR #$PR failed."
    exit 1
  fi
  LABEL_RESULT=removed
else
  LABEL_RESULT=already-absent
fi
```

Safety rule: if the formal change request fails for any reason other than the
pre-detected self-review case, STOP. Do not convert an arbitrary permissions,
network, or API failure into a comment, and do not mutate labels after a failed
review command.

Do not add `DO NOT MERGE` automatically. This repository uses that label for
separate workflow decisions; a change-request review plus removal of `READY`
is the behavior ported from the main QuestDB repository.

## Step 4: Confirm

Read back the final state:

```bash
gh pr view "$PR" --json number,title,url,state,isDraft,reviewDecision,labels
```

Report in one or two lines:
- PR number + title and tagged author;
- `changes requested` posted, or the self-authored comment fallback used;
- whether `READY` was removed or already absent;
- PR URL.
