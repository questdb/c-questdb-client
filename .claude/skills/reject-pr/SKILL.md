---
name: reject-pr
description: Reject a QuestDB client pull request by posting the most recent request-changes review verbatim, tagging the author, requesting changes, and removing READY. Use only after review-pr requests changes and the user explicitly asks to reject.
argument-hint: "[optional PR number or URL to override auto-detection]"
disable-model-invocation: true
allowed-tools: Bash, Read, Write
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
  run `/review-pr` first. Never fabricate a review.
- Its verdict must be **request changes**. If it is `approve` or
  `approve with comments`, STOP and suggest `/approve-pr`. If it is
  `needs discussion`, STOP: a reviewer decision is still required before a
  blocking GitHub review is appropriate.
- Preserve the report verbatim. Do not shorten, summarize, or rewrite it. The
  only addition is the author mention required below.
- Require the report's first line to match exactly:
  `Reviewing PR #<number> at level <N>, head <40-character headRefOid>, base <40-character baseRefOid>.`
  Extract that PR number as `REVIEWED_PR` and the full head OID as
  `REVIEWED_HEAD`. Reject missing, abbreviated, or malformed identities and tell
  the user to rerun `review-pr`.

## Step 1: Detect and validate the PR

An explicit PR number/URL in the arguments overrides branch auto-detection.
Normalize either form to the numeric PR number before constructing file paths.

```bash
REVIEWED_PR='<numeric PR number from the review identity line>'
REVIEWED_HEAD='<full head OID from the review identity line>'
if ! [[ "$REVIEWED_PR" =~ ^[0-9]+$ && "$REVIEWED_HEAD" =~ ^[0-9a-f]{40}$ ]]; then
  echo "The review report has no valid full PR/head identity. Run review-pr again."
  exit 1
fi

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
if ! CURRENT_HEAD=$(gh pr view "$PR" --json headRefOid --jq .headRefOid) ||
   [[ ! "$CURRENT_HEAD" =~ ^[0-9a-f]{40}$ ]]; then
  echo "Could not resolve the current head of PR #$PR."
  exit 1
fi
if [ "$PR" != "$REVIEWED_PR" ]; then
  echo "Review target mismatch: report covers PR #$REVIEWED_PR, not PR #$PR."
  exit 1
fi
if [ "$CURRENT_HEAD" != "$REVIEWED_HEAD" ]; then
  echo "PR #$PR moved from reviewed head $REVIEWED_HEAD to $CURRENT_HEAD. Run review-pr again."
  exit 1
fi
gh pr view "$PR" --json number,title,author,headRefName,headRefOid,url,state,isDraft,labels
if ! AUTHOR=$(gh pr view "$PR" --json author --jq .author.login) || [ -z "$AUTHOR" ]; then
  echo "Could not resolve the author of PR #$PR."
  exit 1
fi
```

Before posting anything, verify:

- the PR is open;
- it is the same PR reviewed by the most recent `review-pr` report;
- its current `headRefOid` exactly matches the report's full `REVIEWED_HEAD`.

A PR or head mismatch is a hard stop: never post a review onto a different PR or commit.
State one line to the user:
`Rejecting PR #<number> — <title> by @<author>`, then proceed.

## Step 2: Write the review body to a file

Write `/tmp/reject-pr-$PR.md` using the `Write` tool. Never interpolate the
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
BODY_FILE="/tmp/reject-pr-$PR.md"
if ! IDENTITY_LINE=$(sed -n '3p' "$BODY_FILE") ||
   ! grep -qxE '^Reviewing PR #[0-9]+ at level [0-3], head [0-9a-f]{40}, base [0-9a-f]{40}\.$' <<< "$IDENTITY_LINE"; then
  echo "The saved review does not begin with a valid full PR/head identity after the author mention. Run review-pr again."
  exit 1
fi
REVIEWED_PR=$(printf '%s\n' "$IDENTITY_LINE" | sed -E 's/^Reviewing PR #([0-9]+) at level .*/\1/')
REVIEWED_HEAD=$(printf '%s\n' "$IDENTITY_LINE" | sed -E 's/^.* head ([0-9a-f]{40}), base .*$/\1/')

verify_reviewed_head() {
  local current_head
  if ! current_head=$(gh pr view "$PR" --json headRefOid --jq .headRefOid) ||
     [[ ! "$current_head" =~ ^[0-9a-f]{40}$ ]]; then
    echo "Could not resolve the current head of PR #$PR."
    return 1
  fi
  if [ "$PR" != "$REVIEWED_PR" ]; then
    echo "Review target mismatch: report covers PR #$REVIEWED_PR, not PR #$PR."
    return 1
  fi
  if [ "$current_head" != "$REVIEWED_HEAD" ]; then
    echo "PR #$PR moved from reviewed head $REVIEWED_HEAD to $current_head. Run review-pr again."
    return 1
  fi
  return 0
}

if ! verify_reviewed_head; then
  exit 1
fi
if ! AUTHOR=$(gh pr view "$PR" --json author --jq .author.login) || [ -z "$AUTHOR" ]; then
  echo "Could not resolve the author of PR #$PR."
  exit 1
fi
if ! CURRENT_USER=$(gh api user --jq .login) || [ -z "$CURRENT_USER" ]; then
  echo "Could not resolve the current GitHub user."
  exit 1
fi

if [ "$CURRENT_USER" = "$AUTHOR" ]; then
  # GitHub forbids requesting changes on your own PR. Preserve the tagged
  # review as a normal comment and make the limitation explicit later.
  if ! gh pr comment "$PR" --body-file "$BODY_FILE"; then
    echo "Failed to post the self-review comment on PR #$PR."
    exit 1
  fi
  REVIEW_RESULT=self-comment
else
  # gh pr review defaults to the latest head. Use the API's explicit commit_id
  # so a concurrent push cannot attach this decision to an unreviewed commit.
  if ! gh api --method POST "repos/{owner}/{repo}/pulls/$PR/reviews" \
      -f event=REQUEST_CHANGES \
      -f commit_id="$REVIEWED_HEAD" \
      -F "body=@$BODY_FILE" \
      --silent; then
    echo "Failed to request changes on reviewed head $REVIEWED_HEAD for PR #$PR."
    exit 1
  fi
  REVIEW_RESULT=changes-requested
fi

# Recheck immediately before label handling; stop if the head moved while posting.
if ! verify_reviewed_head; then
  echo "The review was posted, but READY was not changed because the PR head moved."
  exit 1
fi

# Clear READY only after the review/comment command succeeds.
if ! LABELS=$(gh pr view "$PR" --json labels --jq '.labels[].name'); then
  echo "Change request succeeded, but reading labels on PR #$PR failed."
  exit 1
fi
if printf '%s\n' "$LABELS" | grep -qx "READY"; then
  if ! verify_reviewed_head; then
    echo "READY was not removed because the PR head moved during label handling."
    exit 1
  fi
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
review command. Formal reviews must carry `commit_id="$REVIEWED_HEAD"`.
Recheck `headRefOid` after posting and again immediately before `gh pr edit`;
if either check observes a moved head, leave the label unchanged. The final
head check and label mutation are separate GitHub API calls and cannot be atomic.

Do not add `DO NOT MERGE` automatically. This repository uses that label for
separate workflow decisions; a change-request review plus removal of `READY`
is the behavior ported from the main QuestDB repository.

## Step 4: Confirm

Read back the final state:

```bash
gh pr view "$PR" --json number,title,url,state,isDraft,headRefOid,reviewDecision,labels
```

If the returned `headRefOid` differs from `REVIEWED_HEAD`, report that the final
readiness state raced with a push and do not claim that the label state applies
to the reviewed commit.

Report in one or two lines:
- PR number + title and tagged author;
- `changes requested` posted, or the self-authored comment fallback used;
- whether `READY` was removed or already absent;
- PR URL.
