"use strict";

// Validates a pull request title and reports the verdict to GitHub: it posts a
// commit status and leaves a comment explaining a rejection, updating that comment
// in place while the title stays wrong and deleting it once the title is fixed.
// Everything here runs on the workflow's own GITHUB_TOKEN and uses only the Node
// standard library, so the job installs nothing at run time.

const fs = require("node:fs");
const { validate } = require("./validate");

// Hidden marker on the comment this job writes, so a later run can find that same
// comment and update or delete it rather than stacking a new one on every push.
const MARKER = "<!-- pr-title-check -->";

// The commit status context. The branch protection on main lists no required
// contexts at all, so this string is free and a rejection is visible without
// blocking. That is unlike questdb/questdb, which posts the same string but has
// it named by the master ruleset, where a rename takes a matching ruleset edit or
// every pull request blocks. Making this required is a branch-protection edit,
// separate from this code.
const CONTEXT = "PR title";

const apiUrl = process.env.GITHUB_API_URL || "https://api.github.com";
const repo = process.env.GITHUB_REPOSITORY;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// GitHub occasionally answers a write with a 5xx, and a dropped verdict is worse
// than a slow one, so transient failures are retried. A 4xx is a permanent answer
// about this request, so it fails immediately instead of burning the retries.
async function request(method, path, body) {
  let lastError;
  for (let attempt = 1; attempt <= 3; attempt++) {
    if (attempt > 1) {
      await sleep(2000 * (attempt - 1));
    }
    let response;
    try {
      response = await fetch(`${apiUrl}${path}`, {
        method,
        headers: {
          accept: "application/vnd.github+json",
          authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
          "x-github-api-version": "2022-11-28",
          ...(body ? { "content-type": "application/json" } : {}),
        },
        ...(body ? { body: JSON.stringify(body) } : {}),
      });
    } catch (error) {
      lastError = error;
      continue;
    }
    if (response.status === 204) {
      return null;
    }
    if (response.ok) {
      return response.json();
    }
    const detail = await response.text().catch(() => "");
    lastError = new Error(
      `${method} ${path} answered ${response.status}: ${detail.slice(0, 300)}`
    );
    if (response.status < 500 && response.status !== 429) {
      break;
    }
  }
  throw lastError;
}

function readEvent() {
  return JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH, "utf8"));
}

// A pull_request event carries the title and the head commit directly. A merge
// group carries neither: it names the queued pull request only in its ref, so the
// number is recovered from there and the title read back from the API. GitHub
// writes the pull request title into the squash commit, and a title edited after
// the entry joins the queue passes through no other check, so the merge group is
// validated rather than rubber-stamped. This repository has no merge queue today;
// the path is kept so enabling one does not silently lose the check.
async function resolveTarget() {
  const event = readEvent();
  if (process.env.GITHUB_EVENT_NAME === "pull_request") {
    return {
      event: "pull_request",
      number: event.pull_request.number,
      // Not GITHUB_SHA: on a pull_request event that is the throwaway merge commit,
      // and a status posted there is invisible to the pull request.
      sha: event.pull_request.head.sha,
      title: event.pull_request.title,
    };
  }
  // refs/heads/gh-readonly-queue/<base>/pr-<number>-<sha>. A group holding more
  // than one entry names only the last one, so that is the title being checked.
  const ref = (event.merge_group && event.merge_group.head_ref) || process.env.GITHUB_REF || "";
  const match = ref.match(/^refs\/heads\/gh-readonly-queue\/.*\/pr-(\d+)-/);
  if (!match) {
    throw new Error(`cannot read a pull request number from ${ref}`);
  }
  const number = Number(match[1]);
  const pullRequest = await request("GET", `/repos/${repo}/pulls/${number}`);
  return {
    event: "merge_group",
    number,
    sha: (event.merge_group && event.merge_group.head_sha) || process.env.GITHUB_SHA,
    title: pullRequest.title,
  };
}

// Every match, not just the first. A pull request that ends up carrying two of
// these — a race between two runs, or a write that half succeeded — would
// otherwise shed one comment per run and keep the rest, which reads to the author
// as a complaint that no longer clears when the title is fixed.
async function findComments(number) {
  const found = [];
  for (let page = 1; page <= 10; page++) {
    const comments = await request(
      "GET",
      `/repos/${repo}/issues/${number}/comments?per_page=100&page=${page}`
    );
    for (const comment of comments) {
      if (typeof comment.body === "string" && comment.body.includes(MARKER)) {
        found.push(comment);
      }
    }
    if (comments.length < 100) {
      break;
    }
  }
  return found;
}

function commentBody(title, reason) {
  return [
    MARKER,
    "### This pull request title does not follow the required format",
    "",
    // Four backticks so a title containing a fence of its own cannot break out.
    "````",
    title,
    "````",
    "",
    reason,
    "",
    "_Edit the title and this comment removes itself on the next run._",
  ].join("\n");
}

// The comment is an explanation, not the gate: the status is. A comment that
// cannot be written is reported and stepped over, so an unrelated API problem
// cannot fail a pull request whose title is perfectly valid.
async function syncComment(number, title, reason) {
  const existing = await findComments(number);
  if (!reason) {
    for (const comment of existing) {
      await request("DELETE", `/repos/${repo}/issues/comments/${comment.id}`);
    }
    return;
  }
  const body = commentBody(title, reason);
  if (existing.length === 0) {
    await request("POST", `/repos/${repo}/issues/${number}/comments`, { body });
    return;
  }
  // Keep one and reword it only when the reason actually changed, so a rerun on an
  // unchanged bad title does not bump the comment and re-notify everyone watching.
  if (existing[0].body !== body) {
    await request("PATCH", `/repos/${repo}/issues/comments/${existing[0].id}`, { body });
  }
  for (const duplicate of existing.slice(1)) {
    await request("DELETE", `/repos/${repo}/issues/comments/${duplicate.id}`);
  }
}

async function run() {
  // Falls back to the event's own commit so that a failure while resolving the
  // target still has somewhere to publish a verdict.
  let sha = process.env.GITHUB_SHA;
  try {
    const target = await resolveTarget();
    sha = target.sha;

    let reason = "";
    validate({
      title: target.title,
      onError: (message) => {
        reason = message;
      },
    });

    // A merge group has no conversation of its own, and commenting would land on
    // the pull request a second time, so that path reports by status alone.
    if (target.event === "pull_request") {
      try {
        await syncComment(target.number, target.title, reason);
      } catch (error) {
        console.log(`::warning::could not update the explanation comment: ${error.message}`);
      }
    }

    if (reason) {
      await postStatus(sha, "failure", `PR #${target.number} title must match type(subType): description`);
      console.log(`::error::${reason}`);
      process.exitCode = 1;
      return;
    }
    await postStatus(sha, "success", `Title of PR #${target.number} validated`);
    console.log(`Title of PR #${target.number} is valid: ${target.title}`);
  } catch (error) {
    // A required check that never reports leaves a pull request stuck behind a
    // check that is merely missing, and leaves a merge group to wait out its
    // status-check timeout before being ejected with nothing naming the cause.
    // Publish a verdict even when the run itself came apart.
    console.log(`::error::${error.message}`);
    process.exitCode = 1;
    try {
      await postStatus(sha, "failure", "PR title check could not run; see the workflow run");
    } catch (statusError) {
      console.log(`::error::could not post the ${CONTEXT} status: ${statusError.message}`);
    }
  }
}

function postStatus(sha, state, description) {
  return request("POST", `/repos/${repo}/statuses/${sha}`, {
    state,
    context: CONTEXT,
    // GitHub truncates a description past 140 characters.
    description: description.slice(0, 140),
  });
}

if (require.main === module) {
  run();
}

module.exports = { run, MARKER, CONTEXT, commentBody };
