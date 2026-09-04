This folder holds the validation rules applied to GitHub pull request titles, and
the job that reports on them.

- `validate.js` — the rules themselves: `type(subType): description`.
- `check.js` — reads the title from the workflow event, posts the `PR title` commit
  status, and leaves a comment explaining a rejection. The comment is updated in
  place while the title stays wrong and deleted once it is fixed.
- Tests run with node and need no dependencies: `node ./validate.test.js` and
  `node ./check.test.js`.

Run by [.github/workflows/pr_title.yml](../../.github/workflows/pr_title.yml) on
pull requests and on merge groups. It authenticates with the workflow's own
`GITHUB_TOKEN`, so it needs no bot account and no personal access token. Node is
the only thing it needs, which the runner already ships; nothing here touches the
Rust or CMake build.

## Where the subType list came from

Ported from `ci/validate-pr-title` in questdb/questdb, but the list is this
repository's own. Copying the server list would have rejected 91% of what has been
merged here, because this is a client: `sql`, `wal` and `repl` mean nothing, and
`ingress`, `egress`, `qwp-ws` and `system_test` have no counterpart there.

The 91% is mostly history rather than current practice. This repository moved to
`type(subType):` recently, and the shape of merged titles shows it:

| window | `type(subType):` | `type:` | no prefix |
| --- | --- | --- | --- |
| last 20 merged | 90% | 10% | 0% |
| last 50 merged | 60% | 22% | 18% |
| older than that | 3% | 63% | 34% |

So the list is drawn from the current era — every subType used across the last 50
merged and all open pull requests — rather than from the whole history. Against
the last 20 merged it rejects 10%, and both of those are bare `chore:`/`feat:`
titles that need a subType.

## Two things to know before changing the rules

`build` is the only type allowed to skip the subType, matching the other questdb
repositories. Roughly one recent pull request in ten here uses a bare `chore:` or
`feat:` and has to gain a subType. Making the subType optional for every type is a
one-character change — `?` on the group in `prTitleRegex` — and would take the
rejection rate on the last 20 merged from 10% to 0%, at the cost of accepting
titles that name no area. That is a deliberate choice, not an oversight.

`qwp` is listed before `qwp-ws`. That is only safe because the closing `\)` in the
pattern forces the engine to backtrack into the longer branch after `qwp` matches
and the paren does not follow. validate.test.js pins both spellings so a
reordering or a rewrite cannot quietly start rejecting `qwp-ws`.
