const allowedTypes = [
  "feat",
  "fix",
  "chore",
  "docs",
  "style",
  "refactor",
  "perf",
  "test",
  "ci",
  "revert",
];

// Derived from what this repository actually merges rather than copied from the
// server repositories: it is a client, so `sql`, `wal`, `repl` and the rest have
// no meaning here, and `ingress`, `egress` and `system_test` have no counterpart
// there. The list covers every subType used across the last 50 merged and all
// open pull requests; see readme.md for the measurement.
const allowedSubTypes = [
  // shared with the server repositories
  "build",
  "core",
  "ilp",
  "qwp",
  // client-side transports and surfaces
  "qwp-ws",
  "ingress",
  "egress",
  "arrow",
  "oidc",
  "rust",
  // test estate
  "system_test",
  "e2e",
  "soak",
  "test",
  // build and infrastructure
  "ci",
  "tooling",
  "maven",
  "azure",
];

const errorMessage = `
Please update the PR title to match this format:
\`type(subType): description\`

Where \`type\` is one of:
${allowedTypes.map((t) => `\`${t}\``).join(", ")}

And: \`subType\` is one of:
${allowedSubTypes.map((t) => `\`${t}\``).join(", ")}

For Example:

\`\`\`
fix(ingress): publish the dispatcher close under the inbox mutex
\`\`\`
`.trim();

/* The valid PR title formats are:
 * 1. allowedType(allowedSubType): description
 * 2. build: description
 *
 * Note that format 2 is available to `build` alone. Every other type has to name
 * a subType, so `feat: thing` is rejected while `build: 4.0.1` is accepted. This
 * matches the other questdb repositories; roughly one recent pull request in ten
 * here uses a bare `chore:` or `feat:` and has to gain a subType.
 *
 * A `!` before the colon is the Conventional Commits marker for a breaking
 * change, as in `feat(qwp)!: ...`, and is accepted on either format.
 *
 * `qwp` is listed before `qwp-ws`, which is only safe because the trailing `\\)`
 * forces the engine to backtrack into the longer branch; validate.test.js pins
 * both so a reordering cannot quietly start rejecting `qwp-ws`.
 * consult ./validate.test.js for a full list
 * */
const prTitleRegex = new RegExp(
  `^(((?:${allowedTypes.join("|")})\\((?:${allowedSubTypes.join(
    "|"
  )})\\))|build)!?: .*`
);

function validate({ title, onError }) {
  // Early return for title that matches predefined regex.
  // No action required in such case.
  if (title.match(prTitleRegex)) {
    return;
  }

  onError(errorMessage);
}

module.exports = {
  allowedTypes,
  allowedSubTypes,
  validate,
};
