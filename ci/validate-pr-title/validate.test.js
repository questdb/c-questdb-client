const assert = require("node:assert").strict;
const { validate, allowedTypes, allowedSubTypes } = require("./validate");

const testValid = (title) =>
  assert.doesNotThrow(
    () =>
      validate({
        title,
        onError: () => {
          throw new Error(`should accept "${title}"`);
        },
      }),
    `should accept "${title}"`
  );

// onError has to be a real callback here. Passing a bare `onError` identifier makes
// this assertion pass on the ReferenceError that raises instead of on the title
// being rejected, which lets every negative case below succeed against a validator
// that accepts everything.
const testInvalid = (title) =>
  assert.throws(
    () =>
      validate({
        title,
        onError: () => {
          throw new Error(`rejected "${title}"`);
        },
      }),
    `should NOT accept "${title}"`
  );

allowedTypes.forEach((type) => {
  allowedSubTypes.forEach((subType) => {
    testValid(`${type}(${subType}): foo`);
  });
});

testValid("build: 6.6");
testValid("build: hello world");
testInvalid("build");

testValid(`build: house`);
testInvalid(`build(house)`);

testInvalid(`foo: bar`);
testInvalid(`update(bar): baz`);
testInvalid(`ui: updating stuff`);

// Titles this repository actually merges.
testValid("fix(ingress): publish the dispatcher close under the inbox mutex");
testValid("fix(system_test): cap QWP fuzz concurrency on macOS");
testValid("feat(qwp-ws): remove max_in_flight, drop the in-flight window");
testValid("fix(egress): allow synchronized cursor thread handoff");
testValid("chore(tooling): follow review-pr skill improvements in main repo");
testValid("ci(maven): rerun the Maven compile task when it fails");
testValid("test(soak): stop the leak check failing on healthy runs");
testValid("fix(arrow): preflight unsupported structs and metadata");
testValid("feat(oidc): add device-flow authentication");
testValid("ci(azure): move Linux validation to Hetzner Incus");

// A subType that is a prefix of another must not shadow it. `qwp` is listed first,
// so `qwp-ws` only matches because the closing paren forces a backtrack; if the
// list is ever reordered or the regex rewritten, this is what catches it.
testValid("feat(qwp): standalone direct sender");
testValid("feat(qwp-ws): websocket transport");
testInvalid("feat(qwp-nonsense): not a real area");
testInvalid("feat(system): not a real area");

// The Conventional Commits breaking-change marker, on both accepted formats.
testValid("feat(qwp)!: drop the legacy sender constructor");
testValid("build!: require CMake 3.25");
testInvalid("feat(qwp)!");
testInvalid("feat(nonsense)!: still an unknown area");

// Areas that belong to the server repositories, not this client.
testInvalid("fix(sql): not an area of this repository");
testInvalid("fix(wal): not an area of this repository");
testInvalid("fix(repl): not an area of this repository");

// Only `build` may skip the subType. Every other type has to name one.
testInvalid("chore: java-parity pool startup, eager by default");
testInvalid("feat: columnar DataFrame ingest");
testInvalid("docs: add missing documentation for decimal datatype");

// Unstructured titles, which is what this mostly exists to catch.
testInvalid("Remove noexcept from line_sender::protocol_version()");
testInvalid("Implement C++ line_sender::flush_and_keep_with_flags()");
testInvalid("TEST: c-questdb-client vs questdb PR #6890");
testInvalid("[DO NOT MERGE] ci: diagnose macOS QWP add-column stalls");

console.log("all validate.js rules passed");
