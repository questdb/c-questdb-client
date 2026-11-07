/*******************************************************************************
 *     ___                  _   ____  ____
 *    / _ \ _   _  ___  ___| |_|  _ \| __ )
 *   | | | | | | |/ _ \/ __| __| | | |  _ \
 *   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *    \__\_\\__,_|\___||___/\__|____/|____/
 *
 *  Copyright (c) 2014-2019 Appsicle
 *  Copyright (c) 2019-2025 QuestDB
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

//! The `error` parameter of a `WWW-Authenticate: Bearer` challenge (RFC 6750
//! §3, RFC 7235 §4.1), which decides whether an HTTP 401 is worth a token
//! refresh (design/qwp-token-provider-spec.md §8.2): `invalid_token` is,
//! `insufficient_scope` is not.
//!
//! The parser is tolerant. It walks a comma-separated list of challenges --
//! `scheme [token68 | auth-param, ...]` -- accepts quoted and unquoted values,
//! and ignores what it cannot read. Only the first `error` parameter of a
//! `Bearer` challenge counts. A port of the Java client's `BearerChallenge`.

/// The `error` value that means the presented token itself is bad.
pub(crate) const INVALID_TOKEN: &str = "invalid_token";

/// Longest Bearer `error` value kept, once sanitized.
const MAX_BEARER_ERROR_CHARS: usize = 64;

/// The `error` parameter of the first `Bearer` challenge that carries one in
/// `www_authenticate` (one or more header values joined with commas).
pub(crate) fn bearer_error(www_authenticate: &str) -> Option<String> {
    let s: Vec<char> = www_authenticate.chars().collect();
    let n = s.len();
    let mut in_bearer = false;
    let mut i = 0;
    while i < n {
        let c = s[i];
        if c == ',' || is_whitespace(c) {
            i += 1;
            continue;
        }
        let start = i;
        while i < n && is_token_char(s[i]) {
            i += 1;
        }
        if i == start {
            i += 1; // not a token character: skip it
            continue;
        }
        let token: String = s[start..i].iter().collect();
        let mut j = skip_whitespace(&s, i);
        if j < n && s[j] == '=' {
            // auth-param: name = ( token / quoted-string )
            j = skip_whitespace(&s, j + 1);
            let mut value = String::new();
            if j < n && s[j] == '"' {
                j += 1;
                while j < n {
                    let q = s[j];
                    j += 1;
                    if q == '\\' && j < n {
                        value.push(s[j]);
                        j += 1;
                    } else if q == '"' {
                        break;
                    } else {
                        value.push(q);
                    }
                }
            } else {
                while j < n && s[j] != ',' && !is_whitespace(s[j]) {
                    value.push(s[j]);
                    j += 1;
                }
            }
            if in_bearer && token.eq_ignore_ascii_case("error") {
                return Some(value);
            }
            i = j;
        } else {
            // A new challenge's auth-scheme, or a token68 (no parameters).
            in_bearer = token.eq_ignore_ascii_case("Bearer");
            i = j;
        }
    }
    None
}

/// The Bearer `error` of a rejected request's `WWW-Authenticate` header,
/// sanitized and capped for diagnostics and the refresh decision.
pub(crate) fn sanitized_bearer_error(www_authenticate: Option<&str>) -> Option<String> {
    let error = bearer_error(www_authenticate?)?;
    let clean = crate::display_text::sanitize_display_text(&error);
    Some(clean.chars().take(MAX_BEARER_ERROR_CHARS).collect())
}

/// Whether a 401 whose Bearer challenge carried `bearer_error` warrants a token
/// refresh: when there is no such error parameter (the status code alone
/// decides), or when it is `invalid_token`.
pub(crate) fn allows_token_refresh(bearer_error: Option<&str>) -> bool {
    bearer_error.is_none_or(|error| error == INVALID_TOKEN)
}

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '!' | '#'
                | '$'
                | '%'
                | '&'
                | '\''
                | '*'
                | '+'
                | '-'
                | '.'
                | '^'
                | '_'
                | '`'
                | '|'
                | '~'
        )
}

fn is_whitespace(c: char) -> bool {
    c == ' ' || c == '\t'
}

fn skip_whitespace(s: &[char], mut i: usize) -> usize {
    while i < s.len() && is_whitespace(s[i]) {
        i += 1;
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_error_reads_the_first_bearer_error_parameter() {
        assert_eq!(bearer_error(""), None);
        assert_eq!(bearer_error("Bearer"), None);
        assert_eq!(bearer_error("Bearer realm=\"questdb\""), None);
        assert_eq!(
            bearer_error(
                "Bearer realm=\"questdb\", error=\"invalid_token\", \
                 error_description=\"The access token expired\""
            )
            .as_deref(),
            Some("invalid_token")
        );
        assert_eq!(
            bearer_error("Bearer error=insufficient_scope").as_deref(),
            Some("insufficient_scope")
        );
        assert_eq!(
            bearer_error("bearer ERROR=\"invalid_token\"").as_deref(),
            Some("invalid_token")
        );
        assert_eq!(
            bearer_error("Basic realm=\"x\", Bearer error=\"invalid_token\"").as_deref(),
            Some("invalid_token")
        );
        assert_eq!(bearer_error("Basic error=\"invalid_token\""), None);
        assert_eq!(
            bearer_error("Basic realm=\"x\", DPoP error=\"invalid_token\""),
            None
        );
        assert_eq!(
            bearer_error("Bearer error=\"a\\\"b\"").as_deref(),
            Some("a\"b")
        );
        assert_eq!(
            bearer_error("Bearer error=invalid_token, error=other").as_deref(),
            Some("invalid_token")
        );
        assert_eq!(bearer_error("\u{0}\"=,,=\"Bearer"), None);
    }

    #[test]
    fn only_invalid_token_or_no_error_allows_a_refresh() {
        assert!(allows_token_refresh(None));
        assert!(allows_token_refresh(Some(INVALID_TOKEN)));
        assert!(!allows_token_refresh(Some("insufficient_scope")));
        assert!(!allows_token_refresh(Some("invalid_request")));
        for (header, refreshable) in [
            (None, true),
            (Some("Basic realm=\"questdb\""), true),
            (Some("Bearer realm=\"questdb\""), true),
            (Some("Bearer error=\"invalid_token\""), true),
            (Some("Bearer error=\"insufficient_scope\""), false),
        ] {
            assert_eq!(
                allows_token_refresh(sanitized_bearer_error(header).as_deref()),
                refreshable,
                "{header:?}"
            );
        }
    }

    #[test]
    fn a_hostile_error_value_is_sanitized_and_capped() {
        let header = format!("Bearer error=\"bad\r\n\u{202e}{}\"", "x".repeat(500));
        let error = sanitized_bearer_error(Some(&header)).unwrap();
        assert!(!error.contains('\r') && !error.contains('\u{202e}'));
        assert!(error.chars().count() <= MAX_BEARER_ERROR_CHARS);
        assert!(!allows_token_refresh(Some(&error)));
    }
}
