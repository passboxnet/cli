//! Rules for `pbx scan`: known token formats first, then generic
//! assignments of high-entropy values to secret-looking names. Tuned for
//! few false positives: placeholders, references and code expressions are
//! not reported.

use std::sync::LazyLock;

use regex::Regex;

/// A secret found in a text. Offsets are byte offsets into the text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    pub rule: &'static str,
    pub description: &'static str,
    pub start: usize,
    pub end: usize,
    /// The variable or key the secret is assigned to, if any.
    pub variable: Option<String>,
    /// Whether `--fix` can replace it with a reference (single-line values).
    pub fixable: bool,
}

struct Rule {
    id: &'static str,
    description: &'static str,
    regex: Regex,
    /// Capture group of the secret (0 = whole match).
    group: usize,
    check: fn(&str) -> bool,
}

fn always(_: &str) -> bool {
    true
}

fn rule(
    id: &'static str,
    description: &'static str,
    pattern: &str,
    group: usize,
    check: fn(&str) -> bool,
) -> Rule {
    Rule {
        id,
        description,
        regex: Regex::new(pattern).expect("valid rule"),
        group,
        check,
    }
}

static RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    vec![
        rule(
            "aws-access-key-id",
            "AWS access key ID",
            r"\b((?:AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b",
            1,
            not_example,
        ),
        rule(
            "aws-secret-access-key",
            "AWS secret access key",
            r#"(?i)aws.{0,24}(?:secret|private).{0,24}?["']?\s*(?:=|:|:=|=>)\s*["']?([A-Za-z0-9/+]{40})(?:[^A-Za-z0-9/+=]|$)"#,
            1,
            high_entropy_40,
        ),
        rule(
            "github-token",
            "GitHub token",
            r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255})\b",
            1,
            not_example,
        ),
        rule(
            "github-fine-grained-token",
            "GitHub fine-grained token",
            r"\b(github_pat_[A-Za-z0-9_]{60,255})\b",
            1,
            not_example,
        ),
        rule(
            "gitlab-token",
            "GitLab token",
            r"\b((?:glpat|gldt|glrt|glptt|glcbt|gloas)-[A-Za-z0-9_\-]{20,})\b",
            1,
            not_example,
        ),
        rule(
            "slack-token",
            "Slack token",
            r"\b(xox[abposr]-[0-9]{6,}-[A-Za-z0-9-]{10,})\b",
            1,
            not_example,
        ),
        rule(
            "slack-webhook",
            "Slack webhook URL",
            r"(https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9]{8,}/[A-Za-z0-9]{8,}/[A-Za-z0-9]{16,})",
            1,
            not_example,
        ),
        rule(
            "stripe-secret-key",
            "Stripe secret key",
            r"\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,247})\b",
            1,
            not_example,
        ),
        rule(
            "openai-api-key",
            "OpenAI API key",
            r"\b(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{40,})",
            1,
            not_example,
        ),
        rule(
            "anthropic-api-key",
            "Anthropic API key",
            r"\b(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,})",
            1,
            not_example,
        ),
        rule(
            "google-api-key",
            "Google API key",
            r"\b(AIza[0-9A-Za-z_\-]{35})(?:[^0-9A-Za-z_\-]|$)",
            1,
            not_example,
        ),
        rule(
            "npm-token",
            "npm access token",
            r"\b(npm_[A-Za-z0-9]{36})\b",
            1,
            not_example,
        ),
        rule(
            "pypi-token",
            "PyPI API token",
            r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})",
            1,
            always,
        ),
        rule(
            "jwt",
            "JSON Web Token",
            r"\b(eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{16,})",
            1,
            is_jwt,
        ),
        rule(
            "url-password",
            "Password in a URL",
            r"\b[a-zA-Z][a-zA-Z0-9+.\-]{1,20}://[^/\s:@'\x22]{1,64}:([^/\s:@'\x22]{6,128})@[A-Za-z0-9.\-]+",
            1,
            url_password,
        ),
    ]
});

static PRIVATE_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?)-----",
    )
    .expect("valid rule")
});

static ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?:^|[^A-Za-z0-9_])([A-Za-z0-9_.\-]*(?:secret|token|passwd|password|passwort|pwd|api[_\-]?key|apikey|access[_\-]?key|auth[_\-]?key|private[_\-]?key|signing[_\-]?key|credential)[A-Za-z0-9_.\-]*)["']?\s*(?:=|:=|=>|:)\s*["'`]?([^\s"'`;,)\]}]{12,256})"#,
    )
    .expect("valid rule")
});

/// Shannon entropy in bits per character.
pub fn entropy(value: &str) -> f64 {
    let mut counts = std::collections::HashMap::new();
    let mut n = 0usize;
    for c in value.chars() {
        *counts.entry(c).or_insert(0usize) += 1;
        n += 1;
    }
    counts
        .values()
        .map(|&k| {
            let p = k as f64 / n as f64;
            -p * p.log2()
        })
        .sum()
}

const PLACEHOLDERS: &[&str] = &[
    "example",
    "sample",
    "dummy",
    "changeme",
    "change_me",
    "change-me",
    "placeholder",
    "your_",
    "your-",
    "yourkey",
    "xxxx",
    "****",
    "....",
    "redacted",
    "replace",
    "insert",
    "todo",
    "fixme",
    "<",
    ">",
    "${",
    "{{",
    "%(",
    "$(",
    "process.env",
    "os.environ",
    "getenv",
    "env[",
    "env(",
    "secrets.",
    "vault:",
    "pbx://",
    "op://",
    "bw://",
    "keyring",
    "fake",
    "notreal",
    "not-a-",
    "lorem",
    "1234567890",
    "abcdefgh",
    "qwerty",
];

fn placeholder(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    PLACEHOLDERS.iter().any(|p| lower.contains(p))
        || value
            .chars()
            .all(|c| c == value.chars().next().unwrap_or(' '))
}

fn not_example(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    !(lower.contains("example") || lower.contains("xxxxxxxx") || lower.ends_with("0000000000"))
}

fn high_entropy_40(value: &str) -> bool {
    !placeholder(value) && entropy(value) >= 4.0
}

fn base64url_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for c in text.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            b'=' => break,
            _ => return None,
        };
        buffer = (buffer << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(out)
}

fn is_jwt(value: &str) -> bool {
    let header = value.split('.').next().unwrap_or_default();
    base64url_decode(header)
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .is_some_and(|h| h.contains("\"alg\"") && !h.contains("\"none\""))
}

fn url_password(value: &str) -> bool {
    !placeholder(value)
        && !value.starts_with('$')
        && !matches!(
            value.to_ascii_lowercase().as_str(),
            "password" | "passwort" | "secret" | "pass" | "pwd" | "postgres" | "root" | "admin"
        )
}

fn char_classes(value: &str) -> usize {
    [
        value.chars().any(|c| c.is_ascii_lowercase()),
        value.chars().any(|c| c.is_ascii_uppercase()),
        value.chars().any(|c| c.is_ascii_digit()),
        value.chars().any(|c| !c.is_ascii_alphanumeric()),
    ]
    .iter()
    .filter(|b| **b)
    .count()
}

/// A value that is code, not a literal: `config.api.token`, `getToken()`,
/// a path or a URL without credentials.
fn expression(value: &str) -> bool {
    static DOTTED: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^[A-Za-z_$][A-Za-z0-9_$]*(?:(?:\.|::|->)[A-Za-z_$][A-Za-z0-9_$]*)+(?:\(.*)?$")
            .expect("valid")
    });
    DOTTED.is_match(value)
        || value.contains('(')
        || value.starts_with('/')
        || value.starts_with("./")
        || value.starts_with("../")
        || value.starts_with('~')
        || value.starts_with('$')
        || value.starts_with('@')
        || value.starts_with("http://")
        || value.starts_with("https://")
        || value.starts_with("file:")
}

/// A generic value is reported only when it looks random: long enough,
/// several character classes, high entropy, and no placeholder or code.
fn generic_secret(value: &str) -> bool {
    let len = value.chars().count();
    if !(16..=256).contains(&len) || placeholder(value) || expression(value) {
        return false;
    }
    let classes = char_classes(value);
    let bits = entropy(value);
    let hex = value.chars().all(|c| c.is_ascii_hexdigit());
    if hex {
        return len >= 32 && bits >= 3.3;
    }
    classes >= 2 && value.chars().any(|c| c.is_ascii_digit()) && bits >= 3.5
}

fn line_ignored(text: &str, offset: usize) -> bool {
    let start = text[..offset].rfind('\n').map_or(0, |i| i + 1);
    let end = text[offset..].find('\n').map_or(text.len(), |i| offset + i);
    text[start..end].contains("pbx-scan:ignore")
}

fn overlaps(found: &[Match], start: usize, end: usize) -> bool {
    found.iter().any(|m| start < m.end && m.start < end)
}

fn variable_before(text: &str, start: usize) -> Option<String> {
    static NAME: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"([A-Za-z_][A-Za-z0-9_.\-]{0,63})["']?\s*(?:=|:=|=>|:)\s*["'`]?$"#)
            .expect("valid")
    });
    let line_start = text[..start].rfind('\n').map_or(0, |i| i + 1);
    let before = text[line_start..start].trim_start_matches("export ");
    NAME.captures(before)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_owned())
}

/// All secrets in `text`, in order of position.
pub fn scan(text: &str) -> Vec<Match> {
    let mut found: Vec<Match> = Vec::new();
    for m in PRIVATE_KEY.find_iter(text) {
        if line_ignored(text, m.start()) {
            continue;
        }
        let end = text[m.end()..]
            .find("-----END ")
            .and_then(|i| {
                let from = m.end() + i;
                text[from + 9..].find("-----").map(|j| from + 9 + j + 5)
            })
            .unwrap_or(m.end());
        // Skip key headers in documentation without key material.
        let body = &text[m.end()..end];
        if end != m.end() && body.chars().filter(|c| c.is_ascii_alphanumeric()).count() < 64 {
            continue;
        }
        found.push(Match {
            rule: "private-key",
            description: "Private key",
            start: m.start(),
            end,
            variable: None,
            fixable: false,
        });
    }
    for rule in RULES.iter() {
        for caps in rule.regex.captures_iter(text) {
            let Some(m) = caps.get(rule.group) else {
                continue;
            };
            if overlaps(&found, m.start(), m.end())
                || line_ignored(text, m.start())
                || !(rule.check)(m.as_str())
            {
                continue;
            }
            found.push(Match {
                rule: rule.id,
                description: rule.description,
                start: m.start(),
                end: m.end(),
                variable: variable_before(text, m.start()),
                fixable: true,
            });
        }
    }
    for caps in ASSIGNMENT.captures_iter(text) {
        let (Some(name), Some(value)) = (caps.get(1), caps.get(2)) else {
            continue;
        };
        if overlaps(&found, value.start(), value.end())
            || line_ignored(text, value.start())
            || !generic_secret(value.as_str())
        {
            continue;
        }
        found.push(Match {
            rule: "generic-secret",
            description: "Secret assigned to a secret-looking name",
            start: value.start(),
            end: value.end(),
            variable: Some(name.as_str().to_owned()),
            fixable: true,
        });
    }
    found.sort_by_key(|m| m.start);
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(text: &str) -> Vec<&'static str> {
        scan(text).iter().map(|m| m.rule).collect()
    }

    // Test tokens are assembled at run time, so this file itself does not
    // look like it leaks secrets to other scanners.
    fn token(prefix: &str, body: &str, n: usize) -> String {
        format!("{prefix}{}", body.repeat(n))
    }

    #[test]
    fn finds_known_tokens() {
        let aws = token("AKIA", "Q3ZT", 4);
        assert_eq!(
            rules(&format!("AWS_ACCESS_KEY_ID={aws}\n")),
            ["aws-access-key-id"]
        );
        let secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLQKa";
        let text = format!("aws_secret_access_key = {secret}\n");
        assert_eq!(rules(&text), ["aws-secret-access-key"]);
        let gh = token("ghp_", "a1B2c3D4e5F6", 3);
        let found = scan(&format!("export GITHUB_TOKEN=\"{gh}\""));
        assert_eq!(found[0].rule, "github-token");
        assert_eq!(found[0].variable.as_deref(), Some("GITHUB_TOKEN"));
        assert_eq!(rules(&token("glpat-", "x9Y8z7W6v5", 2)), ["gitlab-token"]);
        assert_eq!(
            rules(&format!(
                "token: {}",
                token("xoxb-1234567890-", "aB3dE5gH7j", 2)
            )),
            ["slack-token"]
        );
        assert_eq!(
            rules(&format!("key = '{}'", token("sk_live_", "4eC39HqLyjWD", 2))),
            ["stripe-secret-key"]
        );
        assert_eq!(
            rules(&format!("const k = {}", token("AIza", "SyD3fG5", 5))),
            ["google-api-key"]
        );
    }

    #[test]
    fn finds_private_keys_and_jwts() {
        let pem = format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n",
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW".repeat(2)
        );
        let found = scan(&pem);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule, "private-key");
        assert!(!found[0].fixable);
        assert_eq!(found[0].end, pem.trim_end().len());
        // Only the marker, as in documentation: not reported.
        assert!(
            rules(
                "Paste the -----BEGIN RSA PRIVATE KEY----- ... -----END RSA PRIVATE KEY----- block"
            )
            .is_empty()
        );

        // {"alg":"HS256","typ":"JWT"}
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        assert_eq!(rules(&format!("Authorization: Bearer {jwt}")), ["jwt"]);
        assert!(
            rules("eyJub3RhbGciOjF9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N").is_empty()
        );
    }

    #[test]
    fn finds_generic_and_url_secrets() {
        let found = scan("DB_PASSWORD=Xk9#mQ2$vL7pR4tZ\n");
        assert_eq!(found[0].rule, "generic-secret");
        assert_eq!(found[0].variable.as_deref(), Some("DB_PASSWORD"));
        assert_eq!(
            rules("\"client_secret\": \"9f8e7d6c5b4a39281706f5e4d3c2b1a0\""),
            ["generic-secret"]
        );
        assert_eq!(
            rules("DATABASE_URL=postgres://app:Vq8sL2mX9z@db.internal:5432/app"),
            ["url-password"]
        );
    }

    #[test]
    fn ignores_placeholders_and_code() {
        for text in [
            "password = \"changeme\"",
            "API_KEY=your_api_key_here",
            "token: ${GITHUB_TOKEN}",
            "secret = process.env.SECRET_VALUE_1",
            "const token = getToken(config, 42)",
            "password_reset_url = https://example.com/reset/abc123XYZ",
            "API_TOKEN=pbx://Private/Deploy/token",
            "SECRET_KEY = settings.DEFAULT_SECRET_KEY",
            "password: <%= ENV['DB_PASSWORD'] %>",
            "token_type = bearer",
            "aws_secret_access_key = AKIAIOSFODNN7EXAMPLE",
            "DATABASE_URL=postgres://user:password@localhost/db",
            "DATABASE_URL=postgres://user:${DB_PASS}@localhost/db",
            "passwordHash = sha256Hex",
            "secret = abcdefghijklmnopqrstu",
            "integrity sha512-Abc",
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
        ] {
            assert!(rules(text).is_empty(), "{text}: {:?}", rules(text));
        }
        let gh = token("ghp_", "a1B2c3D4e5F6", 3);
        assert!(rules(&format!("GITHUB_TOKEN={gh} # pbx-scan:ignore")).is_empty());
    }
}
