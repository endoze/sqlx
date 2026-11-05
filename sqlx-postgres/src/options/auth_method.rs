use std::fmt::{self, Display};
use std::str::FromStr;

use crate::error::Error;

/// An authentication method a PostgreSQL server can ask the client to use.
///
/// Used by [`require_auth`](super::PgConnectOptions::require_auth).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PgAuthMethod {
    /// The server accepts the connection without an authentication exchange, as with `trust`
    /// or `cert` in `pg_hba.conf`.
    None,

    /// The server asks for the password in cleartext.
    Password,

    /// The server asks for an MD5 hash of the password and a salt.
    Md5,

    /// The server runs a SCRAM-SHA-256 exchange, which proves the password without sending it.
    ScramSha256,
}

impl PgAuthMethod {
    const ALL: [Self; 4] = [Self::None, Self::Password, Self::Md5, Self::ScramSha256];

    fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Password => "password",
            Self::Md5 => "md5",
            Self::ScramSha256 => "scram-sha-256",
        }
    }
}

impl Display for PgAuthMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for PgAuthMethod {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        Self::ALL
            .into_iter()
            .find(|method| method.as_str() == s)
            .ok_or_else(|| {
                Error::Configuration(format!("unknown value {s:?} for `require_auth`").into())
            })
    }
}

/// Parses libpq's `require_auth` syntax into the methods it allows.
///
/// The value is a comma-separated list of methods. Prefixing every method with `!` allows all
/// methods except those listed. libpq's `gss` and `sspi` are accepted and allow nothing, since
/// SQLx can't authenticate with them.
pub(crate) fn parse_require_auth(s: &str) -> Result<Vec<PgAuthMethod>, Error> {
    let negated = s.starts_with('!');
    let mut listed = Vec::new();

    for item in s.split(',') {
        let name = match (negated, item.strip_prefix('!')) {
            (true, Some(name)) => name,
            (false, None) => item,
            _ => {
                return Err(Error::Configuration(
                    format!("`require_auth` can't mix negated and plain methods: {s:?}").into(),
                ))
            }
        };

        if listed.contains(&name) {
            return Err(Error::Configuration(
                format!("`require_auth` lists {name:?} more than once").into(),
            ));
        }

        listed.push(name);
    }

    let mut methods = Vec::new();

    for name in &listed {
        if !matches!(*name, "gss" | "sspi") {
            methods.push(name.parse::<PgAuthMethod>()?);
        }
    }

    if negated {
        methods = PgAuthMethod::ALL
            .into_iter()
            .filter(|method| !methods.contains(method))
            .collect();
    }

    Ok(methods)
}

/// Writes `methods` in libpq's `require_auth` syntax, so that it parses back to the same set.
pub(crate) fn format_require_auth(methods: &[PgAuthMethod]) -> String {
    if methods.is_empty() {
        return PgAuthMethod::ALL
            .iter()
            .map(|method| format!("!{method}"))
            .collect::<Vec<_>>()
            .join(",");
    }

    methods
        .iter()
        .map(|method| method.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;
    use PgAuthMethod::*;

    #[test]
    fn it_parses_a_plain_list() {
        assert_eq!(
            parse_require_auth("scram-sha-256,none").unwrap(),
            [ScramSha256, None]
        );
    }

    #[test]
    fn it_parses_a_negated_list() {
        assert_eq!(
            parse_require_auth("!password,!md5").unwrap(),
            [None, ScramSha256]
        );
    }

    #[test]
    fn it_accepts_gss_and_sspi_without_allowing_anything() {
        assert_eq!(
            parse_require_auth("gss,scram-sha-256").unwrap(),
            [ScramSha256]
        );
        assert_eq!(parse_require_auth("!sspi").unwrap(), PgAuthMethod::ALL);
    }

    #[test]
    fn it_rejects_invalid_lists() {
        for value in ["", "md5,!none", "!md5,none", "md5,md5", "scram", "MD5"] {
            assert!(
                parse_require_auth(value).is_err(),
                "{value:?} should not parse"
            );
        }
    }

    #[test]
    fn it_round_trips_through_the_url_format() {
        for methods in [&[ScramSha256][..], &[None, Md5], &PgAuthMethod::ALL, &[]] {
            let parsed = parse_require_auth(&format_require_auth(methods)).unwrap();

            assert_eq!(parsed, methods);
        }
    }
}
