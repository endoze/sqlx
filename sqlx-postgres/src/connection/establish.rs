use crate::HashMap;

use crate::common::StatementCache;
use crate::connection::{sasl, stream::PgStream};
use crate::error::Error;
use crate::io::StatementId;
use crate::message::{
    Authentication, BackendKeyData, BackendMessageFormat, Password, ReadyForQuery, Startup,
};
use crate::{PgAuthMethod, PgConnectOptions, PgConnection};

use super::PgConnectionInner;

// https://www.postgresql.org/docs/current/protocol-flow.html#id-1.10.5.7.3
// https://www.postgresql.org/docs/current/protocol-flow.html#id-1.10.5.7.11

impl PgConnection {
    pub(crate) async fn establish(options: &PgConnectOptions) -> Result<Self, Error> {
        // Upgrade to TLS if we were asked to and the server supports it
        let mut stream = PgStream::connect(options).await?;

        // To begin a session, a frontend opens a connection to the server
        // and sends a startup message.

        let mut params = vec![
            // Sets the display format for date and time values,
            // as well as the rules for interpreting ambiguous date input values.
            ("DateStyle", "ISO, MDY"),
            // Sets the client-side encoding (character set).
            // <https://www.postgresql.org/docs/devel/multibyte.html#MULTIBYTE-CHARSET-SUPPORTED>
            ("client_encoding", "UTF8"),
            // Sets the time zone for displaying and interpreting time stamps.
            ("TimeZone", "UTC"),
        ];

        if let Some(ref extra_float_digits) = options.extra_float_digits {
            params.push(("extra_float_digits", extra_float_digits));
        }

        if let Some(ref application_name) = options.application_name {
            params.push(("application_name", application_name));
        }

        if let Some(ref options) = options.options {
            params.push(("options", options));
        }

        stream.write(Startup {
            username: Some(&options.username),
            database: options.database.as_deref(),
            params: &params,
        })?;

        stream.flush().await?;

        // The server then uses this information and the contents of
        // its configuration files (such as pg_hba.conf) to determine whether the connection is
        // provisionally acceptable, and what additional
        // authentication is required (if any).

        let mut process_id = 0;
        let mut secret_key = 0;
        let transaction_status;
        let mut auth_requested = false;

        loop {
            let message = stream.recv().await?;
            match message.format {
                BackendMessageFormat::Authentication => match message.decode()? {
                    Authentication::Ok => {
                        // the authentication exchange is successfully completed
                        if !auth_requested {
                            check_auth_method(options, PgAuthMethod::None)?;
                        }
                    }

                    Authentication::CleartextPassword => {
                        // The frontend must now send a [PasswordMessage] containing the
                        // password in clear-text form.

                        check_auth_method(options, PgAuthMethod::Password)?;
                        auth_requested = true;

                        stream
                            .send(Password::Cleartext(
                                options.password.as_deref().unwrap_or_default(),
                            ))
                            .await?;
                    }

                    Authentication::Md5Password(body) => {
                        // The frontend must now send a [PasswordMessage] containing the
                        // password (with user name) encrypted via MD5, then encrypted again
                        // using the 4-byte random salt specified in the
                        // [AuthenticationMD5Password] message.

                        check_auth_method(options, PgAuthMethod::Md5)?;
                        auth_requested = true;

                        stream
                            .send(Password::Md5 {
                                username: &options.username,
                                password: options.password.as_deref().unwrap_or_default(),
                                salt: body.salt,
                            })
                            .await?;
                    }

                    Authentication::Sasl(body) => {
                        check_auth_method(options, PgAuthMethod::ScramSha256)?;
                        auth_requested = true;

                        sasl::authenticate(&mut stream, options, body).await?;
                    }

                    method => {
                        return Err(err_protocol!(
                            "unsupported authentication method: {:?}",
                            method
                        ));
                    }
                },

                BackendMessageFormat::BackendKeyData => {
                    // provides secret-key data that the frontend must save if it wants to be
                    // able to issue cancel requests later

                    let data: BackendKeyData = message.decode()?;

                    process_id = data.process_id;
                    secret_key = data.secret_key;
                }

                BackendMessageFormat::ReadyForQuery => {
                    // start-up is completed. The frontend can now issue commands
                    transaction_status = message.decode::<ReadyForQuery>()?.transaction_status;

                    break;
                }

                _ => {
                    return Err(err_protocol!(
                        "establish: unexpected message: {:?}",
                        message.format
                    ))
                }
            }
        }

        Ok(PgConnection {
            inner: Box::new(PgConnectionInner {
                stream,
                process_id,
                secret_key,
                transaction_status,
                transaction_depth: 0,
                pending_ready_for_query_count: 0,
                next_statement_id: StatementId::NAMED_START,
                cache_statement: StatementCache::new(options.statement_cache_capacity),
                cache_type_oid: HashMap::new(),
                cache_type_info: HashMap::new(),
                cache_elem_type_to_array: HashMap::new(),
                cache_table_data: HashMap::new(),
                log_settings: options.log_settings.clone(),
            }),
        })
    }
}

/// Fails if `require_auth` is set and doesn't allow `method`.
fn check_auth_method(options: &PgConnectOptions, method: PgAuthMethod) -> Result<(), Error> {
    let Some(allowed) = &options.require_auth else {
        return Ok(());
    };

    if allowed.contains(&method) {
        return Ok(());
    }

    let reason = match method {
        PgAuthMethod::None => "server did not request authentication".to_owned(),
        method => format!("server requested {method} authentication"),
    };

    Err(Error::Configuration(
        format!("{reason}, which `require_auth` does not allow").into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_allows_every_method_by_default() {
        let options = PgConnectOptions::new_without_pgpass();

        check_auth_method(&options, PgAuthMethod::Password).unwrap();
        check_auth_method(&options, PgAuthMethod::None).unwrap();
    }

    #[test]
    fn it_refuses_methods_outside_require_auth() {
        let options =
            PgConnectOptions::new_without_pgpass().require_auth([PgAuthMethod::ScramSha256]);

        check_auth_method(&options, PgAuthMethod::ScramSha256).unwrap();

        for method in [
            PgAuthMethod::None,
            PgAuthMethod::Password,
            PgAuthMethod::Md5,
        ] {
            assert!(matches!(
                check_auth_method(&options, method),
                Err(Error::Configuration(_))
            ));
        }
    }
}
