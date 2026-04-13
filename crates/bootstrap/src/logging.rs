use env_logger::Env;
use log::{info, warn};
use pyregistry_infrastructure::{LoggingConfig, LoggingTimestamp};
use regex::Regex;
use std::io::Write;
use std::sync::LazyLock;

pub(crate) fn log_build_mode() {
    if cfg!(debug_assertions) {
        warn!(
            "running an unoptimized debug build; use `cargo run --release -p pyregistry -- ...` or `scripts/pyregistry-release.sh` for serving, mirroring, and wheel scans"
        );
    } else {
        info!("running optimized release build");
    }
}
pub(crate) fn init_logging(logging: &LoggingConfig, redact_logs: bool) {
    let mut builder =
        env_logger::Builder::from_env(Env::default().default_filter_or(logging.filter.as_str()));
    match logging.timestamp {
        LoggingTimestamp::Off => {
            builder.format_timestamp(None);
        }
        LoggingTimestamp::Seconds => {
            builder.format_timestamp_secs();
        }
        LoggingTimestamp::Millis => {
            builder.format_timestamp_millis();
        }
        LoggingTimestamp::Micros => {
            builder.format_timestamp_micros();
        }
        LoggingTimestamp::Nanos => {
            builder.format_timestamp_nanos();
        }
    }
    builder
        .format_module_path(logging.module_path)
        .format_target(logging.target);
    if redact_logs {
        let logging = logging.clone();
        builder.format(move |formatter, record| format_redacted_log(formatter, record, &logging));
    }
    builder.init();
}

fn format_redacted_log(
    formatter: &mut env_logger::fmt::Formatter,
    record: &log::Record<'_>,
    logging: &LoggingConfig,
) -> std::io::Result<()> {
    write_log_header(formatter, record, logging)?;
    writeln!(
        formatter,
        "{}",
        redact_log_message(&record.args().to_string())
    )
}

fn write_log_header(
    formatter: &mut env_logger::fmt::Formatter,
    record: &log::Record<'_>,
    logging: &LoggingConfig,
) -> std::io::Result<()> {
    let mut values = Vec::new();
    match logging.timestamp {
        LoggingTimestamp::Off => {}
        LoggingTimestamp::Seconds => values.push(format!("{}", formatter.timestamp_seconds())),
        LoggingTimestamp::Millis => values.push(format!("{}", formatter.timestamp_millis())),
        LoggingTimestamp::Micros => values.push(format!("{}", formatter.timestamp_micros())),
        LoggingTimestamp::Nanos => values.push(format!("{}", formatter.timestamp_nanos())),
    }
    values.push(format!("{:<5}", record.level()));
    if logging.module_path
        && let Some(module_path) = record.module_path()
    {
        values.push(module_path.to_string());
    }
    if logging.target && !record.target().is_empty() {
        values.push(record.target().to_string());
    }
    if values.is_empty() {
        Ok(())
    } else {
        write!(formatter, "[{}] ", values.join(" "))
    }
}

pub(crate) fn redact_log_message(message: &str) -> String {
    static URL_CREDENTIALS: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)\b([a-z][a-z0-9+.-]*://[^/\s:@]+:)[^@\s/]+@")
            .expect("URL credential redaction regex")
    });
    static AUTHORIZATION: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)\b((?:proxy-)?authorization)(\s*[:=]\s*)([^,\s]+)(?:\s+([^,\s]+))?")
            .expect("authorization redaction regex")
    });
    static SENSITIVE_KEY_VALUE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r#"(?ix)
            \b(
                admin_password|api[_-]?key|cookie|credential|oidc[_-]?token|
                pass(?:word|wd)?|secret|secret[_-]?access[_-]?key|session|
                session[_-]?token|token
            )\b
            (\s*[:=]\s*)
            (?:"[^"]*"|'[^']*'|`[^`]*`|[^"',`\s)\]}]+)
        "#,
        )
        .expect("sensitive key-value redaction regex")
    });
    static PYREGISTRY_TOKEN: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\b(?:oidc|pyr)_[A-Za-z0-9._~+/=-]{8,}\b")
            .expect("pyregistry token redaction regex")
    });
    static JWT: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
            .expect("JWT redaction regex")
    });
    static EMAIL: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
            .expect("email redaction regex")
    });

    let redacted = URL_CREDENTIALS.replace_all(message, "${1}<redacted>@");
    let redacted = AUTHORIZATION.replace_all(&redacted, |captures: &regex::Captures<'_>| {
        let key = &captures[1];
        let separator = &captures[2];
        let scheme_or_value = &captures[3];
        if matches!(
            scheme_or_value.to_ascii_lowercase().as_str(),
            "bearer" | "basic"
        ) {
            format!("{key}{separator}{scheme_or_value} <redacted>")
        } else {
            format!("{key}{separator}<redacted>")
        }
    });
    let redacted = SENSITIVE_KEY_VALUE.replace_all(&redacted, "$1$2<redacted>");
    let redacted = PYREGISTRY_TOKEN.replace_all(&redacted, "<redacted-token>");
    let redacted = JWT.replace_all(&redacted, "<redacted-jwt>");
    EMAIL
        .replace_all(&redacted, "<redacted-email>")
        .into_owned()
}
