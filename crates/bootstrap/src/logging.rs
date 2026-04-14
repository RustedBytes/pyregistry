use anyhow::{Context, Result};
use env_logger::{Logger, Target};
use log::{LevelFilter, Log, Metadata, Record, info, warn};
use pyregistry_infrastructure::{LoggingConfig, LoggingFileFormat, LoggingTimestamp};
use regex::Regex;
use serde_json::{Map, Value};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
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
pub(crate) fn init_logging(logging: &LoggingConfig, redact_logs: bool) -> Result<()> {
    let mut console_builder = logger_builder(logging);
    apply_plain_format(&mut console_builder, logging, redact_logs);
    let suppress_turso_connection = suppresses_turso_connection(&logging.filter);
    if let Some(file_path) = &logging.file_path {
        let console = console_builder.build();
        let mut file_builder = logger_builder(logging);
        file_builder.target(Target::Pipe(Box::new(open_log_file(file_path)?)));
        match logging.file_format {
            LoggingFileFormat::Plain => {
                apply_plain_format(&mut file_builder, logging, redact_logs);
            }
            LoggingFileFormat::Json => {
                let logging = logging.clone();
                file_builder.format(move |formatter, record| {
                    format_json_log(formatter, record, &logging, redact_logs)
                });
            }
        }
        let file = file_builder.build();
        let max_level = max_level(console.filter(), file.filter());
        log::set_boxed_logger(Box::new(SplitLogger {
            console,
            file,
            suppress_turso_connection,
        }))
        .context("failed to initialize logging")?;
        log::set_max_level(max_level);
        return Ok(());
    }
    let console = console_builder.build();
    let max_level = console.filter();
    log::set_boxed_logger(Box::new(SingleLogger {
        inner: console,
        suppress_turso_connection,
    }))
    .context("failed to initialize logging")?;
    log::set_max_level(max_level);
    Ok(())
}

fn logger_builder(logging: &LoggingConfig) -> env_logger::Builder {
    let mut builder = env_logger::Builder::new();
    builder.parse_filters(logging.filter.as_str());
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
    builder
}

fn apply_plain_format(
    builder: &mut env_logger::Builder,
    logging: &LoggingConfig,
    redact_logs: bool,
) {
    if redact_logs {
        let logging = logging.clone();
        builder.format(move |formatter, record| format_redacted_log(formatter, record, &logging));
    }
}

fn open_log_file(path: &Path) -> Result<File> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent).with_context(|| {
            format!("failed to create log file directory `{}`", parent.display())
        })?;
    }
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("failed to open log file `{}`", path.display()))
}

struct SplitLogger {
    console: Logger,
    file: Logger,
    suppress_turso_connection: bool,
}

impl Log for SplitLogger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        if self.suppresses_metadata(metadata) {
            return false;
        }
        self.console.enabled(metadata) || self.file.enabled(metadata)
    }

    fn log(&self, record: &Record<'_>) {
        if self.suppresses_record(record) {
            return;
        }
        self.console.log(record);
        self.file.log(record);
    }

    fn flush(&self) {
        self.console.flush();
        self.file.flush();
    }
}

impl SplitLogger {
    fn suppresses_metadata(&self, metadata: &Metadata<'_>) -> bool {
        self.suppress_turso_connection && is_turso_connection_target(metadata.target())
    }

    fn suppresses_record(&self, record: &Record<'_>) -> bool {
        suppresses_turso_connection_record(self.suppress_turso_connection, record)
    }
}

struct SingleLogger {
    inner: Logger,
    suppress_turso_connection: bool,
}

impl Log for SingleLogger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        if self.suppress_turso_connection && is_turso_connection_target(metadata.target()) {
            return false;
        }
        self.inner.enabled(metadata)
    }

    fn log(&self, record: &Record<'_>) {
        if suppresses_turso_connection_record(self.suppress_turso_connection, record) {
            return;
        }
        self.inner.log(record);
    }

    fn flush(&self) {
        self.inner.flush();
    }
}

fn suppresses_turso_connection(filter: &str) -> bool {
    let mut suppress = false;
    for directive in filter
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        let directive = directive
            .split_once('/')
            .map_or(directive, |(level, _)| level);
        let Some((target, level)) = directive.rsplit_once('=') else {
            continue;
        };
        if target.trim() == "turso_core::connection" {
            suppress = level.trim().eq_ignore_ascii_case("off");
        }
    }
    suppress
}

fn suppresses_turso_connection_record(suppress: bool, record: &Record<'_>) -> bool {
    suppress
        && (is_turso_connection_target(record.target())
            || record.module_path().is_some_and(is_turso_connection_target))
}

fn is_turso_connection_target(value: &str) -> bool {
    value == "turso_core::connection"
}

fn max_level(left: LevelFilter, right: LevelFilter) -> LevelFilter {
    if left > right { left } else { right }
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

fn format_json_log(
    formatter: &mut env_logger::fmt::Formatter,
    record: &log::Record<'_>,
    logging: &LoggingConfig,
    redact_logs: bool,
) -> std::io::Result<()> {
    let mut entry = Map::new();
    if let Some(timestamp) = log_timestamp(formatter, logging.timestamp) {
        entry.insert("timestamp".into(), Value::String(timestamp));
    }
    entry.insert("level".into(), Value::String(record.level().to_string()));
    if logging.module_path
        && let Some(module_path) = record.module_path()
    {
        entry.insert("module_path".into(), Value::String(module_path.to_string()));
    }
    if logging.target && !record.target().is_empty() {
        entry.insert("target".into(), Value::String(record.target().to_string()));
    }
    let message = record.args().to_string();
    let message = if redact_logs {
        redact_log_message(&message)
    } else {
        message
    };
    entry.insert("message".into(), Value::String(message));
    serde_json::to_writer(&mut *formatter, &Value::Object(entry))?;
    writeln!(formatter)
}

fn log_timestamp(
    formatter: &mut env_logger::fmt::Formatter,
    timestamp: LoggingTimestamp,
) -> Option<String> {
    match timestamp {
        LoggingTimestamp::Off => None,
        LoggingTimestamp::Seconds => Some(format!("{}", formatter.timestamp_seconds())),
        LoggingTimestamp::Millis => Some(format!("{}", formatter.timestamp_millis())),
        LoggingTimestamp::Micros => Some(format!("{}", formatter.timestamp_micros())),
        LoggingTimestamp::Nanos => Some(format!("{}", formatter.timestamp_nanos())),
    }
}

fn write_log_header(
    formatter: &mut env_logger::fmt::Formatter,
    record: &log::Record<'_>,
    logging: &LoggingConfig,
) -> std::io::Result<()> {
    let mut values = Vec::new();
    if let Some(timestamp) = log_timestamp(formatter, logging.timestamp) {
        values.push(timestamp);
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

#[cfg(test)]
mod tests {
    use super::{suppresses_turso_connection, suppresses_turso_connection_record};
    use log::{Level, Record};

    #[test]
    fn turso_connection_suppression_follows_configured_filter_directives() {
        assert!(suppresses_turso_connection(
            "info,turso_core::connection=off"
        ));
        assert!(!suppresses_turso_connection("info"));
        assert!(!suppresses_turso_connection(
            "info,turso_core::connection=off,turso_core::connection=info"
        ));
    }

    #[test]
    fn turso_connection_suppression_checks_module_path_and_target() {
        let args = format_args!("_prepare;");
        let module_path_record = Record::builder()
            .args(args)
            .level(Level::Info)
            .target("turso_core")
            .module_path(Some("turso_core::connection"))
            .build();
        assert!(suppresses_turso_connection_record(
            true,
            &module_path_record
        ));

        let args = format_args!("_prepare;");
        let target_record = Record::builder()
            .args(args)
            .level(Level::Info)
            .target("turso_core::connection")
            .module_path(Some("turso_core"))
            .build();
        assert!(suppresses_turso_connection_record(true, &target_record));
        assert!(!suppresses_turso_connection_record(false, &target_record));
    }
}
