use pyregistry_domain::TrustedPublisherProvider;
use rand::distr::{Alphanumeric, SampleString};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;
use url::Url;

const DEFAULT_CONFIG_PATH: &str = "pyregistry.toml";

#[derive(Debug, Clone)]
pub struct Settings {
    pub bind_address: String,
    pub blob_root: PathBuf,
    pub superadmin_email: String,
    pub superadmin_password: String,
    pub cookie_secret: String,
    pub database_store: DatabaseStoreKind,
    pub artifact_storage: ArtifactStorageConfig,
    pub pypi: PypiConfig,
    pub sqlite: Option<SqliteConfig>,
    pub postgres: Option<PostgresConfig>,
    pub security: SecurityConfig,
    pub rate_limit: RateLimitConfig,
    pub validation: ValidationConfig,
    pub logging: LoggingConfig,
    pub oidc_issuers: Vec<OidcIssuerConfig>,
}

impl Settings {
    pub fn from_env() -> Result<Self, SettingsError> {
        let database_store = std::env::var("DATABASE_STORE")
            .ok()
            .map(|raw| DatabaseStoreKind::parse(&raw))
            .transpose()?
            .unwrap_or(DatabaseStoreKind::Sqlite);
        let blob_root = std::env::var("BLOB_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(".pyregistry/blobs"));
        let artifact_storage = artifact_storage_from_env(&blob_root)?;
        let postgres = std::env::var("DATABASE_URL")
            .or_else(|_| std::env::var("POSTGRES_URL"))
            .ok()
            .map(|connection_url| PostgresConfig {
                connection_url,
                max_connections: read_env_u32("POSTGRES_MAX_CONNECTIONS", 20),
                min_connections: read_env_u32("POSTGRES_MIN_CONNECTIONS", 2),
                acquire_timeout_seconds: read_env_u64("POSTGRES_ACQUIRE_TIMEOUT_SECONDS", 10),
            });
        let sqlite = Some(SqliteConfig {
            path: std::env::var("SQLITE_PATH")
                .or_else(|_| std::env::var("SQLITE_DATABASE_PATH"))
                .map(PathBuf::from)
                .unwrap_or_else(|_| default_sqlite_config().path),
        });
        let logging = LoggingConfig {
            filter: std::env::var("LOG_FILTER").unwrap_or_else(|_| "info".into()),
            module_path: read_env_bool("LOG_MODULE_PATH", true),
            target: read_env_bool("LOG_TARGET", false),
            timestamp: read_env_timestamp("LOG_TIMESTAMP", LoggingTimestamp::Seconds),
        };
        let oidc_issuers = std::env::var("OIDC_ISSUERS")
            .ok()
            .map(|raw| {
                raw.split(',')
                    .filter_map(|entry| {
                        let parts: Vec<_> = entry.split('|').collect();
                        if parts.len() < 4 {
                            return None;
                        }

                        Some(OidcIssuerConfig {
                            provider: match parts[0].to_ascii_lowercase().as_str() {
                                "github" => TrustedPublisherProvider::GitHubActions,
                                _ => TrustedPublisherProvider::GitLab,
                            },
                            issuer: parts[1].to_string(),
                            jwks_url: parts[2].to_string(),
                            audience: parts[3].to_string(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_else(default_oidc_issuers);

        let settings = Self {
            bind_address: std::env::var("BIND_ADDRESS").unwrap_or_else(|_| "127.0.0.1:3000".into()),
            blob_root,
            superadmin_email: std::env::var("SUPERADMIN_EMAIL")
                .unwrap_or_else(|_| "admin@pyregistry.local".into()),
            superadmin_password: std::env::var("SUPERADMIN_PASSWORD")
                .unwrap_or_else(|_| "change-me-now".into()),
            cookie_secret: std::env::var("COOKIE_SECRET")
                .unwrap_or_else(|_| random_cookie_secret()),
            database_store,
            artifact_storage,
            pypi: PypiConfig {
                base_url: std::env::var("PYPI_BASE_URL")
                    .or_else(|_| std::env::var("PYPI_URL"))
                    .unwrap_or_else(|_| default_pypi_config().base_url),
                mirror_download_concurrency: read_env_usize(
                    "PYPI_MIRROR_DOWNLOAD_CONCURRENCY",
                    default_mirror_download_concurrency(),
                ),
                artifact_download_max_attempts: read_env_usize(
                    "PYPI_ARTIFACT_DOWNLOAD_MAX_ATTEMPTS",
                    default_artifact_download_max_attempts(),
                ),
                artifact_download_initial_backoff_millis: read_env_u64(
                    "PYPI_ARTIFACT_DOWNLOAD_INITIAL_BACKOFF_MILLIS",
                    default_artifact_download_initial_backoff_millis(),
                ),
                mirror_update_enabled: read_env_bool("PYPI_MIRROR_UPDATE_ENABLED", true),
                mirror_update_interval_seconds: read_env_u64(
                    "PYPI_MIRROR_UPDATE_INTERVAL_SECONDS",
                    default_mirror_update_interval_seconds(),
                ),
                mirror_update_on_startup: read_env_bool("PYPI_MIRROR_UPDATE_ON_STARTUP", true),
            },
            sqlite,
            postgres,
            security: SecurityConfig {
                yara_rules_path: std::env::var("YARA_RULES_PATH")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| default_security_config().yara_rules_path),
                scanner_ignores: SecurityScannerIgnoreConfig {
                    pysentry_vulnerability_ids: read_csv_env("PYSENTRY_IGNORE_VULNERABILITY_IDS"),
                    yara_rule_ids: read_csv_env("YARA_IGNORE_RULE_IDS"),
                    foxguard_rule_ids: read_csv_env("FOXGUARD_IGNORE_RULE_IDS"),
                },
                vulnerability_webhook: vulnerability_webhook_from_env()?,
            },
            rate_limit: RateLimitConfig {
                enabled: read_env_bool("RATE_LIMIT_ENABLED", true),
                requests_per_minute: read_env_u32(
                    "RATE_LIMIT_REQUESTS_PER_MINUTE",
                    default_rate_limit_config().requests_per_minute,
                ),
                burst: read_env_u32("RATE_LIMIT_BURST", default_rate_limit_config().burst),
                max_tracked_clients: read_env_usize(
                    "RATE_LIMIT_MAX_TRACKED_CLIENTS",
                    default_rate_limit_config().max_tracked_clients,
                ),
                trust_proxy_headers: read_env_bool("RATE_LIMIT_TRUST_PROXY_HEADERS", false),
            },
            validation: ValidationConfig {
                distribution_parallelism: read_env_usize(
                    "VALIDATION_DISTRIBUTION_PARALLELISM",
                    default_validation_parallelism(),
                ),
            },
            logging,
            oidc_issuers,
        };
        settings.validate()?;
        Ok(settings)
    }

    #[must_use]
    pub fn new_local_template() -> Self {
        Self {
            bind_address: "127.0.0.1:3000".into(),
            blob_root: PathBuf::from(".pyregistry/blobs"),
            superadmin_email: "admin@pyregistry.local".into(),
            superadmin_password: "change-me-now".into(),
            cookie_secret: random_cookie_secret(),
            database_store: DatabaseStoreKind::Sqlite,
            artifact_storage: default_artifact_storage_config(".pyregistry/blobs"),
            pypi: default_pypi_config(),
            sqlite: Some(default_sqlite_config()),
            postgres: Some(default_postgres_config()),
            security: default_security_config(),
            rate_limit: default_rate_limit_config(),
            validation: default_validation_config(),
            logging: default_logging_config(),
            oidc_issuers: default_oidc_issuers(),
        }
    }

    #[must_use]
    pub fn new_minio_template() -> Self {
        let mut settings = Self::new_local_template();
        settings.artifact_storage = minio_artifact_storage_config();
        settings
    }

    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self, SettingsError> {
        ensure_toml_config_path(path.as_ref())?;
        let raw = fs::read_to_string(path.as_ref()).map_err(|source| SettingsError::Io {
            path: path.as_ref().to_path_buf(),
            source,
        })?;
        let file: SettingsFile =
            toml::from_str(&raw).map_err(|source| SettingsError::ParseToml {
                path: path.as_ref().to_path_buf(),
                source,
            })?;
        file.try_into()
    }

    pub fn load_for_cli(config_path: Option<PathBuf>) -> Result<Self, SettingsError> {
        match config_path {
            Some(path) => Self::load_from_path(path),
            None => {
                let default_path = PathBuf::from(DEFAULT_CONFIG_PATH);
                if default_path.exists() {
                    Self::load_from_path(default_path)
                } else {
                    Self::from_env()
                }
            }
        }
    }

    pub fn write_to_path(&self, path: impl AsRef<Path>, force: bool) -> Result<(), SettingsError> {
        let path = path.as_ref();
        ensure_toml_config_path(path)?;
        if path.exists() && !force {
            return Err(SettingsError::AlreadyExists(path.to_path_buf()));
        }

        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).map_err(|source| SettingsError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }

        let file = SettingsFile::from(self.clone());
        let mut content = toml::to_string_pretty(&file).map_err(SettingsError::SerializeToml)?;
        append_artifact_storage_help(&mut content, &self.artifact_storage);
        fs::write(path, content).map_err(|source| SettingsError::Io {
            path: path.to_path_buf(),
            source,
        })
    }

    #[must_use]
    pub fn default_config_path() -> PathBuf {
        PathBuf::from(DEFAULT_CONFIG_PATH)
    }

    #[must_use]
    pub fn log_safe_summary(&self) -> String {
        format!(
            "bind_address={}, blob_root={}, superadmin_email={}, database_store={}, artifact_storage={}, pypi={}, sqlite={}, postgres={}, security={}, rate_limit={}, validation={}, logging={}, oidc_issuers={}",
            self.bind_address,
            self.blob_root.display(),
            self.superadmin_email,
            self.database_store.as_str(),
            self.artifact_storage.log_safe_summary(),
            self.pypi.log_safe_summary(),
            self.sqlite
                .as_ref()
                .map_or_else(|| "disabled".to_string(), SqliteConfig::log_safe_summary),
            self.postgres
                .as_ref()
                .map_or_else(|| "disabled".to_string(), PostgresConfig::log_safe_summary),
            self.security.log_safe_summary(),
            self.rate_limit.log_safe_summary(),
            self.validation.log_safe_summary(),
            self.logging.log_safe_summary(),
            self.oidc_issuers.len()
        )
    }

    fn validate(&self) -> Result<(), SettingsError> {
        if matches!(self.database_store, DatabaseStoreKind::Pgsql) && self.postgres.is_none() {
            return Err(SettingsError::InvalidDatabaseStore(
                "database_store `pgsql` requires a [postgres] config section or DATABASE_URL"
                    .into(),
            ));
        }
        if matches!(self.database_store, DatabaseStoreKind::Sqlite) && self.sqlite.is_none() {
            return Err(SettingsError::InvalidDatabaseStore(
                "database_store `sqlite` requires a [sqlite] config section or SQLITE_PATH".into(),
            ));
        }
        if let Some(sqlite) = &self.sqlite
            && sqlite.path.as_os_str().is_empty()
        {
            return Err(SettingsError::InvalidSqliteConfig(
                "sqlite path must not be empty".into(),
            ));
        }
        if self.artifact_storage.opendal.scheme.trim().is_empty() {
            return Err(SettingsError::InvalidArtifactStorageConfig(
                "opendal scheme must not be empty".into(),
            ));
        }
        if self.pypi.mirror_download_concurrency == 0 {
            return Err(SettingsError::InvalidPypiConfig(
                "mirror_download_concurrency must be greater than zero".into(),
            ));
        }
        if self.pypi.artifact_download_max_attempts == 0 {
            return Err(SettingsError::InvalidPypiConfig(
                "artifact_download_max_attempts must be greater than zero".into(),
            ));
        }
        if self.pypi.artifact_download_initial_backoff_millis == 0 {
            return Err(SettingsError::InvalidPypiConfig(
                "artifact_download_initial_backoff_millis must be greater than zero".into(),
            ));
        }
        if self.pypi.mirror_update_interval_seconds == 0 {
            return Err(SettingsError::InvalidPypiConfig(
                "mirror_update_interval_seconds must be greater than zero".into(),
            ));
        }
        if self.artifact_storage.opendal.scheme == "fs"
            && self
                .artifact_storage
                .opendal
                .options
                .get("root")
                .map(|root| root.trim().is_empty())
                .unwrap_or(true)
        {
            return Err(SettingsError::InvalidArtifactStorageConfig(
                "opendal fs storage requires options.root".into(),
            ));
        }
        if self.artifact_storage.opendal.scheme == "s3" {
            validate_s3_opendal_options(&self.artifact_storage.opendal.options)?;
        }
        if self.security.yara_rules_path.as_os_str().is_empty() {
            return Err(SettingsError::InvalidSecurityConfig(
                "security.yara_rules_path must not be empty".into(),
            ));
        }
        self.security.validate()?;
        self.rate_limit.validate()?;
        self.validation.validate()?;

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ArtifactStorageConfig {
    pub backend: ArtifactStorageBackend,
    pub opendal: OpenDalStorageConfig,
}

impl ArtifactStorageConfig {
    #[must_use]
    pub fn log_safe_summary(&self) -> String {
        match self.backend {
            ArtifactStorageBackend::FileSystem => {
                format!("backend=filesystem, {}", self.opendal.log_safe_summary())
            }
            ArtifactStorageBackend::OpenDal => {
                format!("backend=opendal, {}", self.opendal.log_safe_summary())
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactStorageBackend {
    FileSystem,
    OpenDal,
}

impl ArtifactStorageBackend {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FileSystem => "filesystem",
            Self::OpenDal => "opendal",
        }
    }

    fn parse(raw: &str) -> Result<Self, SettingsError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "filesystem" | "file-system" | "fs" | "local" => Ok(Self::FileSystem),
            "opendal" => Ok(Self::OpenDal),
            other => Err(SettingsError::InvalidArtifactStorageConfig(format!(
                "unsupported artifact storage backend `{other}`; expected `opendal` or `filesystem`"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenDalStorageConfig {
    pub scheme: String,
    pub options: BTreeMap<String, String>,
}

impl OpenDalStorageConfig {
    #[must_use]
    pub fn log_safe_summary(&self) -> String {
        let options = self
            .options
            .iter()
            .map(|(key, value)| {
                if is_sensitive_option_key(key) {
                    format!("{key}=<redacted>")
                } else {
                    format!("{key}={value}")
                }
            })
            .collect::<Vec<_>>()
            .join(",");
        format!("scheme={}, options={{{}}}", self.scheme, options)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseStoreKind {
    InMemory,
    Sqlite,
    Pgsql,
}

impl DatabaseStoreKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InMemory => "in-memory",
            Self::Sqlite => "sqlite",
            Self::Pgsql => "pgsql",
        }
    }

    fn parse(raw: &str) -> Result<Self, SettingsError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "in-memory" | "inmemory" | "memory" | "mem" => Ok(Self::InMemory),
            "sqlite" | "sqlite3" => Ok(Self::Sqlite),
            "pgsql" | "postgres" | "postgresql" => Ok(Self::Pgsql),
            other => Err(SettingsError::InvalidDatabaseStore(format!(
                "unsupported database_store `{other}`; expected `sqlite`, `in-memory`, or `pgsql`"
            ))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PypiConfig {
    pub base_url: String,
    pub mirror_download_concurrency: usize,
    pub artifact_download_max_attempts: usize,
    pub artifact_download_initial_backoff_millis: u64,
    pub mirror_update_enabled: bool,
    pub mirror_update_interval_seconds: u64,
    pub mirror_update_on_startup: bool,
}

impl PypiConfig {
    #[must_use]
    pub fn log_safe_summary(&self) -> String {
        format!(
            "base_url={}, mirror_download_concurrency={}, artifact_download_max_attempts={}, artifact_download_initial_backoff_millis={}, mirror_update_enabled={}, mirror_update_interval_seconds={}, mirror_update_on_startup={}",
            self.base_url,
            self.mirror_download_concurrency,
            self.artifact_download_max_attempts,
            self.artifact_download_initial_backoff_millis,
            self.mirror_update_enabled,
            self.mirror_update_interval_seconds,
            self.mirror_update_on_startup
        )
    }
}

#[derive(Debug, Clone)]
pub struct PostgresConfig {
    pub connection_url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub acquire_timeout_seconds: u64,
}

impl PostgresConfig {
    #[must_use]
    pub fn log_safe_summary(&self) -> String {
        let endpoint = Url::parse(&self.connection_url)
            .ok()
            .map(|url| {
                let host = url.host_str().unwrap_or("unknown");
                let port = url
                    .port()
                    .map_or_else(|| "default".to_string(), |port| port.to_string());
                let database = url.path().trim_start_matches('/');
                if database.is_empty() {
                    format!("{host}:{port}")
                } else {
                    format!("{host}:{port}/{database}")
                }
            })
            .unwrap_or_else(|| "configured".into());

        format!(
            "enabled(endpoint={}, min_connections={}, max_connections={}, acquire_timeout_seconds={})",
            endpoint, self.min_connections, self.max_connections, self.acquire_timeout_seconds
        )
    }
}

#[derive(Debug, Clone)]
pub struct SqliteConfig {
    pub path: PathBuf,
}

impl SqliteConfig {
    #[must_use]
    pub fn log_safe_summary(&self) -> String {
        format!("enabled(path={})", self.path.display())
    }
}

#[derive(Debug, Clone)]
pub struct SecurityConfig {
    pub yara_rules_path: PathBuf,
    pub scanner_ignores: SecurityScannerIgnoreConfig,
    pub vulnerability_webhook: VulnerabilityWebhookConfig,
}

impl SecurityConfig {
    #[must_use]
    pub fn log_safe_summary(&self) -> String {
        format!(
            "yara_rules_path={}, scanner_ignores={}, vulnerability_webhook={}",
            self.yara_rules_path.display(),
            self.scanner_ignores.log_safe_summary(),
            self.vulnerability_webhook.log_safe_summary()
        )
    }

    fn validate(&self) -> Result<(), SettingsError> {
        if self.yara_rules_path.as_os_str().is_empty() {
            return Err(SettingsError::InvalidSecurityConfig(
                "yara_rules_path must not be empty".into(),
            ));
        }
        self.vulnerability_webhook.validate()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecurityScannerIgnoreConfig {
    pub pysentry_vulnerability_ids: Vec<String>,
    pub yara_rule_ids: Vec<String>,
    pub foxguard_rule_ids: Vec<String>,
}

impl SecurityScannerIgnoreConfig {
    #[must_use]
    pub fn log_safe_summary(&self) -> String {
        format!(
            "pysentry_vulnerability_ids={}, yara_rule_ids={}, foxguard_rule_ids={}",
            self.pysentry_vulnerability_ids.len(),
            self.yara_rule_ids.len(),
            self.foxguard_rule_ids.len()
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VulnerabilityWebhookConfig {
    pub url: Option<String>,
    pub username: Option<String>,
    pub timeout_seconds: u64,
}

impl VulnerabilityWebhookConfig {
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.url.is_some()
    }

    #[must_use]
    pub fn log_safe_summary(&self) -> String {
        let Some(url) = &self.url else {
            return "disabled".into();
        };
        let endpoint = Url::parse(url)
            .ok()
            .map(|url| {
                let host = url.host_str().unwrap_or("configured");
                let path = url.path();
                if path.is_empty() || path == "/" {
                    host.to_string()
                } else {
                    format!("{host}/<redacted>")
                }
            })
            .unwrap_or_else(|| "configured".into());
        let username = self.username.as_deref().unwrap_or("default");
        format!(
            "enabled(endpoint={}, username={}, timeout_seconds={})",
            endpoint, username, self.timeout_seconds
        )
    }

    fn validate(&self) -> Result<(), SettingsError> {
        if self.timeout_seconds == 0 {
            return Err(SettingsError::InvalidSecurityConfig(
                "vulnerability_webhook.timeout_seconds must be greater than zero".into(),
            ));
        }
        let Some(url) = &self.url else {
            return Ok(());
        };
        let parsed = Url::parse(url).map_err(|error| {
            SettingsError::InvalidSecurityConfig(format!(
                "vulnerability_webhook.url must be a valid URL: {error}"
            ))
        })?;
        match parsed.scheme() {
            "http" | "https" => Ok(()),
            other => Err(SettingsError::InvalidSecurityConfig(format!(
                "vulnerability_webhook.url must use http or https, got `{other}`"
            ))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub requests_per_minute: u32,
    pub burst: u32,
    pub max_tracked_clients: usize,
    pub trust_proxy_headers: bool,
}

impl RateLimitConfig {
    #[must_use]
    pub fn log_safe_summary(&self) -> String {
        format!(
            "enabled={}, requests_per_minute={}, burst={}, max_tracked_clients={}, trust_proxy_headers={}",
            self.enabled,
            self.requests_per_minute,
            self.burst,
            self.max_tracked_clients,
            self.trust_proxy_headers
        )
    }

    fn validate(&self) -> Result<(), SettingsError> {
        if self.requests_per_minute == 0 {
            return Err(SettingsError::InvalidRateLimitConfig(
                "requests_per_minute must be greater than zero".into(),
            ));
        }
        if self.burst == 0 {
            return Err(SettingsError::InvalidRateLimitConfig(
                "burst must be greater than zero".into(),
            ));
        }
        if self.max_tracked_clients == 0 {
            return Err(SettingsError::InvalidRateLimitConfig(
                "max_tracked_clients must be greater than zero".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ValidationConfig {
    pub distribution_parallelism: usize,
}

impl ValidationConfig {
    #[must_use]
    pub fn log_safe_summary(&self) -> String {
        format!("distribution_parallelism={}", self.distribution_parallelism)
    }

    fn validate(&self) -> Result<(), SettingsError> {
        if self.distribution_parallelism == 0 {
            return Err(SettingsError::InvalidValidationConfig(
                "distribution_parallelism must be greater than zero".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct LoggingConfig {
    pub filter: String,
    pub module_path: bool,
    pub target: bool,
    pub timestamp: LoggingTimestamp,
}

impl LoggingConfig {
    #[must_use]
    pub fn log_safe_summary(&self) -> String {
        format!(
            "filter={}, module_path={}, target={}, timestamp={}",
            self.filter,
            self.module_path,
            self.target,
            self.timestamp.as_str()
        )
    }
}

#[derive(Debug, Clone, Copy)]
pub enum LoggingTimestamp {
    Off,
    Seconds,
    Millis,
    Micros,
    Nanos,
}

impl LoggingTimestamp {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Seconds => "seconds",
            Self::Millis => "millis",
            Self::Micros => "micros",
            Self::Nanos => "nanos",
        }
    }
}

#[derive(Debug, Clone)]
pub struct OidcIssuerConfig {
    pub provider: TrustedPublisherProvider,
    pub issuer: String,
    pub jwks_url: String,
    pub audience: String,
}

#[derive(Debug, Error)]
pub enum SettingsError {
    #[error("could not read or write config at `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("could not parse TOML config at `{path}`: {source}")]
    ParseToml {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("unsupported config file format for `{0}`; only .toml config files are supported")]
    UnsupportedConfigFormat(PathBuf),
    #[error("invalid OIDC provider `{0}` in config")]
    InvalidOidcProvider(String),
    #[error("invalid pypi config: {0}")]
    InvalidPypiConfig(String),
    #[error("invalid postgres config: {0}")]
    InvalidPostgresConfig(String),
    #[error("invalid sqlite config: {0}")]
    InvalidSqliteConfig(String),
    #[error("invalid database store config: {0}")]
    InvalidDatabaseStore(String),
    #[error("invalid artifact storage config: {0}")]
    InvalidArtifactStorageConfig(String),
    #[error("invalid security config: {0}")]
    InvalidSecurityConfig(String),
    #[error("invalid rate limit config: {0}")]
    InvalidRateLimitConfig(String),
    #[error("invalid validation config: {0}")]
    InvalidValidationConfig(String),
    #[error("invalid logging config: {0}")]
    InvalidLoggingConfig(String),
    #[error("could not serialize TOML config: {0}")]
    SerializeToml(#[source] toml::ser::Error),
    #[error("config file `{0}` already exists; pass --force to overwrite it")]
    AlreadyExists(PathBuf),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SettingsFile {
    bind_address: String,
    blob_root: PathBuf,
    superadmin_email: String,
    superadmin_password: String,
    cookie_secret: String,
    database_store: Option<String>,
    artifact_storage: Option<ArtifactStorageConfigFile>,
    pypi: Option<PypiConfigFile>,
    sqlite: Option<SqliteConfigFile>,
    postgres: Option<PostgresConfigFile>,
    security: Option<SecurityConfigFile>,
    rate_limit: Option<RateLimitConfigFile>,
    validation: Option<ValidationConfigFile>,
    logging: Option<LoggingConfigFile>,
    oidc_issuers: Vec<OidcIssuerConfigFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ArtifactStorageConfigFile {
    backend: Option<String>,
    opendal: Option<OpenDalStorageConfigFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OpenDalStorageConfigFile {
    scheme: String,
    #[serde(default)]
    options: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PypiConfigFile {
    base_url: String,
    mirror_download_concurrency: Option<usize>,
    artifact_download_max_attempts: Option<usize>,
    artifact_download_initial_backoff_millis: Option<u64>,
    mirror_update_enabled: Option<bool>,
    mirror_update_interval_seconds: Option<u64>,
    mirror_update_on_startup: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PostgresConfigFile {
    connection_url: String,
    max_connections: u32,
    min_connections: u32,
    acquire_timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SqliteConfigFile {
    path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SecurityConfigFile {
    yara_rules_path: PathBuf,
    #[serde(default)]
    scanner_ignores: SecurityScannerIgnoreConfigFile,
    vulnerability_webhook: Option<VulnerabilityWebhookConfigFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct SecurityScannerIgnoreConfigFile {
    #[serde(default)]
    pysentry_vulnerability_ids: Vec<String>,
    #[serde(default)]
    yara_rule_ids: Vec<String>,
    #[serde(default)]
    foxguard_rule_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VulnerabilityWebhookConfigFile {
    url: Option<String>,
    username: Option<String>,
    timeout_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RateLimitConfigFile {
    enabled: bool,
    requests_per_minute: u32,
    burst: u32,
    max_tracked_clients: usize,
    trust_proxy_headers: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ValidationConfigFile {
    distribution_parallelism: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LoggingConfigFile {
    filter: String,
    module_path: bool,
    target: bool,
    timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OidcIssuerConfigFile {
    provider: String,
    issuer: String,
    jwks_url: String,
    audience: String,
}

impl TryFrom<SettingsFile> for Settings {
    type Error = SettingsError;

    fn try_from(value: SettingsFile) -> Result<Self, Self::Error> {
        let artifact_storage = value
            .artifact_storage
            .map(ArtifactStorageConfig::try_from)
            .transpose()?
            .unwrap_or_else(|| default_artifact_storage_config(value.blob_root.to_string_lossy()));
        let settings = Self {
            bind_address: value.bind_address,
            blob_root: value.blob_root,
            superadmin_email: value.superadmin_email,
            superadmin_password: value.superadmin_password,
            cookie_secret: value.cookie_secret,
            database_store: value
                .database_store
                .as_deref()
                .map(DatabaseStoreKind::parse)
                .transpose()?
                .unwrap_or(DatabaseStoreKind::Sqlite),
            artifact_storage,
            pypi: value
                .pypi
                .map(PypiConfig::try_from)
                .transpose()?
                .unwrap_or_else(default_pypi_config),
            sqlite: Some(
                value
                    .sqlite
                    .map(SqliteConfig::try_from)
                    .transpose()?
                    .unwrap_or_else(default_sqlite_config),
            ),
            postgres: value.postgres.map(PostgresConfig::try_from).transpose()?,
            security: value
                .security
                .map(SecurityConfig::try_from)
                .transpose()?
                .unwrap_or_else(default_security_config),
            rate_limit: value
                .rate_limit
                .map(RateLimitConfig::try_from)
                .transpose()?
                .unwrap_or_else(default_rate_limit_config),
            validation: value
                .validation
                .map(ValidationConfig::try_from)
                .transpose()?
                .unwrap_or_else(default_validation_config),
            logging: value
                .logging
                .map(LoggingConfig::try_from)
                .transpose()?
                .unwrap_or_else(default_logging_config),
            oidc_issuers: value
                .oidc_issuers
                .into_iter()
                .map(OidcIssuerConfig::try_from)
                .collect::<Result<Vec<_>, _>>()?,
        };
        settings.validate()?;
        Ok(settings)
    }
}

impl From<Settings> for SettingsFile {
    fn from(value: Settings) -> Self {
        Self {
            bind_address: value.bind_address,
            blob_root: value.blob_root,
            superadmin_email: value.superadmin_email,
            superadmin_password: value.superadmin_password,
            cookie_secret: value.cookie_secret,
            database_store: Some(value.database_store.as_str().into()),
            artifact_storage: Some(value.artifact_storage.into()),
            pypi: Some(value.pypi.into()),
            sqlite: value.sqlite.map(Into::into),
            postgres: value.postgres.map(Into::into),
            security: Some(value.security.into()),
            rate_limit: Some(value.rate_limit.into()),
            validation: Some(value.validation.into()),
            logging: Some(value.logging.into()),
            oidc_issuers: value.oidc_issuers.into_iter().map(Into::into).collect(),
        }
    }
}

impl TryFrom<ArtifactStorageConfigFile> for ArtifactStorageConfig {
    type Error = SettingsError;

    fn try_from(value: ArtifactStorageConfigFile) -> Result<Self, Self::Error> {
        let backend = value
            .backend
            .as_deref()
            .map(ArtifactStorageBackend::parse)
            .transpose()?
            .unwrap_or(ArtifactStorageBackend::OpenDal);
        let opendal = value
            .opendal
            .map(OpenDalStorageConfig::try_from)
            .transpose()?
            .unwrap_or_else(|| default_opendal_storage_config(".pyregistry/blobs"));

        Ok(Self { backend, opendal })
    }
}

impl From<ArtifactStorageConfig> for ArtifactStorageConfigFile {
    fn from(value: ArtifactStorageConfig) -> Self {
        Self {
            backend: Some(value.backend.as_str().into()),
            opendal: Some(value.opendal.into()),
        }
    }
}

impl TryFrom<OpenDalStorageConfigFile> for OpenDalStorageConfig {
    type Error = SettingsError;

    fn try_from(value: OpenDalStorageConfigFile) -> Result<Self, Self::Error> {
        let scheme = value.scheme.trim().to_ascii_lowercase();
        if scheme.is_empty() {
            return Err(SettingsError::InvalidArtifactStorageConfig(
                "opendal scheme must not be empty".into(),
            ));
        }

        Ok(Self {
            scheme,
            options: value.options,
        })
    }
}

impl From<OpenDalStorageConfig> for OpenDalStorageConfigFile {
    fn from(value: OpenDalStorageConfig) -> Self {
        Self {
            scheme: value.scheme,
            options: value.options,
        }
    }
}

impl TryFrom<PypiConfigFile> for PypiConfig {
    type Error = SettingsError;

    fn try_from(value: PypiConfigFile) -> Result<Self, Self::Error> {
        let base_url = value.base_url.trim().trim_end_matches('/').to_string();
        if base_url.is_empty() {
            return Err(SettingsError::InvalidPypiConfig(
                "base_url must not be empty".into(),
            ));
        }
        Url::parse(&base_url).map_err(|error| {
            SettingsError::InvalidPypiConfig(format!("base_url must be a valid URL: {error}"))
        })?;
        let mirror_download_concurrency = value
            .mirror_download_concurrency
            .unwrap_or_else(default_mirror_download_concurrency);
        if mirror_download_concurrency == 0 {
            return Err(SettingsError::InvalidPypiConfig(
                "mirror_download_concurrency must be greater than zero".into(),
            ));
        }
        let artifact_download_max_attempts = value
            .artifact_download_max_attempts
            .unwrap_or_else(default_artifact_download_max_attempts);
        if artifact_download_max_attempts == 0 {
            return Err(SettingsError::InvalidPypiConfig(
                "artifact_download_max_attempts must be greater than zero".into(),
            ));
        }
        let artifact_download_initial_backoff_millis = value
            .artifact_download_initial_backoff_millis
            .unwrap_or_else(default_artifact_download_initial_backoff_millis);
        if artifact_download_initial_backoff_millis == 0 {
            return Err(SettingsError::InvalidPypiConfig(
                "artifact_download_initial_backoff_millis must be greater than zero".into(),
            ));
        }
        let mirror_update_interval_seconds = value
            .mirror_update_interval_seconds
            .unwrap_or_else(default_mirror_update_interval_seconds);
        if mirror_update_interval_seconds == 0 {
            return Err(SettingsError::InvalidPypiConfig(
                "mirror_update_interval_seconds must be greater than zero".into(),
            ));
        }

        Ok(Self {
            base_url,
            mirror_download_concurrency,
            artifact_download_max_attempts,
            artifact_download_initial_backoff_millis,
            mirror_update_enabled: value.mirror_update_enabled.unwrap_or(true),
            mirror_update_interval_seconds,
            mirror_update_on_startup: value.mirror_update_on_startup.unwrap_or(true),
        })
    }
}

impl From<PypiConfig> for PypiConfigFile {
    fn from(value: PypiConfig) -> Self {
        Self {
            base_url: value.base_url,
            mirror_download_concurrency: Some(value.mirror_download_concurrency),
            artifact_download_max_attempts: Some(value.artifact_download_max_attempts),
            artifact_download_initial_backoff_millis: Some(
                value.artifact_download_initial_backoff_millis,
            ),
            mirror_update_enabled: Some(value.mirror_update_enabled),
            mirror_update_interval_seconds: Some(value.mirror_update_interval_seconds),
            mirror_update_on_startup: Some(value.mirror_update_on_startup),
        }
    }
}

impl TryFrom<PostgresConfigFile> for PostgresConfig {
    type Error = SettingsError;

    fn try_from(value: PostgresConfigFile) -> Result<Self, Self::Error> {
        if value.connection_url.trim().is_empty() {
            return Err(SettingsError::InvalidPostgresConfig(
                "connection_url must not be empty".into(),
            ));
        }
        if value.min_connections > value.max_connections {
            return Err(SettingsError::InvalidPostgresConfig(
                "min_connections cannot be greater than max_connections".into(),
            ));
        }
        if value.max_connections == 0 {
            return Err(SettingsError::InvalidPostgresConfig(
                "max_connections must be greater than zero".into(),
            ));
        }

        Ok(Self {
            connection_url: value.connection_url,
            max_connections: value.max_connections,
            min_connections: value.min_connections,
            acquire_timeout_seconds: value.acquire_timeout_seconds,
        })
    }
}

impl From<PostgresConfig> for PostgresConfigFile {
    fn from(value: PostgresConfig) -> Self {
        Self {
            connection_url: value.connection_url,
            max_connections: value.max_connections,
            min_connections: value.min_connections,
            acquire_timeout_seconds: value.acquire_timeout_seconds,
        }
    }
}

impl TryFrom<SqliteConfigFile> for SqliteConfig {
    type Error = SettingsError;

    fn try_from(value: SqliteConfigFile) -> Result<Self, Self::Error> {
        if value.path.as_os_str().is_empty() {
            return Err(SettingsError::InvalidSqliteConfig(
                "path must not be empty".into(),
            ));
        }

        Ok(Self { path: value.path })
    }
}

impl From<SqliteConfig> for SqliteConfigFile {
    fn from(value: SqliteConfig) -> Self {
        Self { path: value.path }
    }
}

impl TryFrom<SecurityConfigFile> for SecurityConfig {
    type Error = SettingsError;

    fn try_from(value: SecurityConfigFile) -> Result<Self, Self::Error> {
        if value.yara_rules_path.as_os_str().is_empty() {
            return Err(SettingsError::InvalidSecurityConfig(
                "yara_rules_path must not be empty".into(),
            ));
        }

        let config = Self {
            yara_rules_path: value.yara_rules_path,
            scanner_ignores: value.scanner_ignores.into(),
            vulnerability_webhook: value
                .vulnerability_webhook
                .map(VulnerabilityWebhookConfig::try_from)
                .transpose()?
                .unwrap_or_else(default_vulnerability_webhook_config),
        };
        config.validate()?;
        Ok(config)
    }
}

impl From<SecurityConfig> for SecurityConfigFile {
    fn from(value: SecurityConfig) -> Self {
        Self {
            yara_rules_path: value.yara_rules_path,
            scanner_ignores: value.scanner_ignores.into(),
            vulnerability_webhook: Some(value.vulnerability_webhook.into()),
        }
    }
}

impl From<SecurityScannerIgnoreConfigFile> for SecurityScannerIgnoreConfig {
    fn from(value: SecurityScannerIgnoreConfigFile) -> Self {
        Self {
            pysentry_vulnerability_ids: clean_ignore_values(value.pysentry_vulnerability_ids),
            yara_rule_ids: clean_ignore_values(value.yara_rule_ids),
            foxguard_rule_ids: clean_ignore_values(value.foxguard_rule_ids),
        }
    }
}

impl From<SecurityScannerIgnoreConfig> for SecurityScannerIgnoreConfigFile {
    fn from(value: SecurityScannerIgnoreConfig) -> Self {
        Self {
            pysentry_vulnerability_ids: value.pysentry_vulnerability_ids,
            yara_rule_ids: value.yara_rule_ids,
            foxguard_rule_ids: value.foxguard_rule_ids,
        }
    }
}

impl TryFrom<VulnerabilityWebhookConfigFile> for VulnerabilityWebhookConfig {
    type Error = SettingsError;

    fn try_from(value: VulnerabilityWebhookConfigFile) -> Result<Self, Self::Error> {
        let config = Self {
            url: value
                .url
                .map(|url| url.trim().to_string())
                .filter(|url| !url.is_empty()),
            username: value
                .username
                .map(|username| username.trim().to_string())
                .filter(|username| !username.is_empty()),
            timeout_seconds: value
                .timeout_seconds
                .unwrap_or_else(default_vulnerability_webhook_timeout_seconds),
        };
        config.validate()?;
        Ok(config)
    }
}

impl From<VulnerabilityWebhookConfig> for VulnerabilityWebhookConfigFile {
    fn from(value: VulnerabilityWebhookConfig) -> Self {
        Self {
            url: value.url,
            username: value.username,
            timeout_seconds: Some(value.timeout_seconds),
        }
    }
}

impl TryFrom<RateLimitConfigFile> for RateLimitConfig {
    type Error = SettingsError;

    fn try_from(value: RateLimitConfigFile) -> Result<Self, Self::Error> {
        let config = Self {
            enabled: value.enabled,
            requests_per_minute: value.requests_per_minute,
            burst: value.burst,
            max_tracked_clients: value.max_tracked_clients,
            trust_proxy_headers: value.trust_proxy_headers,
        };
        config.validate()?;
        Ok(config)
    }
}

impl From<RateLimitConfig> for RateLimitConfigFile {
    fn from(value: RateLimitConfig) -> Self {
        Self {
            enabled: value.enabled,
            requests_per_minute: value.requests_per_minute,
            burst: value.burst,
            max_tracked_clients: value.max_tracked_clients,
            trust_proxy_headers: value.trust_proxy_headers,
        }
    }
}

impl TryFrom<ValidationConfigFile> for ValidationConfig {
    type Error = SettingsError;

    fn try_from(value: ValidationConfigFile) -> Result<Self, Self::Error> {
        let config = Self {
            distribution_parallelism: value.distribution_parallelism,
        };
        config.validate()?;
        Ok(config)
    }
}

impl From<ValidationConfig> for ValidationConfigFile {
    fn from(value: ValidationConfig) -> Self {
        Self {
            distribution_parallelism: value.distribution_parallelism,
        }
    }
}

impl TryFrom<LoggingConfigFile> for LoggingConfig {
    type Error = SettingsError;

    fn try_from(value: LoggingConfigFile) -> Result<Self, Self::Error> {
        let filter = value.filter.trim().to_string();
        if filter.is_empty() {
            return Err(SettingsError::InvalidLoggingConfig(
                "filter must not be empty".into(),
            ));
        }

        Ok(Self {
            filter,
            module_path: value.module_path,
            target: value.target,
            timestamp: parse_logging_timestamp(&value.timestamp)?,
        })
    }
}

impl From<LoggingConfig> for LoggingConfigFile {
    fn from(value: LoggingConfig) -> Self {
        Self {
            filter: value.filter,
            module_path: value.module_path,
            target: value.target,
            timestamp: value.timestamp.as_str().into(),
        }
    }
}

impl TryFrom<OidcIssuerConfigFile> for OidcIssuerConfig {
    type Error = SettingsError;

    fn try_from(value: OidcIssuerConfigFile) -> Result<Self, Self::Error> {
        let provider = match value.provider.to_ascii_lowercase().as_str() {
            "github" | "github-actions" => TrustedPublisherProvider::GitHubActions,
            "gitlab" => TrustedPublisherProvider::GitLab,
            _ => return Err(SettingsError::InvalidOidcProvider(value.provider)),
        };

        Ok(Self {
            provider,
            issuer: value.issuer,
            jwks_url: value.jwks_url,
            audience: value.audience,
        })
    }
}

impl From<OidcIssuerConfig> for OidcIssuerConfigFile {
    fn from(value: OidcIssuerConfig) -> Self {
        let provider = match value.provider {
            TrustedPublisherProvider::GitHubActions => "github",
            TrustedPublisherProvider::GitLab => "gitlab",
        };

        Self {
            provider: provider.into(),
            issuer: value.issuer,
            jwks_url: value.jwks_url,
            audience: value.audience,
        }
    }
}

fn default_oidc_issuers() -> Vec<OidcIssuerConfig> {
    vec![OidcIssuerConfig {
        provider: TrustedPublisherProvider::GitHubActions,
        issuer: "https://issuer.pyregistry.local".into(),
        jwks_url: "http://127.0.0.1:8081/jwks.json".into(),
        audience: "pyregistry".into(),
    }]
}

fn default_pypi_config() -> PypiConfig {
    PypiConfig {
        base_url: "https://pypi.org".into(),
        mirror_download_concurrency: default_mirror_download_concurrency(),
        artifact_download_max_attempts: default_artifact_download_max_attempts(),
        artifact_download_initial_backoff_millis: default_artifact_download_initial_backoff_millis(
        ),
        mirror_update_enabled: true,
        mirror_update_interval_seconds: default_mirror_update_interval_seconds(),
        mirror_update_on_startup: true,
    }
}

fn default_mirror_download_concurrency() -> usize {
    4
}

fn default_artifact_download_max_attempts() -> usize {
    3
}

fn default_artifact_download_initial_backoff_millis() -> u64 {
    250
}

fn default_mirror_update_interval_seconds() -> u64 {
    60 * 60
}

fn default_artifact_storage_config(root: impl AsRef<str>) -> ArtifactStorageConfig {
    ArtifactStorageConfig {
        backend: ArtifactStorageBackend::OpenDal,
        opendal: default_opendal_storage_config(root),
    }
}

fn default_opendal_storage_config(root: impl AsRef<str>) -> OpenDalStorageConfig {
    OpenDalStorageConfig {
        scheme: "fs".into(),
        options: BTreeMap::from([("root".into(), root.as_ref().into())]),
    }
}

fn minio_artifact_storage_config() -> ArtifactStorageConfig {
    ArtifactStorageConfig {
        backend: ArtifactStorageBackend::OpenDal,
        opendal: minio_opendal_storage_config(),
    }
}

fn minio_opendal_storage_config() -> OpenDalStorageConfig {
    OpenDalStorageConfig {
        scheme: "s3".into(),
        options: minio_opendal_options(),
    }
}

fn minio_opendal_options() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("bucket".into(), "pyregistry".into()),
        ("endpoint".into(), "http://127.0.0.1:9000".into()),
        ("region".into(), "us-east-1".into()),
        ("access_key_id".into(), "pyregistry".into()),
        ("secret_access_key".into(), "pyregistry123".into()),
        ("root".into(), "/artifacts".into()),
        ("disable_config_load".into(), "true".into()),
        ("disable_ec2_metadata".into(), "true".into()),
        ("enable_virtual_host_style".into(), "false".into()),
    ])
}

fn default_postgres_config() -> PostgresConfig {
    PostgresConfig {
        connection_url: "postgres://pyregistry:pyregistry@127.0.0.1:5432/pyregistry".into(),
        max_connections: 20,
        min_connections: 2,
        acquire_timeout_seconds: 10,
    }
}

fn default_sqlite_config() -> SqliteConfig {
    SqliteConfig {
        path: PathBuf::from(".pyregistry/pyregistry.sqlite3"),
    }
}

fn default_security_config() -> SecurityConfig {
    SecurityConfig {
        yara_rules_path: PathBuf::from("supplied/signature-base/yara"),
        scanner_ignores: SecurityScannerIgnoreConfig::default(),
        vulnerability_webhook: default_vulnerability_webhook_config(),
    }
}

fn default_vulnerability_webhook_config() -> VulnerabilityWebhookConfig {
    VulnerabilityWebhookConfig {
        url: None,
        username: Some("Pyregistry".into()),
        timeout_seconds: default_vulnerability_webhook_timeout_seconds(),
    }
}

fn default_vulnerability_webhook_timeout_seconds() -> u64 {
    10
}

fn default_rate_limit_config() -> RateLimitConfig {
    RateLimitConfig {
        enabled: true,
        requests_per_minute: 120,
        burst: 60,
        max_tracked_clients: 10_000,
        trust_proxy_headers: false,
    }
}

fn default_validation_config() -> ValidationConfig {
    ValidationConfig {
        distribution_parallelism: default_validation_parallelism(),
    }
}

fn default_validation_parallelism() -> usize {
    std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(4)
}

fn default_logging_config() -> LoggingConfig {
    LoggingConfig {
        filter: "info".into(),
        module_path: true,
        target: false,
        timestamp: LoggingTimestamp::Seconds,
    }
}

fn read_env_u32(name: &str, default: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|raw| raw.parse::<u32>().ok())
        .unwrap_or(default)
}

fn read_env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .unwrap_or(default)
}

fn read_env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn read_env_bool(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .and_then(|raw| match raw.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        })
        .unwrap_or(default)
}

fn read_csv_env(name: &str) -> Vec<String> {
    std::env::var(name)
        .ok()
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn clean_ignore_values(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect()
}

fn vulnerability_webhook_from_env() -> Result<VulnerabilityWebhookConfig, SettingsError> {
    let config = VulnerabilityWebhookConfig {
        url: std::env::var("VULNERABILITY_WEBHOOK_URL")
            .ok()
            .map(|url| url.trim().to_string())
            .filter(|url| !url.is_empty()),
        username: std::env::var("VULNERABILITY_WEBHOOK_USERNAME")
            .ok()
            .map(|username| username.trim().to_string())
            .filter(|username| !username.is_empty())
            .or_else(|| default_vulnerability_webhook_config().username),
        timeout_seconds: read_env_u64(
            "VULNERABILITY_WEBHOOK_TIMEOUT_SECONDS",
            default_vulnerability_webhook_timeout_seconds(),
        ),
    };
    config.validate()?;
    Ok(config)
}

fn artifact_storage_from_env(blob_root: &Path) -> Result<ArtifactStorageConfig, SettingsError> {
    let backend = std::env::var("ARTIFACT_STORAGE_BACKEND")
        .ok()
        .map(|raw| ArtifactStorageBackend::parse(&raw))
        .transpose()?
        .unwrap_or(ArtifactStorageBackend::OpenDal);
    let scheme = std::env::var("OPENDAL_SCHEME").unwrap_or_else(|_| "fs".into());
    let mut options = parse_opendal_options_env()?;

    for (env_name, option_name) in [
        ("OPENDAL_ROOT", "root"),
        ("OPENDAL_BUCKET", "bucket"),
        ("OPENDAL_ENDPOINT", "endpoint"),
        ("OPENDAL_REGION", "region"),
        ("OPENDAL_ACCESS_KEY_ID", "access_key_id"),
        ("OPENDAL_SECRET_ACCESS_KEY", "secret_access_key"),
        ("OPENDAL_SESSION_TOKEN", "session_token"),
        ("OPENDAL_DISABLE_CONFIG_LOAD", "disable_config_load"),
        ("OPENDAL_DISABLE_EC2_METADATA", "disable_ec2_metadata"),
        (
            "OPENDAL_ENABLE_VIRTUAL_HOST_STYLE",
            "enable_virtual_host_style",
        ),
        ("OPENDAL_ALLOW_ANONYMOUS", "allow_anonymous"),
    ] {
        if let Ok(value) = std::env::var(env_name) {
            options.insert(option_name.into(), value);
        }
    }

    if scheme.eq_ignore_ascii_case("fs") {
        options
            .entry("root".into())
            .or_insert_with(|| blob_root.to_string_lossy().into_owned());
    }

    Ok(ArtifactStorageConfig {
        backend,
        opendal: OpenDalStorageConfig {
            scheme: scheme.trim().to_ascii_lowercase(),
            options,
        },
    })
}

fn validate_s3_opendal_options(options: &BTreeMap<String, String>) -> Result<(), SettingsError> {
    require_opendal_option(
        options,
        "bucket",
        "opendal s3 storage requires options.bucket",
    )?;

    if let Some(root) = options.get("root").map(String::as_str).map(str::trim)
        && !root.is_empty()
        && !root.starts_with('/')
    {
        return Err(SettingsError::InvalidArtifactStorageConfig(
            "opendal s3 options.root must be an absolute prefix like `/artifacts`".into(),
        ));
    }

    if let Some(endpoint) = options.get("endpoint").map(String::as_str).map(str::trim)
        && endpoint.is_empty()
    {
        return Err(SettingsError::InvalidArtifactStorageConfig(
            "opendal s3 options.endpoint must not be empty when set".into(),
        ));
    }

    Ok(())
}

fn require_opendal_option(
    options: &BTreeMap<String, String>,
    key: &str,
    message: &str,
) -> Result<(), SettingsError> {
    if options
        .get(key)
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some()
    {
        return Ok(());
    }

    Err(SettingsError::InvalidArtifactStorageConfig(message.into()))
}

fn parse_opendal_options_env() -> Result<BTreeMap<String, String>, SettingsError> {
    let Some(raw) = std::env::var("OPENDAL_OPTIONS")
        .ok()
        .map(|raw| raw.trim().to_string())
        .filter(|raw| !raw.is_empty())
    else {
        return Ok(BTreeMap::new());
    };

    let mut options = BTreeMap::new();
    for entry in raw
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        let Some((key, value)) = entry.split_once('=') else {
            return Err(SettingsError::InvalidArtifactStorageConfig(format!(
                "OPENDAL_OPTIONS entry `{entry}` must use key=value syntax"
            )));
        };
        let key = key.trim();
        if key.is_empty() {
            return Err(SettingsError::InvalidArtifactStorageConfig(
                "OPENDAL_OPTIONS keys must not be empty".into(),
            ));
        }
        options.insert(key.into(), value.trim().into());
    }

    Ok(options)
}

fn is_sensitive_option_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.contains("secret")
        || key.contains("password")
        || key.contains("token")
        || key == "access_key_id"
        || key == "access_key"
}

fn read_env_timestamp(name: &str, default: LoggingTimestamp) -> LoggingTimestamp {
    std::env::var(name)
        .ok()
        .and_then(|raw| parse_logging_timestamp(&raw).ok())
        .unwrap_or(default)
}

fn parse_logging_timestamp(raw: &str) -> Result<LoggingTimestamp, SettingsError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "off" | "none" => Ok(LoggingTimestamp::Off),
        "seconds" | "secs" | "sec" => Ok(LoggingTimestamp::Seconds),
        "millis" | "milliseconds" | "ms" => Ok(LoggingTimestamp::Millis),
        "micros" | "microseconds" | "us" => Ok(LoggingTimestamp::Micros),
        "nanos" | "nanoseconds" | "ns" => Ok(LoggingTimestamp::Nanos),
        other => Err(SettingsError::InvalidLoggingConfig(format!(
            "unsupported timestamp value `{other}`"
        ))),
    }
}

fn random_cookie_secret() -> String {
    Alphanumeric.sample_string(&mut rand::rng(), 64)
}

fn ensure_toml_config_path(path: &Path) -> Result<(), SettingsError> {
    if path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| extension.eq_ignore_ascii_case("toml"))
        .unwrap_or(false)
    {
        return Ok(());
    }

    Err(SettingsError::UnsupportedConfigFormat(path.to_path_buf()))
}

fn append_artifact_storage_help(content: &mut String, artifact_storage: &ArtifactStorageConfig) {
    append_toml_artifact_storage_help(content, artifact_storage);
}

fn append_toml_artifact_storage_help(
    content: &mut String,
    artifact_storage: &ArtifactStorageConfig,
) {
    if artifact_storage.opendal.scheme == "s3" {
        content.push_str(
            r#"
# Artifact storage is configured for OpenDAL S3.
# The defaults above target the docker-compose MinIO service.
# Make sure the `pyregistry` bucket exists before serving.
"#,
        );
        return;
    }

    content.push_str(
        r#"
# MinIO/S3 artifact storage example:
# To use the docker-compose MinIO service, replace [artifact_storage.opendal]
# and [artifact_storage.opendal.options] above with the following fields.
#
# [artifact_storage.opendal]
# scheme = "s3"
#
# [artifact_storage.opendal.options]
# bucket = "pyregistry"
# endpoint = "http://127.0.0.1:9000"
# region = "us-east-1"
# access_key_id = "pyregistry"
# secret_access_key = "pyregistry123"
# root = "/artifacts"
# disable_config_load = "true"
# disable_ec2_metadata = "true"
# enable_virtual_host_style = "false"
"#,
    );
}

#[cfg(test)]
mod tests;
