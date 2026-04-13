use super::*;
use uuid::Uuid;

#[test]
fn round_trips_settings_through_toml_shape() {
    let original = Settings::new_local_template();
    let raw = toml::to_string_pretty(&SettingsFile::from(original.clone())).expect("serialize");
    let parsed: SettingsFile = toml::from_str(&raw).expect("parse");
    let round_trip = Settings::try_from(parsed).expect("settings");

    assert_eq!(round_trip.bind_address, original.bind_address);
    assert_eq!(round_trip.blob_root, original.blob_root);
    assert_eq!(round_trip.superadmin_email, original.superadmin_email);
    assert_eq!(round_trip.database_store, original.database_store);
    assert_eq!(
        round_trip.artifact_storage.backend,
        original.artifact_storage.backend
    );
    assert_eq!(
        round_trip.artifact_storage.opendal,
        original.artifact_storage.opendal
    );
    assert_eq!(round_trip.pypi.base_url, original.pypi.base_url);
    assert_eq!(
        round_trip.pypi.mirror_download_concurrency,
        original.pypi.mirror_download_concurrency
    );
    assert_eq!(
        round_trip.pypi.artifact_download_max_attempts,
        original.pypi.artifact_download_max_attempts
    );
    assert_eq!(
        round_trip.pypi.artifact_download_initial_backoff_millis,
        original.pypi.artifact_download_initial_backoff_millis
    );
    assert_eq!(
        round_trip.pypi.mirror_update_enabled,
        original.pypi.mirror_update_enabled
    );
    assert_eq!(
        round_trip.pypi.mirror_update_interval_seconds,
        original.pypi.mirror_update_interval_seconds
    );
    assert_eq!(
        round_trip.pypi.mirror_update_on_startup,
        original.pypi.mirror_update_on_startup
    );
    assert_eq!(
        round_trip.rate_limit.requests_per_minute,
        original.rate_limit.requests_per_minute
    );
    assert_eq!(round_trip.rate_limit.burst, original.rate_limit.burst);
    assert_eq!(
        round_trip.rate_limit.trust_proxy_headers,
        original.rate_limit.trust_proxy_headers
    );
    assert_eq!(
        round_trip.validation.distribution_parallelism,
        original.validation.distribution_parallelism
    );
    assert_eq!(
        round_trip.sqlite.as_ref().map(|sqlite| &sqlite.path),
        original.sqlite.as_ref().map(|sqlite| &sqlite.path)
    );
    assert_eq!(
        round_trip
            .postgres
            .as_ref()
            .map(|postgres| &postgres.connection_url),
        original
            .postgres
            .as_ref()
            .map(|postgres| &postgres.connection_url)
    );
    assert_eq!(round_trip.logging.filter, original.logging.filter);
    assert_eq!(round_trip.logging.module_path, original.logging.module_path);
    assert_eq!(round_trip.logging.target, original.logging.target);
    assert_eq!(
        round_trip.logging.timestamp.as_str(),
        original.logging.timestamp.as_str()
    );
    assert_eq!(round_trip.oidc_issuers.len(), original.oidc_issuers.len());
}

#[test]
fn rejects_zero_mirror_download_concurrency() {
    let error = PypiConfig::try_from(PypiConfigFile {
        base_url: "https://pypi.org".into(),
        mirror_download_concurrency: Some(0),
        artifact_download_max_attempts: Some(default_artifact_download_max_attempts()),
        artifact_download_initial_backoff_millis: Some(
            default_artifact_download_initial_backoff_millis(),
        ),
        mirror_update_enabled: Some(true),
        mirror_update_interval_seconds: Some(default_mirror_update_interval_seconds()),
        mirror_update_on_startup: Some(true),
    })
    .expect_err("zero concurrency should fail");

    assert!(matches!(error, SettingsError::InvalidPypiConfig(_)));
}

#[test]
fn rejects_zero_mirror_update_interval() {
    let error = PypiConfig::try_from(PypiConfigFile {
        base_url: "https://pypi.org".into(),
        mirror_download_concurrency: Some(default_mirror_download_concurrency()),
        artifact_download_max_attempts: Some(default_artifact_download_max_attempts()),
        artifact_download_initial_backoff_millis: Some(
            default_artifact_download_initial_backoff_millis(),
        ),
        mirror_update_enabled: Some(true),
        mirror_update_interval_seconds: Some(0),
        mirror_update_on_startup: Some(true),
    })
    .expect_err("zero update interval should fail");

    assert!(matches!(error, SettingsError::InvalidPypiConfig(_)));
}

#[test]
fn rejects_zero_artifact_download_retry_values() {
    let attempts_error = PypiConfig::try_from(PypiConfigFile {
        base_url: "https://pypi.org".into(),
        mirror_download_concurrency: Some(default_mirror_download_concurrency()),
        artifact_download_max_attempts: Some(0),
        artifact_download_initial_backoff_millis: Some(
            default_artifact_download_initial_backoff_millis(),
        ),
        mirror_update_enabled: Some(true),
        mirror_update_interval_seconds: Some(default_mirror_update_interval_seconds()),
        mirror_update_on_startup: Some(true),
    })
    .expect_err("zero artifact download attempts should fail");
    assert!(matches!(
        attempts_error,
        SettingsError::InvalidPypiConfig(_)
    ));

    let backoff_error = PypiConfig::try_from(PypiConfigFile {
        base_url: "https://pypi.org".into(),
        mirror_download_concurrency: Some(default_mirror_download_concurrency()),
        artifact_download_max_attempts: Some(default_artifact_download_max_attempts()),
        artifact_download_initial_backoff_millis: Some(0),
        mirror_update_enabled: Some(true),
        mirror_update_interval_seconds: Some(default_mirror_update_interval_seconds()),
        mirror_update_on_startup: Some(true),
    })
    .expect_err("zero artifact download backoff should fail");
    assert!(matches!(backoff_error, SettingsError::InvalidPypiConfig(_)));
}

#[test]
fn rejects_zero_rate_limit_values() {
    let error = RateLimitConfig::try_from(RateLimitConfigFile {
        enabled: true,
        requests_per_minute: 0,
        burst: 60,
        max_tracked_clients: 10_000,
        trust_proxy_headers: false,
    })
    .expect_err("zero requests per minute should fail");

    assert!(matches!(error, SettingsError::InvalidRateLimitConfig(_)));
}

#[test]
fn rejects_zero_validation_parallelism() {
    let error = ValidationConfig::try_from(ValidationConfigFile {
        distribution_parallelism: 0,
    })
    .expect_err("zero distribution validation parallelism should fail");

    assert!(matches!(error, SettingsError::InvalidValidationConfig(_)));
}

#[test]
fn minio_template_uses_s3_opendal_options() {
    let settings = Settings::new_minio_template();

    assert_eq!(
        settings.artifact_storage.backend,
        ArtifactStorageBackend::OpenDal
    );
    assert_eq!(settings.artifact_storage.opendal.scheme, "s3");
    assert_eq!(
        settings.artifact_storage.opendal.options.get("bucket"),
        Some(&"pyregistry".to_string())
    );
    assert_eq!(
        settings.artifact_storage.opendal.options.get("endpoint"),
        Some(&"http://127.0.0.1:9000".to_string())
    );
    assert_eq!(
        settings
            .artifact_storage
            .opendal
            .options
            .get("disable_config_load"),
        Some(&"true".to_string())
    );
}

#[test]
fn rejects_s3_storage_without_bucket() {
    let file = SettingsFile {
        bind_address: "127.0.0.1:3000".into(),
        blob_root: PathBuf::from(".pyregistry/blobs"),
        superadmin_email: "admin@pyregistry.local".into(),
        superadmin_password: "change-me-now".into(),
        cookie_secret: "secret".into(),
        database_store: Some("in-memory".into()),
        artifact_storage: Some(ArtifactStorageConfigFile {
            backend: Some("opendal".into()),
            opendal: Some(OpenDalStorageConfigFile {
                scheme: "s3".into(),
                options: BTreeMap::from([("endpoint".into(), "http://127.0.0.1:9000".into())]),
            }),
        }),
        pypi: Some(PypiConfigFile {
            base_url: "https://pypi.org".into(),
            mirror_download_concurrency: Some(default_mirror_download_concurrency()),
            artifact_download_max_attempts: Some(default_artifact_download_max_attempts()),
            artifact_download_initial_backoff_millis: Some(
                default_artifact_download_initial_backoff_millis(),
            ),
            mirror_update_enabled: Some(true),
            mirror_update_interval_seconds: Some(default_mirror_update_interval_seconds()),
            mirror_update_on_startup: Some(true),
        }),
        sqlite: Some(default_sqlite_config().into()),
        postgres: Some(default_postgres_config().into()),
        security: Some(default_security_config().into()),
        rate_limit: Some(default_rate_limit_config().into()),
        validation: Some(default_validation_config().into()),
        logging: Some(LoggingConfigFile {
            filter: "info".into(),
            module_path: true,
            target: false,
            timestamp: "seconds".into(),
        }),
        oidc_issuers: default_oidc_issuers().into_iter().map(Into::into).collect(),
    };

    let error = Settings::try_from(file).expect_err("missing bucket should fail");

    assert!(matches!(
        error,
        SettingsError::InvalidArtifactStorageConfig(_)
    ));
}

#[test]
fn write_local_config_includes_minio_s3_help() {
    let target = std::env::temp_dir().join(format!("pyregistry-{}.toml", Uuid::new_v4()));
    Settings::new_local_template()
        .write_to_path(&target, true)
        .expect("write config");

    let raw = fs::read_to_string(&target).expect("read config");

    assert!(raw.contains("MinIO/S3 artifact storage example"));
    assert!(raw.contains("# scheme = \"s3\""));
    assert!(raw.contains("# bucket = \"pyregistry\""));

    let _ = fs::remove_file(target);
}

#[test]
fn write_minio_config_uses_active_s3_fields() {
    let target = std::env::temp_dir().join(format!("pyregistry-{}.toml", Uuid::new_v4()));
    Settings::new_minio_template()
        .write_to_path(&target, true)
        .expect("write config");

    let raw = fs::read_to_string(&target).expect("read config");

    assert!(raw.contains("scheme = \"s3\""));
    assert!(raw.contains("bucket = \"pyregistry\""));
    assert!(raw.contains("endpoint = \"http://127.0.0.1:9000\""));
    assert!(raw.contains("disable_config_load = \"true\""));

    let loaded = Settings::load_from_path(&target).expect("load generated config");
    assert_eq!(loaded.artifact_storage.opendal.scheme, "s3");

    let _ = fs::remove_file(target);
}

#[test]
fn rejects_non_toml_config_paths() {
    let target = std::env::temp_dir().join(format!("pyregistry-{}.yaml", Uuid::new_v4()));
    let write_error = Settings::new_local_template()
        .write_to_path(&target, true)
        .expect_err("non-TOML config paths should fail on write");

    assert!(matches!(
        write_error,
        SettingsError::UnsupportedConfigFormat(_)
    ));

    fs::write(&target, "bind_address = \"127.0.0.1:3000\"").expect("write config fixture");
    let load_error =
        Settings::load_from_path(&target).expect_err("non-TOML config paths should fail on load");

    assert!(matches!(
        load_error,
        SettingsError::UnsupportedConfigFormat(_)
    ));

    let _ = fs::remove_file(target);
}

#[test]
fn rejects_pgsql_store_without_postgres_config() {
    let file = SettingsFile {
        bind_address: "127.0.0.1:3000".into(),
        blob_root: PathBuf::from(".pyregistry/blobs"),
        superadmin_email: "admin@pyregistry.local".into(),
        superadmin_password: "change-me-now".into(),
        cookie_secret: "secret".into(),
        database_store: Some("pgsql".into()),
        artifact_storage: Some(ArtifactStorageConfigFile {
            backend: Some("opendal".into()),
            opendal: Some(OpenDalStorageConfigFile {
                scheme: "fs".into(),
                options: BTreeMap::from([("root".into(), ".pyregistry/blobs".into())]),
            }),
        }),
        pypi: Some(PypiConfigFile {
            base_url: "https://pypi.org".into(),
            mirror_download_concurrency: Some(default_mirror_download_concurrency()),
            artifact_download_max_attempts: Some(default_artifact_download_max_attempts()),
            artifact_download_initial_backoff_millis: Some(
                default_artifact_download_initial_backoff_millis(),
            ),
            mirror_update_enabled: Some(true),
            mirror_update_interval_seconds: Some(default_mirror_update_interval_seconds()),
            mirror_update_on_startup: Some(true),
        }),
        sqlite: Some(default_sqlite_config().into()),
        postgres: None,
        security: Some(default_security_config().into()),
        rate_limit: Some(default_rate_limit_config().into()),
        validation: Some(default_validation_config().into()),
        logging: Some(LoggingConfigFile {
            filter: "info".into(),
            module_path: true,
            target: false,
            timestamp: "seconds".into(),
        }),
        oidc_issuers: default_oidc_issuers().into_iter().map(Into::into).collect(),
    };

    let error = Settings::try_from(file).expect_err("pgsql store should require postgres");
    assert!(matches!(error, SettingsError::InvalidDatabaseStore(_)));
}

#[test]
fn parses_database_store_aliases_and_rejects_unknown_values() {
    for (raw, expected) in [
        ("in-memory", DatabaseStoreKind::InMemory),
        ("inmemory", DatabaseStoreKind::InMemory),
        ("memory", DatabaseStoreKind::InMemory),
        ("mem", DatabaseStoreKind::InMemory),
        ("sqlite", DatabaseStoreKind::Sqlite),
        ("sqlite3", DatabaseStoreKind::Sqlite),
        ("pgsql", DatabaseStoreKind::Pgsql),
        ("postgres", DatabaseStoreKind::Pgsql),
        ("postgresql", DatabaseStoreKind::Pgsql),
    ] {
        assert_eq!(
            DatabaseStoreKind::parse(raw).expect("database store"),
            expected
        );
        assert!(!expected.as_str().is_empty());
    }

    assert!(matches!(
        DatabaseStoreKind::parse("mysql"),
        Err(SettingsError::InvalidDatabaseStore(_))
    ));
}

#[test]
fn parses_artifact_storage_aliases_and_rejects_unknown_values() {
    for (raw, expected) in [
        ("filesystem", ArtifactStorageBackend::FileSystem),
        ("file-system", ArtifactStorageBackend::FileSystem),
        ("fs", ArtifactStorageBackend::FileSystem),
        ("local", ArtifactStorageBackend::FileSystem),
        ("opendal", ArtifactStorageBackend::OpenDal),
    ] {
        assert_eq!(
            ArtifactStorageBackend::parse(raw).expect("artifact storage backend"),
            expected
        );
        assert!(!expected.as_str().is_empty());
    }

    assert!(matches!(
        ArtifactStorageBackend::parse("s3"),
        Err(SettingsError::InvalidArtifactStorageConfig(_))
    ));
}

#[test]
fn log_safe_summaries_are_human_readable_and_redact_secrets() {
    let storage = ArtifactStorageConfig {
        backend: ArtifactStorageBackend::OpenDal,
        opendal: OpenDalStorageConfig {
            scheme: "s3".into(),
            options: BTreeMap::from([
                ("bucket".into(), "pyregistry".into()),
                ("access_key_id".into(), "public-ish".into()),
                ("secret_access_key".into(), "secret".into()),
                ("session_token".into(), "token".into()),
                ("password".into(), "password".into()),
                ("root".into(), "/artifacts".into()),
            ]),
        },
    };

    let storage_summary = storage.log_safe_summary();
    assert!(storage_summary.contains("backend=opendal"));
    assert!(storage_summary.contains("bucket=pyregistry"));
    assert!(storage_summary.contains("root=/artifacts"));
    assert!(storage_summary.contains("access_key_id=<redacted>"));
    assert!(storage_summary.contains("secret_access_key=<redacted>"));
    assert!(storage_summary.contains("session_token=<redacted>"));
    assert!(storage_summary.contains("password=<redacted>"));
    assert!(!storage_summary.contains("secret_access_key=secret"));

    let postgres_summary = PostgresConfig {
        connection_url: "postgres://user:pass@db.example:5433/registry".into(),
        max_connections: 10,
        min_connections: 1,
        acquire_timeout_seconds: 5,
    }
    .log_safe_summary();
    assert!(postgres_summary.contains("db.example:5433/registry"));
    assert!(!postgres_summary.contains("user:pass"));

    let invalid_postgres_summary = PostgresConfig {
        connection_url: "not a url".into(),
        max_connections: 10,
        min_connections: 1,
        acquire_timeout_seconds: 5,
    }
    .log_safe_summary();
    assert!(invalid_postgres_summary.contains("endpoint=configured"));

    let settings = Settings::new_minio_template();
    let summary = settings.log_safe_summary();
    assert!(summary.contains("database_store=sqlite"));
    assert!(summary.contains("artifact_storage=backend=opendal"));
    assert!(summary.contains("oidc_issuers=1"));
    assert!(!summary.contains("pyregistry123"));
}

#[test]
fn component_log_summaries_include_operational_knobs() {
    let pypi = PypiConfig {
        base_url: "https://mirror.example".into(),
        mirror_download_concurrency: 8,
        artifact_download_max_attempts: 4,
        artifact_download_initial_backoff_millis: 125,
        mirror_update_enabled: false,
        mirror_update_interval_seconds: 30,
        mirror_update_on_startup: false,
    };
    assert_eq!(
        pypi.log_safe_summary(),
        "base_url=https://mirror.example, mirror_download_concurrency=8, artifact_download_max_attempts=4, artifact_download_initial_backoff_millis=125, mirror_update_enabled=false, mirror_update_interval_seconds=30, mirror_update_on_startup=false"
    );
    assert_eq!(
        SqliteConfig {
            path: PathBuf::from("registry.sqlite3")
        }
        .log_safe_summary(),
        "enabled(path=registry.sqlite3)"
    );
    assert_eq!(
        SecurityConfig {
            yara_rules_path: PathBuf::from("rules"),
            scanner_ignores: SecurityScannerIgnoreConfig {
                pysentry_vulnerability_ids: vec!["GHSA-demo".into()],
                yara_rule_ids: vec!["YaraDemo".into(), "sigfile:YaraOther".into()],
                foxguard_rule_ids: vec!["secret/aws-access-key-id".into()],
            },
            vulnerability_webhook: VulnerabilityWebhookConfig {
                url: Some("https://discord.example/api/webhooks/token".into()),
                username: Some("Security Bot".into()),
                timeout_seconds: 7,
            },
        }
        .log_safe_summary(),
        "yara_rules_path=rules, scanner_ignores=pysentry_vulnerability_ids=1, yara_rule_ids=2, foxguard_rule_ids=1, vulnerability_webhook=enabled(endpoint=discord.example/<redacted>, username=Security Bot, timeout_seconds=7)"
    );
    assert_eq!(
        RateLimitConfig {
            enabled: true,
            requests_per_minute: 1,
            burst: 2,
            max_tracked_clients: 3,
            trust_proxy_headers: true,
        }
        .log_safe_summary(),
        "enabled=true, requests_per_minute=1, burst=2, max_tracked_clients=3, trust_proxy_headers=true"
    );
    assert_eq!(
        ValidationConfig {
            distribution_parallelism: 7,
        }
        .log_safe_summary(),
        "distribution_parallelism=7"
    );
    assert_eq!(
        LoggingConfig {
            filter: "debug".into(),
            module_path: false,
            target: true,
            timestamp: LoggingTimestamp::Micros,
        }
        .log_safe_summary(),
        "filter=debug, module_path=false, target=true, timestamp=micros"
    );
}

#[test]
fn rejects_invalid_component_config_files() {
    assert!(matches!(
        OpenDalStorageConfig::try_from(OpenDalStorageConfigFile {
            scheme: " ".into(),
            options: BTreeMap::new(),
        }),
        Err(SettingsError::InvalidArtifactStorageConfig(_))
    ));
    assert!(matches!(
        PypiConfig::try_from(PypiConfigFile {
            base_url: " ".into(),
            mirror_download_concurrency: None,
            artifact_download_max_attempts: None,
            artifact_download_initial_backoff_millis: None,
            mirror_update_enabled: None,
            mirror_update_interval_seconds: None,
            mirror_update_on_startup: None,
        }),
        Err(SettingsError::InvalidPypiConfig(_))
    ));
    assert!(matches!(
        PypiConfig::try_from(PypiConfigFile {
            base_url: "not-a-url".into(),
            mirror_download_concurrency: None,
            artifact_download_max_attempts: None,
            artifact_download_initial_backoff_millis: None,
            mirror_update_enabled: None,
            mirror_update_interval_seconds: None,
            mirror_update_on_startup: None,
        }),
        Err(SettingsError::InvalidPypiConfig(_))
    ));
    assert!(matches!(
        PostgresConfig::try_from(PostgresConfigFile {
            connection_url: " ".into(),
            max_connections: 10,
            min_connections: 1,
            acquire_timeout_seconds: 5,
        }),
        Err(SettingsError::InvalidPostgresConfig(_))
    ));
    assert!(matches!(
        PostgresConfig::try_from(PostgresConfigFile {
            connection_url: "postgres://localhost/db".into(),
            max_connections: 1,
            min_connections: 2,
            acquire_timeout_seconds: 5,
        }),
        Err(SettingsError::InvalidPostgresConfig(_))
    ));
    assert!(matches!(
        PostgresConfig::try_from(PostgresConfigFile {
            connection_url: "postgres://localhost/db".into(),
            max_connections: 0,
            min_connections: 0,
            acquire_timeout_seconds: 5,
        }),
        Err(SettingsError::InvalidPostgresConfig(_))
    ));
    assert!(matches!(
        SqliteConfig::try_from(SqliteConfigFile {
            path: PathBuf::new()
        }),
        Err(SettingsError::InvalidSqliteConfig(_))
    ));
    assert!(matches!(
        SecurityConfig::try_from(SecurityConfigFile {
            yara_rules_path: PathBuf::new(),
            scanner_ignores: SecurityScannerIgnoreConfigFile::default(),
            vulnerability_webhook: None,
        }),
        Err(SettingsError::InvalidSecurityConfig(_))
    ));
    assert!(matches!(
        VulnerabilityWebhookConfig::try_from(VulnerabilityWebhookConfigFile {
            url: Some("file:///tmp/webhook".into()),
            username: None,
            timeout_seconds: Some(10),
        }),
        Err(SettingsError::InvalidSecurityConfig(_))
    ));
    assert!(matches!(
        VulnerabilityWebhookConfig::try_from(VulnerabilityWebhookConfigFile {
            url: Some("https://discord.example/webhook".into()),
            username: None,
            timeout_seconds: Some(0),
        }),
        Err(SettingsError::InvalidSecurityConfig(_))
    ));
    assert!(matches!(
        LoggingConfig::try_from(LoggingConfigFile {
            filter: " ".into(),
            module_path: true,
            target: false,
            timestamp: "seconds".into(),
        }),
        Err(SettingsError::InvalidLoggingConfig(_))
    ));
}

#[test]
fn rejects_all_zero_rate_limit_branches() {
    for config in [
        RateLimitConfigFile {
            enabled: true,
            requests_per_minute: 0,
            burst: 1,
            max_tracked_clients: 1,
            trust_proxy_headers: false,
        },
        RateLimitConfigFile {
            enabled: true,
            requests_per_minute: 1,
            burst: 0,
            max_tracked_clients: 1,
            trust_proxy_headers: false,
        },
        RateLimitConfigFile {
            enabled: true,
            requests_per_minute: 1,
            burst: 1,
            max_tracked_clients: 0,
            trust_proxy_headers: false,
        },
    ] {
        assert!(matches!(
            RateLimitConfig::try_from(config),
            Err(SettingsError::InvalidRateLimitConfig(_))
        ));
    }
}

#[test]
fn parses_logging_timestamp_aliases_and_rejects_unknown_values() {
    for (raw, expected) in [
        ("off", LoggingTimestamp::Off),
        ("none", LoggingTimestamp::Off),
        ("seconds", LoggingTimestamp::Seconds),
        ("secs", LoggingTimestamp::Seconds),
        ("sec", LoggingTimestamp::Seconds),
        ("millis", LoggingTimestamp::Millis),
        ("milliseconds", LoggingTimestamp::Millis),
        ("ms", LoggingTimestamp::Millis),
        ("micros", LoggingTimestamp::Micros),
        ("microseconds", LoggingTimestamp::Micros),
        ("us", LoggingTimestamp::Micros),
        ("nanos", LoggingTimestamp::Nanos),
        ("nanoseconds", LoggingTimestamp::Nanos),
        ("ns", LoggingTimestamp::Nanos),
    ] {
        let parsed = parse_logging_timestamp(raw).expect("timestamp");
        assert_eq!(parsed.as_str(), expected.as_str());
    }

    assert!(matches!(
        parse_logging_timestamp("minutes"),
        Err(SettingsError::InvalidLoggingConfig(_))
    ));
}

#[test]
fn validates_s3_opendal_options() {
    let valid = BTreeMap::from([
        ("bucket".into(), "pyregistry".into()),
        ("root".into(), "/artifacts".into()),
        ("endpoint".into(), "http://127.0.0.1:9000".into()),
    ]);
    validate_s3_opendal_options(&valid).expect("valid s3 options");

    let missing_bucket = BTreeMap::from([("endpoint".into(), "http://127.0.0.1:9000".into())]);
    assert!(matches!(
        validate_s3_opendal_options(&missing_bucket),
        Err(SettingsError::InvalidArtifactStorageConfig(_))
    ));

    let relative_root = BTreeMap::from([
        ("bucket".into(), "pyregistry".into()),
        ("root".into(), "artifacts".into()),
    ]);
    assert!(matches!(
        validate_s3_opendal_options(&relative_root),
        Err(SettingsError::InvalidArtifactStorageConfig(_))
    ));

    let empty_endpoint = BTreeMap::from([
        ("bucket".into(), "pyregistry".into()),
        ("endpoint".into(), " ".into()),
    ]);
    assert!(matches!(
        validate_s3_opendal_options(&empty_endpoint),
        Err(SettingsError::InvalidArtifactStorageConfig(_))
    ));
}

#[test]
fn converts_oidc_issuer_files_and_rejects_unknown_provider() {
    let github = OidcIssuerConfig::try_from(OidcIssuerConfigFile {
        provider: "github-actions".into(),
        issuer: "issuer".into(),
        jwks_url: "jwks".into(),
        audience: "aud".into(),
    })
    .expect("github issuer");
    assert_eq!(github.provider, TrustedPublisherProvider::GitHubActions);

    let gitlab = OidcIssuerConfig::try_from(OidcIssuerConfigFile {
        provider: "gitlab".into(),
        issuer: "issuer".into(),
        jwks_url: "jwks".into(),
        audience: "aud".into(),
    })
    .expect("gitlab issuer");
    assert_eq!(gitlab.provider, TrustedPublisherProvider::GitLab);

    let file = OidcIssuerConfigFile::from(gitlab);
    assert_eq!(file.provider, "gitlab");
    assert!(matches!(
        OidcIssuerConfig::try_from(OidcIssuerConfigFile {
            provider: "circleci".into(),
            issuer: "issuer".into(),
            jwks_url: "jwks".into(),
            audience: "aud".into(),
        }),
        Err(SettingsError::InvalidOidcProvider(_))
    ));
}

#[test]
fn write_config_refuses_overwrite_without_force_and_loads_parse_errors() {
    let target = std::env::temp_dir().join(format!("pyregistry-{}.toml", Uuid::new_v4()));
    Settings::new_local_template()
        .write_to_path(&target, true)
        .expect("initial write");

    let overwrite_error = Settings::new_local_template()
        .write_to_path(&target, false)
        .expect_err("overwrite should require force");
    assert!(matches!(overwrite_error, SettingsError::AlreadyExists(_)));

    fs::write(&target, "not = [valid").expect("write malformed toml");
    let parse_error = Settings::load_from_path(&target).expect_err("parse should fail");
    assert!(matches!(parse_error, SettingsError::ParseToml { .. }));

    let _ = fs::remove_file(target);
}

#[test]
fn loads_runtime_settings_from_environment() {
    let mut env = EnvGuard::new(&[
        "DATABASE_STORE",
        "BLOB_ROOT",
        "ARTIFACT_STORAGE_BACKEND",
        "OPENDAL_SCHEME",
        "OPENDAL_OPTIONS",
        "OPENDAL_ROOT",
        "DATABASE_URL",
        "POSTGRES_MAX_CONNECTIONS",
        "POSTGRES_MIN_CONNECTIONS",
        "POSTGRES_ACQUIRE_TIMEOUT_SECONDS",
        "SQLITE_PATH",
        "LOG_FILTER",
        "LOG_MODULE_PATH",
        "LOG_TARGET",
        "LOG_TIMESTAMP",
        "OIDC_ISSUERS",
        "BIND_ADDRESS",
        "SUPERADMIN_EMAIL",
        "SUPERADMIN_PASSWORD",
        "COOKIE_SECRET",
        "PYPI_URL",
        "PYPI_MIRROR_DOWNLOAD_CONCURRENCY",
        "PYPI_ARTIFACT_DOWNLOAD_MAX_ATTEMPTS",
        "PYPI_ARTIFACT_DOWNLOAD_INITIAL_BACKOFF_MILLIS",
        "PYPI_MIRROR_UPDATE_ENABLED",
        "PYPI_MIRROR_UPDATE_INTERVAL_SECONDS",
        "PYPI_MIRROR_UPDATE_ON_STARTUP",
        "YARA_RULES_PATH",
        "PYSENTRY_IGNORE_VULNERABILITY_IDS",
        "YARA_IGNORE_RULE_IDS",
        "FOXGUARD_IGNORE_RULE_IDS",
        "VULNERABILITY_WEBHOOK_URL",
        "VULNERABILITY_WEBHOOK_USERNAME",
        "VULNERABILITY_WEBHOOK_TIMEOUT_SECONDS",
        "RATE_LIMIT_ENABLED",
        "RATE_LIMIT_REQUESTS_PER_MINUTE",
        "RATE_LIMIT_BURST",
        "RATE_LIMIT_MAX_TRACKED_CLIENTS",
        "RATE_LIMIT_TRUST_PROXY_HEADERS",
        "VALIDATION_DISTRIBUTION_PARALLELISM",
    ]);
    env.set("DATABASE_STORE", "in-memory");
    env.set("BLOB_ROOT", "/tmp/pyregistry/blobs");
    env.set("ARTIFACT_STORAGE_BACKEND", "filesystem");
    env.set("OPENDAL_SCHEME", "fs");
    env.set("OPENDAL_OPTIONS", "cache=on, temporary = true ");
    env.set("OPENDAL_ROOT", "/tmp/pyregistry/custom-blobs");
    env.set(
        "DATABASE_URL",
        "postgres://user:pass@localhost:5432/registry",
    );
    env.set("POSTGRES_MAX_CONNECTIONS", "9");
    env.set("POSTGRES_MIN_CONNECTIONS", "3");
    env.set("POSTGRES_ACQUIRE_TIMEOUT_SECONDS", "7");
    env.set("SQLITE_PATH", "/tmp/pyregistry.sqlite3");
    env.set("LOG_FILTER", "debug,pyregistry=trace");
    env.set("LOG_MODULE_PATH", "false");
    env.set("LOG_TARGET", "true");
    env.set("LOG_TIMESTAMP", "nanos");
    env.set(
            "OIDC_ISSUERS",
            "github|https://github-issuer|https://github-issuer/jwks|pyregistry,gitlab|https://gitlab.example|https://gitlab.example/jwks|gitlab-aud",
        );
    env.set("BIND_ADDRESS", "0.0.0.0:8080");
    env.set("SUPERADMIN_EMAIL", "root@example.test");
    env.set("SUPERADMIN_PASSWORD", "secret");
    env.set("COOKIE_SECRET", "cookie-secret");
    env.set("PYPI_URL", "https://mirror.example/simple-root");
    env.set("PYPI_MIRROR_DOWNLOAD_CONCURRENCY", "6");
    env.set("PYPI_ARTIFACT_DOWNLOAD_MAX_ATTEMPTS", "5");
    env.set("PYPI_ARTIFACT_DOWNLOAD_INITIAL_BACKOFF_MILLIS", "100");
    env.set("PYPI_MIRROR_UPDATE_ENABLED", "off");
    env.set("PYPI_MIRROR_UPDATE_INTERVAL_SECONDS", "120");
    env.set("PYPI_MIRROR_UPDATE_ON_STARTUP", "no");
    env.set("YARA_RULES_PATH", "/tmp/yara");
    env.set(
        "PYSENTRY_IGNORE_VULNERABILITY_IDS",
        "GHSA-demo, CVE-2026-0001",
    );
    env.set("YARA_IGNORE_RULE_IDS", "Pyregistry_Test, sigdemo:OtherRule");
    env.set("FOXGUARD_IGNORE_RULE_IDS", "secret/aws-access-key-id");
    env.set(
        "VULNERABILITY_WEBHOOK_URL",
        "https://discord.example/api/webhooks/secret-token",
    );
    env.set("VULNERABILITY_WEBHOOK_USERNAME", "Security Bot");
    env.set("VULNERABILITY_WEBHOOK_TIMEOUT_SECONDS", "6");
    env.set("RATE_LIMIT_ENABLED", "yes");
    env.set("RATE_LIMIT_REQUESTS_PER_MINUTE", "240");
    env.set("RATE_LIMIT_BURST", "80");
    env.set("RATE_LIMIT_MAX_TRACKED_CLIENTS", "1234");
    env.set("RATE_LIMIT_TRUST_PROXY_HEADERS", "on");
    env.set("VALIDATION_DISTRIBUTION_PARALLELISM", "11");

    let settings = Settings::from_env().expect("settings from env");

    assert_eq!(settings.bind_address, "0.0.0.0:8080");
    assert_eq!(settings.database_store, DatabaseStoreKind::InMemory);
    assert_eq!(
        settings.artifact_storage.backend,
        ArtifactStorageBackend::FileSystem
    );
    assert_eq!(settings.artifact_storage.opendal.scheme, "fs");
    assert_eq!(
        settings.artifact_storage.opendal.options.get("root"),
        Some(&"/tmp/pyregistry/custom-blobs".to_string())
    );
    assert_eq!(
        settings.artifact_storage.opendal.options.get("cache"),
        Some(&"on".to_string())
    );
    assert_eq!(settings.pypi.base_url, "https://mirror.example/simple-root");
    assert_eq!(settings.pypi.mirror_download_concurrency, 6);
    assert_eq!(settings.pypi.artifact_download_max_attempts, 5);
    assert_eq!(settings.pypi.artifact_download_initial_backoff_millis, 100);
    assert!(!settings.pypi.mirror_update_enabled);
    assert_eq!(settings.pypi.mirror_update_interval_seconds, 120);
    assert!(!settings.pypi.mirror_update_on_startup);
    assert_eq!(settings.postgres.as_ref().unwrap().max_connections, 9);
    assert_eq!(settings.postgres.as_ref().unwrap().min_connections, 3);
    assert_eq!(
        settings.postgres.as_ref().unwrap().acquire_timeout_seconds,
        7
    );
    assert_eq!(
        settings.sqlite.as_ref().unwrap().path,
        PathBuf::from("/tmp/pyregistry.sqlite3")
    );
    assert_eq!(settings.logging.filter, "debug,pyregistry=trace");
    assert!(!settings.logging.module_path);
    assert!(settings.logging.target);
    assert_eq!(settings.logging.timestamp.as_str(), "nanos");
    assert_eq!(settings.oidc_issuers.len(), 2);
    assert_eq!(
        settings.oidc_issuers[1].provider,
        TrustedPublisherProvider::GitLab
    );
    assert_eq!(
        settings.security.yara_rules_path,
        PathBuf::from("/tmp/yara")
    );
    assert_eq!(
        settings.security.scanner_ignores.pysentry_vulnerability_ids,
        vec!["GHSA-demo", "CVE-2026-0001"]
    );
    assert_eq!(
        settings.security.scanner_ignores.yara_rule_ids,
        vec!["Pyregistry_Test", "sigdemo:OtherRule"]
    );
    assert_eq!(
        settings.security.scanner_ignores.foxguard_rule_ids,
        vec!["secret/aws-access-key-id"]
    );
    assert_eq!(
        settings.security.vulnerability_webhook.url.as_deref(),
        Some("https://discord.example/api/webhooks/secret-token")
    );
    assert_eq!(
        settings.security.vulnerability_webhook.username.as_deref(),
        Some("Security Bot")
    );
    assert_eq!(settings.security.vulnerability_webhook.timeout_seconds, 6);
    assert_eq!(settings.rate_limit.requests_per_minute, 240);
    assert_eq!(settings.rate_limit.burst, 80);
    assert_eq!(settings.rate_limit.max_tracked_clients, 1234);
    assert!(settings.rate_limit.trust_proxy_headers);
    assert_eq!(settings.validation.distribution_parallelism, 11);
}

#[test]
fn rejects_invalid_opendal_options_environment() {
    let mut env = EnvGuard::new(&["OPENDAL_OPTIONS"]);
    env.set("OPENDAL_OPTIONS", "valid=true,broken");

    let error = parse_opendal_options_env().expect_err("invalid options should fail");

    assert!(matches!(
        error,
        SettingsError::InvalidArtifactStorageConfig(_)
    ));
}

struct EnvGuard {
    saved: Vec<(&'static str, Option<String>)>,
}

impl EnvGuard {
    fn new(names: &[&'static str]) -> Self {
        let saved = names
            .iter()
            .map(|name| {
                let value = std::env::var(name).ok();
                // SAFETY: nextest executes each test case in an isolated process, and
                // this guard restores the process environment before the test exits.
                unsafe {
                    std::env::remove_var(name);
                }
                (*name, value)
            })
            .collect();
        Self { saved }
    }

    fn set(&mut self, name: &'static str, value: &str) {
        // SAFETY: see EnvGuard::new; environment mutation is scoped to this test process.
        unsafe {
            std::env::set_var(name, value);
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (name, value) in self.saved.drain(..) {
            // SAFETY: see EnvGuard::new; restoration happens before test process exit.
            unsafe {
                if let Some(value) = value {
                    std::env::set_var(name, value);
                } else {
                    std::env::remove_var(name);
                }
            }
        }
    }
}
