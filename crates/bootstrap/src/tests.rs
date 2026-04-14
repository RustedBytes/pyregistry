use crate::cli::{
    Cli, Command, InitStorageTemplate, apply_cli_overrides, cli_debug_summary,
    describe_settings_source, init_config,
};
use crate::commands::{
    check_registry, create_tenant, ensure_wheel_is_available, validate_distribution,
    validate_registry_distributions,
};
use crate::logging::{log_build_mode, redact_log_message};
use crate::reports::{
    audit_heading, print_distribution_validation_report,
    print_registry_distribution_validation_report, print_registry_security_report,
    print_wheel_audit_report,
};
use crate::server::{
    WatchCancellation, enabled_build_features, force_http_shutdown_after_signal,
    log_mirror_refresh_report, spawn_mirror_updater, wait_for_mirror_updater,
};
use clap::{CommandFactory, Parser};
use pyregistry_application::{
    CancellationSignal, DistributionChecksumStatus, DistributionInspection, DistributionKind,
    DistributionValidationReport, MirrorRefreshReport, PackageSecuritySummary,
    RegistryDistributionValidationItem, RegistryDistributionValidationReport,
    RegistryDistributionValidationStatus, RegistryPackageSecurityReport, RegistrySecurityReport,
    WheelAuditFinding, WheelAuditFindingKind, WheelAuditReport, WheelSourceSecurityScanSummary,
    WheelVirusScanSummary,
};
use pyregistry_infrastructure::{
    ArtifactStorageBackend, DatabaseStoreKind, Settings, build_application,
};
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::sync::watch;
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

fn unique_suffix() -> String {
    format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos()
    )
}

fn in_memory_settings() -> Settings {
    let mut settings = Settings::new_local_template();
    settings.database_store = DatabaseStoreKind::InMemory;
    settings.sqlite = None;
    settings.blob_root =
        std::env::temp_dir().join(format!("pyregistry-cli-blobs-{}", unique_suffix()));
    settings.artifact_storage.backend = ArtifactStorageBackend::FileSystem;
    settings.pypi.mirror_update_enabled = false;
    settings.security.yara_rules_path = settings.blob_root.join("yara-rules");
    std::fs::create_dir_all(&settings.security.yara_rules_path)
        .expect("create test YARA rules dir");
    std::fs::write(
        settings
            .security
            .yara_rules_path
            .join("pyregistry-test.yar"),
        "rule PyregistryCliTestRule { condition: false }",
    )
    .expect("write test YARA rule");
    settings
}

#[test]
fn enabled_build_features_reports_active_cargo_features() {
    let features = enabled_build_features();

    assert!(features.iter().all(|feature| !feature.trim().is_empty()));
    if cfg!(feature = "sqlite") {
        assert!(features.iter().any(|feature| feature == "sqlite"));
    }
}

#[test]
fn cli_help_and_version_are_renderable() {
    Cli::command().debug_assert();

    let help = Cli::command().render_long_help().to_string();
    assert!(help.contains("Internal Python package registry service"));
    assert!(help.contains("--redact-logs"));
    assert!(help.contains("--yara-rules-path"));
    assert!(help.contains("--allow-insecure"));
    assert!(help.contains("validate-dist-all"));

    let version = Cli::try_parse_from(["pyregistry", "--version"]).expect_err("version exits");
    assert_eq!(version.kind(), clap::error::ErrorKind::DisplayVersion);
}

#[test]
fn cli_parses_subcommands_and_global_config() {
    let cli = Cli::try_parse_from([
        "pyregistry",
        "--config",
        "custom.toml",
        "init-config",
        "--path",
        "out.toml",
        "--storage",
        "minio",
        "--force",
    ])
    .expect("init-config");
    assert_eq!(cli.config.as_deref(), Some(Path::new("custom.toml")));
    assert!(!cli.redact_logs);
    assert!(matches!(
        cli.command,
        Some(Command::InitConfig {
            storage: InitStorageTemplate::Minio,
            force: true,
            ..
        })
    ));

    let cli = Cli::try_parse_from([
        "pyregistry",
        "--redact-logs",
        "audit-wheel",
        "--project",
        "rsloop",
        "--wheel",
        "rsloop.whl",
    ])
    .expect("audit-wheel");
    assert!(cli.redact_logs);
    assert!(matches!(cli.command, Some(Command::AuditWheel { .. })));

    let cli = Cli::try_parse_from([
        "pyregistry",
        "create-tenant",
        "--slug",
        "acme",
        "--display-name",
        "Acme Corp",
        "--admin-email",
        "tenant-admin@acme.test",
        "--admin-password",
        "tenant-secret",
        "--enable-mirroring",
    ])
    .expect("create-tenant");
    assert!(matches!(
        cli.command,
        Some(Command::CreateTenant {
            enable_mirroring: true,
            ..
        })
    ));
    let summary = cli_debug_summary(&cli);
    assert!(summary.contains("admin_password: <redacted>"));
    assert!(!summary.contains("tenant-secret"));

    let cli = Cli::try_parse_from([
        "pyregistry",
        "check-registry",
        "--yara-rules-path",
        "custom-yara",
    ])
    .expect("yara rules override");
    assert_eq!(
        cli.yara_rules_path.as_deref(),
        Some(Path::new("custom-yara"))
    );
    assert!(matches!(cli.command, Some(Command::CheckRegistry { .. })));

    let cli = Cli::try_parse_from([
        "pyregistry",
        "validate-dist-all",
        "--tenant",
        "acme",
        "--project",
        "demo",
        "--parallelism",
        "4",
    ])
    .expect("validate-dist-all");
    assert!(matches!(
        cli.command,
        Some(Command::ValidateDistAll {
            parallelism: Some(4),
            ..
        })
    ));

    let cli = Cli::try_parse_from(["pyregistry", "--allow-insecure", "serve"])
        .expect("allow insecure before serve");
    assert!(cli.allow_insecure);
    assert!(matches!(cli.command, Some(Command::Serve)));

    let cli = Cli::try_parse_from(["pyregistry", "serve", "--allow-insecure"])
        .expect("allow insecure after serve");
    assert!(cli.allow_insecure);
    assert!(matches!(cli.command, Some(Command::Serve)));
}

#[test]
fn cli_yara_rules_override_updates_settings_boundary_config() {
    let mut settings = Settings::new_local_template();

    apply_cli_overrides(&mut settings, Some(Path::new("rules/custom"))).expect("override");

    assert_eq!(
        settings.security.yara_rules_path,
        PathBuf::from("rules/custom")
    );
}

#[test]
fn log_redaction_removes_sensitive_values() {
    let message = concat!(
        "admin_email=admin@example.test admin_password=\"tenant secret\" ",
        "Authorization: Bearer pyr_abcdefghijklmnopqrstuvwxyz ",
        "oidc_token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.signature ",
        "url=https://__token__:pyr_secretsecret@registry.example/simple/ ",
        "cookie=admin_session=abc123"
    );

    let redacted = redact_log_message(message);

    assert!(redacted.contains("admin_email=<redacted-email>"));
    assert!(redacted.contains("admin_password=<redacted>"));
    assert!(redacted.contains("Authorization: Bearer <redacted>"));
    assert!(redacted.contains("oidc_token=<redacted>"));
    assert!(redacted.contains("https://__token__:<redacted>@registry.example/simple/"));
    assert!(redacted.contains("cookie=<redacted>"));
    assert!(!redacted.contains("admin@example.test"));
    assert!(!redacted.contains("tenant secret"));
    assert!(!redacted.contains("pyr_abcdefghijklmnopqrstuvwxyz"));
    assert!(!redacted.contains("signature"));
    assert!(!redacted.contains("abc123"));
}

#[test]
fn init_config_writes_toml_and_honors_force() {
    let path = std::env::temp_dir().join(format!("pyregistry-cli-{}.toml", unique_suffix()));
    init_config(
        Some(path.clone()),
        false,
        InitStorageTemplate::Local,
        Settings::new_local_template(),
    )
    .expect("write config");
    let content = std::fs::read_to_string(&path).expect("config content");
    assert!(content.contains("database_store"));

    let duplicate = init_config(
        Some(path.clone()),
        false,
        InitStorageTemplate::Local,
        Settings::new_local_template(),
    )
    .expect_err("duplicate");
    assert!(
        duplicate
            .to_string()
            .contains("failed to write config file")
    );

    init_config(
        Some(path.clone()),
        true,
        InitStorageTemplate::Minio,
        Settings::new_minio_template(),
    )
    .expect("force write");
    let content = std::fs::read_to_string(&path).expect("config content");
    assert!(content.contains("scheme = \"s3\""));

    let _ = std::fs::remove_file(path);
}

#[test]
fn describe_settings_source_reports_explicit_config_or_default_lookup() {
    assert_eq!(
        describe_settings_source(Some(Path::new("custom.toml"))),
        "explicit config file custom.toml"
    );

    let implicit = describe_settings_source(None);
    assert!(
        implicit == "environment variables" || implicit.starts_with("default config file "),
        "unexpected source: {implicit}"
    );
}

#[tokio::test]
async fn watch_cancellation_observes_shutdown_signal() {
    let (tx, rx) = watch::channel(false);
    let cancellation = WatchCancellation::new(rx);
    assert!(!cancellation.is_cancelled());

    tx.send(true).expect("send shutdown");
    cancellation.cancelled().await;
    assert!(cancellation.is_cancelled());
}

#[tokio::test]
async fn force_http_shutdown_waits_until_signal_then_grace_period() {
    let (tx, rx) = watch::channel(false);
    let task = tokio::spawn(force_http_shutdown_after_signal(
        rx,
        Duration::from_millis(1),
    ));
    assert!(!task.is_finished());

    tx.send(true).expect("send shutdown");
    task.await.expect("forced shutdown task");
}

#[tokio::test]
async fn validate_registry_distribution_command_rejects_ambiguous_scope_and_zero_parallelism() {
    let settings = Settings::new_local_template();

    let error = validate_registry_distributions(
        settings.clone(),
        "test".into(),
        None,
        Some("demo".into()),
        None,
    )
    .await
    .expect_err("project requires tenant");
    assert!(error.to_string().contains("--project requires --tenant"));

    let error = validate_registry_distributions(
        settings,
        "test".into(),
        Some("acme".into()),
        None,
        Some(0),
    )
    .await
    .expect_err("parallelism");
    assert!(error.to_string().contains("--parallelism"));
}

#[tokio::test]
async fn check_registry_command_rejects_project_without_tenant() {
    let error = check_registry(
        Settings::new_local_template(),
        "test".into(),
        None,
        Some("demo".into()),
    )
    .await
    .expect_err("project requires tenant");

    assert!(error.to_string().contains("--project requires --tenant"));
}

#[tokio::test]
async fn registry_commands_succeed_for_empty_in_memory_registry() {
    let settings = in_memory_settings();

    check_registry(settings.clone(), "test settings".into(), None, None)
        .await
        .expect("empty registry security check");
    validate_registry_distributions(
        settings.clone(),
        "test settings".into(),
        None,
        None,
        Some(1),
    )
    .await
    .expect("empty registry distribution validation");

    let _ = std::fs::remove_dir_all(settings.blob_root);
}

#[tokio::test]
async fn create_tenant_command_creates_tenant_and_admin() {
    let mut settings = in_memory_settings();
    let sqlite_path =
        std::env::temp_dir().join(format!("pyregistry-cli-{}.sqlite3", unique_suffix()));
    settings.database_store = DatabaseStoreKind::Sqlite;
    settings.sqlite = Some(pyregistry_infrastructure::SqliteConfig {
        path: sqlite_path.clone(),
    });

    create_tenant(
        settings.clone(),
        "test settings".into(),
        "acme".into(),
        "Acme Corp".into(),
        "tenant-admin@acme.test".into(),
        "tenant-secret".into(),
        true,
    )
    .await
    .expect("create tenant");

    let app = build_application(&settings)
        .await
        .expect("build application");
    let tenants = app.list_tenants().await.expect("tenants");
    assert_eq!(tenants.len(), 1);
    assert_eq!(tenants[0].slug.as_str(), "acme");
    assert!(tenants[0].mirror_rule.enabled);
    assert!(
        app.login_admin("tenant-admin@acme.test", "tenant-secret")
            .await
            .is_ok()
    );

    let _ = std::fs::remove_file(sqlite_path);
    let _ = std::fs::remove_dir_all(settings.blob_root);
}

#[tokio::test]
async fn ensure_wheel_is_available_accepts_existing_local_file() {
    let path = std::env::temp_dir().join(format!("pyregistry-cli-{}.whl", unique_suffix()));
    std::fs::write(&path, b"not a real wheel, only an existence check").expect("wheel file");

    ensure_wheel_is_available("demo", &path, &Settings::new_local_template())
        .await
        .expect("local wheel");

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn ensure_wheel_is_available_rejects_missing_path_without_filename() {
    let error = ensure_wheel_is_available("demo", Path::new(""), &Settings::new_local_template())
        .await
        .expect_err("empty path has no downloadable filename");

    assert!(error.to_string().contains("does not contain a file name"));
}

#[test]
fn validate_distribution_accepts_matching_checksum_and_rejects_mismatch() {
    let bytes = build_source_zip_bytes();
    let path = std::env::temp_dir().join(format!("pyregistry-cli-{}.zip", unique_suffix()));
    std::fs::write(&path, &bytes).expect("write zip");

    validate_distribution(path.clone(), None).expect("valid distribution");
    let error = validate_distribution(path.clone(), Some("a".repeat(64)))
        .expect_err("checksum mismatch should fail");
    assert!(error.to_string().contains("distribution validation failed"));

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn mirror_updater_respects_disabled_config_and_shutdown_signal() {
    let mut settings = in_memory_settings();
    let app = build_application(&settings)
        .await
        .expect("build test application");
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    assert!(spawn_mirror_updater(app.clone(), &settings, shutdown_rx).is_none());

    settings.pypi.mirror_update_enabled = true;
    settings.pypi.mirror_update_on_startup = false;
    settings.pypi.mirror_update_interval_seconds = 3600;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let handle = spawn_mirror_updater(app, &settings, shutdown_rx).expect("mirror updater task");
    shutdown_tx.send(true).expect("send shutdown");
    wait_for_mirror_updater(Some(handle)).await;

    let _ = std::fs::remove_dir_all(settings.blob_root);
}

#[tokio::test]
async fn force_http_shutdown_returns_when_shutdown_channel_closes() {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(force_http_shutdown_after_signal(
        shutdown_rx,
        Duration::from_secs(60),
    ));
    drop(shutdown_tx);

    task.await.expect("forced shutdown task");
}

#[test]
fn prints_distribution_validation_reports_for_all_checksum_states() {
    for checksum in [
        DistributionChecksumStatus::NotProvided,
        DistributionChecksumStatus::Matched {
            expected: "a".repeat(64),
        },
        DistributionChecksumStatus::Mismatched {
            expected: "a".repeat(64),
            actual: "b".repeat(64),
        },
    ] {
        print_distribution_validation_report(&DistributionValidationReport {
            file_path: PathBuf::from("demo-1.0.0.zip"),
            inspection: DistributionInspection {
                kind: DistributionKind::SourceZip,
                size_bytes: 123,
                sha256: "b".repeat(64),
                archive_entry_count: 2,
                file_type: pyregistry_application::FileTypeInspection {
                    detector: "fake".into(),
                    label: "zip".into(),
                    mime_type: "application/zip".into(),
                    group: "archive".into(),
                    description: "Zip archive data".into(),
                    score: 1.0,
                    actual_extension: Some("zip".into()),
                    expected_extensions: vec!["zip".into()],
                    matches_extension: true,
                },
            },
            checksum,
        });
    }
}

#[test]
fn prints_registry_distribution_validation_reports_for_empty_valid_and_invalid_sets() {
    print_registry_distribution_validation_report(&RegistryDistributionValidationReport::default());

    let mut valid = RegistryDistributionValidationReport::default();
    valid.push_item(registry_validation_item(
        RegistryDistributionValidationStatus::Valid,
        None,
        None,
        None,
        None,
    ));
    print_registry_distribution_validation_report(&valid);

    let mut invalid = RegistryDistributionValidationReport::default();
    invalid.push_item(registry_validation_item(
        RegistryDistributionValidationStatus::ChecksumMismatch,
        Some("b".repeat(64)),
        Some(321),
        Some(5),
        Some("checksum mismatch".into()),
    ));
    invalid.push_item(registry_validation_item(
        RegistryDistributionValidationStatus::MissingBlob,
        None,
        None,
        None,
        Some("not found".into()),
    ));
    print_registry_distribution_validation_report(&invalid);
}

fn registry_validation_item(
    status: RegistryDistributionValidationStatus,
    actual_sha256: Option<String>,
    actual_size_bytes: Option<u64>,
    archive_entry_count: Option<usize>,
    error: Option<String>,
) -> RegistryDistributionValidationItem {
    RegistryDistributionValidationItem {
        tenant_slug: "acme".into(),
        project_name: "demo".into(),
        version: "1.0.0".into(),
        filename: "demo-1.0.0.zip".into(),
        object_key: "objects/demo.zip".into(),
        expected_sha256: "a".repeat(64),
        actual_sha256,
        recorded_size_bytes: 123,
        actual_size_bytes,
        kind: Some(DistributionKind::SourceZip),
        detected_file_type: Some("zip".into()),
        detected_mime_type: Some("application/zip".into()),
        extension_matches: Some(true),
        archive_entry_count,
        status,
        error,
    }
}

#[test]
fn prints_wheel_audit_report_for_clean_and_findings_cases() {
    print_wheel_audit_report(&WheelAuditReport {
        project_name: "demo".into(),
        wheel_filename: "demo.whl".into(),
        scanned_file_count: 1,
        source_security_scan: WheelSourceSecurityScanSummary::default(),
        virus_scan: WheelVirusScanSummary::default(),
        findings: Vec::new(),
    });

    let findings = [
        WheelAuditFindingKind::UnexpectedExecutable,
        WheelAuditFindingKind::NetworkString,
        WheelAuditFindingKind::PostInstallClue,
        WheelAuditFindingKind::PythonAstSuspiciousBehavior,
        WheelAuditFindingKind::SuspiciousDependency,
        WheelAuditFindingKind::SourceSecurityFinding,
        WheelAuditFindingKind::VirusSignatureMatch,
    ]
    .into_iter()
    .map(|kind| {
        let heading = audit_heading(kind.clone());
        WheelAuditFinding {
            kind,
            path: Some("demo/__init__.py".into()),
            summary: format!("finding for {heading}"),
            evidence: vec!["evidence".into()],
        }
    })
    .collect();

    print_wheel_audit_report(&WheelAuditReport {
        project_name: "demo".into(),
        wheel_filename: "demo.whl".into(),
        scanned_file_count: 7,
        source_security_scan: WheelSourceSecurityScanSummary {
            enabled: true,
            scanned_file_count: 7,
            finding_count: 1,
            scan_error: Some("foxguard warning".into()),
        },
        virus_scan: WheelVirusScanSummary {
            enabled: true,
            scanned_file_count: 7,
            signature_rule_count: 100,
            skipped_rule_count: 2,
            match_count: 1,
            scan_error: Some("yara warning".into()),
        },
        findings,
    });
}

#[test]
fn prints_registry_security_report_for_empty_and_vulnerable_packages() {
    print_registry_security_report(&RegistrySecurityReport {
        package_count: 0,
        file_count: 0,
        vulnerable_file_count: 0,
        vulnerability_count: 0,
        highest_severity: None,
        packages: Vec::new(),
    });

    print_registry_security_report(&RegistrySecurityReport {
        package_count: 1,
        file_count: 2,
        vulnerable_file_count: 1,
        vulnerability_count: 3,
        highest_severity: Some("HIGH".into()),
        packages: vec![RegistryPackageSecurityReport {
            tenant_slug: "acme".into(),
            project_name: "demo".into(),
            normalized_name: "demo".into(),
            security: PackageSecuritySummary {
                scanned_file_count: 2,
                vulnerable_file_count: 1,
                vulnerability_count: 3,
                highest_severity: Some("HIGH".into()),
                scan_error: Some("advisory db warning".into()),
                ..PackageSecuritySummary::default()
            },
        }],
    });
}

#[test]
fn mirror_refresh_report_logging_and_build_mode_logging_are_callable() {
    log_build_mode();
    log_mirror_refresh_report(
        &MirrorRefreshReport {
            tenant_count: 1,
            mirrored_project_count: 2,
            refreshed_project_count: 1,
            failed_project_count: 1,
            failures: vec![pyregistry_application::MirrorRefreshFailure {
                tenant_slug: "acme".into(),
                project_name: "demo".into(),
                error: "network".into(),
            }],
        },
        Duration::from_millis(25),
    );
}

fn build_source_zip_bytes() -> Vec<u8> {
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut writer = ZipWriter::new(&mut cursor);
        writer
            .start_file(
                "demo_pkg-0.1.0/pyproject.toml",
                SimpleFileOptions::default(),
            )
            .expect("start pyproject");
        writer
            .write_all(b"[project]\nname = \"demo-pkg\"\n")
            .expect("write pyproject");
        writer.finish().expect("finish zip");
    }
    cursor.into_inner()
}
