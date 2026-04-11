use anyhow::Context;
use async_trait::async_trait;
use clap::{Parser, Subcommand, ValueEnum};
use env_logger::Env;
use log::{debug, error, info, warn};
use pyregistry_application::{
    ApplicationError, AuditWheelCommand, CancellationSignal, DistributionChecksumStatus,
    DistributionFileInspector, DistributionValidationReport, DistributionValidationUseCase,
    MirrorRefreshReport, PyregistryApp, RegistryDistributionValidationItem,
    RegistryDistributionValidationReport, RegistryDistributionValidationStatus,
    RegistrySecurityReport, ValidateDistributionCommand, ValidateRegistryDistributionsCommand,
    WheelAuditFinding, WheelAuditFindingKind, WheelAuditReport, WheelAuditUseCase,
};
use pyregistry_infrastructure::{
    ArtifactDownloadRetryPolicy, FilesystemDistributionInspector, LoggingConfig, LoggingTimestamp,
    PypiMirrorClient, Settings, YaraWheelVirusScanner, ZipWheelArchiveReader, build_application,
    seed_application,
};
use pyregistry_web::{
    AppState, MirrorJobs, RateLimitConfig as WebRateLimitConfig, RateLimiter, router,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::{RwLock, watch};
use tokio::task::JoinHandle;
use tower_http::trace::TraceLayer;

const FORCED_HTTP_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
const MIRROR_UPDATER_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

#[derive(Debug, Parser)]
#[command(
    name = "pyregistry",
    version,
    about = "Internal Python package registry service",
    propagate_version = true
)]
struct Cli {
    #[arg(
        long,
        global = true,
        value_name = "PATH",
        help = "Load runtime settings from a TOML config file"
    )]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(about = "Run the HTTP service")]
    Serve,
    #[command(about = "Write a starter TOML config file")]
    InitConfig {
        #[arg(
            long,
            value_name = "PATH",
            help = "Where to write the TOML config file"
        )]
        path: Option<PathBuf>,
        #[arg(
            long,
            value_enum,
            default_value_t = InitStorageTemplate::Local,
            help = "Artifact storage template to write"
        )]
        storage: InitStorageTemplate,
        #[arg(long, help = "Overwrite the file if it already exists")]
        force: bool,
    },
    #[command(about = "Inspect a wheel for suspicious install-time signals")]
    AuditWheel {
        #[arg(long, value_name = "PROJECT", help = "Expected project name")]
        project: String,
        #[arg(long, value_name = "PATH", help = "Path to the wheel file")]
        wheel: PathBuf,
    },
    #[command(
        name = "validate-dist",
        visible_alias = "validate-artifact",
        about = "Validate a downloaded wheel or source distribution"
    )]
    ValidateDist {
        #[arg(
            long,
            alias = "path",
            value_name = "PATH",
            help = "Path to a .whl, .tar.gz, .tgz, or .zip distribution file"
        )]
        file: PathBuf,
        #[arg(
            long,
            value_name = "HEX",
            help = "Expected SHA-256 checksum to compare against"
        )]
        sha256: Option<String>,
    },
    #[command(
        name = "validate-dist-all",
        about = "Validate every stored wheel and source tar.gz file in the registry"
    )]
    ValidateDistAll {
        #[arg(long, value_name = "TENANT", help = "Limit validation to one tenant")]
        tenant: Option<String>,
        #[arg(
            long,
            value_name = "PROJECT",
            help = "Limit validation to one project; requires --tenant"
        )]
        project: Option<String>,
        #[arg(
            long,
            value_name = "N",
            help = "Parallel artifact validation workers; defaults to validation.distribution_parallelism"
        )]
        parallelism: Option<usize>,
    },
    #[command(about = "Check package versions stored in the registry for known vulnerabilities")]
    CheckRegistry {
        #[arg(long, value_name = "TENANT", help = "Limit checks to one tenant")]
        tenant: Option<String>,
        #[arg(
            long,
            value_name = "PROJECT",
            help = "Limit checks to one project; requires --tenant"
        )]
        project: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum InitStorageTemplate {
    #[value(name = "local")]
    Local,
    #[value(name = "minio")]
    Minio,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config_path = cli.config.clone();
    let cli_debug = format!("{cli:?}");

    match cli.command.unwrap_or(Command::Serve) {
        Command::Serve => {
            let config_source = describe_settings_source(config_path.as_deref());
            let settings =
                Settings::load_for_cli(config_path).context("failed to load settings")?;
            init_logging(&settings.logging);
            log_build_mode();
            debug!("parsed CLI arguments: {cli_debug}");
            serve(settings, config_source).await
        }
        Command::InitConfig {
            path,
            storage,
            force,
        } => {
            let settings = match storage {
                InitStorageTemplate::Local => Settings::new_local_template(),
                InitStorageTemplate::Minio => Settings::new_minio_template(),
            };
            init_logging(&settings.logging);
            debug!("parsed CLI arguments: {cli_debug}");
            init_config(path, force, storage, settings)
        }
        Command::AuditWheel { project, wheel } => {
            let settings =
                Settings::load_for_cli(config_path).context("failed to load settings")?;
            init_logging(&settings.logging);
            log_build_mode();
            debug!("parsed CLI arguments: {cli_debug}");
            audit_wheel(project, wheel, &settings).await
        }
        Command::ValidateDist { file, sha256 } => {
            let settings =
                Settings::load_for_cli(config_path).context("failed to load settings")?;
            init_logging(&settings.logging);
            log_build_mode();
            debug!("parsed CLI arguments: {cli_debug}");
            validate_distribution(file, sha256)
        }
        Command::ValidateDistAll {
            tenant,
            project,
            parallelism,
        } => {
            let config_source = describe_settings_source(config_path.as_deref());
            let settings =
                Settings::load_for_cli(config_path).context("failed to load settings")?;
            init_logging(&settings.logging);
            log_build_mode();
            debug!("parsed CLI arguments: {cli_debug}");
            validate_registry_distributions(settings, config_source, tenant, project, parallelism)
                .await
        }
        Command::CheckRegistry { tenant, project } => {
            let config_source = describe_settings_source(config_path.as_deref());
            let settings =
                Settings::load_for_cli(config_path).context("failed to load settings")?;
            init_logging(&settings.logging);
            log_build_mode();
            debug!("parsed CLI arguments: {cli_debug}");
            check_registry(settings, config_source, tenant, project).await
        }
    }
}

fn log_build_mode() {
    if cfg!(debug_assertions) {
        warn!(
            "running an unoptimized debug build; use `cargo run --release -p pyregistry -- ...` or `scripts/pyregistry-release.sh` for serving, mirroring, and wheel scans"
        );
    } else {
        info!("running optimized release build");
    }
}

fn init_config(
    path: Option<PathBuf>,
    force: bool,
    storage: InitStorageTemplate,
    settings: Settings,
) -> anyhow::Result<()> {
    let target_path = path.unwrap_or_else(Settings::default_config_path);
    info!(
        "initializing starter config file at {} (storage={storage:?}, force={force})",
        target_path.display(),
    );
    settings
        .write_to_path(&target_path, force)
        .with_context(|| format!("failed to write config file to {}", target_path.display()))?;
    info!("wrote starter config file to {}", target_path.display());
    println!("wrote config to {}", target_path.display());
    if matches!(storage, InitStorageTemplate::Minio) {
        println!(
            "configured artifact storage for MinIO at http://127.0.0.1:9000; create bucket `pyregistry` before serving"
        );
    }
    Ok(())
}

async fn serve(settings: Settings, config_source: String) -> anyhow::Result<()> {
    info!("starting pyregistry server");
    info!("loading settings from {config_source}");
    info!("runtime settings: {}", settings.log_safe_summary());
    if let Ok(override_filter) = std::env::var("RUST_LOG") {
        info!("RUST_LOG override detected: {override_filter}");
    }
    debug!(
        "configured OIDC issuers: {:?}",
        settings
            .oidc_issuers
            .iter()
            .map(|issuer| (
                &issuer.provider,
                issuer.issuer.as_str(),
                issuer.audience.as_str()
            ))
            .collect::<Vec<_>>()
    );

    info!("building application services");
    let app = build_application(&settings)
        .await
        .context("failed to build application services")?;
    info!("seeding bootstrap data");
    seed_application(&app, &settings)
        .await
        .context("failed to seed application")?;
    info!("bootstrap data ready");

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mirror_updater = spawn_mirror_updater(app.clone(), &settings, shutdown_rx.clone());
    let forced_shutdown_rx = shutdown_rx.clone();

    info!("binding TCP listener on {}", settings.bind_address);
    let listener = TcpListener::bind(&settings.bind_address)
        .await
        .with_context(|| format!("failed to bind {}", settings.bind_address))?;
    let state = AppState {
        app,
        sessions: Arc::new(RwLock::new(HashMap::new())),
        mirror_jobs: MirrorJobs::default(),
        rate_limiter: RateLimiter::new(WebRateLimitConfig {
            enabled: settings.rate_limit.enabled,
            requests_per_minute: settings.rate_limit.requests_per_minute,
            burst: settings.rate_limit.burst,
            max_tracked_clients: settings.rate_limit.max_tracked_clients,
            trust_proxy_headers: settings.rate_limit.trust_proxy_headers,
        }),
    };
    info!(
        "HTTP API rate limiting: {}",
        state.rate_limiter.log_safe_summary()
    );
    let router = router(state).layer(TraceLayer::new_for_http());

    info!("pyregistry listening on http://{}", settings.bind_address);
    let server = axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal(shutdown_tx.clone()));

    let serve_result = tokio::select! {
        result = server => result,
        () = force_http_shutdown_after_signal(forced_shutdown_rx, FORCED_HTTP_SHUTDOWN_GRACE) => {
            warn!(
                "forcing HTTP shutdown after {:.1}s grace period",
                FORCED_HTTP_SHUTDOWN_GRACE.as_secs_f64()
            );
            Ok(())
        }
    };

    let _ = shutdown_tx.send(true);
    wait_for_mirror_updater(mirror_updater).await;

    if let Err(error) = serve_result {
        error!("axum server terminated with an error: {error}");
        return Err(error).context("axum server failed");
    }

    info!("pyregistry server shutdown complete");
    Ok(())
}

fn spawn_mirror_updater(
    app: Arc<PyregistryApp>,
    settings: &Settings,
    mut shutdown: watch::Receiver<bool>,
) -> Option<JoinHandle<()>> {
    if !settings.pypi.mirror_update_enabled {
        info!("background mirrored package updater is disabled");
        return None;
    }

    let interval = Duration::from_secs(settings.pypi.mirror_update_interval_seconds);
    let run_on_startup = settings.pypi.mirror_update_on_startup;
    info!(
        "starting background mirrored package updater: interval_seconds={}, run_on_startup={}",
        settings.pypi.mirror_update_interval_seconds, run_on_startup
    );

    Some(tokio::spawn(async move {
        if run_on_startup {
            run_mirror_update_cycle(&app, &shutdown).await;
            if *shutdown.borrow() {
                info!(
                    "background mirrored package updater stopping after startup cycle cancellation"
                );
                return;
            }
        }

        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    match changed {
                        Ok(()) if *shutdown.borrow() => {
                            info!("background mirrored package updater received shutdown signal");
                            break;
                        }
                        Ok(()) => {}
                        Err(_) => {
                            info!("background mirrored package updater shutdown channel closed");
                            break;
                        }
                    }
                }
                _ = tokio::time::sleep(interval) => {
                    if *shutdown.borrow() {
                        info!("background mirrored package updater stopping before next cycle");
                        break;
                    }
                    run_mirror_update_cycle(&app, &shutdown).await;
                }
            }
        }

        info!("background mirrored package updater stopped");
    }))
}

async fn wait_for_mirror_updater(handle: Option<JoinHandle<()>>) {
    if let Some(mut handle) = handle {
        tokio::select! {
            result = &mut handle => {
                if let Err(error) = result {
                    error!("background mirrored package updater task failed: {error}");
                }
            }
            _ = tokio::time::sleep(MIRROR_UPDATER_SHUTDOWN_GRACE) => {
                warn!(
                    "background mirrored package updater did not stop within {:.1}s; aborting task",
                    MIRROR_UPDATER_SHUTDOWN_GRACE.as_secs_f64()
                );
                handle.abort();
                if let Err(error) = handle.await
                    && !error.is_cancelled()
                {
                    error!("background mirrored package updater task failed during abort: {error}");
                }
            }
        }
    }
}

async fn run_mirror_update_cycle(app: &Arc<PyregistryApp>, shutdown: &watch::Receiver<bool>) {
    let started = Instant::now();
    info!("background mirrored package updater cycle started");
    let cancellation = WatchCancellation::new(shutdown.clone());
    match app
        .refresh_mirrored_projects_with_cancellation(&cancellation)
        .await
    {
        Ok(report) => log_mirror_refresh_report(&report, started.elapsed()),
        Err(ApplicationError::Cancelled(reason)) => {
            info!("background mirrored package updater cycle cancelled: {reason}")
        }
        Err(error) => warn!("background mirrored package updater cycle failed: {error}"),
    }
}

#[derive(Clone)]
struct WatchCancellation {
    shutdown: watch::Receiver<bool>,
}

impl WatchCancellation {
    fn new(shutdown: watch::Receiver<bool>) -> Self {
        Self { shutdown }
    }
}

#[async_trait]
impl CancellationSignal for WatchCancellation {
    fn is_cancelled(&self) -> bool {
        *self.shutdown.borrow()
    }

    async fn cancelled(&self) {
        let mut shutdown = self.shutdown.clone();
        if *shutdown.borrow() {
            return;
        }

        loop {
            if shutdown.changed().await.is_err() || *shutdown.borrow() {
                return;
            }
        }
    }
}

fn log_mirror_refresh_report(report: &MirrorRefreshReport, elapsed: Duration) {
    info!(
        "background mirrored package updater cycle finished in {:.2}s: tenants={}, mirrored_projects={}, refreshed={}, failed={}",
        elapsed.as_secs_f64(),
        report.tenant_count,
        report.mirrored_project_count,
        report.refreshed_project_count,
        report.failed_project_count
    );
    for failure in &report.failures {
        warn!(
            "background mirrored package updater failure: tenant=`{}` project=`{}` error={}",
            failure.tenant_slug, failure.project_name, failure.error
        );
    }
}

async fn shutdown_signal(shutdown_tx: watch::Sender<bool>) {
    let ctrl_c = async {
        match tokio::signal::ctrl_c().await {
            Ok(()) => "SIGINT",
            Err(error) => {
                error!("failed to listen for Ctrl+C/SIGINT: {error}");
                std::future::pending::<&'static str>().await
            }
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
                "SIGTERM"
            }
            Err(error) => {
                error!("failed to listen for SIGTERM: {error}");
                std::future::pending::<&'static str>().await
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<&'static str>();

    let received_signal = tokio::select! {
        signal = ctrl_c => signal,
        signal = terminate => signal,
    };
    info!("received {received_signal}; starting graceful HTTP shutdown");
    let _ = shutdown_tx.send(true);
}

async fn force_http_shutdown_after_signal(
    mut shutdown: watch::Receiver<bool>,
    grace_period: Duration,
) {
    if !*shutdown.borrow() {
        loop {
            if shutdown.changed().await.is_err() {
                return;
            }
            if *shutdown.borrow() {
                break;
            }
        }
    }

    tokio::time::sleep(grace_period).await;
}

fn init_logging(logging: &LoggingConfig) {
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
        .format_target(logging.target)
        .init();
}

fn describe_settings_source(config_path: Option<&Path>) -> String {
    match config_path {
        Some(path) => format!("explicit config file {}", path.display()),
        None => {
            let default_path = Settings::default_config_path();
            if default_path.exists() {
                format!("default config file {}", default_path.display())
            } else {
                "environment variables".to_string()
            }
        }
    }
}

async fn audit_wheel(project: String, wheel: PathBuf, settings: &Settings) -> anyhow::Result<()> {
    info!(
        "running wheel audit for project `{}` against {}",
        project,
        wheel.display()
    );
    ensure_wheel_is_available(&project, &wheel, settings).await?;
    let use_case = WheelAuditUseCase::new(
        Arc::new(ZipWheelArchiveReader),
        Arc::new(YaraWheelVirusScanner::from_rules_dir(
            settings.security.yara_rules_path.clone(),
        )),
    );
    let report = use_case
        .audit(AuditWheelCommand {
            project_name: project,
            wheel_path: wheel,
        })
        .context("wheel audit failed")?;
    print_wheel_audit_report(&report);
    Ok(())
}

async fn check_registry(
    settings: Settings,
    config_source: String,
    tenant: Option<String>,
    project: Option<String>,
) -> anyhow::Result<()> {
    if project.is_some() && tenant.is_none() {
        anyhow::bail!("--project requires --tenant so the package scope is unambiguous");
    }

    info!("checking registry security using settings from {config_source}");
    let app = build_application(&settings)
        .await
        .context("failed to build application services")?;
    seed_application(&app, &settings)
        .await
        .context("failed to seed application")?;
    let report = app
        .check_registry_security(tenant.as_deref(), project.as_deref())
        .await
        .context("registry security check failed")?;
    print_registry_security_report(&report);
    Ok(())
}

fn validate_distribution(file: PathBuf, sha256: Option<String>) -> anyhow::Result<()> {
    info!("validating distribution file {}", file.display());
    let use_case = DistributionValidationUseCase::new(Arc::new(FilesystemDistributionInspector));
    let report = use_case
        .validate(ValidateDistributionCommand {
            file_path: file,
            expected_sha256: sha256,
        })
        .context("distribution validation failed")?;

    print_distribution_validation_report(&report);
    if !report.is_valid() {
        anyhow::bail!("distribution checksum validation failed");
    }

    Ok(())
}

async fn validate_registry_distributions(
    settings: Settings,
    config_source: String,
    tenant: Option<String>,
    project: Option<String>,
    parallelism_override: Option<usize>,
) -> anyhow::Result<()> {
    if project.is_some() && tenant.is_none() {
        anyhow::bail!("--project requires --tenant so the package scope is unambiguous");
    }
    if matches!(parallelism_override, Some(0)) {
        anyhow::bail!("--parallelism must be greater than zero");
    }

    let parallelism = parallelism_override.unwrap_or(settings.validation.distribution_parallelism);
    info!(
        "validating stored registry distributions using settings from {config_source} with parallelism={parallelism}"
    );
    let app = build_application(&settings)
        .await
        .context("failed to build application services")?;
    seed_application(&app, &settings)
        .await
        .context("failed to seed application")?;
    let inspector: Arc<dyn DistributionFileInspector> = Arc::new(FilesystemDistributionInspector);
    let report = app
        .validate_registry_distributions(
            inspector,
            ValidateRegistryDistributionsCommand {
                tenant_slug: tenant,
                project_name: project,
                parallelism,
            },
        )
        .await
        .context("registry distribution validation failed")?;

    print_registry_distribution_validation_report(&report);
    if !report.is_valid() {
        anyhow::bail!(
            "registry distribution validation failed: {} invalid file(s)",
            report.invalid_count
        );
    }

    Ok(())
}

async fn ensure_wheel_is_available(
    project: &str,
    wheel: &Path,
    settings: &Settings,
) -> anyhow::Result<()> {
    if wheel.exists() {
        info!("using local wheel file at {}", wheel.display());
        return Ok(());
    }

    let filename = wheel
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "wheel path `{}` does not contain a file name",
                wheel.display()
            )
        })?;
    info!(
        "wheel file {} is not present locally; downloading `{}` from configured PyPI upstream {}",
        wheel.display(),
        filename,
        settings.pypi.base_url
    );

    let retry_policy = ArtifactDownloadRetryPolicy::new(
        settings.pypi.artifact_download_max_attempts,
        Duration::from_millis(settings.pypi.artifact_download_initial_backoff_millis),
    );
    let mirror_client = PypiMirrorClient::with_retry_policy(&settings.pypi.base_url, retry_policy)
        .context("configured PyPI base URL is invalid")?;
    tokio::select! {
        result = mirror_client.download_project_artifact_by_filename(project, filename, wheel) => {
            result.with_context(|| {
                format!(
                    "failed to download `{filename}` for project `{project}` into {}",
                    wheel.display()
                )
            })?;
        }
        signal = tokio::signal::ctrl_c() => {
            match signal {
                Ok(()) => anyhow::bail!("wheel download cancelled by Ctrl+C"),
                Err(error) => return Err(error).context("failed to listen for Ctrl+C while downloading wheel"),
            }
        }
    }
    Ok(())
}

fn print_distribution_validation_report(report: &DistributionValidationReport) {
    println!("Distribution validation: {}", report.file_path.display());
    println!("Kind: {}", report.inspection.kind.label());
    println!("Size: {} bytes", report.inspection.size_bytes);
    println!("SHA256: {}", report.inspection.sha256);
    println!(
        "Archive: valid ({} file entries read)",
        report.inspection.archive_entry_count
    );

    match &report.checksum {
        DistributionChecksumStatus::NotProvided => {
            println!("Checksum: not provided");
        }
        DistributionChecksumStatus::Matched { expected } => {
            println!("Checksum: matched ({expected})");
        }
        DistributionChecksumStatus::Mismatched { expected, actual } => {
            println!("Checksum: mismatch");
            println!("Expected: {expected}");
            println!("Actual:   {actual}");
        }
    }
}

fn print_registry_distribution_validation_report(report: &RegistryDistributionValidationReport) {
    println!("Registry distribution validation");
    println!("Tenants checked: {}", report.tenant_count);
    println!("Projects checked: {}", report.project_count);
    println!("Releases checked: {}", report.release_count);
    println!("Files checked: {}", report.artifact_count);
    println!("Valid files: {}", report.valid_count);
    println!("Invalid files: {}", report.invalid_count);
    println!("Missing blobs: {}", report.missing_blob_count);
    println!("Checksum mismatches: {}", report.checksum_mismatch_count);
    println!("Invalid archives: {}", report.invalid_archive_count);
    println!(
        "Unsupported distributions: {}",
        report.unsupported_distribution_count
    );
    println!("Storage errors: {}", report.storage_error_count);

    if report.items.is_empty() {
        println!();
        println!("No distribution files were found for the selected scope.");
        return;
    }

    let invalid_items = report
        .items
        .iter()
        .filter(|item| item.status != RegistryDistributionValidationStatus::Valid)
        .collect::<Vec<_>>();
    if invalid_items.is_empty() {
        println!();
        println!("All stored distribution files are valid.");
        return;
    }

    println!();
    println!("Invalid files");
    for item in invalid_items {
        print_registry_distribution_validation_item(item);
    }
}

fn print_registry_distribution_validation_item(item: &RegistryDistributionValidationItem) {
    println!(
        "- {}/{}/{} {}: {}",
        item.tenant_slug,
        item.project_name,
        item.version,
        item.filename,
        item.status.label()
    );
    if let Some(actual_sha256) = &item.actual_sha256 {
        println!("  expected sha256: {}", item.expected_sha256);
        println!("  actual sha256:   {actual_sha256}");
    }
    if let Some(actual_size_bytes) = item.actual_size_bytes {
        println!(
            "  size: recorded={} bytes actual={} bytes",
            item.recorded_size_bytes, actual_size_bytes
        );
    }
    if let Some(entry_count) = item.archive_entry_count {
        println!("  archive entries read: {entry_count}");
    }
    if let Some(error) = &item.error {
        println!("  error: {error}");
    }
}

fn print_wheel_audit_report(report: &WheelAuditReport) {
    println!("Wheel audit: {}", report.wheel_filename);
    println!("Project: {}", report.project_name);
    println!("Scanned files: {}", report.scanned_file_count);
    print_virus_scan_summary(report);

    if report.findings.is_empty() {
        println!();
        println!("No suspicious heuristic signals or YARA virus signatures were detected.");
        return;
    }

    for kind in [
        WheelAuditFindingKind::UnexpectedExecutable,
        WheelAuditFindingKind::NetworkString,
        WheelAuditFindingKind::PostInstallClue,
        WheelAuditFindingKind::PythonAstSuspiciousBehavior,
        WheelAuditFindingKind::SuspiciousDependency,
        WheelAuditFindingKind::VirusSignatureMatch,
    ] {
        let findings: Vec<_> = report
            .findings
            .iter()
            .filter(|finding| finding.kind == kind)
            .collect();
        if findings.is_empty() {
            continue;
        }

        println!();
        println!("{} ({})", audit_heading(kind), findings.len());
        for finding in findings {
            print_wheel_finding(finding);
        }
    }
}

fn print_wheel_finding(finding: &WheelAuditFinding) {
    match &finding.path {
        Some(path) => println!("- {} [{}]", finding.summary, path),
        None => println!("- {}", finding.summary),
    }
    for evidence in &finding.evidence {
        println!("  evidence: {}", evidence);
    }
}

fn print_virus_scan_summary(report: &WheelAuditReport) {
    println!(
        "YARA virus scan: {}",
        if report.virus_scan.enabled {
            "enabled"
        } else {
            "unavailable"
        }
    );
    println!(
        "YARA rules loaded: {} (skipped {})",
        report.virus_scan.signature_rule_count, report.virus_scan.skipped_rule_count
    );
    println!(
        "YARA files scanned: {}, signature matches: {}",
        report.virus_scan.scanned_file_count, report.virus_scan.match_count
    );
    if let Some(error) = &report.virus_scan.scan_error {
        println!("YARA scan warning: {error}");
    }
}

fn audit_heading(kind: WheelAuditFindingKind) -> &'static str {
    match kind {
        WheelAuditFindingKind::UnexpectedExecutable => "Unexpected executables or shell scripts",
        WheelAuditFindingKind::NetworkString => "Network-related strings inside binaries",
        WheelAuditFindingKind::PostInstallClue => "Post-install behavior clues",
        WheelAuditFindingKind::PythonAstSuspiciousBehavior => "Python AST suspicious behavior",
        WheelAuditFindingKind::SuspiciousDependency => "Suspicious dependencies in METADATA",
        WheelAuditFindingKind::VirusSignatureMatch => "YARA virus signature matches",
    }
}

fn print_registry_security_report(report: &RegistrySecurityReport) {
    println!("Registry security check");
    println!("Packages checked: {}", report.package_count);
    println!("Release files scanned: {}", report.file_count);
    println!("Vulnerable files: {}", report.vulnerable_file_count);
    println!("Advisory matches: {}", report.vulnerability_count);
    if let Some(severity) = &report.highest_severity {
        println!("Highest severity: {severity}");
    }

    if report.packages.is_empty() {
        println!();
        println!("No packages were found for the selected scope.");
        return;
    }

    for package in &report.packages {
        println!();
        println!(
            "{} / {} ({})",
            package.tenant_slug, package.project_name, package.normalized_name
        );
        if let Some(error) = &package.security.scan_error {
            println!("  Scan warning: {error}");
        }
        println!(
            "  Files scanned: {}, vulnerable files: {}, advisory matches: {}",
            package.security.scanned_file_count,
            package.security.vulnerable_file_count,
            package.security.vulnerability_count
        );
        if let Some(severity) = &package.security.highest_severity {
            println!("  Highest severity: {severity}");
        }
    }
}
