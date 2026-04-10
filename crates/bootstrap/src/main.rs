use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use env_logger::Env;
use log::{debug, error, info};
use pyregistry_application::{
    AuditWheelCommand, RegistrySecurityReport, WheelAuditFinding, WheelAuditFindingKind,
    WheelAuditReport, WheelAuditUseCase,
};
use pyregistry_infrastructure::{
    LoggingConfig, LoggingTimestamp, PypiMirrorClient, Settings, YaraWheelVirusScanner,
    ZipWheelArchiveReader, build_application, seed_application,
};
use pyregistry_web::{AppState, MirrorJobs, router};
use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tower_http::trace::TraceLayer;

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
        help = "Load runtime settings from a TOML or YAML config file"
    )]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(about = "Run the HTTP service")]
    Serve,
    #[command(about = "Write a starter TOML or YAML config file")]
    InitConfig {
        #[arg(
            long,
            value_name = "PATH",
            help = "Where to write the TOML or YAML config file"
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
            debug!("parsed CLI arguments: {cli_debug}");
            audit_wheel(project, wheel, &settings).await
        }
        Command::CheckRegistry { tenant, project } => {
            let config_source = describe_settings_source(config_path.as_deref());
            let settings =
                Settings::load_for_cli(config_path).context("failed to load settings")?;
            init_logging(&settings.logging);
            debug!("parsed CLI arguments: {cli_debug}");
            check_registry(settings, config_source, tenant, project).await
        }
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
    let app = build_application(&settings).context("failed to build application services")?;
    info!("seeding bootstrap data");
    seed_application(&app, &settings)
        .await
        .context("failed to seed application")?;
    info!("bootstrap data ready");

    info!("binding TCP listener on {}", settings.bind_address);
    let listener = TcpListener::bind(&settings.bind_address)
        .await
        .with_context(|| format!("failed to bind {}", settings.bind_address))?;
    let state = AppState {
        app,
        sessions: Arc::new(RwLock::new(HashMap::new())),
        mirror_jobs: MirrorJobs::default(),
    };
    let router = router(state).layer(TraceLayer::new_for_http());

    info!("pyregistry listening on http://{}", settings.bind_address);
    if let Err(error) = axum::serve(listener, router).await {
        error!("axum server terminated with an error: {error}");
        return Err(error).context("axum server failed");
    }

    Ok(())
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
    ensure_wheel_is_available(&project, &wheel).await?;
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
    let app = build_application(&settings).context("failed to build application services")?;
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

async fn ensure_wheel_is_available(project: &str, wheel: &Path) -> anyhow::Result<()> {
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
        "wheel file {} is not present locally; downloading `{}` from PyPI",
        wheel.display(),
        filename
    );

    let mirror_client = PypiMirrorClient::default();
    mirror_client
        .download_project_artifact_by_filename(project, filename, wheel)
        .await
        .with_context(|| {
            format!(
                "failed to download `{filename}` for project `{project}` into {}",
                wheel.display()
            )
        })?;
    Ok(())
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
