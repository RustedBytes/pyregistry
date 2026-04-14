use anyhow::{Context, bail};
use clap::{Parser, Subcommand, ValueEnum};
use log::{debug, info};
use pyregistry_infrastructure::Settings;
use std::path::{Path, PathBuf};

use crate::commands::{
    audit_wheel, check_registry, create_tenant, validate_distribution,
    validate_registry_distributions,
};
use crate::logging::{init_logging, log_build_mode};
use crate::server::serve;
#[derive(Debug, Parser)]
#[command(
    name = "pyregistry",
    version,
    about = "Internal Python package registry service",
    propagate_version = true
)]
pub(crate) struct Cli {
    #[arg(
        long,
        global = true,
        value_name = "PATH",
        help = "Load runtime settings from a TOML config file"
    )]
    pub(crate) config: Option<PathBuf>,

    #[arg(
        long,
        global = true,
        help = "Redact secrets and personally identifying values from log messages"
    )]
    pub(crate) redact_logs: bool,

    #[arg(
        long,
        global = true,
        alias = "yara-rules-dir",
        value_name = "PATH",
        help = "Override the YARA rules directory from config or YARA_RULES_PATH"
    )]
    pub(crate) yara_rules_path: Option<PathBuf>,

    #[command(subcommand)]
    pub(crate) command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
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
        name = "create-tenant",
        about = "Create a tenant and its first tenant admin account"
    )]
    CreateTenant {
        #[arg(long, value_name = "SLUG", help = "Tenant slug, for example `acme`")]
        slug: String,
        #[arg(
            long,
            value_name = "NAME",
            help = "Tenant display name shown in the admin UI"
        )]
        display_name: String,
        #[arg(
            long,
            value_name = "EMAIL",
            help = "Email address for the tenant admin account"
        )]
        admin_email: String,
        #[arg(
            long,
            value_name = "PASSWORD",
            help = "Initial password for the tenant admin account"
        )]
        admin_password: String,
        #[arg(
            long,
            help = "Allow read-through mirroring from the configured PyPI upstream"
        )]
        enable_mirroring: bool,
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
pub(crate) enum InitStorageTemplate {
    #[value(name = "local")]
    Local,
    #[value(name = "minio")]
    Minio,
}

pub(crate) async fn run() -> anyhow::Result<()> {
    execute(Cli::parse()).await
}

pub(crate) async fn execute(cli: Cli) -> anyhow::Result<()> {
    let config_path = cli.config.clone();
    let redact_logs = cli.redact_logs;
    let yara_rules_path = cli.yara_rules_path.clone();
    let cli_debug = cli_debug_summary(&cli);

    match cli.command.unwrap_or(Command::Serve) {
        Command::Serve => {
            let config_source = describe_settings_source(config_path.as_deref());
            let mut settings =
                Settings::load_for_cli(config_path.clone()).context("failed to load settings")?;
            apply_cli_overrides(&mut settings, yara_rules_path.as_deref())?;
            init_logging(&settings.logging, redact_logs)?;
            log_build_mode();
            debug!("parsed CLI arguments: {cli_debug}");
            serve(settings, config_source).await
        }
        Command::InitConfig {
            path,
            storage,
            force,
        } => {
            let mut settings = match storage {
                InitStorageTemplate::Local => Settings::new_local_template(),
                InitStorageTemplate::Minio => Settings::new_minio_template(),
            };
            apply_cli_overrides(&mut settings, yara_rules_path.as_deref())?;
            init_logging(&settings.logging, redact_logs)?;
            debug!("parsed CLI arguments: {cli_debug}");
            init_config(path, force, storage, settings)
        }
        Command::AuditWheel { project, wheel } => {
            let mut settings =
                Settings::load_for_cli(config_path.clone()).context("failed to load settings")?;
            apply_cli_overrides(&mut settings, yara_rules_path.as_deref())?;
            init_logging(&settings.logging, redact_logs)?;
            log_build_mode();
            debug!("parsed CLI arguments: {cli_debug}");
            audit_wheel(project, wheel, &settings).await
        }
        Command::CreateTenant {
            slug,
            display_name,
            admin_email,
            admin_password,
            enable_mirroring,
        } => {
            let config_source = describe_settings_source(config_path.as_deref());
            let mut settings =
                Settings::load_for_cli(config_path.clone()).context("failed to load settings")?;
            apply_cli_overrides(&mut settings, yara_rules_path.as_deref())?;
            init_logging(&settings.logging, redact_logs)?;
            log_build_mode();
            debug!("parsed CLI arguments: {cli_debug}");
            create_tenant(
                settings,
                config_source,
                slug,
                display_name,
                admin_email,
                admin_password,
                enable_mirroring,
            )
            .await
        }
        Command::ValidateDist { file, sha256 } => {
            let mut settings =
                Settings::load_for_cli(config_path.clone()).context("failed to load settings")?;
            apply_cli_overrides(&mut settings, yara_rules_path.as_deref())?;
            init_logging(&settings.logging, redact_logs)?;
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
            let mut settings =
                Settings::load_for_cli(config_path.clone()).context("failed to load settings")?;
            apply_cli_overrides(&mut settings, yara_rules_path.as_deref())?;
            init_logging(&settings.logging, redact_logs)?;
            log_build_mode();
            debug!("parsed CLI arguments: {cli_debug}");
            validate_registry_distributions(settings, config_source, tenant, project, parallelism)
                .await
        }
        Command::CheckRegistry { tenant, project } => {
            let config_source = describe_settings_source(config_path.as_deref());
            let mut settings =
                Settings::load_for_cli(config_path.clone()).context("failed to load settings")?;
            apply_cli_overrides(&mut settings, yara_rules_path.as_deref())?;
            init_logging(&settings.logging, redact_logs)?;
            log_build_mode();
            debug!("parsed CLI arguments: {cli_debug}");
            check_registry(settings, config_source, tenant, project).await
        }
    }
}

pub(crate) fn apply_cli_overrides(
    settings: &mut Settings,
    yara_rules_path: Option<&Path>,
) -> anyhow::Result<()> {
    if let Some(path) = yara_rules_path {
        if path.as_os_str().is_empty() {
            bail!("--yara-rules-path must not be empty");
        }
        settings.security.yara_rules_path = path.to_path_buf();
    }
    Ok(())
}

pub(crate) fn cli_debug_summary(cli: &Cli) -> String {
    match &cli.command {
        Some(Command::CreateTenant {
            slug,
            display_name,
            admin_email,
            enable_mirroring,
            ..
        }) => format!(
            "Cli {{ config: {:?}, redact_logs: {}, yara_rules_path: {:?}, command: CreateTenant {{ slug: {:?}, display_name: {:?}, admin_email: {:?}, admin_password: <redacted>, enable_mirroring: {} }} }}",
            cli.config,
            cli.redact_logs,
            cli.yara_rules_path,
            slug,
            display_name,
            admin_email,
            enable_mirroring,
        ),
        _ => format!("{cli:?}"),
    }
}

pub(crate) fn init_config(
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

pub(crate) fn describe_settings_source(config_path: Option<&Path>) -> String {
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
