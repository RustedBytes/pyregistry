use anyhow::Context;
use log::info;
use pyregistry_application::{
    AuditWheelCommand, DistributionFileInspector, DistributionValidationUseCase,
    ValidateDistributionCommand, ValidateRegistryDistributionsCommand, WheelAuditUseCase,
};
use pyregistry_infrastructure::{
    ArtifactDownloadRetryPolicy, FilesystemDistributionInspector,
    FoxGuardWheelSourceSecurityScanner, PypiMirrorClient, Settings, YaraWheelVirusScanner,
    ZipWheelArchiveReader, build_application, seed_application,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::reports::{
    print_distribution_validation_report, print_registry_distribution_validation_report,
    print_registry_security_report, print_wheel_audit_report,
};
pub(crate) async fn audit_wheel(
    project: String,
    wheel: PathBuf,
    settings: &Settings,
) -> anyhow::Result<()> {
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
        Arc::new(FoxGuardWheelSourceSecurityScanner::default()),
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

pub(crate) async fn check_registry(
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

pub(crate) fn validate_distribution(file: PathBuf, sha256: Option<String>) -> anyhow::Result<()> {
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
        anyhow::bail!("distribution validation failed");
    }

    Ok(())
}

pub(crate) async fn validate_registry_distributions(
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

pub(crate) async fn ensure_wheel_is_available(
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
