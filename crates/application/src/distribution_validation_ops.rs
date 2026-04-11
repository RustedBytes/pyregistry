use crate::{
    ApplicationError, DistributionChecksumStatus, DistributionFileInspector,
    DistributionValidationReport, ObjectStorage, PyregistryApp, RegistryDistributionValidationItem,
    RegistryDistributionValidationReport, RegistryDistributionValidationStatus,
    ValidateDistributionCommand, ValidateRegistryDistributionsCommand,
};
use futures_channel::oneshot;
use futures_util::{StreamExt, stream};
use log::{info, warn};
use pyregistry_domain::{Artifact, DigestSet, Project, ProjectName, Release, Tenant};
use rayon::{ThreadPool, ThreadPoolBuilder};
use std::sync::Arc;

pub struct DistributionValidationUseCase {
    inspector: Arc<dyn DistributionFileInspector>,
}

impl DistributionValidationUseCase {
    #[must_use]
    pub fn new(inspector: Arc<dyn DistributionFileInspector>) -> Self {
        Self { inspector }
    }

    pub fn validate(
        &self,
        command: ValidateDistributionCommand,
    ) -> Result<DistributionValidationReport, ApplicationError> {
        info!(
            "validating Python distribution file `{}`",
            command.file_path.display()
        );
        let inspection = self.inspector.inspect_distribution(&command.file_path)?;
        let checksum = match command.expected_sha256 {
            Some(expected_sha256) => {
                let expected = DigestSet::new(expected_sha256, None)?.sha256;
                if expected == inspection.sha256 {
                    info!(
                        "distribution checksum matched for `{}` ({})",
                        command.file_path.display(),
                        inspection.sha256
                    );
                    DistributionChecksumStatus::Matched { expected }
                } else {
                    warn!(
                        "distribution checksum mismatch for `{}`: expected={}, actual={}",
                        command.file_path.display(),
                        expected,
                        inspection.sha256
                    );
                    DistributionChecksumStatus::Mismatched {
                        expected,
                        actual: inspection.sha256.clone(),
                    }
                }
            }
            None => DistributionChecksumStatus::NotProvided,
        };

        Ok(DistributionValidationReport {
            file_path: command.file_path,
            inspection,
            checksum,
        })
    }
}

impl PyregistryApp {
    pub async fn validate_registry_distributions(
        &self,
        inspector: Arc<dyn DistributionFileInspector>,
        command: ValidateRegistryDistributionsCommand,
    ) -> Result<RegistryDistributionValidationReport, ApplicationError> {
        let parallelism = command.parallelism.max(1);
        info!(
            "validating registry distributions with tenant_filter={:?} project_filter={:?} parallelism={}",
            command.tenant_slug, command.project_name, parallelism
        );
        let tenants = self
            .tenants_for_distribution_validation(command.tenant_slug.as_deref())
            .await?;
        let mut report = RegistryDistributionValidationReport {
            tenant_count: tenants.len(),
            ..RegistryDistributionValidationReport::default()
        };
        let mut targets = Vec::new();

        for tenant in tenants {
            let projects = self
                .projects_for_distribution_validation(&tenant, command.project_name.as_deref())
                .await?;
            report.project_count += projects.len();

            for project in projects {
                let releases = self.store.list_releases(project.id).await?;
                report.release_count += releases.len();
                for release in releases {
                    for artifact in self.store.list_artifacts(release.id).await? {
                        targets.push(RegistryDistributionValidationTarget {
                            tenant: tenant.clone(),
                            project: project.clone(),
                            release: release.clone(),
                            artifact,
                        });
                    }
                }
            }
        }

        info!(
            "queued {} registry distribution file(s) for validation with {} worker(s)",
            targets.len(),
            parallelism
        );
        let rayon_pool = Arc::new(
            ThreadPoolBuilder::new()
                .num_threads(parallelism)
                .thread_name(|index| format!("pyregistry-dist-validate-{index}"))
                .build()
                .map_err(|error| {
                    ApplicationError::External(format!(
                        "could not build distribution validation worker pool: {error}"
                    ))
                })?,
        );
        let object_storage = self.object_storage.clone();
        let items = stream::iter(targets)
            .map(|target| {
                validate_registry_target(
                    object_storage.clone(),
                    inspector.clone(),
                    rayon_pool.clone(),
                    target,
                )
            })
            .buffer_unordered(parallelism)
            .collect::<Vec<_>>()
            .await;

        for item in items {
            report.push_item(item);
        }

        info!(
            "registry distribution validation finished: files={}, valid={}, invalid={}, missing_blobs={}, checksum_mismatches={}, invalid_archives={}, unsupported={}, storage_errors={}, parallelism={}",
            report.artifact_count,
            report.valid_count,
            report.invalid_count,
            report.missing_blob_count,
            report.checksum_mismatch_count,
            report.invalid_archive_count,
            report.unsupported_distribution_count,
            report.storage_error_count,
            parallelism
        );
        Ok(report)
    }

    async fn tenants_for_distribution_validation(
        &self,
        tenant_filter: Option<&str>,
    ) -> Result<Vec<Tenant>, ApplicationError> {
        if let Some(tenant_slug) = tenant_filter {
            return Ok(vec![self.require_tenant(tenant_slug).await?]);
        }
        self.store.list_tenants().await
    }

    async fn projects_for_distribution_validation(
        &self,
        tenant: &Tenant,
        project_filter: Option<&str>,
    ) -> Result<Vec<Project>, ApplicationError> {
        if let Some(project_name) = project_filter {
            let project_name = ProjectName::new(project_name)?;
            let project = self
                .store
                .get_project_by_normalized_name(tenant.id, project_name.normalized())
                .await?
                .ok_or_else(|| {
                    ApplicationError::NotFound(format!(
                        "project `{}` in tenant `{}`",
                        project_name.original(),
                        tenant.slug.as_str()
                    ))
                })?;
            return Ok(vec![project]);
        }
        self.store.list_projects(tenant.id).await
    }
}

#[derive(Debug, Clone)]
struct RegistryDistributionValidationTarget {
    tenant: Tenant,
    project: Project,
    release: Release,
    artifact: Artifact,
}

async fn validate_registry_target(
    object_storage: Arc<dyn ObjectStorage>,
    inspector: Arc<dyn DistributionFileInspector>,
    rayon_pool: Arc<ThreadPool>,
    target: RegistryDistributionValidationTarget,
) -> RegistryDistributionValidationItem {
    if !is_supported_distribution_filename(&target.artifact.filename) {
        return registry_distribution_item(
            &target.tenant,
            &target.project,
            &target.release,
            &target.artifact,
            RegistryDistributionValidationStatus::UnsupportedDistribution,
            None,
            Some(
                "only .whl, .tar.gz, .tgz, and .zip files are supported by this validator"
                    .to_string(),
            ),
        );
    }

    let bytes = match object_storage.get(&target.artifact.object_key).await {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            return registry_distribution_item(
                &target.tenant,
                &target.project,
                &target.release,
                &target.artifact,
                RegistryDistributionValidationStatus::MissingBlob,
                None,
                Some(format!(
                    "object storage key `{}` is missing",
                    target.artifact.object_key
                )),
            );
        }
        Err(error) => {
            return registry_distribution_item(
                &target.tenant,
                &target.project,
                &target.release,
                &target.artifact,
                RegistryDistributionValidationStatus::StorageError,
                None,
                Some(error.to_string()),
            );
        }
    };

    let inspection = match inspect_distribution_bytes_on_rayon(
        rayon_pool,
        inspector,
        target.artifact.filename.clone(),
        bytes,
    )
    .await
    {
        Ok(inspection) => inspection,
        Err(error) => {
            return registry_distribution_item(
                &target.tenant,
                &target.project,
                &target.release,
                &target.artifact,
                RegistryDistributionValidationStatus::InvalidArchive,
                None,
                Some(error.to_string()),
            );
        }
    };

    let status = if inspection.sha256 == target.artifact.digests.sha256 {
        RegistryDistributionValidationStatus::Valid
    } else {
        RegistryDistributionValidationStatus::ChecksumMismatch
    };
    let error = if matches!(
        status,
        RegistryDistributionValidationStatus::ChecksumMismatch
    ) {
        Some(format!(
            "expected sha256 {}, got {}",
            target.artifact.digests.sha256, inspection.sha256
        ))
    } else {
        None
    };

    registry_distribution_item(
        &target.tenant,
        &target.project,
        &target.release,
        &target.artifact,
        status,
        Some(inspection),
        error,
    )
}

async fn inspect_distribution_bytes_on_rayon(
    rayon_pool: Arc<ThreadPool>,
    inspector: Arc<dyn DistributionFileInspector>,
    filename: String,
    bytes: Vec<u8>,
) -> Result<crate::DistributionInspection, ApplicationError> {
    let (sender, receiver) = oneshot::channel();
    rayon_pool.spawn(move || {
        let result = inspector.inspect_distribution_bytes(&filename, &bytes);
        let _ = sender.send(result);
    });
    receiver.await.map_err(|_| {
        ApplicationError::External(
            "distribution validation worker stopped before sending a result".to_string(),
        )
    })?
}

fn is_supported_distribution_filename(filename: &str) -> bool {
    let filename = filename.to_ascii_lowercase();
    filename.ends_with(".whl")
        || filename.ends_with(".tar.gz")
        || filename.ends_with(".tgz")
        || filename.ends_with(".zip")
}

fn registry_distribution_item(
    tenant: &Tenant,
    project: &Project,
    release: &Release,
    artifact: &Artifact,
    status: RegistryDistributionValidationStatus,
    inspection: Option<crate::DistributionInspection>,
    error: Option<String>,
) -> RegistryDistributionValidationItem {
    RegistryDistributionValidationItem {
        tenant_slug: tenant.slug.as_str().to_string(),
        project_name: project.name.original().to_string(),
        version: release.version.as_str().to_string(),
        filename: artifact.filename.clone(),
        object_key: artifact.object_key.clone(),
        expected_sha256: artifact.digests.sha256.clone(),
        actual_sha256: inspection.as_ref().map(|value| value.sha256.clone()),
        recorded_size_bytes: artifact.size_bytes,
        actual_size_bytes: inspection.as_ref().map(|value| value.size_bytes),
        kind: inspection.as_ref().map(|value| value.kind),
        archive_entry_count: inspection.map(|value| value.archive_entry_count),
        status,
        error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DistributionInspection, DistributionKind};
    use std::path::Path;

    struct FakeInspector {
        inspection: DistributionInspection,
    }

    impl DistributionFileInspector for FakeInspector {
        fn inspect_distribution(
            &self,
            _path: &Path,
        ) -> Result<DistributionInspection, ApplicationError> {
            Ok(self.inspection.clone())
        }

        fn inspect_distribution_bytes(
            &self,
            _filename: &str,
            _bytes: &[u8],
        ) -> Result<DistributionInspection, ApplicationError> {
            Ok(self.inspection.clone())
        }
    }

    #[test]
    fn validates_distribution_without_expected_checksum() {
        let use_case = DistributionValidationUseCase::new(Arc::new(FakeInspector {
            inspection: fake_inspection("a".repeat(64)),
        }));

        let report = use_case
            .validate(ValidateDistributionCommand {
                file_path: "demo-0.1.0-py3-none-any.whl".into(),
                expected_sha256: None,
            })
            .expect("validation report");

        assert!(report.is_valid());
        assert_eq!(report.checksum, DistributionChecksumStatus::NotProvided);
    }

    #[test]
    fn reports_matched_checksum() {
        let expected = "A".repeat(64);
        let use_case = DistributionValidationUseCase::new(Arc::new(FakeInspector {
            inspection: fake_inspection(expected.to_ascii_lowercase()),
        }));

        let report = use_case
            .validate(ValidateDistributionCommand {
                file_path: "demo-0.1.0-py3-none-any.whl".into(),
                expected_sha256: Some(expected),
            })
            .expect("validation report");

        assert!(report.is_valid());
        assert_eq!(
            report.checksum,
            DistributionChecksumStatus::Matched {
                expected: "a".repeat(64)
            }
        );
    }

    #[test]
    fn reports_checksum_mismatch_without_hiding_actual_digest() {
        let actual = "b".repeat(64);
        let use_case = DistributionValidationUseCase::new(Arc::new(FakeInspector {
            inspection: fake_inspection(actual.clone()),
        }));

        let report = use_case
            .validate(ValidateDistributionCommand {
                file_path: "demo-0.1.0-py3-none-any.whl".into(),
                expected_sha256: Some("a".repeat(64)),
            })
            .expect("validation report");

        assert!(!report.is_valid());
        assert_eq!(
            report.checksum,
            DistributionChecksumStatus::Mismatched {
                expected: "a".repeat(64),
                actual
            }
        );
    }

    #[test]
    fn recognizes_zip_source_distributions_as_supported() {
        assert!(is_supported_distribution_filename("scipy-0.12.0.zip"));
        assert!(is_supported_distribution_filename("demo-0.1.0.tar.gz"));
        assert!(is_supported_distribution_filename("demo-0.1.0.tgz"));
        assert!(is_supported_distribution_filename(
            "demo-0.1.0-py3-none-any.whl"
        ));
        assert!(!is_supported_distribution_filename("demo-0.1.0.exe"));
    }

    fn fake_inspection(sha256: String) -> DistributionInspection {
        DistributionInspection {
            kind: DistributionKind::Wheel,
            size_bytes: 42,
            sha256,
            archive_entry_count: 2,
        }
    }
}
