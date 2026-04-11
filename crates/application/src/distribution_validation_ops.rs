use crate::{
    ApplicationError, DistributionChecksumStatus, DistributionFileInspector,
    DistributionValidationReport, PyregistryApp, RegistryDistributionValidationItem,
    RegistryDistributionValidationReport, RegistryDistributionValidationStatus,
    ValidateDistributionCommand, ValidateRegistryDistributionsCommand,
};
use log::{info, warn};
use pyregistry_domain::{Artifact, DigestSet, Project, ProjectName, Release, Tenant};
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
        inspector: &dyn DistributionFileInspector,
        command: ValidateRegistryDistributionsCommand,
    ) -> Result<RegistryDistributionValidationReport, ApplicationError> {
        info!(
            "validating registry distributions with tenant_filter={:?} project_filter={:?}",
            command.tenant_slug, command.project_name
        );
        let tenants = self
            .tenants_for_distribution_validation(command.tenant_slug.as_deref())
            .await?;
        let mut report = RegistryDistributionValidationReport {
            tenant_count: tenants.len(),
            ..RegistryDistributionValidationReport::default()
        };

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
                        let item = self
                            .validate_registry_artifact(
                                inspector, &tenant, &project, &release, artifact,
                            )
                            .await;
                        report.push_item(item);
                    }
                }
            }
        }

        info!(
            "registry distribution validation finished: files={}, valid={}, invalid={}, missing_blobs={}, checksum_mismatches={}, invalid_archives={}, unsupported={}, storage_errors={}",
            report.artifact_count,
            report.valid_count,
            report.invalid_count,
            report.missing_blob_count,
            report.checksum_mismatch_count,
            report.invalid_archive_count,
            report.unsupported_distribution_count,
            report.storage_error_count
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

    async fn validate_registry_artifact(
        &self,
        inspector: &dyn DistributionFileInspector,
        tenant: &Tenant,
        project: &Project,
        release: &Release,
        artifact: Artifact,
    ) -> RegistryDistributionValidationItem {
        if !is_supported_distribution_filename(&artifact.filename) {
            return registry_distribution_item(
                tenant,
                project,
                release,
                &artifact,
                RegistryDistributionValidationStatus::UnsupportedDistribution,
                None,
                Some(
                    "only .whl, .tar.gz, and .tgz files are supported by this validator"
                        .to_string(),
                ),
            );
        }

        let bytes = match self.object_storage.get(&artifact.object_key).await {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                return registry_distribution_item(
                    tenant,
                    project,
                    release,
                    &artifact,
                    RegistryDistributionValidationStatus::MissingBlob,
                    None,
                    Some(format!(
                        "object storage key `{}` is missing",
                        artifact.object_key
                    )),
                );
            }
            Err(error) => {
                return registry_distribution_item(
                    tenant,
                    project,
                    release,
                    &artifact,
                    RegistryDistributionValidationStatus::StorageError,
                    None,
                    Some(error.to_string()),
                );
            }
        };

        let inspection = match inspector.inspect_distribution_bytes(&artifact.filename, &bytes) {
            Ok(inspection) => inspection,
            Err(error) => {
                return registry_distribution_item(
                    tenant,
                    project,
                    release,
                    &artifact,
                    RegistryDistributionValidationStatus::InvalidArchive,
                    None,
                    Some(error.to_string()),
                );
            }
        };

        let status = if inspection.sha256 == artifact.digests.sha256 {
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
                artifact.digests.sha256, inspection.sha256
            ))
        } else {
            None
        };

        registry_distribution_item(
            tenant,
            project,
            release,
            &artifact,
            status,
            Some(inspection),
            error,
        )
    }
}

fn is_supported_distribution_filename(filename: &str) -> bool {
    let filename = filename.to_ascii_lowercase();
    filename.ends_with(".whl") || filename.ends_with(".tar.gz") || filename.ends_with(".tgz")
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

    fn fake_inspection(sha256: String) -> DistributionInspection {
        DistributionInspection {
            kind: DistributionKind::Wheel,
            size_bytes: 42,
            sha256,
            archive_entry_count: 2,
        }
    }
}
