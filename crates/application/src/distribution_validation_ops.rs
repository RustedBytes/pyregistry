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
            "registry distribution validation finished: files={}, valid={}, invalid={}, missing_blobs={}, checksum_mismatches={}, extension_mismatches={}, invalid_archives={}, unsupported={}, storage_errors={}, parallelism={}",
            report.artifact_count,
            report.valid_count,
            report.invalid_count,
            report.missing_blob_count,
            report.checksum_mismatch_count,
            report.extension_mismatch_count,
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

struct RegistryDistributionValidationOutcome {
    status: RegistryDistributionValidationStatus,
    inspection: Option<crate::DistributionInspection>,
    error: Option<String>,
}

async fn validate_registry_target(
    object_storage: Arc<dyn ObjectStorage>,
    inspector: Arc<dyn DistributionFileInspector>,
    rayon_pool: Arc<ThreadPool>,
    target: RegistryDistributionValidationTarget,
) -> RegistryDistributionValidationItem {
    if !is_supported_distribution_filename(&target.artifact.filename) {
        return registry_distribution_item(&target, unsupported_distribution_outcome());
    }

    let bytes = match object_storage.get(&target.artifact.object_key).await {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return registry_distribution_item(&target, missing_blob_outcome(&target)),
        Err(error) => return registry_distribution_item(&target, storage_error_outcome(error)),
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
            return registry_distribution_item(&target, invalid_archive_outcome(error));
        }
    };

    registry_distribution_item(&target, inspected_distribution_outcome(&target, inspection))
}

fn unsupported_distribution_outcome() -> RegistryDistributionValidationOutcome {
    RegistryDistributionValidationOutcome {
        status: RegistryDistributionValidationStatus::UnsupportedDistribution,
        inspection: None,
        error: Some(
            "only .whl, .tar.gz, .tgz, and .zip files are supported by this validator".to_string(),
        ),
    }
}

fn missing_blob_outcome(
    target: &RegistryDistributionValidationTarget,
) -> RegistryDistributionValidationOutcome {
    RegistryDistributionValidationOutcome {
        status: RegistryDistributionValidationStatus::MissingBlob,
        inspection: None,
        error: Some(format!(
            "object storage key `{}` is missing",
            target.artifact.object_key
        )),
    }
}

fn storage_error_outcome(error: ApplicationError) -> RegistryDistributionValidationOutcome {
    RegistryDistributionValidationOutcome {
        status: RegistryDistributionValidationStatus::StorageError,
        inspection: None,
        error: Some(error.to_string()),
    }
}

fn invalid_archive_outcome(error: ApplicationError) -> RegistryDistributionValidationOutcome {
    RegistryDistributionValidationOutcome {
        status: RegistryDistributionValidationStatus::InvalidArchive,
        inspection: None,
        error: Some(error.to_string()),
    }
}

fn inspected_distribution_outcome(
    target: &RegistryDistributionValidationTarget,
    inspection: crate::DistributionInspection,
) -> RegistryDistributionValidationOutcome {
    let extension_mismatch_error = if inspection.file_type.extension_mismatch() {
        Some(format!(
            "extension `{}` does not match detected file type `{}` ({})",
            inspection
                .file_type
                .actual_extension
                .as_deref()
                .unwrap_or("<none>"),
            inspection.file_type.label,
            inspection.file_type.mime_type
        ))
    } else {
        None
    };
    let status = if inspection.file_type.extension_mismatch() {
        RegistryDistributionValidationStatus::ExtensionMismatch
    } else if inspection.sha256 == target.artifact.digests.sha256 {
        RegistryDistributionValidationStatus::Valid
    } else {
        RegistryDistributionValidationStatus::ChecksumMismatch
    };
    let error = match status {
        RegistryDistributionValidationStatus::ChecksumMismatch => Some(format!(
            "expected sha256 {}, got {}",
            target.artifact.digests.sha256, inspection.sha256
        )),
        RegistryDistributionValidationStatus::ExtensionMismatch => extension_mismatch_error,
        _ => None,
    };

    RegistryDistributionValidationOutcome {
        status,
        inspection: Some(inspection),
        error,
    }
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
        if sender.send(result).is_err() {
            warn!("distribution validation worker result receiver was dropped");
        }
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
    target: &RegistryDistributionValidationTarget,
    outcome: RegistryDistributionValidationOutcome,
) -> RegistryDistributionValidationItem {
    let inspection = outcome.inspection;
    RegistryDistributionValidationItem {
        tenant_slug: target.tenant.slug.as_str().to_string(),
        project_name: target.project.name.original().to_string(),
        version: target.release.version.as_str().to_string(),
        filename: target.artifact.filename.clone(),
        object_key: target.artifact.object_key.clone(),
        expected_sha256: target.artifact.digests.sha256.clone(),
        actual_sha256: inspection.as_ref().map(|value| value.sha256.clone()),
        recorded_size_bytes: target.artifact.size_bytes,
        actual_size_bytes: inspection.as_ref().map(|value| value.size_bytes),
        kind: inspection.as_ref().map(|value| value.kind),
        detected_file_type: inspection
            .as_ref()
            .map(|value| value.file_type.label.clone()),
        detected_mime_type: inspection
            .as_ref()
            .map(|value| value.file_type.mime_type.clone()),
        extension_matches: inspection
            .as_ref()
            .map(|value| value.file_type.matches_extension),
        archive_entry_count: inspection.map(|value| value.archive_entry_count),
        status: outcome.status,
        error: outcome.error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DistributionInspection, DistributionKind};
    use async_trait::async_trait;
    use chrono::{TimeZone, Utc};
    use pyregistry_domain::{
        ArtifactId, ArtifactKind, MirrorRule, ProjectId, ProjectSource, ReleaseId, ReleaseVersion,
        TenantId, TenantSlug,
    };
    use std::collections::HashMap;
    use std::path::Path;
    use std::sync::{Mutex, Once};
    use uuid::Uuid;

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

    struct FailingBytesInspector;

    impl DistributionFileInspector for FailingBytesInspector {
        fn inspect_distribution(
            &self,
            _path: &Path,
        ) -> Result<DistributionInspection, ApplicationError> {
            Err(ApplicationError::External("unused path inspection".into()))
        }

        fn inspect_distribution_bytes(
            &self,
            _filename: &str,
            _bytes: &[u8],
        ) -> Result<DistributionInspection, ApplicationError> {
            Err(ApplicationError::External("broken archive".into()))
        }
    }

    #[derive(Default)]
    struct FakeObjectStorage {
        objects: Mutex<HashMap<String, Vec<u8>>>,
        fail_get: bool,
    }

    #[async_trait]
    impl ObjectStorage for FakeObjectStorage {
        async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), ApplicationError> {
            self.objects
                .lock()
                .expect("object storage")
                .insert(key.to_string(), bytes);
            Ok(())
        }

        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, ApplicationError> {
            if self.fail_get {
                return Err(ApplicationError::External("storage offline".into()));
            }
            Ok(self
                .objects
                .lock()
                .expect("object storage")
                .get(key)
                .cloned())
        }

        async fn size_bytes(&self, key: &str) -> Result<Option<u64>, ApplicationError> {
            Ok(self
                .objects
                .lock()
                .expect("object storage")
                .get(key)
                .map(|bytes| bytes.len() as u64))
        }

        async fn delete(&self, key: &str) -> Result<(), ApplicationError> {
            self.objects.lock().expect("object storage").remove(key);
            Ok(())
        }
    }

    #[test]
    fn validates_distribution_without_expected_checksum() {
        init_test_logger();
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
        init_test_logger();
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
        init_test_logger();
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

    #[tokio::test]
    async fn test_doubles_cover_unused_port_methods() {
        init_test_logger();
        let failing = FailingBytesInspector;
        assert!(
            failing
                .inspect_distribution(Path::new("unused.whl"))
                .expect_err("path inspection should fail")
                .to_string()
                .contains("unused path inspection")
        );

        let storage = FakeObjectStorage::default();
        storage
            .put("objects/demo.whl", b"payload".to_vec())
            .await
            .expect("put object");
        assert!(
            storage
                .get("objects/demo.whl")
                .await
                .expect("get")
                .is_some()
        );
        storage
            .delete("objects/demo.whl")
            .await
            .expect("delete object");
        assert!(
            storage
                .get("objects/demo.whl")
                .await
                .expect("get")
                .is_none()
        );
    }

    #[tokio::test]
    async fn registry_target_validation_reports_terminal_statuses() {
        init_test_logger();
        let pool = Arc::new(
            ThreadPoolBuilder::new()
                .num_threads(1)
                .build()
                .expect("rayon pool"),
        );

        let unsupported = validate_registry_target(
            Arc::new(FakeObjectStorage::default()),
            Arc::new(FakeInspector {
                inspection: fake_inspection("a".repeat(64)),
            }),
            pool.clone(),
            validation_target("demo.exe", "objects/demo.exe", "a".repeat(64), 10),
        )
        .await;
        assert_eq!(
            unsupported.status,
            RegistryDistributionValidationStatus::UnsupportedDistribution
        );
        assert!(unsupported.error.as_deref().unwrap().contains(".zip"));

        let missing = validate_registry_target(
            Arc::new(FakeObjectStorage::default()),
            Arc::new(FakeInspector {
                inspection: fake_inspection("a".repeat(64)),
            }),
            pool.clone(),
            validation_target(
                "demo-0.1.0-py3-none-any.whl",
                "objects/missing.whl",
                "a".repeat(64),
                10,
            ),
        )
        .await;
        assert_eq!(
            missing.status,
            RegistryDistributionValidationStatus::MissingBlob
        );
        assert_eq!(missing.actual_sha256, None);

        let storage_error = validate_registry_target(
            Arc::new(FakeObjectStorage {
                objects: Mutex::new(HashMap::new()),
                fail_get: true,
            }),
            Arc::new(FakeInspector {
                inspection: fake_inspection("a".repeat(64)),
            }),
            pool.clone(),
            validation_target(
                "demo-0.1.0-py3-none-any.whl",
                "objects/error.whl",
                "a".repeat(64),
                10,
            ),
        )
        .await;
        assert_eq!(
            storage_error.status,
            RegistryDistributionValidationStatus::StorageError
        );

        let storage = Arc::new(FakeObjectStorage::default());
        storage
            .put("objects/invalid.whl", b"not a zip".to_vec())
            .await
            .expect("put invalid bytes");
        let invalid = validate_registry_target(
            storage,
            Arc::new(FailingBytesInspector),
            pool.clone(),
            validation_target(
                "demo-0.1.0-py3-none-any.whl",
                "objects/invalid.whl",
                "a".repeat(64),
                9,
            ),
        )
        .await;
        assert_eq!(
            invalid.status,
            RegistryDistributionValidationStatus::InvalidArchive
        );
        assert!(invalid.error.as_deref().unwrap().contains("broken archive"));

        let storage = Arc::new(FakeObjectStorage::default());
        storage
            .put("objects/mismatch.whl", b"payload".to_vec())
            .await
            .expect("put mismatch bytes");
        let mismatch = validate_registry_target(
            storage,
            Arc::new(FakeInspector {
                inspection: fake_inspection("b".repeat(64)),
            }),
            pool.clone(),
            validation_target(
                "demo-0.1.0-py3-none-any.whl",
                "objects/mismatch.whl",
                "a".repeat(64),
                7,
            ),
        )
        .await;
        assert_eq!(
            mismatch.status,
            RegistryDistributionValidationStatus::ChecksumMismatch
        );
        let expected_actual_sha256 = "b".repeat(64);
        assert_eq!(
            mismatch.actual_sha256.as_deref(),
            Some(expected_actual_sha256.as_str())
        );
        assert!(
            mismatch
                .error
                .as_deref()
                .unwrap()
                .contains("expected sha256")
        );

        let storage = Arc::new(FakeObjectStorage::default());
        storage
            .put("objects/valid.whl", b"payload".to_vec())
            .await
            .expect("put valid bytes");
        let valid = validate_registry_target(
            storage,
            Arc::new(FakeInspector {
                inspection: fake_inspection("c".repeat(64)),
            }),
            pool,
            validation_target(
                "demo-0.1.0-py3-none-any.whl",
                "objects/valid.whl",
                "c".repeat(64),
                7,
            ),
        )
        .await;
        assert_eq!(valid.status, RegistryDistributionValidationStatus::Valid);
        assert_eq!(valid.actual_size_bytes, Some(42));
        assert_eq!(valid.kind, Some(DistributionKind::Wheel));
        assert_eq!(valid.detected_file_type.as_deref(), Some("zip"));
        assert_eq!(valid.extension_matches, Some(true));
        assert_eq!(valid.archive_entry_count, Some(2));
        assert_eq!(valid.error, None);
    }

    static TEST_LOGGER: TestLogger = TestLogger;
    static INIT_TEST_LOGGER: Once = Once::new();

    struct TestLogger;

    impl log::Log for TestLogger {
        fn enabled(&self, _metadata: &log::Metadata<'_>) -> bool {
            true
        }

        fn log(&self, record: &log::Record<'_>) {
            let _ = format!("{}", record.args());
        }

        fn flush(&self) {}
    }

    fn init_test_logger() {
        INIT_TEST_LOGGER.call_once(|| {
            let _ = log::set_logger(&TEST_LOGGER);
            log::set_max_level(log::LevelFilter::Trace);
        });
    }

    fn fake_inspection(sha256: String) -> DistributionInspection {
        DistributionInspection {
            kind: DistributionKind::Wheel,
            size_bytes: 42,
            sha256,
            archive_entry_count: 2,
            file_type: crate::FileTypeInspection {
                detector: "fake".into(),
                label: "zip".into(),
                mime_type: "application/zip".into(),
                group: "archive".into(),
                description: "Zip archive data".into(),
                score: 1.0,
                actual_extension: Some("whl".into()),
                expected_extensions: vec!["whl".into()],
                matches_extension: true,
            },
        }
    }

    fn validation_target(
        filename: &str,
        object_key: &str,
        expected_sha256: String,
        size_bytes: u64,
    ) -> RegistryDistributionValidationTarget {
        let now = Utc
            .with_ymd_and_hms(2026, 4, 11, 12, 0, 0)
            .single()
            .expect("fixed time");
        let tenant = Tenant::new(
            TenantId::new(Uuid::from_u128(1)),
            TenantSlug::new("acme").expect("tenant slug"),
            "Acme",
            MirrorRule { enabled: false },
            now,
        )
        .expect("tenant");
        let project = Project::new(
            ProjectId::new(Uuid::from_u128(2)),
            tenant.id,
            ProjectName::new("demo").expect("project name"),
            ProjectSource::Local,
            "Demo",
            "Demo",
            now,
        );
        let release = Release {
            id: ReleaseId::new(Uuid::from_u128(3)),
            project_id: project.id,
            version: ReleaseVersion::new("0.1.0").expect("version"),
            yanked: None,
            created_at: now,
        };
        let artifact = Artifact {
            id: ArtifactId::new(Uuid::from_u128(4)),
            release_id: release.id,
            filename: filename.to_string(),
            kind: ArtifactKind::Wheel,
            size_bytes,
            digests: DigestSet::new(expected_sha256, None).expect("digest"),
            object_key: object_key.to_string(),
            upstream_url: None,
            provenance_key: None,
            yanked: None,
            created_at: now,
        };

        RegistryDistributionValidationTarget {
            tenant,
            project,
            release,
            artifact,
        }
    }
}
