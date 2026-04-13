use async_trait::async_trait;
use log::warn;
use pyregistry_application::{
    ApplicationError, DependencyVulnerabilityQuery, DependencyVulnerabilityReport,
    PackageVulnerabilityQuery, PackageVulnerabilityReport, VulnerabilityScanner,
};
use std::path::PathBuf;

const PACKAGE_LOOKUP_UNAVAILABLE: &str =
    "PySentry vulnerability lookup is unavailable on Windows GNU targets";
const DEPENDENCY_LOOKUP_UNAVAILABLE: &str =
    "PySentry dependency vulnerability lookup is unavailable on Windows GNU targets";

pub struct PySentryVulnerabilityScanner {
    cache_dir: PathBuf,
}

impl PySentryVulnerabilityScanner {
    #[must_use]
    pub fn new(cache_dir: impl Into<PathBuf>) -> Self {
        Self {
            cache_dir: cache_dir.into(),
        }
    }

    #[must_use]
    pub fn with_ignored_vulnerability_ids(
        cache_dir: impl Into<PathBuf>,
        _ignored_vulnerability_ids: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Self {
        Self::new(cache_dir)
    }
}

#[async_trait]
impl VulnerabilityScanner for PySentryVulnerabilityScanner {
    async fn scan_package_versions(
        &self,
        packages: &[PackageVulnerabilityQuery],
    ) -> Result<Vec<PackageVulnerabilityReport>, ApplicationError> {
        if packages.is_empty() {
            return Ok(Vec::new());
        }

        warn!(
            "PySentry vulnerability lookup is unavailable on Windows GNU targets; cache path was {}",
            self.cache_dir.display()
        );
        Ok(packages
            .iter()
            .map(|query| PackageVulnerabilityReport::failed(query, PACKAGE_LOOKUP_UNAVAILABLE))
            .collect())
    }

    async fn scan_dependency_versions(
        &self,
        dependencies: &[DependencyVulnerabilityQuery],
    ) -> Result<Vec<DependencyVulnerabilityReport>, ApplicationError> {
        if dependencies.is_empty() {
            return Ok(Vec::new());
        }

        warn!(
            "PySentry dependency vulnerability lookup is unavailable on Windows GNU targets; cache path was {}",
            self.cache_dir.display()
        );
        Ok(dependencies
            .iter()
            .map(|query| {
                DependencyVulnerabilityReport::failed(query, DEPENDENCY_LOOKUP_UNAVAILABLE)
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[tokio::test]
    async fn returns_empty_report_for_empty_input() {
        let scanner = PySentryVulnerabilityScanner::new(
            std::env::temp_dir().join(format!("pyregistry-pysentry-{}", Uuid::new_v4())),
        );

        let reports = scanner
            .scan_package_versions(&[])
            .await
            .expect("empty scan");

        assert!(reports.is_empty());
    }

    #[tokio::test]
    async fn reports_unavailable_for_non_empty_input() {
        let scanner = PySentryVulnerabilityScanner::new(
            std::env::temp_dir().join(format!("pyregistry-pysentry-{}", Uuid::new_v4())),
        );

        let reports = scanner
            .scan_package_versions(&[PackageVulnerabilityQuery {
                package_name: "demo".into(),
                version: "1.0.0".into(),
            }])
            .await
            .expect("unavailable report");

        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].package_name, "demo");
        assert_eq!(reports[0].version, "1.0.0");
        assert!(
            reports[0]
                .scan_error
                .as_deref()
                .is_some_and(|message| message.contains("Windows GNU"))
        );
    }

    #[tokio::test]
    async fn reports_dependency_lookup_unavailable_for_non_empty_input() {
        let scanner = PySentryVulnerabilityScanner::new(
            std::env::temp_dir().join(format!("pyregistry-pysentry-{}", Uuid::new_v4())),
        );

        let reports = scanner
            .scan_dependency_versions(&[DependencyVulnerabilityQuery {
                package_name: "requests".into(),
                version: "2.19.0".into(),
            }])
            .await
            .expect("unavailable report");

        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].package_name, "requests");
        assert_eq!(reports[0].version, "2.19.0");
        assert!(
            reports[0]
                .scan_error
                .as_deref()
                .is_some_and(|message| message.contains("Windows GNU"))
        );
    }
}
