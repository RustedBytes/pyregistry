use async_trait::async_trait;
use log::warn;
use pyregistry_application::{
    ApplicationError, PackageVulnerabilityQuery, PackageVulnerabilityReport, VulnerabilityScanner,
};
use std::path::PathBuf;

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
        Err(ApplicationError::External(
            "PySentry vulnerability lookup is unavailable on Windows GNU targets".into(),
        ))
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

        let result = scanner
            .scan_package_versions(&[PackageVulnerabilityQuery {
                package_name: "demo".into(),
                version: "1.0.0".into(),
            }])
            .await;

        assert!(
            matches!(result, Err(ApplicationError::External(message)) if message.contains("Windows GNU"))
        );
    }
}
