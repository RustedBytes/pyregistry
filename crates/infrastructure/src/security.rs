use async_trait::async_trait;
use log::{debug, info, warn};
use pyregistry_application::{
    ApplicationError, PackageVulnerability, PackageVulnerabilityQuery, PackageVulnerabilityReport,
    VulnerabilityScanner,
};
use pysentry::{
    AuditCache, MatcherConfig, PackageName, Severity, SeverityLevel, Version, VulnerabilityMatcher,
    VulnerabilitySource, VulnerabilitySourceType,
    config::HttpConfig,
    dependency::scanner::{DependencySource, ScannedDependency},
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::str::FromStr;

pub struct PySentryVulnerabilityScanner {
    cache_dir: PathBuf,
    source_type: VulnerabilitySourceType,
    vulnerability_ttl_hours: u64,
}

impl PySentryVulnerabilityScanner {
    #[must_use]
    pub fn new(cache_dir: impl Into<PathBuf>) -> Self {
        Self {
            cache_dir: cache_dir.into(),
            source_type: VulnerabilitySourceType::Pypa,
            vulnerability_ttl_hours: 48,
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

        info!(
            "running PySentry vulnerability lookup for {} package version(s)",
            packages.len()
        );
        debug!("using PySentry cache at {}", self.cache_dir.display());

        let mut reports = packages
            .iter()
            .map(|query| (query_key(query), PackageVulnerabilityReport::clean(query)))
            .collect::<BTreeMap<_, _>>();
        let mut seen = BTreeSet::new();
        let mut dependencies = Vec::new();
        let mut fetch_packages = Vec::new();
        let mut parsed_to_original = BTreeMap::new();

        for query in packages {
            let original_key = query_key(query);
            if !seen.insert(original_key.clone()) {
                continue;
            }

            let package_name = match PackageName::from_str(&query.package_name) {
                Ok(package_name) => package_name,
                Err(error) => {
                    reports.insert(
                        original_key,
                        PackageVulnerabilityReport::failed(
                            query,
                            format!("invalid package name for PySentry: {error}"),
                        ),
                    );
                    continue;
                }
            };
            let version = match Version::from_str(&query.version) {
                Ok(version) => version,
                Err(error) => {
                    reports.insert(
                        original_key,
                        PackageVulnerabilityReport::failed(
                            query,
                            format!("invalid package version for PySentry: {error}"),
                        ),
                    );
                    continue;
                }
            };

            parsed_to_original.insert(
                (package_name.to_string(), version.to_string()),
                query_key(query),
            );
            fetch_packages.push((package_name.to_string(), version.to_string()));
            dependencies.push(ScannedDependency {
                name: package_name,
                version,
                is_direct: true,
                source: DependencySource::Registry,
                path: None,
                source_file: Some("pyregistry release index".into()),
            });
        }

        if dependencies.is_empty() {
            warn!("PySentry scan had no parseable package versions to check");
            return Ok(packages
                .iter()
                .filter_map(|query| reports.get(&query_key(query)).cloned())
                .collect());
        }

        let cache = AuditCache::new(self.cache_dir.clone());
        let source = VulnerabilitySource::new(
            self.source_type.clone(),
            cache,
            false,
            HttpConfig::default(),
            self.vulnerability_ttl_hours,
        );
        let database = source
            .fetch_vulnerabilities(&fetch_packages)
            .await
            .map_err(|error| {
                ApplicationError::External(format!("PySentry vulnerability lookup failed: {error}"))
            })?;
        let matcher = VulnerabilityMatcher::new(
            database,
            MatcherConfig::new(SeverityLevel::Low, Vec::new(), Vec::new(), false, false),
        );
        let matches = matcher
            .find_vulnerabilities(&dependencies)
            .map_err(|error| {
                ApplicationError::External(format!(
                    "PySentry vulnerability matching failed: {error}"
                ))
            })?;
        let matches = matcher.filter_matches(matches);

        for vulnerability_match in matches {
            let parsed_key = (
                vulnerability_match.package_name.to_string(),
                vulnerability_match.installed_version.to_string(),
            );
            let Some(original_key) = parsed_to_original.get(&parsed_key).cloned() else {
                warn!(
                    "PySentry returned vulnerability for unmatched package `{}` version `{}`",
                    vulnerability_match.package_name, vulnerability_match.installed_version
                );
                continue;
            };

            if let Some(report) = reports.get_mut(&original_key) {
                report
                    .vulnerabilities
                    .push(map_vulnerability(vulnerability_match));
            }
        }

        Ok(packages
            .iter()
            .filter_map(|query| reports.get(&query_key(query)).cloned())
            .collect())
    }
}

fn map_vulnerability(
    value: pysentry::vulnerability::database::VulnerabilityMatch,
) -> PackageVulnerability {
    let severity = severity_label(value.vulnerability.severity, value.vulnerability.cvss_score);

    PackageVulnerability {
        id: value.vulnerability.id,
        summary: value.vulnerability.summary,
        severity,
        fixed_versions: value
            .vulnerability
            .fixed_versions
            .into_iter()
            .map(|version| version.to_string())
            .collect(),
        references: value.vulnerability.references,
        source: value.vulnerability.source,
        cvss_score: value.vulnerability.cvss_score,
    }
}

fn severity_label(severity: Severity, cvss_score: Option<f32>) -> String {
    let effective_severity = if matches!(severity, Severity::Unknown) {
        cvss_score
            .map(Severity::from_cvss_score)
            .unwrap_or(severity)
    } else {
        severity
    };

    effective_severity.to_string()
}

fn query_key(query: &PackageVulnerabilityQuery) -> (String, String) {
    (query.package_name.clone(), query.version.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[tokio::test]
    async fn reports_invalid_versions_without_network_lookup() {
        let scanner = PySentryVulnerabilityScanner::new(
            std::env::temp_dir().join(format!("pyregistry-pysentry-{}", Uuid::new_v4())),
        );

        let reports = scanner
            .scan_package_versions(&[PackageVulnerabilityQuery {
                package_name: "demo".into(),
                version: "not a valid version".into(),
            }])
            .await
            .expect("scan result");

        assert_eq!(reports.len(), 1);
        assert!(
            reports[0]
                .scan_error
                .as_deref()
                .is_some_and(|error| { error.contains("invalid package version for PySentry") })
        );
    }

    #[tokio::test]
    async fn returns_empty_report_without_network_lookup_for_empty_input() {
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
    async fn reports_invalid_package_names_without_network_lookup() {
        let scanner = PySentryVulnerabilityScanner::new(
            std::env::temp_dir().join(format!("pyregistry-pysentry-{}", Uuid::new_v4())),
        );

        let reports = scanner
            .scan_package_versions(&[PackageVulnerabilityQuery {
                package_name: "bad package name!".into(),
                version: "1.0.0".into(),
            }])
            .await
            .expect("scan result");

        assert_eq!(reports.len(), 1);
        assert!(
            reports[0]
                .scan_error
                .as_deref()
                .is_some_and(|error| error.contains("invalid package name for PySentry"))
        );
    }

    #[test]
    fn query_keys_preserve_requested_name_and_version() {
        let query = PackageVulnerabilityQuery {
            package_name: "Demo-Pkg".into(),
            version: "1.0.0".into(),
        };

        assert_eq!(query_key(&query), ("Demo-Pkg".into(), "1.0.0".into()));
    }

    #[test]
    fn derives_unknown_pysentry_severity_from_cvss_score() {
        assert_eq!(severity_label(Severity::Unknown, Some(9.8)), "CRITICAL");
        assert_eq!(severity_label(Severity::Unknown, Some(7.5)), "HIGH");
        assert_eq!(severity_label(Severity::Unknown, Some(5.0)), "MEDIUM");
        assert_eq!(severity_label(Severity::Unknown, Some(3.0)), "LOW");
        assert_eq!(severity_label(Severity::Unknown, None), "UNKNOWN");
    }

    #[test]
    fn keeps_explicit_pysentry_severity_over_cvss_score() {
        assert_eq!(severity_label(Severity::High, Some(9.8)), "HIGH");
    }

    #[test]
    fn maps_pysentry_vulnerability_matches_to_application_dtos() {
        let vulnerability = pysentry::vulnerability::database::Vulnerability {
            id: "GHSA-demo".into(),
            summary: "demo vulnerability".into(),
            description: Some("long description".into()),
            severity: Severity::Unknown,
            affected_versions: Vec::new(),
            fixed_versions: vec![Version::from_str("1.2.3").expect("version")],
            references: vec!["https://example.test/advisory".into()],
            cvss_score: Some(9.8),
            cvss_version: Some(3),
            published: None,
            modified: None,
            source: Some("pypa".into()),
            withdrawn: None,
            aliases: vec!["CVE-2026-0001".into()],
        };
        let vulnerability_match = pysentry::vulnerability::database::VulnerabilityMatch {
            package_name: PackageName::from_str("demo").expect("package"),
            installed_version: Version::from_str("1.0.0").expect("version"),
            vulnerability,
            is_direct: true,
        };

        let mapped = map_vulnerability(vulnerability_match);

        assert_eq!(mapped.id, "GHSA-demo");
        assert_eq!(mapped.summary, "demo vulnerability");
        assert_eq!(mapped.severity, "CRITICAL");
        assert_eq!(mapped.fixed_versions, vec!["1.2.3"]);
        assert_eq!(mapped.references, vec!["https://example.test/advisory"]);
        assert_eq!(mapped.source.as_deref(), Some("pypa"));
        assert_eq!(mapped.cvss_score, Some(9.8));
    }
}
