use crate::ignored_findings::IgnoredFindings;
use async_trait::async_trait;
use log::{debug, info, warn};
use pyregistry_application::{
    ApplicationError, DependencyVulnerabilityQuery, DependencyVulnerabilityReport,
    PackageVulnerability, PackageVulnerabilityQuery, PackageVulnerabilityReport,
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
    ignored_vulnerability_ids: IgnoredFindings,
}

impl PySentryVulnerabilityScanner {
    #[must_use]
    pub fn new(cache_dir: impl Into<PathBuf>) -> Self {
        Self::with_ignored_vulnerability_ids(cache_dir, Vec::<String>::new())
    }

    #[must_use]
    pub fn with_ignored_vulnerability_ids(
        cache_dir: impl Into<PathBuf>,
        ignored_vulnerability_ids: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Self {
        Self {
            cache_dir: cache_dir.into(),
            source_type: VulnerabilitySourceType::Pypa,
            vulnerability_ttl_hours: 48,
            ignored_vulnerability_ids: IgnoredFindings::new(ignored_vulnerability_ids),
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
                push_unignored_vulnerability(
                    &self.ignored_vulnerability_ids,
                    &mut report.vulnerabilities,
                    map_vulnerability(vulnerability_match),
                );
            }
        }

        Ok(packages
            .iter()
            .filter_map(|query| reports.get(&query_key(query)).cloned())
            .collect())
    }

    async fn scan_dependency_versions(
        &self,
        dependencies: &[DependencyVulnerabilityQuery],
    ) -> Result<Vec<DependencyVulnerabilityReport>, ApplicationError> {
        if dependencies.is_empty() {
            return Ok(Vec::new());
        }

        info!(
            "running PySentry dependency vulnerability lookup for {} pinned requirement(s)",
            dependencies.len()
        );
        debug!("using PySentry cache at {}", self.cache_dir.display());

        let mut reports = dependencies
            .iter()
            .map(|query| {
                (
                    dependency_query_key(query),
                    DependencyVulnerabilityReport::clean(query),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let mut seen = BTreeSet::new();
        let mut scanned_dependencies = Vec::new();
        let mut fetch_packages = Vec::new();
        let mut parsed_to_original = BTreeMap::new();

        for query in dependencies {
            let original_key = dependency_query_key(query);
            if !seen.insert(original_key.clone()) {
                continue;
            }

            let package_name = match PackageName::from_str(&query.package_name) {
                Ok(package_name) => package_name,
                Err(error) => {
                    reports.insert(
                        original_key,
                        DependencyVulnerabilityReport::failed(
                            query,
                            format!("invalid dependency name for PySentry: {error}"),
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
                        DependencyVulnerabilityReport::failed(
                            query,
                            format!("invalid dependency version for PySentry: {error}"),
                        ),
                    );
                    continue;
                }
            };

            parsed_to_original.insert(
                (package_name.to_string(), version.to_string()),
                dependency_query_key(query),
            );
            fetch_packages.push((package_name.to_string(), version.to_string()));
            scanned_dependencies.push(ScannedDependency {
                name: package_name,
                version,
                is_direct: true,
                source: DependencySource::Registry,
                path: None,
                source_file: Some("wheel METADATA Requires-Dist".into()),
            });
        }

        if scanned_dependencies.is_empty() {
            warn!("PySentry dependency scan had no parseable pinned requirements to check");
            return Ok(dependencies
                .iter()
                .filter_map(|query| reports.get(&dependency_query_key(query)).cloned())
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
                ApplicationError::External(format!(
                    "PySentry dependency vulnerability lookup failed: {error}"
                ))
            })?;
        let matcher = VulnerabilityMatcher::new(
            database,
            MatcherConfig::new(SeverityLevel::Low, Vec::new(), Vec::new(), false, false),
        );
        let matches = matcher
            .find_vulnerabilities(&scanned_dependencies)
            .map_err(|error| {
                ApplicationError::External(format!(
                    "PySentry dependency vulnerability matching failed: {error}"
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
                    "PySentry returned vulnerability for unmatched dependency `{}` version `{}`",
                    vulnerability_match.package_name, vulnerability_match.installed_version
                );
                continue;
            };

            if let Some(report) = reports.get_mut(&original_key) {
                push_unignored_vulnerability(
                    &self.ignored_vulnerability_ids,
                    &mut report.vulnerabilities,
                    map_vulnerability(vulnerability_match),
                );
            }
        }

        Ok(dependencies
            .iter()
            .filter_map(|query| reports.get(&dependency_query_key(query)).cloned())
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

fn push_unignored_vulnerability(
    ignored_vulnerability_ids: &IgnoredFindings,
    vulnerabilities: &mut Vec<PackageVulnerability>,
    vulnerability: PackageVulnerability,
) {
    if !ignored_vulnerability_ids.matches(&vulnerability.id) {
        vulnerabilities.push(vulnerability);
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

fn dependency_query_key(query: &DependencyVulnerabilityQuery) -> (String, String) {
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
    fn scanner_defaults_and_severity_labels_are_stable() {
        let cache_dir =
            std::env::temp_dir().join(format!("pyregistry-pysentry-config-{}", Uuid::new_v4()));
        let scanner = PySentryVulnerabilityScanner::new(cache_dir.clone());

        assert_eq!(scanner.cache_dir, cache_dir);
        assert_eq!(scanner.vulnerability_ttl_hours, 48);
        assert!(matches!(scanner.source_type, VulnerabilitySourceType::Pypa));
        assert!(!scanner.ignored_vulnerability_ids.matches("GHSA-demo"));

        let cases = [
            (Severity::Low, None, "LOW"),
            (Severity::Medium, None, "MEDIUM"),
            (Severity::High, None, "HIGH"),
            (Severity::Critical, None, "CRITICAL"),
            (Severity::Unknown, None, "UNKNOWN"),
            (Severity::Unknown, Some(0.1), "LOW"),
            (Severity::Unknown, Some(4.0), "MEDIUM"),
            (Severity::Unknown, Some(7.0), "HIGH"),
            (Severity::Unknown, Some(9.0), "CRITICAL"),
            (Severity::Low, Some(9.8), "LOW"),
            (Severity::Medium, Some(9.8), "MEDIUM"),
            (Severity::Critical, Some(0.1), "CRITICAL"),
        ];

        for (severity, cvss_score, expected) in cases {
            assert_eq!(severity_label(severity, cvss_score), expected);
        }

        let query = PackageVulnerabilityQuery {
            package_name: "Demo-Pkg".into(),
            version: "1.2.3".into(),
        };
        assert_eq!(query_key(&query), ("Demo-Pkg".into(), "1.2.3".into()));
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

    #[test]
    fn ignores_configured_pysentry_vulnerability_ids() {
        let ignores = IgnoredFindings::new(["ghsa-demo"]);
        let mut vulnerabilities = Vec::new();

        push_unignored_vulnerability(
            &ignores,
            &mut vulnerabilities,
            PackageVulnerability {
                id: "GHSA-DEMO".into(),
                summary: "ignored".into(),
                severity: "LOW".into(),
                fixed_versions: Vec::new(),
                references: Vec::new(),
                source: None,
                cvss_score: None,
            },
        );
        push_unignored_vulnerability(
            &ignores,
            &mut vulnerabilities,
            PackageVulnerability {
                id: "GHSA-KEPT".into(),
                summary: "kept".into(),
                severity: "LOW".into(),
                fixed_versions: Vec::new(),
                references: Vec::new(),
                source: None,
                cvss_score: None,
            },
        );

        assert_eq!(vulnerabilities.len(), 1);
        assert_eq!(vulnerabilities[0].id, "GHSA-KEPT");
    }
}
