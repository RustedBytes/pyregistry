use crate::{
    ApplicationError, ArtifactSecurityDetails, DependencyVulnerabilityDetails,
    DependencyVulnerabilityQuery, DependencyVulnerabilityReport, PackageDetails,
    PackageReleaseDetails, PackageSecuritySummary, PackageVulnerabilityQuery, PyregistryApp,
    RegistryPackageSecurityReport, RegistrySecurityReport, VulnerablePackageNotification,
    WheelArchiveSnapshot, severity_rank,
};
use log::{debug, info, warn};
use pyregistry_domain::{Project, Tenant};
use std::collections::{BTreeMap, BTreeSet};

impl PyregistryApp {
    pub(crate) async fn attach_package_security(
        &self,
        package_name: &str,
        normalized_name: &str,
        releases: &mut [PackageReleaseDetails],
    ) -> PackageSecuritySummary {
        let mut queries = BTreeMap::new();
        let mut file_count = 0usize;

        for release in releases.iter_mut() {
            if release.artifacts.is_empty() {
                continue;
            }
            queries
                .entry(release.version.clone())
                .or_insert_with(|| PackageVulnerabilityQuery {
                    package_name: normalized_name.to_string(),
                    version: release.version.clone(),
                });
            for artifact in &mut release.artifacts {
                file_count += 1;
                artifact.security = ArtifactSecurityDetails::pending();
            }
        }

        if queries.is_empty() {
            return PackageSecuritySummary::default();
        }

        info!(
            "running PySentry vulnerability scan for package `{package_name}` across {} release version(s) and {} file(s)",
            queries.len(),
            file_count
        );

        let reports = match self
            .vulnerability_scanner
            .scan_package_versions(&queries.values().cloned().collect::<Vec<_>>())
            .await
        {
            Ok(reports) => reports,
            Err(error) => {
                warn!("PySentry vulnerability scan failed for package `{package_name}`: {error}");
                let message = error.to_string();
                for release in releases {
                    for artifact in &mut release.artifacts {
                        artifact.security = ArtifactSecurityDetails::failed(message.clone());
                    }
                }
                return PackageSecuritySummary {
                    scanned_file_count: 0,
                    vulnerable_file_count: 0,
                    vulnerability_count: 0,
                    highest_severity: None,
                    scan_error: Some(message),
                    ..PackageSecuritySummary::default()
                };
            }
        };

        let reports_by_version = reports
            .into_iter()
            .map(|report| (report.version.clone(), report))
            .collect::<BTreeMap<_, _>>();

        let mut summary = PackageSecuritySummary {
            scanned_file_count: 0,
            vulnerable_file_count: 0,
            vulnerability_count: 0,
            highest_severity: None,
            scan_error: None,
            ..PackageSecuritySummary::default()
        };
        let mut per_version_errors = BTreeSet::new();

        for release in releases.iter_mut() {
            let Some(report) = reports_by_version.get(&release.version) else {
                let message = "vulnerability scan did not return a result for this version";
                per_version_errors.insert(format!("{}: {message}", release.version));
                for artifact in &mut release.artifacts {
                    artifact.security = ArtifactSecurityDetails::failed(message);
                }
                continue;
            };

            if let Some(error) = &report.scan_error {
                per_version_errors.insert(format!("{}: {error}", release.version));
                for artifact in &mut release.artifacts {
                    artifact.security = ArtifactSecurityDetails::failed(error.clone());
                }
                continue;
            }

            for artifact in &mut release.artifacts {
                let security = ArtifactSecurityDetails::scanned(report.vulnerabilities.clone());
                summary.scanned_file_count += 1;
                summary.vulnerability_count += security.vulnerability_count;
                if security.vulnerability_count > 0 {
                    summary.vulnerable_file_count += 1;
                }
                summary.highest_severity = max_severity(
                    summary.highest_severity.take(),
                    security.highest_severity.clone(),
                );
                artifact.security = security;
            }
        }

        self.attach_dependency_security(package_name, releases, &mut summary)
            .await;

        if !per_version_errors.is_empty() {
            summary.scan_error = Some(
                per_version_errors
                    .into_iter()
                    .collect::<Vec<_>>()
                    .join("; "),
            );
        }

        debug!(
            "PySentry scan summary for package `{package_name}`: scanned_files={}, vulnerable_files={}, vulnerabilities={}, highest={:?}",
            summary.scanned_file_count,
            summary.vulnerable_file_count,
            summary.vulnerability_count,
            summary.highest_severity
        );
        summary
    }

    async fn attach_dependency_security(
        &self,
        package_name: &str,
        releases: &mut [PackageReleaseDetails],
        summary: &mut PackageSecuritySummary,
    ) {
        let mut targets = Vec::new();
        let mut queries = BTreeMap::new();

        for (release_index, release) in releases.iter_mut().enumerate() {
            for (artifact_index, artifact) in release.artifacts.iter_mut().enumerate() {
                if !artifact.filename.to_ascii_lowercase().ends_with(".whl") {
                    continue;
                }

                let bytes = match self.object_storage.get(&artifact.object_key).await {
                    Ok(Some(bytes)) => bytes,
                    Ok(None) => {
                        artifact.security.dependency_scan_error =
                            Some("wheel bytes are not cached, so pinned requirements could not be scanned".into());
                        continue;
                    }
                    Err(error) => {
                        artifact.security.dependency_scan_error = Some(error.to_string());
                        continue;
                    }
                };

                let archive = match self
                    .wheel_archive_reader
                    .read_wheel_bytes(&artifact.filename, &bytes)
                {
                    Ok(archive) => archive,
                    Err(error) => {
                        artifact.security.dependency_scan_error = Some(error.to_string());
                        continue;
                    }
                };

                let requirements = pinned_requirements_from_wheel(&archive);
                if requirements.is_empty() {
                    continue;
                }

                for requirement in requirements {
                    queries
                        .entry((
                            requirement.package_name.clone(),
                            requirement.version.clone(),
                        ))
                        .or_insert_with(|| DependencyVulnerabilityQuery {
                            package_name: requirement.package_name.clone(),
                            version: requirement.version.clone(),
                        });
                    targets.push(DependencyScanTarget {
                        release_index,
                        artifact_index,
                        requirement,
                    });
                }
            }
        }

        if queries.is_empty() {
            return;
        }

        info!(
            "running PySentry dependency vulnerability scan for package `{package_name}` across {} pinned requirement(s)",
            queries.len()
        );

        let reports = match self
            .vulnerability_scanner
            .scan_dependency_versions(&queries.values().cloned().collect::<Vec<_>>())
            .await
        {
            Ok(reports) => reports,
            Err(error) => {
                warn!(
                    "PySentry dependency vulnerability scan failed for package `{package_name}`: {error}"
                );
                let message = error.to_string();
                summary.dependency_scan_error = Some(message.clone());
                for target in targets {
                    releases[target.release_index].artifacts[target.artifact_index]
                        .security
                        .dependency_scan_error = Some(message.clone());
                }
                return;
            }
        };

        let reports_by_dependency = reports
            .into_iter()
            .map(|report| {
                (
                    (report.package_name.clone(), report.version.clone()),
                    report,
                )
            })
            .collect::<BTreeMap<_, _>>();

        let mut details_by_artifact: BTreeMap<(usize, usize), Vec<DependencyVulnerabilityDetails>> =
            BTreeMap::new();
        let mut errors_by_artifact: BTreeMap<(usize, usize), BTreeSet<String>> = BTreeMap::new();

        for target in targets {
            let key = (
                target.requirement.package_name.clone(),
                target.requirement.version.clone(),
            );
            let report = reports_by_dependency.get(&key).cloned().unwrap_or_else(|| {
                DependencyVulnerabilityReport::failed(
                    &DependencyVulnerabilityQuery {
                        package_name: target.requirement.package_name.clone(),
                        version: target.requirement.version.clone(),
                    },
                    "dependency vulnerability scan did not return a result",
                )
            });

            if let Some(error) = &report.scan_error {
                errors_by_artifact
                    .entry((target.release_index, target.artifact_index))
                    .or_default()
                    .insert(format!(
                        "{}=={}: {error}",
                        target.requirement.package_name, target.requirement.version
                    ));
            }

            details_by_artifact
                .entry((target.release_index, target.artifact_index))
                .or_default()
                .push(DependencyVulnerabilityDetails::from_report(
                    target.requirement.requirement,
                    report,
                ));
        }

        for ((release_index, artifact_index), dependencies) in details_by_artifact {
            let scan_error = errors_by_artifact
                .remove(&(release_index, artifact_index))
                .map(|errors| errors.into_iter().collect::<Vec<_>>().join("; "));
            let artifact = &mut releases[release_index].artifacts[artifact_index];
            artifact.security = artifact
                .security
                .clone()
                .with_dependencies(dependencies, scan_error);
            summary.scanned_dependency_count += artifact.security.dependency_count;
            summary.vulnerable_dependency_count += artifact.security.vulnerable_dependency_count;
            summary.dependency_vulnerability_count +=
                artifact.security.dependency_vulnerability_count;
        }
    }

    pub async fn check_registry_security(
        &self,
        tenant_filter: Option<&str>,
        project_filter: Option<&str>,
    ) -> Result<RegistrySecurityReport, ApplicationError> {
        info!(
            "checking registry package security with tenant_filter={tenant_filter:?} project_filter={project_filter:?}"
        );
        let tenants = self.tenants_for_security_check(tenant_filter).await?;
        let mut packages = Vec::new();

        for tenant in tenants {
            let projects = self
                .projects_for_security_check(&tenant, project_filter)
                .await?;
            for project in projects {
                let details = self
                    .get_package_details(tenant.slug.as_str(), project.name.original())
                    .await?;
                packages.push(security_report_for_package(&tenant, details));
            }
        }

        let report = registry_security_report(packages);
        self.notify_vulnerable_packages(&report).await;
        Ok(report)
    }

    async fn tenants_for_security_check(
        &self,
        tenant_filter: Option<&str>,
    ) -> Result<Vec<Tenant>, ApplicationError> {
        if let Some(tenant_slug) = tenant_filter {
            return Ok(vec![self.require_tenant(tenant_slug).await?]);
        }
        self.store.list_tenants().await
    }

    async fn projects_for_security_check(
        &self,
        tenant: &Tenant,
        project_filter: Option<&str>,
    ) -> Result<Vec<Project>, ApplicationError> {
        if let Some(project_name) = project_filter {
            return Ok(vec![
                self.ensure_project_available(tenant.slug.as_str(), project_name)
                    .await?,
            ]);
        }
        self.store.list_projects(tenant.id).await
    }

    async fn notify_vulnerable_packages(&self, report: &RegistrySecurityReport) {
        for package in report
            .packages
            .iter()
            .filter(|package| package.security.vulnerability_count > 0)
        {
            let notification = VulnerablePackageNotification::from_registry_package(package);
            if let Err(error) = self
                .vulnerability_notifier
                .notify_vulnerable_package(&notification)
                .await
            {
                warn!(
                    "failed to send vulnerable package notification for tenant `{}` project `{}`: {error}",
                    notification.tenant_slug, notification.project_name
                );
            }
        }
    }
}

fn security_report_for_package(
    tenant: &Tenant,
    details: PackageDetails,
) -> RegistryPackageSecurityReport {
    RegistryPackageSecurityReport {
        tenant_slug: tenant.slug.as_str().to_string(),
        project_name: details.project_name,
        normalized_name: details.normalized_name,
        security: details.security,
    }
}

fn registry_security_report(
    packages: Vec<RegistryPackageSecurityReport>,
) -> RegistrySecurityReport {
    let mut report = RegistrySecurityReport {
        package_count: packages.len(),
        file_count: 0,
        vulnerable_file_count: 0,
        vulnerability_count: 0,
        highest_severity: None,
        packages,
    };

    for package in &report.packages {
        report.file_count += package.security.scanned_file_count;
        report.vulnerable_file_count += package.security.vulnerable_file_count;
        report.vulnerability_count += package.security.vulnerability_count;
        report.highest_severity = max_severity(
            report.highest_severity.take(),
            package.security.highest_severity.clone(),
        );
    }

    report
}

fn max_severity(left: Option<String>, right: Option<String>) -> Option<String> {
    match (left, right) {
        (Some(left), Some(right)) => {
            if severity_rank(&right) > severity_rank(&left) {
                Some(right)
            } else {
                Some(left)
            }
        }
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}

#[derive(Debug, Clone)]
struct DependencyScanTarget {
    release_index: usize,
    artifact_index: usize,
    requirement: PinnedRequirement,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PinnedRequirement {
    requirement: String,
    package_name: String,
    version: String,
}

fn pinned_requirements_from_wheel(archive: &WheelArchiveSnapshot) -> Vec<PinnedRequirement> {
    let mut requirements = Vec::new();

    for entry in &archive.entries {
        if !entry.path.ends_with(".dist-info/METADATA") {
            continue;
        }

        let Ok(metadata) = std::str::from_utf8(&entry.contents) else {
            continue;
        };

        let mut current_header = String::new();
        for line in metadata.lines() {
            if line.starts_with(' ') || line.starts_with('\t') {
                current_header.push_str(line.trim());
                continue;
            }

            if let Some(requirement) = pinned_requirement_from_header(&current_header) {
                requirements.push(requirement);
            }
            current_header = line.to_string();
        }

        if let Some(requirement) = pinned_requirement_from_header(&current_header) {
            requirements.push(requirement);
        }
    }

    requirements.sort_by(|left, right| {
        left.package_name
            .cmp(&right.package_name)
            .then_with(|| left.version.cmp(&right.version))
    });
    requirements.dedup_by(|left, right| {
        left.package_name == right.package_name && left.version == right.version
    });
    requirements
}

fn pinned_requirement_from_header(header: &str) -> Option<PinnedRequirement> {
    let requirement = header.strip_prefix("Requires-Dist:")?.trim();
    pinned_requirement(requirement)
}

fn pinned_requirement(requirement: &str) -> Option<PinnedRequirement> {
    let requirement_without_marker = requirement.split(';').next()?.trim();
    let requirement_without_parens = requirement_without_marker
        .trim_start_matches('(')
        .trim_end_matches(')')
        .trim();
    if requirement_without_parens.contains("===") {
        return None;
    }
    let (name_part, version_part) = requirement_without_parens.split_once("==")?;
    if version_part.contains('*') {
        return None;
    }

    let name = name_part
        .trim()
        .split(&['[', ' ', '\t', '<', '>', '=', '!', '~', '('][..])
        .next()
        .unwrap_or("")
        .trim();
    let version = version_part
        .trim()
        .trim_start_matches('(')
        .trim_end_matches(')')
        .trim_end_matches(',')
        .trim()
        .trim_matches('"')
        .trim_matches('\'');

    if name.is_empty() || version.is_empty() {
        return None;
    }

    Some(PinnedRequirement {
        requirement: requirement.to_string(),
        package_name: name.to_ascii_lowercase().replace('_', "-"),
        version: version.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_security_report_aggregates_package_summaries() {
        let report = registry_security_report(vec![
            package_report("acme", "demo", 2, 1, 3, Some("MEDIUM")),
            package_report("acme", "helper", 1, 1, 1, Some("CRITICAL")),
            package_report("tools", "clean", 4, 0, 0, None),
        ]);

        assert_eq!(report.package_count, 3);
        assert_eq!(report.file_count, 7);
        assert_eq!(report.vulnerable_file_count, 2);
        assert_eq!(report.vulnerability_count, 4);
        assert_eq!(report.highest_severity.as_deref(), Some("CRITICAL"));
    }

    #[test]
    fn max_severity_keeps_stronger_or_existing_value() {
        assert_eq!(
            max_severity(Some("LOW".into()), Some("HIGH".into())).as_deref(),
            Some("HIGH")
        );
        assert_eq!(
            max_severity(Some("MEDIUM".into()), Some("UNKNOWN".into())).as_deref(),
            Some("MEDIUM")
        );
        assert_eq!(
            max_severity(Some("LOW".into()), None).as_deref(),
            Some("LOW")
        );
        assert_eq!(
            max_severity(None, Some("CRITICAL".into())).as_deref(),
            Some("CRITICAL")
        );
        assert_eq!(max_severity(None, None), None);
    }

    #[test]
    fn extracts_only_pinned_wheel_requirements_for_dependency_scans() {
        let archive = WheelArchiveSnapshot {
            wheel_filename: "demo-1.0.0-py3-none-any.whl".into(),
            entries: vec![crate::WheelArchiveEntry {
                path: "demo-1.0.0.dist-info/METADATA".into(),
                contents: b"Name: demo\nRequires-Dist: requests==2.19.0\nRequires-Dist: flask>=2\nRequires-Dist: urllib3[secure]==1.24.1 ; python_version >= '3.9'\nRequires-Dist: wildcard==1.*\n".to_vec(),
            }],
        };

        let requirements = pinned_requirements_from_wheel(&archive);

        assert_eq!(
            requirements,
            vec![
                PinnedRequirement {
                    requirement: "requests==2.19.0".into(),
                    package_name: "requests".into(),
                    version: "2.19.0".into(),
                },
                PinnedRequirement {
                    requirement: "urllib3[secure]==1.24.1 ; python_version >= '3.9'".into(),
                    package_name: "urllib3".into(),
                    version: "1.24.1".into(),
                },
            ]
        );
    }

    fn package_report(
        tenant_slug: &str,
        project_name: &str,
        scanned_file_count: usize,
        vulnerable_file_count: usize,
        vulnerability_count: usize,
        highest_severity: Option<&str>,
    ) -> RegistryPackageSecurityReport {
        RegistryPackageSecurityReport {
            tenant_slug: tenant_slug.into(),
            project_name: project_name.into(),
            normalized_name: project_name.into(),
            security: PackageSecuritySummary {
                scanned_file_count,
                vulnerable_file_count,
                vulnerability_count,
                highest_severity: highest_severity.map(str::to_string),
                scan_error: None,
                ..PackageSecuritySummary::default()
            },
        }
    }
}
