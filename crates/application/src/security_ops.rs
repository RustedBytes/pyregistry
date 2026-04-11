use crate::{
    ApplicationError, ArtifactSecurityDetails, PackageDetails, PackageReleaseDetails,
    PackageSecuritySummary, PackageVulnerabilityQuery, PyregistryApp,
    RegistryPackageSecurityReport, RegistrySecurityReport, severity_rank,
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
        };
        let mut per_version_errors = BTreeSet::new();

        for release in releases {
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

        Ok(registry_security_report(packages))
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
            },
        }
    }
}
