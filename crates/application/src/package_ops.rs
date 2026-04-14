use crate::{
    ApplicationError, CancellationSignal, MirrorRefreshFailure, MirrorRefreshReport,
    MirroredProjectSnapshot, NeverCancelled, ProvenanceDescriptor, PyregistryApp,
    SimpleArtifactLink, SimpleProject, SimpleProjectPage, WheelAuditFindingNotification,
    WheelAuditUseCase,
};
use futures_util::{
    FutureExt, StreamExt,
    future::{self, Either},
    stream,
};
use log::{debug, info, warn};
use pyregistry_domain::{
    Artifact, ArtifactId, AttestationBundle, AttestationSource, DigestSet, Project, ProjectId,
    ProjectName, ProjectSource, Release, ReleaseId, ReleaseVersion,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

impl PyregistryApp {
    pub async fn resolve_project_from_mirror(
        &self,
        tenant_slug: &str,
        project_name: &str,
    ) -> Result<Option<Project>, ApplicationError> {
        let cancellation = NeverCancelled;
        self.resolve_project_from_mirror_with_cancellation(tenant_slug, project_name, &cancellation)
            .await
    }

    pub async fn resolve_project_from_mirror_with_cancellation(
        &self,
        tenant_slug: &str,
        project_name: &str,
        cancellation: &dyn CancellationSignal,
    ) -> Result<Option<Project>, ApplicationError> {
        info!(
            "resolving tenant `{tenant_slug}` project `{project_name}` from local storage or mirror"
        );
        fail_if_cancelled(cancellation, "mirror project resolution")?;
        let tenant = self.require_tenant(tenant_slug).await?;
        let project_name = ProjectName::new(project_name)?;

        if let Some(project) = self
            .store
            .get_project_by_normalized_name(tenant.id, project_name.normalized())
            .await?
            && matches!(project.source, ProjectSource::Local)
        {
            debug!(
                "using local project `{}` for tenant `{tenant_slug}` without consulting the mirror",
                project.name.original()
            );
            return Ok(Some(project));
        }

        if !tenant.mirror_rule.enabled {
            info!(
                "mirror lookup skipped for tenant `{tenant_slug}` project `{}` because mirroring is disabled",
                project_name.original()
            );
            return Ok(None);
        }

        let fetch_project = self
            .mirror_client
            .fetch_project(project_name.original())
            .boxed();
        let cancelled = cancellation.cancelled().boxed();
        let snapshot = match future::select(fetch_project, cancelled).await {
            Either::Left((result, _)) => result?,
            Either::Right(((), _)) => {
                return Err(ApplicationError::Cancelled("mirror metadata fetch".into()));
            }
        };

        let Some(snapshot) = snapshot else {
            info!(
                "mirror lookup did not find upstream project `{}` for tenant `{tenant_slug}`",
                project_name.original()
            );
            return Ok(None);
        };

        info!(
            "mirror lookup fetched upstream project `{}` for tenant `{tenant_slug}`",
            project_name.original()
        );
        self.store_mirrored_project(tenant_slug, tenant.id, snapshot, cancellation)
            .await
    }

    pub async fn evict_mirror_cache(
        &self,
        tenant_slug: &str,
        project_name: &str,
    ) -> Result<(), ApplicationError> {
        info!("evicting mirror cache for tenant `{tenant_slug}` project `{project_name}`");
        let tenant = self.require_tenant(tenant_slug).await?;
        let project_name = ProjectName::new(project_name)?;
        let project = self
            .store
            .get_project_by_normalized_name(tenant.id, project_name.normalized())
            .await?
            .ok_or_else(|| ApplicationError::NotFound("package".into()))?;
        if !matches!(project.source, ProjectSource::Mirrored) {
            warn!(
                "mirror cache eviction skipped for tenant `{tenant_slug}` project `{}` because it is not mirrored",
                project.name.original()
            );
            return Ok(());
        }
        self.purge_project_internal(&project).await?;
        info!(
            "evicted mirrored project `{}` from tenant `{tenant_slug}`",
            project.name.original()
        );
        Ok(())
    }

    pub async fn refresh_mirrored_projects(&self) -> Result<MirrorRefreshReport, ApplicationError> {
        let cancellation = NeverCancelled;
        self.refresh_mirrored_projects_with_cancellation(&cancellation)
            .await
    }

    pub async fn refresh_mirrored_projects_with_cancellation(
        &self,
        cancellation: &dyn CancellationSignal,
    ) -> Result<MirrorRefreshReport, ApplicationError> {
        info!("starting background refresh for mirrored projects");
        let tenants = self.store.list_tenants().await?;
        let mut report = MirrorRefreshReport::default();

        for tenant in tenants {
            fail_if_cancelled(cancellation, "mirrored project refresh")?;
            if !tenant.mirror_rule.enabled {
                debug!(
                    "skipping mirrored project refresh for tenant `{}` because mirroring is disabled",
                    tenant.slug.as_str()
                );
                continue;
            }

            report.tenant_count += 1;
            let projects = self.store.list_projects(tenant.id).await?;
            for project in projects
                .into_iter()
                .filter(|project| matches!(project.source, ProjectSource::Mirrored))
            {
                fail_if_cancelled(cancellation, "mirrored project refresh")?;
                report.mirrored_project_count += 1;
                let tenant_slug = tenant.slug.as_str().to_string();
                let project_name = project.name.original().to_string();
                match self
                    .resolve_project_from_mirror_with_cancellation(
                        &tenant_slug,
                        &project_name,
                        cancellation,
                    )
                    .await
                {
                    Ok(Some(_)) => {
                        report.refreshed_project_count += 1;
                        info!(
                            "refreshed mirrored project `{project_name}` for tenant `{tenant_slug}`"
                        );
                    }
                    Ok(None) => {
                        report.failed_project_count += 1;
                        warn!(
                            "mirrored project refresh returned no upstream project for tenant `{tenant_slug}` project `{project_name}`"
                        );
                        report.failures.push(MirrorRefreshFailure {
                            tenant_slug,
                            project_name,
                            error: "upstream project was not found".into(),
                        });
                    }
                    Err(error) => {
                        report.failed_project_count += 1;
                        warn!(
                            "failed to refresh mirrored project `{project_name}` for tenant `{tenant_slug}`: {error}"
                        );
                        report.failures.push(MirrorRefreshFailure {
                            tenant_slug,
                            project_name,
                            error: error.to_string(),
                        });
                    }
                }
            }
        }

        info!(
            "background mirrored project refresh finished: tenants={}, mirrored_projects={}, refreshed={}, failed={}",
            report.tenant_count,
            report.mirrored_project_count,
            report.refreshed_project_count,
            report.failed_project_count
        );
        Ok(report)
    }

    pub async fn list_simple_projects(
        &self,
        tenant_slug: &str,
    ) -> Result<Vec<SimpleProject>, ApplicationError> {
        let tenant = self.require_tenant(tenant_slug).await?;
        let mut projects = self.store.list_projects(tenant.id).await?;
        projects.sort_by(|left, right| left.name.normalized().cmp(right.name.normalized()));
        let projects = projects
            .into_iter()
            .map(|project| SimpleProject {
                name: project.name.original().to_string(),
                normalized_name: project.name.normalized().to_string(),
            })
            .collect::<Vec<_>>();
        debug!(
            "built simple index listing for tenant `{tenant_slug}` with {} project(s)",
            projects.len()
        );
        Ok(projects)
    }

    pub async fn get_simple_project_index(
        &self,
        tenant_slug: &str,
        project_name: &str,
    ) -> Result<SimpleProjectPage, ApplicationError> {
        let project = self
            .ensure_project_available(tenant_slug, project_name)
            .await?;
        let mut release_artifact_groups = self.store.list_release_artifacts(project.id).await?;
        release_artifact_groups
            .sort_by(|left, right| right.release.version.cmp(&left.release.version));
        let mut artifacts = Vec::new();

        for group in release_artifact_groups {
            let mut release_artifacts = group.artifacts;
            release_artifacts.sort_by(|left, right| left.filename.cmp(&right.filename));
            for artifact in release_artifacts {
                artifacts.push(SimpleArtifactLink {
                    filename: artifact.filename.clone(),
                    version: group.release.version.as_str().to_string(),
                    sha256: artifact.digests.sha256.clone(),
                    url: format!(
                        "/t/{}/files/{}/{}/{}",
                        tenant_slug,
                        project.name.normalized(),
                        group.release.version.as_str(),
                        artifact.filename
                    ),
                    provenance_url: Some(format!(
                        "/t/{}/provenance/{}/{}/{}",
                        tenant_slug,
                        project.name.normalized(),
                        group.release.version.as_str(),
                        artifact.filename
                    )),
                    yanked_reason: artifact
                        .yanked
                        .as_ref()
                        .and_then(|state| state.reason.clone())
                        .or_else(|| {
                            group
                                .release
                                .yanked
                                .as_ref()
                                .and_then(|state| state.reason.clone())
                        }),
                });
            }
        }

        let page = SimpleProjectPage {
            tenant_slug: tenant_slug.to_string(),
            project_name: project.name.original().to_string(),
            artifacts,
        };
        debug!(
            "built simple project page for tenant `{}` project `{}` with {} artifact link(s)",
            page.tenant_slug,
            page.project_name,
            page.artifacts.len()
        );
        Ok(page)
    }

    pub async fn download_artifact(
        &self,
        tenant_slug: &str,
        project_name: &str,
        version: &str,
        filename: &str,
    ) -> Result<Vec<u8>, ApplicationError> {
        info!(
            "downloading artifact for tenant `{tenant_slug}` project `{project_name}` version `{version}` filename `{filename}`"
        );
        let artifact = self
            .find_artifact(tenant_slug, project_name, version, filename)
            .await?;

        if let Some(bytes) = self.object_storage.get(&artifact.object_key).await? {
            info!(
                "served artifact `{filename}` for tenant `{tenant_slug}` from local object storage"
            );
            return Ok(bytes);
        }

        let upstream_url = artifact
            .upstream_url
            .as_deref()
            .ok_or_else(|| ApplicationError::NotFound("artifact bytes".into()))?;
        let bytes = self
            .mirror_client
            .fetch_artifact_bytes(upstream_url)
            .await?;
        validate_mirrored_artifact_payload(&artifact, &bytes)?;
        self.object_storage
            .put(&artifact.object_key, bytes.clone())
            .await?;
        info!(
            "fetched artifact `{filename}` for tenant `{tenant_slug}` from upstream and cached it locally"
        );
        Ok(bytes)
    }

    pub async fn get_provenance(
        &self,
        tenant_slug: &str,
        project_name: &str,
        version: &str,
        filename: &str,
    ) -> Result<ProvenanceDescriptor, ApplicationError> {
        debug!(
            "loading provenance for tenant `{tenant_slug}` project `{project_name}` version `{version}` filename `{filename}`"
        );
        let artifact = self
            .find_artifact(tenant_slug, project_name, version, filename)
            .await?;
        let attestation = self
            .store
            .get_attestation_by_artifact(artifact.id)
            .await?
            .ok_or_else(|| ApplicationError::NotFound("provenance".into()))?;

        Ok(ProvenanceDescriptor {
            filename: filename.to_string(),
            media_type: attestation.media_type,
            payload: attestation.payload,
            source: format!("{:?}", attestation.source).to_ascii_lowercase(),
        })
    }

    async fn store_mirrored_project(
        &self,
        tenant_slug: &str,
        tenant_id: pyregistry_domain::TenantId,
        snapshot: MirroredProjectSnapshot,
        cancellation: &dyn CancellationSignal,
    ) -> Result<Option<Project>, ApplicationError> {
        let artifact_total = snapshot.artifacts.len();
        let now = self.clock.now();
        let canonical_name = ProjectName::new(snapshot.canonical_name)?;
        let mut project = self
            .store
            .get_project_by_normalized_name(tenant_id, canonical_name.normalized())
            .await?
            .unwrap_or_else(|| {
                Project::new(
                    ProjectId::new(self.ids.next()),
                    tenant_id,
                    canonical_name.clone(),
                    ProjectSource::Mirrored,
                    snapshot.summary.clone(),
                    snapshot.description.clone(),
                    now,
                )
            });
        project.source = ProjectSource::Mirrored;
        project.summary = snapshot.summary;
        project.description = snapshot.description;
        project.updated_at = now;
        self.store.save_project(project.clone()).await?;

        let mut cache_candidates = Vec::new();
        for mirrored in snapshot.artifacts {
            fail_if_cancelled(cancellation, "storing mirrored project metadata")?;
            let version = ReleaseVersion::new(mirrored.version.clone())?;
            let release = self
                .store
                .get_release_by_version(project.id, &version)
                .await?
                .unwrap_or(Release {
                    id: ReleaseId::new(self.ids.next()),
                    project_id: project.id,
                    version: version.clone(),
                    yanked: None,
                    created_at: now,
                });
            self.store.save_release(release.clone()).await?;

            if let Some(mut artifact) = self
                .store
                .get_artifact_by_filename(release.id, &mirrored.filename)
                .await?
            {
                if artifact.upstream_url.as_deref() != Some(mirrored.download_url.as_str()) {
                    artifact.upstream_url = Some(mirrored.download_url.clone());
                    self.store.save_artifact(artifact.clone()).await?;
                }
                cache_candidates.push(MirroredArtifactCacheCandidate { version, artifact });
                continue;
            }

            let mut artifact = Artifact::new(
                ArtifactId::new(self.ids.next()),
                release.id,
                mirrored.filename.clone(),
                mirrored.size_bytes,
                DigestSet::new(mirrored.sha256, mirrored.blake2b_256)?,
                format!(
                    "{}/{}/{}/{}",
                    tenant_slug,
                    project.name.normalized(),
                    release.version.as_str(),
                    mirrored.filename
                ),
                now,
            )?;
            artifact.upstream_url = Some(mirrored.download_url);
            if let Some(provenance_payload) = mirrored.provenance_payload {
                let provenance_key = format!("{}.provenance.json", artifact.object_key);
                self.object_storage
                    .put(&provenance_key, provenance_payload.clone().into_bytes())
                    .await?;
                artifact.provenance_key = Some(provenance_key);
                self.store
                    .save_attestation(AttestationBundle {
                        artifact_id: artifact.id,
                        media_type: "application/vnd.pypi.integrity.v1+json".into(),
                        payload: provenance_payload,
                        source: AttestationSource::Mirrored,
                        recorded_at: now,
                    })
                    .await?;
            }
            self.store.save_artifact(artifact.clone()).await?;
            cache_candidates.push(MirroredArtifactCacheCandidate { version, artifact });
        }

        let cache_candidates =
            select_eager_cache_candidates(cache_candidates, self.mirror_eager_download_percent);
        let cached_artifact_count = self
            .cache_mirrored_artifacts_parallel(
                tenant_slug,
                project.name.normalized(),
                cache_candidates,
                cancellation,
            )
            .await?;

        info!(
            "stored mirrored project `{}` for tenant `{tenant_slug}` with {} artifact record(s), {} eagerly cached",
            project.name.original(),
            artifact_total,
            cached_artifact_count
        );
        Ok(Some(project))
    }

    async fn cache_mirrored_artifacts_parallel(
        &self,
        tenant_slug: &str,
        normalized_project_name: &str,
        candidates: Vec<MirroredArtifactCacheCandidate>,
        cancellation: &dyn CancellationSignal,
    ) -> Result<usize, ApplicationError> {
        if candidates.is_empty() {
            return Ok(0);
        }
        fail_if_cancelled(cancellation, "mirrored artifact downloads")?;

        let candidate_count = candidates.len();
        let concurrency = self.mirror_download_concurrency.min(candidate_count).max(1);
        info!(
            "caching {candidate_count} mirrored artifact payload(s) for tenant `{tenant_slug}` project `{normalized_project_name}` with concurrency={concurrency}"
        );

        let mut downloads = stream::iter(candidates.into_iter().map(|candidate| async move {
            self.cache_mirrored_artifact_bytes(
                tenant_slug,
                normalized_project_name,
                &candidate.version,
                &candidate.artifact,
            )
            .await
        }))
        .buffer_unordered(concurrency);

        let mut cached_artifact_count = 0usize;
        loop {
            fail_if_cancelled(cancellation, "mirrored artifact downloads")?;

            let next_download = downloads.next().boxed();
            let cancelled = cancellation.cancelled().boxed();
            match future::select(next_download, cancelled).await {
                Either::Left((Some(result), _)) => {
                    if result? {
                        cached_artifact_count += 1;
                    }
                }
                Either::Left((None, _)) => break,
                Either::Right(((), _)) => {
                    warn!(
                        "cancelling mirrored artifact downloads for tenant `{tenant_slug}` project `{normalized_project_name}` after caching {cached_artifact_count} of {candidate_count} payload(s)"
                    );
                    return Err(ApplicationError::Cancelled(
                        "mirrored artifact downloads".into(),
                    ));
                }
            }
        }

        info!(
            "cached {cached_artifact_count} of {candidate_count} mirrored artifact payload(s) for tenant `{tenant_slug}` project `{normalized_project_name}`"
        );
        Ok(cached_artifact_count)
    }

    async fn cache_mirrored_artifact_bytes(
        &self,
        tenant_slug: &str,
        normalized_project_name: &str,
        version: &ReleaseVersion,
        artifact: &Artifact,
    ) -> Result<bool, ApplicationError> {
        if self
            .object_storage
            .get(&artifact.object_key)
            .await?
            .is_some()
        {
            debug!(
                "mirror artifact `{}` for tenant `{tenant_slug}` project `{}` version `{}` is already cached locally",
                artifact.filename,
                normalized_project_name,
                version.as_str()
            );
            return Ok(false);
        }

        let upstream_url = artifact
            .upstream_url
            .as_deref()
            .ok_or_else(|| ApplicationError::NotFound("upstream artifact URL".into()))?;
        info!(
            "eagerly downloading mirrored artifact `{}` for tenant `{tenant_slug}` project `{}` version `{}`",
            artifact.filename,
            normalized_project_name,
            version.as_str()
        );
        let bytes = self
            .mirror_client
            .fetch_artifact_bytes(upstream_url)
            .await?;
        validate_mirrored_artifact_payload(artifact, &bytes)?;
        self.object_storage
            .put(&artifact.object_key, bytes.clone())
            .await?;
        self.audit_cached_mirrored_wheel(
            tenant_slug,
            normalized_project_name,
            version,
            artifact,
            &bytes,
        )
        .await;
        info!(
            "cached mirrored artifact `{}` for tenant `{tenant_slug}` project `{}` version `{}`",
            artifact.filename,
            normalized_project_name,
            version.as_str()
        );
        Ok(true)
    }

    async fn audit_cached_mirrored_wheel(
        &self,
        tenant_slug: &str,
        normalized_project_name: &str,
        version: &ReleaseVersion,
        artifact: &Artifact,
        bytes: &[u8],
    ) {
        if !artifact.filename.to_ascii_lowercase().ends_with(".whl") {
            return;
        }

        info!(
            "running wheel security audit for mirrored artifact `{}` in tenant `{tenant_slug}` project `{}` version `{}`",
            artifact.filename,
            normalized_project_name,
            version.as_str()
        );

        let archive = match self
            .wheel_archive_reader
            .read_wheel_bytes(&artifact.filename, bytes)
        {
            Ok(archive) => archive,
            Err(error) => {
                warn!(
                    "wheel security audit could not read mirrored artifact `{}` for tenant `{tenant_slug}` project `{}` version `{}`: {error}",
                    artifact.filename,
                    normalized_project_name,
                    version.as_str()
                );
                return;
            }
        };

        let report = match WheelAuditUseCase::new(
            self.wheel_archive_reader.clone(),
            self.wheel_virus_scanner.clone(),
            self.wheel_source_security_scanner.clone(),
        )
        .audit_archive(normalized_project_name.to_string(), archive)
        {
            Ok(report) => report,
            Err(error) => {
                warn!(
                    "wheel security audit failed for mirrored artifact `{}` in tenant `{tenant_slug}` project `{}` version `{}`: {error}",
                    artifact.filename,
                    normalized_project_name,
                    version.as_str()
                );
                return;
            }
        };

        if report.findings.is_empty() {
            debug!(
                "wheel security audit found no suspicious findings for mirrored artifact `{}` in tenant `{tenant_slug}` project `{}` version `{}`",
                artifact.filename,
                normalized_project_name,
                version.as_str()
            );
            return;
        }

        let notification = WheelAuditFindingNotification::from_audit_report(
            tenant_slug,
            version.as_str(),
            &report,
        );
        if let Err(error) = self
            .wheel_audit_notifier
            .notify_wheel_audit_findings(&notification)
            .await
        {
            warn!(
                "failed to send wheel audit finding notification for tenant `{tenant_slug}` project `{}` version `{}` artifact `{}`: {error}",
                normalized_project_name,
                version.as_str(),
                artifact.filename
            );
        }
    }
}

struct MirroredArtifactCacheCandidate {
    version: ReleaseVersion,
    artifact: Artifact,
}

fn select_eager_cache_candidates(
    candidates: Vec<MirroredArtifactCacheCandidate>,
    percent: u8,
) -> Vec<MirroredArtifactCacheCandidate> {
    if percent >= 100 || candidates.is_empty() {
        return candidates;
    }
    if percent == 0 {
        return Vec::new();
    }

    let mut versions = candidates
        .iter()
        .map(|candidate| candidate.version.clone())
        .collect::<Vec<_>>();
    versions.sort();
    versions.dedup();

    let release_count = versions.len();
    let selected_release_count = (release_count * usize::from(percent)).div_ceil(100).max(1);
    let selected_versions = versions
        .into_iter()
        .rev()
        .take(selected_release_count)
        .collect::<BTreeSet<_>>();

    candidates
        .into_iter()
        .filter(|candidate| selected_versions.contains(&candidate.version))
        .collect()
}

fn validate_mirrored_artifact_payload(
    artifact: &Artifact,
    bytes: &[u8],
) -> Result<(), ApplicationError> {
    if bytes.len() as u64 != artifact.size_bytes {
        return Err(ApplicationError::External(format!(
            "mirrored artifact `{}` size mismatch: expected {} byte(s), got {} byte(s)",
            artifact.filename,
            artifact.size_bytes,
            bytes.len()
        )));
    }

    let sha256 = hex::encode(Sha256::digest(bytes));
    if sha256 != artifact.digests.sha256 {
        return Err(ApplicationError::External(format!(
            "mirrored artifact `{}` sha256 mismatch",
            artifact.filename
        )));
    }

    Ok(())
}

fn fail_if_cancelled(
    cancellation: &dyn CancellationSignal,
    operation: &'static str,
) -> Result<(), ApplicationError> {
    if cancellation.is_cancelled() {
        return Err(ApplicationError::Cancelled(operation.into()));
    }

    Ok(())
}

#[cfg(test)]
mod tests;
