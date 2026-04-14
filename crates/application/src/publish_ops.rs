use crate::{
    ApplicationError, AuthenticatedAccess, IssueApiTokenCommand, IssuedApiToken,
    MintOidcPublishTokenCommand, PackagePublishEventKind, PackagePublishNotification,
    PublishTokenGrant, PyregistryApp, RegisterTrustedPublisherCommand, TrustedPublisherDescriptor,
    UploadArtifactCommand,
};
use base64::Engine;
use chrono::Duration;
use log::{debug, info, warn};
use pyregistry_domain::{
    ApiToken, Artifact, ArtifactId, AttestationBundle, AttestationSource, DigestSet, Project,
    ProjectId, ProjectName, ProjectSource, Release, ReleaseId, ReleaseVersion, TokenId, TokenScope,
    TrustedPublisher, TrustedPublisherId, ensure_unique_filenames,
};
use rand::distr::{Alphanumeric, SampleString};
use sha2::{Digest, Sha256};

impl PyregistryApp {
    pub async fn issue_api_token(
        &self,
        command: IssueApiTokenCommand,
    ) -> Result<IssuedApiToken, ApplicationError> {
        info!(
            "issuing API token for tenant `{}` label=`{}` scopes={:?} ttl_hours={:?}",
            command.tenant_slug, command.label, command.scopes, command.ttl_hours
        );
        let tenant = self.require_tenant(&command.tenant_slug).await?;
        let secret = format!("pyr_{}", Alphanumeric.sample_string(&mut rand::rng(), 40));
        let token = ApiToken {
            id: TokenId::new(self.ids.next()),
            tenant_id: tenant.id,
            label: command.label.clone(),
            secret_hash: self.token_hasher.hash(&secret)?,
            scopes: command.scopes,
            publish_identity: None,
            created_at: self.clock.now(),
            expires_at: command
                .ttl_hours
                .map(|ttl| self.clock.now() + Duration::hours(ttl)),
        };
        self.store.save_api_token(token.clone()).await?;

        info!(
            "issued API token `{}` for tenant `{}` with expiry {:?}",
            token.label,
            tenant.slug.as_str(),
            token.expires_at
        );
        Ok(IssuedApiToken {
            label: token.label,
            secret,
            expires_at: token.expires_at,
        })
    }

    pub async fn revoke_api_token(
        &self,
        tenant_slug: &str,
        token_label: &str,
    ) -> Result<(), ApplicationError> {
        info!("revoking API token `{token_label}` for tenant `{tenant_slug}`");
        let tenant = self.require_tenant(tenant_slug).await?;
        let tokens = self.store.list_api_tokens(tenant.id).await?;
        if let Some(token) = tokens.into_iter().find(|token| token.label == token_label) {
            self.store.revoke_api_token(tenant.id, token.id).await?;
            info!("revoked API token `{token_label}` for tenant `{tenant_slug}`");
        } else {
            warn!("no API token labeled `{token_label}` was found for tenant `{tenant_slug}`");
        }
        Ok(())
    }

    pub async fn authenticate_tenant_token(
        &self,
        tenant_slug: &str,
        provided_secret: &str,
        required_scope: TokenScope,
    ) -> Result<AuthenticatedAccess, ApplicationError> {
        debug!(
            "authenticating tenant token for tenant `{tenant_slug}` with required scope {:?}",
            required_scope
        );
        let tenant = self.require_tenant(tenant_slug).await?;
        let hash = self.token_hasher.hash(provided_secret)?;
        let now = self.clock.now();

        let token = self
            .store
            .list_api_tokens(tenant.id)
            .await?
            .into_iter()
            .find(|token| {
                token.secret_hash == hash
                    && token.scopes.contains(&required_scope)
                    && token
                        .expires_at
                        .map(|expires| expires > now)
                        .unwrap_or(true)
            })
            .ok_or_else(|| {
                warn!(
                    "tenant token authentication failed for tenant `{tenant_slug}` and scope {:?}",
                    required_scope
                );
                ApplicationError::Unauthorized("invalid tenant token".into())
            })?;

        debug!(
            "tenant token authentication succeeded for tenant `{}` using token `{}`",
            tenant.slug.as_str(),
            token.label
        );
        Ok(AuthenticatedAccess { tenant, token })
    }

    pub async fn upload_artifact(
        &self,
        access: &AuthenticatedAccess,
        command: UploadArtifactCommand,
    ) -> Result<(), ApplicationError> {
        info!(
            "upload requested for tenant `{}` project `{}` version `{}` filename `{}` ({} bytes)",
            command.tenant_slug,
            command.project_name,
            command.version,
            command.filename,
            command.content.len()
        );
        if access.tenant.slug.as_str() != command.tenant_slug {
            warn!(
                "upload rejected because token tenant `{}` does not match command tenant `{}`",
                access.tenant.slug.as_str(),
                command.tenant_slug
            );
            return Err(ApplicationError::Unauthorized(
                "token tenant does not match upload tenant".into(),
            ));
        }

        let now = self.clock.now();
        let project_name = ProjectName::new(command.project_name)?;
        let version = ReleaseVersion::new(command.version)?;
        let inspection = self
            .distribution_inspector
            .inspect_distribution_bytes(&command.filename, &command.content)?;
        if inspection.file_type.extension_mismatch() {
            warn!(
                "upload rejected because artifact `{}` content type `{}` does not match extension {:?}",
                command.filename, inspection.file_type.label, inspection.file_type.actual_extension
            );
            return Err(ApplicationError::Conflict(format!(
                "artifact `{}` content does not match its distribution extension",
                command.filename
            )));
        }
        let existing_project = self
            .store
            .get_project_by_normalized_name(access.tenant.id, project_name.normalized())
            .await?;
        let is_new_project = existing_project.is_none();
        let mut project = existing_project.unwrap_or_else(|| {
            Project::new(
                ProjectId::new(self.ids.next()),
                access.tenant.id,
                project_name.clone(),
                ProjectSource::Local,
                command.summary.clone(),
                command.description.clone(),
                now,
            )
        });
        project.source = ProjectSource::Local;
        project.summary = command.summary.clone();
        project.description = command.description.clone();
        project.updated_at = now;
        self.store.save_project(project.clone()).await?;

        let (is_new_release, release) = self
            .store
            .get_release_by_version(project.id, &version)
            .await?
            .map_or_else(
                || {
                    (
                        true,
                        Release {
                            id: ReleaseId::new(self.ids.next()),
                            project_id: project.id,
                            version: version.clone(),
                            yanked: None,
                            created_at: now,
                        },
                    )
                },
                |release| (false, release),
            );
        self.store.save_release(release.clone()).await?;

        let existing_artifacts = self.store.list_artifacts(release.id).await?;
        ensure_unique_filenames(&existing_artifacts)?;
        if existing_artifacts
            .iter()
            .any(|artifact| artifact.filename == command.filename)
        {
            warn!(
                "upload rejected because artifact `{}` already exists for tenant `{}` project `{}` version `{}`",
                command.filename,
                access.tenant.slug.as_str(),
                project.name.normalized(),
                version.as_str()
            );
            return Err(ApplicationError::Conflict(format!(
                "artifact `{}` already exists",
                command.filename
            )));
        }

        let sha256 = hex::encode(Sha256::digest(&command.content));
        let object_key = format!(
            "{}/{}/{}/{}",
            access.tenant.slug.as_str(),
            project.name.normalized(),
            version.as_str(),
            command.filename
        );
        self.object_storage
            .put(&object_key, command.content.clone())
            .await?;
        debug!(
            "stored artifact bytes for tenant `{}` at object key `{}`",
            access.tenant.slug.as_str(),
            object_key
        );
        let mut artifact = Artifact::new(
            ArtifactId::new(self.ids.next()),
            release.id,
            command.filename,
            command.content.len() as u64,
            DigestSet::new(sha256, None)?,
            object_key,
            now,
        )?;
        if let Some(identity) = &access.token.publish_identity {
            let attestation_payload = self
                .attestation_signer
                .build_attestation(&project.name, &version, &artifact, identity)
                .await?;
            let provenance_key = format!("{}.provenance.json", artifact.object_key);
            self.object_storage
                .put(&provenance_key, attestation_payload.clone().into_bytes())
                .await?;
            artifact.provenance_key = Some(provenance_key);
            self.store
                .save_attestation(AttestationBundle {
                    artifact_id: artifact.id,
                    media_type: "application/vnd.pypi.integrity.v1+json".into(),
                    payload: attestation_payload,
                    source: AttestationSource::TrustedPublish,
                    recorded_at: now,
                })
                .await?;
            info!(
                "generated trusted publishing attestation for tenant `{}` project `{}` version `{}` filename `{}`",
                access.tenant.slug.as_str(),
                project.name.original(),
                version.as_str(),
                artifact.filename
            );
        }

        let notification = if is_new_project || is_new_release {
            Some(PackagePublishNotification {
                kind: if is_new_project {
                    PackagePublishEventKind::NewPackage
                } else {
                    PackagePublishEventKind::NewVersion
                },
                tenant_slug: access.tenant.slug.as_str().to_string(),
                project_name: project.name.original().to_string(),
                normalized_name: project.name.normalized().to_string(),
                version: version.as_str().to_string(),
                filename: artifact.filename.clone(),
                size_bytes: artifact.size_bytes,
                sha256: artifact.digests.sha256.clone(),
            })
        } else {
            None
        };
        let filename = artifact.filename.clone();
        self.store.save_artifact(artifact).await?;
        if let Some(notification) = notification {
            if let Err(error) = self
                .package_publish_notifier
                .notify_package_publish(&notification)
                .await
            {
                warn!(
                    "package publish webhook notification failed for tenant `{}` project `{}` version `{}` filename `{}`: {}",
                    notification.tenant_slug,
                    notification.project_name,
                    notification.version,
                    notification.filename,
                    error
                );
            }
        }
        info!(
            "upload completed for tenant `{}` project `{}` version `{}` filename `{}`",
            access.tenant.slug.as_str(),
            project.name.original(),
            version.as_str(),
            filename
        );
        Ok(())
    }

    pub async fn register_trusted_publisher(
        &self,
        command: RegisterTrustedPublisherCommand,
    ) -> Result<TrustedPublisherDescriptor, ApplicationError> {
        info!(
            "registering trusted publisher for tenant `{}` project `{}` provider={:?} issuer=`{}` audience=`{}`",
            command.tenant_slug,
            command.project_name,
            command.provider,
            command.issuer,
            command.audience
        );
        let tenant = self.require_tenant(&command.tenant_slug).await?;
        let publisher = TrustedPublisher {
            id: TrustedPublisherId::new(self.ids.next()),
            tenant_id: tenant.id,
            project_name: ProjectName::new(command.project_name)?,
            provider: command.provider,
            issuer: command.issuer.clone(),
            audience: command.audience.clone(),
            claim_rules: command.claim_rules.clone(),
            created_at: self.clock.now(),
        };
        self.store.save_trusted_publisher(publisher.clone()).await?;

        info!(
            "registered trusted publisher for tenant `{}` project `{}`",
            tenant.slug.as_str(),
            publisher.project_name.original()
        );
        Ok(TrustedPublisherDescriptor {
            provider: format!("{:?}", publisher.provider),
            issuer: publisher.issuer,
            audience: publisher.audience,
            project_name: publisher.project_name.original().to_string(),
            claim_rules: publisher.claim_rules,
        })
    }

    pub async fn mint_oidc_publish_token(
        &self,
        command: MintOidcPublishTokenCommand,
    ) -> Result<PublishTokenGrant, ApplicationError> {
        info!(
            "minting OIDC publish token for tenant `{}` project `{}`",
            command.tenant_slug, command.project_name
        );
        let tenant = self.require_tenant(&command.tenant_slug).await?;
        let project_name = ProjectName::new(command.project_name)?;
        let publishers = self
            .store
            .list_trusted_publishers(tenant.id, project_name.normalized())
            .await?;
        if publishers.is_empty() {
            warn!(
                "OIDC publish token mint rejected because tenant `{}` project `{}` has no trusted publishers",
                tenant.slug.as_str(),
                project_name.original()
            );
            return Err(ApplicationError::Unauthorized(
                "no trusted publishers registered for project".into(),
            ));
        }

        let mut matched = None;
        let mut last_error = None;
        let mut audiences = publishers
            .iter()
            .map(|publisher| publisher.audience.clone())
            .collect::<Vec<_>>();
        audiences.sort();
        audiences.dedup();
        for audience in audiences {
            match self
                .oidc_verifier
                .verify(&command.oidc_token, &audience)
                .await
            {
                Ok(identity) => {
                    if let Some(publisher) = publishers
                        .iter()
                        .find(|publisher| publisher.matches(&identity).is_ok())
                    {
                        matched = Some((publisher.clone(), identity));
                        break;
                    }
                    warn!(
                        "OIDC token for issuer `{}` subject `{}` verified for audience `{audience}` but matched no trusted publisher for tenant `{}` project `{}`",
                        identity.issuer,
                        identity.subject,
                        tenant.slug.as_str(),
                        project_name.original()
                    );
                }
                Err(error) => {
                    last_error = Some(error);
                }
            }
        }
        let (publisher, identity) = matched.ok_or_else(|| {
            warn!(
                "OIDC publish token mint rejected because token matched no trusted publisher for tenant `{}` project `{}`",
                tenant.slug.as_str(),
                project_name.original()
            );
            match last_error {
                Some(ApplicationError::External(message)) => ApplicationError::External(message),
                _ => ApplicationError::Unauthorized(
                    "OIDC token does not match a trusted publisher".into(),
                ),
            }
        })?;
        let identity_issuer = identity.issuer.clone();
        let identity_subject = identity.subject.clone();

        let secret = format!(
            "oidc_{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.ids.next().as_bytes())
        );
        let expires_at = self.clock.now() + Duration::minutes(15);
        let token = ApiToken {
            id: TokenId::new(self.ids.next()),
            tenant_id: tenant.id,
            label: format!("oidc:{}:{}", project_name.normalized(), publisher.issuer),
            secret_hash: self.token_hasher.hash(&secret)?,
            scopes: vec![TokenScope::Publish],
            publish_identity: Some(identity),
            created_at: self.clock.now(),
            expires_at: Some(expires_at),
        };
        self.store.save_api_token(token).await?;

        info!(
            "minted short-lived OIDC publish token for tenant `{}` project `{}` using issuer `{}` subject `{}` expiring at {}",
            tenant.slug.as_str(),
            project_name.original(),
            identity_issuer,
            identity_subject,
            expires_at
        );
        Ok(PublishTokenGrant {
            tenant_slug: tenant.slug.as_str().to_string(),
            project_name: project_name.original().to_string(),
            token: secret,
            expires_at,
        })
    }
}
