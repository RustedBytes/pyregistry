use crate::{
    auth::package_access,
    error::{WebError, bad_request, render_html, to_bad_request},
    models::{
        MintOidcRequest, PublishTokenResponse, SimpleArtifactView, SimpleIndexTemplate,
        SimpleProjectTemplate, SimpleProjectView,
    },
    state::AppState,
};
use axum::{
    Json,
    body::Body,
    extract::{Multipart, Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use log::{debug, info};
use pyregistry_application::{MintOidcPublishTokenCommand, UploadArtifactCommand};
use pyregistry_domain::TokenScope;

pub(crate) async fn simple_index(
    State(state): State<AppState>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
) -> Result<Html<String>, WebError> {
    package_access(&state, &tenant, &headers, TokenScope::Read).await?;
    let projects: Vec<_> = state
        .app
        .list_simple_projects(&tenant)
        .await?
        .into_iter()
        .map(|project| SimpleProjectView {
            name: project.name,
            normalized_name: project.normalized_name,
        })
        .collect();
    info!(
        "served simple index for tenant `{tenant}` with {} project(s)",
        projects.len()
    );
    render_html(SimpleIndexTemplate {
        tenant_slug: tenant,
        projects,
    })
}

pub(crate) async fn simple_project(
    State(state): State<AppState>,
    Path((tenant, project)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Html<String>, WebError> {
    package_access(&state, &tenant, &headers, TokenScope::Read).await?;
    let page = state
        .app
        .get_simple_project_index(&tenant, &project)
        .await?;
    let artifacts: Vec<_> = page
        .artifacts
        .into_iter()
        .map(|artifact| SimpleArtifactView {
            filename: artifact.filename,
            version: artifact.version,
            sha256: artifact.sha256,
            url: artifact.url,
            provenance_url: artifact.provenance_url,
            yanked_reason: artifact.yanked_reason,
        })
        .collect();
    info!(
        "served simple project page for tenant `{tenant}` project `{}` with {} artifact(s)",
        page.project_name,
        artifacts.len()
    );
    render_html(SimpleProjectTemplate {
        project_name: page.project_name,
        artifacts,
    })
}

pub(crate) async fn legacy_upload(
    State(state): State<AppState>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, WebError> {
    let access = package_access(&state, &tenant, &headers, TokenScope::Publish).await?;
    let mut name = None;
    let mut version = None;
    let mut summary = String::new();
    let mut description = String::new();
    let mut filename = None;
    let mut content = None;

    while let Some(field) = multipart.next_field().await.map_err(to_bad_request)? {
        match field.name().unwrap_or_default() {
            "name" => name = Some(field.text().await.map_err(to_bad_request)?),
            "version" => version = Some(field.text().await.map_err(to_bad_request)?),
            "summary" => summary = field.text().await.map_err(to_bad_request)?,
            "description" => description = field.text().await.map_err(to_bad_request)?,
            "content" => {
                filename = field.file_name().map(ToString::to_string);
                content = Some(field.bytes().await.map_err(to_bad_request)?.to_vec());
            }
            _ => {}
        }
    }

    let content = content.ok_or_else(|| bad_request("empty upload file"))?;
    let project_name = name.ok_or_else(|| bad_request("missing `name` form field"))?;
    let version = version.ok_or_else(|| bad_request("missing `version` form field"))?;
    let filename = filename.ok_or_else(|| bad_request("missing upload file in `content` field"))?;
    info!(
        "received legacy upload request for tenant `{tenant}` project `{project_name}` version `{version}` filename `{filename}` ({} bytes)",
        content.len()
    );

    state
        .app
        .upload_artifact(
            &access,
            UploadArtifactCommand {
                tenant_slug: tenant,
                project_name,
                version,
                filename,
                summary,
                description,
                content,
            },
        )
        .await?;

    Ok(StatusCode::OK)
}

pub(crate) async fn download_artifact(
    State(state): State<AppState>,
    Path((tenant, project, version, filename)): Path<(String, String, String, String)>,
    headers: HeaderMap,
) -> Result<Response, WebError> {
    package_access(&state, &tenant, &headers, TokenScope::Read).await?;
    info!(
        "artifact download requested for tenant `{tenant}` project `{project}` version `{version}` filename `{filename}`"
    );
    let bytes = state
        .app
        .download_artifact(&tenant, &project, &version, &filename)
        .await?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(bytes))
        .expect("valid response"))
}

pub(crate) async fn get_provenance(
    State(state): State<AppState>,
    Path((tenant, project, version, filename)): Path<(String, String, String, String)>,
    headers: HeaderMap,
) -> Result<Response, WebError> {
    package_access(&state, &tenant, &headers, TokenScope::Read).await?;
    debug!(
        "provenance download requested for tenant `{tenant}` project `{project}` version `{version}` filename `{filename}`"
    );
    let provenance = state
        .app
        .get_provenance(&tenant, &project, &version, &filename)
        .await?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, provenance.media_type)
        .body(Body::from(provenance.payload))
        .expect("valid response"))
}

pub(crate) async fn oidc_audience() -> Json<serde_json::Value> {
    debug!("served OIDC audience metadata");
    Json(serde_json::json!({ "audience": "pyregistry" }))
}

pub(crate) async fn mint_oidc_publish_token(
    State(state): State<AppState>,
    Json(request): Json<MintOidcRequest>,
) -> Result<PublishTokenResponse, WebError> {
    info!(
        "OIDC publish token requested for tenant `{}` project `{}`",
        request.tenant_slug, request.project_name
    );
    let grant = state
        .app
        .mint_oidc_publish_token(MintOidcPublishTokenCommand {
            tenant_slug: request.tenant_slug,
            project_name: request.project_name,
            oidc_token: request.oidc_token,
        })
        .await?;
    info!(
        "OIDC publish token issued for tenant `{}` project `{}` expiring at {}",
        grant.tenant_slug, grant.project_name, grant.expires_at
    );
    Ok(Json(grant))
}
