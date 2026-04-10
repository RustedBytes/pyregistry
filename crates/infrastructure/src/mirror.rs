use async_trait::async_trait;
use log::{debug, info, warn};
use pyregistry_application::{
    ApplicationError, MirrorClient, MirroredArtifactSnapshot, MirroredProjectSnapshot,
};
use reqwest::StatusCode;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use url::Url;

#[derive(Clone)]
pub struct PypiMirrorClient {
    client: reqwest::Client,
    base_url: Url,
}

impl Default for PypiMirrorClient {
    fn default() -> Self {
        Self::new("https://pypi.org").expect("default PyPI URL is valid")
    }
}

impl PypiMirrorClient {
    pub fn new(base_url: &str) -> Result<Self, ApplicationError> {
        let normalized = base_url.trim().trim_end_matches('/');
        let base_url = Url::parse(normalized)
            .map_err(|error| ApplicationError::External(error.to_string()))?;
        Ok(Self {
            client: reqwest::Client::new(),
            base_url,
        })
    }
    fn project_metadata_url(&self, project_name: &str) -> Result<Url, ApplicationError> {
        self.base_url
            .join(&format!("/pypi/{project_name}/json"))
            .map_err(|error| ApplicationError::External(error.to_string()))
    }

    pub async fn download_project_artifact_by_filename(
        &self,
        project_name: &str,
        filename: &str,
        destination: &Path,
    ) -> Result<(), ApplicationError> {
        info!("resolving upstream artifact `{filename}` for project `{project_name}`");
        let project = self
            .fetch_project(project_name)
            .await?
            .ok_or_else(|| ApplicationError::NotFound(format!("project `{project_name}`")))?;
        let artifact =
            find_artifact_by_filename(&project.artifacts, filename).ok_or_else(|| {
                ApplicationError::NotFound(format!(
                    "artifact `{filename}` for project `{project_name}`"
                ))
            })?;

        self.stream_artifact_to_path(&artifact.download_url, artifact.size_bytes, destination)
            .await
    }

    async fn stream_artifact_to_path(
        &self,
        download_url: &str,
        expected_size_bytes: u64,
        destination: &Path,
    ) -> Result<(), ApplicationError> {
        info!(
            "streaming upstream artifact from `{download_url}` to {}",
            destination.display()
        );

        if let Some(parent) = destination
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)
                .await
                .map_err(|error| ApplicationError::External(error.to_string()))?;
        }

        let temp_path = temp_download_path(destination);
        let download_result = async {
            let mut response = self
                .client
                .get(download_url)
                .send()
                .await
                .map_err(|error| ApplicationError::External(error.to_string()))?
                .error_for_status()
                .map_err(|error| ApplicationError::External(error.to_string()))?;

            let mut file = fs::File::create(&temp_path)
                .await
                .map_err(|error| ApplicationError::External(error.to_string()))?;
            let mut downloaded_bytes = 0_u64;

            loop {
                let chunk = response
                    .chunk()
                    .await
                    .map_err(|error| ApplicationError::External(error.to_string()))?;
                let Some(chunk) = chunk else {
                    break;
                };

                file.write_all(&chunk)
                    .await
                    .map_err(|error| ApplicationError::External(error.to_string()))?;
                downloaded_bytes += chunk.len() as u64;
                debug!(
                    "downloaded chunk of {} byte(s) for {}, total={} byte(s)",
                    chunk.len(),
                    destination.display(),
                    downloaded_bytes
                );
            }

            file.flush()
                .await
                .map_err(|error| ApplicationError::External(error.to_string()))?;
            drop(file);

            if expected_size_bytes > 0 && downloaded_bytes != expected_size_bytes {
                return Err(ApplicationError::External(format!(
                    "downloaded size mismatch for {}: expected {} byte(s), got {} byte(s)",
                    destination.display(),
                    expected_size_bytes,
                    downloaded_bytes
                )));
            }

            fs::rename(&temp_path, destination)
                .await
                .map_err(|error| ApplicationError::External(error.to_string()))?;
            info!(
                "saved upstream artifact to {} ({} byte(s))",
                destination.display(),
                downloaded_bytes
            );
            Ok(())
        }
        .await;

        if download_result.is_err() {
            let _ = fs::remove_file(&temp_path).await;
        }

        download_result
    }
}

#[derive(Debug, Deserialize)]
struct PypiResponse {
    info: PypiInfo,
    releases: BTreeMap<String, Vec<PypiReleaseFile>>,
}

#[derive(Debug, Deserialize)]
struct PypiInfo {
    name: String,
    summary: String,
    description: String,
}

#[derive(Debug, Deserialize)]
struct PypiDigests {
    sha256: String,
    blake2b_256: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PypiReleaseFile {
    filename: String,
    size: u64,
    url: String,
    digests: PypiDigests,
}

fn find_artifact_by_filename<'a>(
    artifacts: &'a [MirroredArtifactSnapshot],
    filename: &str,
) -> Option<&'a MirroredArtifactSnapshot> {
    artifacts
        .iter()
        .find(|artifact| artifact.filename == filename)
}

fn temp_download_path(destination: &Path) -> std::path::PathBuf {
    let temp_name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| format!("{name}.part"))
        .unwrap_or_else(|| "download.whl.part".to_string());

    destination.with_file_name(temp_name)
}

#[async_trait]
impl MirrorClient for PypiMirrorClient {
    async fn fetch_project(
        &self,
        project_name: &str,
    ) -> Result<Option<MirroredProjectSnapshot>, ApplicationError> {
        let metadata_url = self.project_metadata_url(project_name)?;
        info!("fetching PyPI metadata for project `{project_name}` from `{metadata_url}`");
        let response = self
            .client
            .get(metadata_url)
            .send()
            .await
            .map_err(|error| ApplicationError::External(error.to_string()))?;

        if response.status() == StatusCode::NOT_FOUND {
            warn!("PyPI returned 404 for project `{project_name}`");
            return Ok(None);
        }

        let payload: PypiResponse = response
            .error_for_status()
            .map_err(|error| ApplicationError::External(error.to_string()))?
            .json()
            .await
            .map_err(|error| ApplicationError::External(error.to_string()))?;

        let mut artifacts = Vec::new();
        for (version, files) in payload.releases {
            for file in files {
                artifacts.push(MirroredArtifactSnapshot {
                    filename: file.filename,
                    version: version.clone(),
                    size_bytes: file.size,
                    sha256: file.digests.sha256,
                    blake2b_256: file.digests.blake2b_256,
                    download_url: file.url,
                    provenance_payload: None,
                });
            }
        }

        debug!(
            "fetched PyPI project `{}` with {} artifact(s)",
            payload.info.name,
            artifacts.len()
        );
        Ok(Some(MirroredProjectSnapshot {
            canonical_name: payload.info.name,
            summary: payload.info.summary,
            description: payload.info.description,
            artifacts,
        }))
    }

    async fn fetch_artifact_bytes(&self, download_url: &str) -> Result<Vec<u8>, ApplicationError> {
        info!("fetching mirrored artifact bytes from `{download_url}`");
        let bytes = self
            .client
            .get(download_url)
            .send()
            .await
            .map_err(|error| ApplicationError::External(error.to_string()))?
            .error_for_status()
            .map_err(|error| ApplicationError::External(error.to_string()))?
            .bytes()
            .await
            .map_err(|error| ApplicationError::External(error.to_string()))?;
        debug!("fetched {} byte(s) from upstream artifact URL", bytes.len());
        Ok(bytes.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::PypiMirrorClient;
    use super::{find_artifact_by_filename, temp_download_path};
    use pyregistry_application::MirroredArtifactSnapshot;
    use std::path::Path;

    #[test]
    fn finds_matching_artifact_by_exact_filename() {
        let artifacts = vec![
            MirroredArtifactSnapshot {
                filename: "demo-0.1.0-py3-none-any.whl".into(),
                version: "0.1.0".into(),
                size_bytes: 123,
                sha256: "abc".into(),
                blake2b_256: None,
                download_url: "https://example.test/demo.whl".into(),
                provenance_payload: None,
            },
            MirroredArtifactSnapshot {
                filename: "demo-0.1.0.tar.gz".into(),
                version: "0.1.0".into(),
                size_bytes: 456,
                sha256: "def".into(),
                blake2b_256: None,
                download_url: "https://example.test/demo.tar.gz".into(),
                provenance_payload: None,
            },
        ];

        let artifact = find_artifact_by_filename(&artifacts, "demo-0.1.0-py3-none-any.whl");

        assert_eq!(
            artifact.map(|artifact| artifact.download_url.as_str()),
            Some("https://example.test/demo.whl")
        );
    }

    #[test]
    fn derives_sidecar_part_path_for_downloads() {
        let temp_path = temp_download_path(Path::new("downloads/demo-0.1.0.whl"));

        assert_eq!(temp_path, Path::new("downloads/demo-0.1.0.whl.part"));
    }

    #[test]
    fn builds_metadata_url_from_configured_base_url() {
        let client =
            PypiMirrorClient::new("https://mirror.example/simple/..").expect("configured base URL");

        let url = client
            .project_metadata_url("demo-pkg")
            .expect("metadata URL");

        assert_eq!(url.as_str(), "https://mirror.example/pypi/demo-pkg/json");
    }
}
