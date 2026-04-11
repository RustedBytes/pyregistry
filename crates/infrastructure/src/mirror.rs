use async_trait::async_trait;
use log::{debug, info, warn};
use pyregistry_application::{
    ApplicationError, MirrorClient, MirroredArtifactSnapshot, MirroredProjectSnapshot,
};
use reqwest::StatusCode;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::time::sleep;
use url::Url;

#[derive(Clone)]
pub struct PypiMirrorClient {
    client: reqwest::Client,
    base_url: Url,
    retry_policy: ArtifactDownloadRetryPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactDownloadRetryPolicy {
    max_attempts: usize,
    initial_backoff: Duration,
}

impl Default for ArtifactDownloadRetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_backoff: Duration::from_millis(250),
        }
    }
}

impl ArtifactDownloadRetryPolicy {
    #[must_use]
    pub fn new(max_attempts: usize, initial_backoff: Duration) -> Self {
        Self {
            max_attempts: max_attempts.max(1),
            initial_backoff,
        }
    }

    #[must_use]
    pub fn max_attempts(self) -> usize {
        self.max_attempts
    }

    #[must_use]
    pub fn initial_backoff(self) -> Duration {
        self.initial_backoff
    }

    #[must_use]
    fn delay_for_attempt(self, attempt: usize) -> Duration {
        let multiplier = 1_u32 << attempt.saturating_sub(1).min(16);
        self.initial_backoff.saturating_mul(multiplier)
    }
}

impl Default for PypiMirrorClient {
    fn default() -> Self {
        Self::new("https://pypi.org").expect("default PyPI URL is valid")
    }
}

impl PypiMirrorClient {
    pub fn new(base_url: &str) -> Result<Self, ApplicationError> {
        Self::with_retry_policy(base_url, ArtifactDownloadRetryPolicy::default())
    }

    pub fn with_retry_policy(
        base_url: &str,
        retry_policy: ArtifactDownloadRetryPolicy,
    ) -> Result<Self, ApplicationError> {
        let normalized = base_url.trim().trim_end_matches('/');
        let base_url = Url::parse(normalized)
            .map_err(|error| ApplicationError::External(error.to_string()))?;
        Ok(Self {
            client: reqwest::Client::new(),
            base_url,
            retry_policy,
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
        for attempt in 1..=self.retry_policy.max_attempts() {
            match self
                .stream_artifact_to_path_once(
                    download_url,
                    expected_size_bytes,
                    destination,
                    &temp_path,
                )
                .await
            {
                Ok(()) => return Ok(()),
                Err(error) if should_retry_download(&error, attempt, self.retry_policy) => {
                    let delay = self.retry_policy.delay_for_attempt(attempt);
                    warn!(
                        "artifact download attempt {}/{} failed for `{download_url}`: {}; retrying in {} ms",
                        attempt,
                        self.retry_policy.max_attempts(),
                        error.error,
                        delay.as_millis()
                    );
                    let _ = fs::remove_file(&temp_path).await;
                    sleep(delay).await;
                }
                Err(error) => {
                    let _ = fs::remove_file(&temp_path).await;
                    return Err(error.error);
                }
            }
        }

        Err(ApplicationError::External(format!(
            "artifact download retry loop exhausted for `{download_url}`"
        )))
    }

    async fn stream_artifact_to_path_once(
        &self,
        download_url: &str,
        expected_size_bytes: u64,
        destination: &Path,
        temp_path: &Path,
    ) -> Result<(), ArtifactDownloadError> {
        let mut response = self.get_artifact_response(download_url).await?;
        let mut file = fs::File::create(temp_path)
            .await
            .map_err(|error| ArtifactDownloadError::fatal(error.to_string()))?;
        let mut downloaded_bytes = 0_u64;

        loop {
            let chunk = response
                .chunk()
                .await
                .map_err(ArtifactDownloadError::from_reqwest)?;
            let Some(chunk) = chunk else {
                break;
            };

            file.write_all(&chunk)
                .await
                .map_err(|error| ArtifactDownloadError::fatal(error.to_string()))?;
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
            .map_err(|error| ArtifactDownloadError::fatal(error.to_string()))?;
        drop(file);

        if expected_size_bytes > 0 && downloaded_bytes != expected_size_bytes {
            return Err(ArtifactDownloadError::retryable(format!(
                "downloaded size mismatch for {}: expected {} byte(s), got {} byte(s)",
                destination.display(),
                expected_size_bytes,
                downloaded_bytes
            )));
        }

        fs::rename(temp_path, destination)
            .await
            .map_err(|error| ArtifactDownloadError::fatal(error.to_string()))?;
        info!(
            "saved upstream artifact to {} ({} byte(s))",
            destination.display(),
            downloaded_bytes
        );
        Ok(())
    }

    async fn fetch_artifact_bytes_with_retries(
        &self,
        download_url: &str,
    ) -> Result<Vec<u8>, ApplicationError> {
        for attempt in 1..=self.retry_policy.max_attempts() {
            match self.fetch_artifact_bytes_once(download_url).await {
                Ok(bytes) => return Ok(bytes),
                Err(error) if should_retry_download(&error, attempt, self.retry_policy) => {
                    let delay = self.retry_policy.delay_for_attempt(attempt);
                    warn!(
                        "artifact download attempt {}/{} failed for `{download_url}`: {}; retrying in {} ms",
                        attempt,
                        self.retry_policy.max_attempts(),
                        error.error,
                        delay.as_millis()
                    );
                    sleep(delay).await;
                }
                Err(error) => return Err(error.error),
            }
        }

        Err(ApplicationError::External(format!(
            "artifact download retry loop exhausted for `{download_url}`"
        )))
    }

    async fn fetch_artifact_bytes_once(
        &self,
        download_url: &str,
    ) -> Result<Vec<u8>, ArtifactDownloadError> {
        let bytes = self
            .get_artifact_response(download_url)
            .await?
            .bytes()
            .await
            .map_err(ArtifactDownloadError::from_reqwest)?;
        debug!("fetched {} byte(s) from upstream artifact URL", bytes.len());
        Ok(bytes.to_vec())
    }

    async fn get_artifact_response(
        &self,
        download_url: &str,
    ) -> Result<reqwest::Response, ArtifactDownloadError> {
        let response = self
            .client
            .get(download_url)
            .send()
            .await
            .map_err(ArtifactDownloadError::from_reqwest)?;
        let status = response.status();
        if !status.is_success() {
            return Err(ArtifactDownloadError {
                error: ApplicationError::External(format!(
                    "upstream artifact request `{download_url}` returned HTTP {status}"
                )),
                retryable: is_retryable_status(status),
            });
        }
        Ok(response)
    }
}

#[derive(Debug)]
struct ArtifactDownloadError {
    error: ApplicationError,
    retryable: bool,
}

impl ArtifactDownloadError {
    fn retryable(message: impl Into<String>) -> Self {
        Self {
            error: ApplicationError::External(message.into()),
            retryable: true,
        }
    }

    fn fatal(message: impl Into<String>) -> Self {
        Self {
            error: ApplicationError::External(message.into()),
            retryable: false,
        }
    }

    fn from_reqwest(error: reqwest::Error) -> Self {
        let retryable = error.is_timeout()
            || error.is_connect()
            || error.is_body()
            || error.status().is_some_and(is_retryable_status);
        Self {
            error: ApplicationError::External(error.to_string()),
            retryable,
        }
    }
}

fn should_retry_download(
    error: &ArtifactDownloadError,
    attempt: usize,
    policy: ArtifactDownloadRetryPolicy,
) -> bool {
    error.retryable && attempt < policy.max_attempts()
}

fn is_retryable_status(status: StatusCode) -> bool {
    status == StatusCode::REQUEST_TIMEOUT
        || status == StatusCode::TOO_MANY_REQUESTS
        || status == StatusCode::INTERNAL_SERVER_ERROR
        || status == StatusCode::BAD_GATEWAY
        || status == StatusCode::SERVICE_UNAVAILABLE
        || status == StatusCode::GATEWAY_TIMEOUT
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
    packagetype: Option<String>,
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
        let mut skipped_file_count = 0usize;
        for (version, files) in payload.releases {
            for file in files {
                if !is_mirrorable_distribution(&file) {
                    skipped_file_count += 1;
                    debug!(
                        "skipping unsupported PyPI release file `{}` with package type {:?}",
                        file.filename, file.packagetype
                    );
                    continue;
                }

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
            "fetched PyPI project `{}` with {} mirrorable artifact(s), skipped {} unsupported file(s)",
            payload.info.name,
            artifacts.len(),
            skipped_file_count
        );
        Ok(Some(MirroredProjectSnapshot {
            canonical_name: payload.info.name,
            summary: payload.info.summary,
            description: payload.info.description,
            artifacts,
        }))
    }

    async fn fetch_artifact_bytes(&self, download_url: &str) -> Result<Vec<u8>, ApplicationError> {
        info!(
            "fetching mirrored artifact bytes from `{download_url}` with up to {} attempt(s)",
            self.retry_policy.max_attempts()
        );
        self.fetch_artifact_bytes_with_retries(download_url).await
    }
}

fn is_mirrorable_distribution(file: &PypiReleaseFile) -> bool {
    if let Some(package_type) = file.packagetype.as_deref() {
        return matches!(
            package_type.trim().to_ascii_lowercase().as_str(),
            "bdist_wheel" | "sdist"
        );
    }

    // Some private PyPI-compatible mirrors omit `packagetype`, so fall back to
    // filename shape while keeping legacy installers like .exe and .egg out.
    is_mirrorable_distribution_filename(&file.filename)
}

fn is_mirrorable_distribution_filename(filename: &str) -> bool {
    filename.ends_with(".whl")
        || filename.ends_with(".tar.gz")
        || filename.ends_with(".tar.bz2")
        || filename.ends_with(".tar.xz")
        || filename.ends_with(".tgz")
        || filename.ends_with(".zip")
}

#[cfg(test)]
mod tests {
    use super::{
        ArtifactDownloadRetryPolicy, PypiDigests, PypiMirrorClient, PypiReleaseFile,
        find_artifact_by_filename, is_mirrorable_distribution, is_mirrorable_distribution_filename,
        is_retryable_status, temp_download_path,
    };
    use pyregistry_application::{MirrorClient, MirroredArtifactSnapshot};
    use std::path::Path;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

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

    #[test]
    fn configures_artifact_download_retry_policy() {
        let policy = ArtifactDownloadRetryPolicy::new(5, Duration::from_millis(10));
        let client = PypiMirrorClient::with_retry_policy("https://mirror.example", policy)
            .expect("configured base URL");

        assert_eq!(client.retry_policy.max_attempts(), 5);
        assert_eq!(
            client.retry_policy.delay_for_attempt(1),
            Duration::from_millis(10)
        );
        assert_eq!(
            client.retry_policy.delay_for_attempt(3),
            Duration::from_millis(40)
        );
    }

    #[test]
    fn classifies_transient_artifact_download_statuses() {
        assert!(is_retryable_status(reqwest::StatusCode::REQUEST_TIMEOUT));
        assert!(is_retryable_status(reqwest::StatusCode::TOO_MANY_REQUESTS));
        assert!(is_retryable_status(reqwest::StatusCode::BAD_GATEWAY));
        assert!(!is_retryable_status(reqwest::StatusCode::NOT_FOUND));
        assert!(!is_retryable_status(reqwest::StatusCode::FORBIDDEN));
    }

    #[tokio::test]
    async fn retries_transient_artifact_byte_downloads() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test HTTP listener");
        let address = listener.local_addr().expect("listener address");
        let attempts = Arc::new(AtomicUsize::new(0));
        let server_attempts = attempts.clone();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket, _) = listener.accept().await.expect("accept request");
                let attempt = server_attempts.fetch_add(1, Ordering::SeqCst) + 1;
                let mut buffer = [0_u8; 1024];
                let _ = socket.read(&mut buffer).await.expect("read request");
                let response = if attempt == 1 {
                    "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .to_string()
                } else {
                    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                        .to_string()
                };
                socket
                    .write_all(response.as_bytes())
                    .await
                    .expect("write response");
            }
        });
        let client = PypiMirrorClient::with_retry_policy(
            "https://pypi.org",
            ArtifactDownloadRetryPolicy::new(2, Duration::from_millis(1)),
        )
        .expect("client");

        let bytes = client
            .fetch_artifact_bytes(&format!("http://{address}/demo.whl"))
            .await
            .expect("download should retry and succeed");

        assert_eq!(bytes, b"ok");
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        server.await.expect("server task");
    }

    #[test]
    fn filters_legacy_pypi_installers_from_mirroring() {
        let wheel = release_file(
            "pandas-2.3.3-cp314-cp314-manylinux.whl",
            Some("bdist_wheel"),
        );
        let sdist = release_file("pandas-2.3.3.tar.gz", Some("sdist"));
        let legacy_installer = release_file("pandas-0.1.win32-py2.5.exe", Some("bdist_wininst"));
        let egg = release_file("pandas-0.7.0-py2.7.egg", Some("bdist_egg"));

        assert!(is_mirrorable_distribution(&wheel));
        assert!(is_mirrorable_distribution(&sdist));
        assert!(!is_mirrorable_distribution(&legacy_installer));
        assert!(!is_mirrorable_distribution(&egg));
    }

    #[test]
    fn falls_back_to_safe_filename_extensions_when_package_type_is_missing() {
        assert!(is_mirrorable_distribution_filename("demo-1.0.0.tar.gz"));
        assert!(is_mirrorable_distribution_filename("demo-1.0.0.tar.bz2"));
        assert!(is_mirrorable_distribution_filename("demo-1.0.0.tar.xz"));
        assert!(is_mirrorable_distribution_filename("demo-1.0.0.tgz"));
        assert!(is_mirrorable_distribution_filename("demo-1.0.0.zip"));
        assert!(is_mirrorable_distribution_filename(
            "demo-1.0.0-py3-none-any.whl"
        ));
        assert!(!is_mirrorable_distribution_filename("demo-1.0.0.exe"));
        assert!(!is_mirrorable_distribution_filename("demo-1.0.0.egg"));
    }

    fn release_file(filename: &str, packagetype: Option<&str>) -> PypiReleaseFile {
        PypiReleaseFile {
            filename: filename.into(),
            packagetype: packagetype.map(str::to_string),
            size: 0,
            url: "https://files.example.test/demo".into(),
            digests: PypiDigests {
                sha256: "0".repeat(64),
                blake2b_256: None,
            },
        }
    }
}
