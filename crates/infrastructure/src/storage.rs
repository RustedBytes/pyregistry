use async_trait::async_trait;
use log::debug;
use opendal::{ErrorKind, Operator};
use pyregistry_application::{ApplicationError, ObjectStorage};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use tokio::fs;

use crate::OpenDalStorageConfig;

pub struct FileSystemObjectStorage {
    root: PathBuf,
}

impl FileSystemObjectStorage {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn path_for(&self, key: &str) -> PathBuf {
        self.root.join(key)
    }
}

pub struct OpenDalObjectStorage {
    operator: Operator,
    scheme: String,
}

impl OpenDalObjectStorage {
    pub fn from_config(config: &OpenDalStorageConfig) -> Result<Self, String> {
        let mut options = config.options.clone();
        normalize_opendal_options(&config.scheme, &mut options)?;
        let operator = Operator::via_iter(&config.scheme, options)
            .map_err(|error| format!("failed to build OpenDAL operator: {error}"))?;
        Ok(Self {
            operator,
            scheme: config.scheme.clone(),
        })
    }

    fn key_for(&self, key: &str) -> String {
        key.trim_start_matches('/').to_string()
    }
}

#[async_trait]
impl ObjectStorage for OpenDalObjectStorage {
    async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), ApplicationError> {
        let key = self.key_for(key);
        debug!(
            "writing {} byte(s) to OpenDAL object storage scheme `{}` key `{}`",
            bytes.len(),
            self.scheme,
            key
        );
        self.operator
            .write(&key, bytes)
            .await
            .map(|_| ())
            .map_err(opendal_to_application_error)
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, ApplicationError> {
        let key = self.key_for(key);
        match self.operator.read(&key).await {
            Ok(bytes) => {
                debug!(
                    "read {} byte(s) from OpenDAL object storage scheme `{}` key `{}`",
                    bytes.len(),
                    self.scheme,
                    key
                );
                Ok(Some(bytes.to_vec()))
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                debug!(
                    "OpenDAL object storage miss for scheme `{}` key `{}`",
                    self.scheme, key
                );
                Ok(None)
            }
            Err(error) => Err(opendal_to_application_error(error)),
        }
    }

    async fn delete(&self, key: &str) -> Result<(), ApplicationError> {
        let key = self.key_for(key);
        self.operator
            .delete(&key)
            .await
            .map(|()| {
                debug!(
                    "deleted OpenDAL object storage scheme `{}` key `{}`",
                    self.scheme, key
                );
            })
            .map_err(opendal_to_application_error)
    }
}

fn normalize_opendal_options(
    scheme: &str,
    options: &mut BTreeMap<String, String>,
) -> Result<(), String> {
    if scheme.eq_ignore_ascii_case("s3") {
        normalize_s3_options(options)?;
        return Ok(());
    }

    if !scheme.eq_ignore_ascii_case("fs") {
        return Ok(());
    }

    normalize_fs_options(options)
}

fn normalize_fs_options(options: &mut BTreeMap<String, String>) -> Result<(), String> {
    let Some(root) = options.get("root").cloned() else {
        return Err("OpenDAL fs storage requires `root` option".into());
    };
    let root = root.trim();
    if root.is_empty() {
        return Err("OpenDAL fs storage requires non-empty `root` option".into());
    }

    let path = Path::new(root);
    if path.is_absolute() {
        return Ok(());
    }

    let absolute = std::env::current_dir()
        .map_err(|error| format!("failed to resolve current directory: {error}"))?
        .join(path);
    options.insert("root".into(), absolute.to_string_lossy().into_owned());
    Ok(())
}

fn normalize_s3_options(options: &mut BTreeMap<String, String>) -> Result<(), String> {
    let Some(bucket) = options.get("bucket").cloned() else {
        return Err("OpenDAL s3 storage requires `bucket` option".into());
    };
    if bucket.trim().is_empty() {
        return Err("OpenDAL s3 storage requires non-empty `bucket` option".into());
    }
    options.insert("bucket".into(), bucket.trim().to_string());

    if let Some(endpoint) = options.get("endpoint").cloned() {
        let endpoint = endpoint.trim().trim_end_matches('/');
        if endpoint.is_empty() {
            return Err("OpenDAL s3 storage `endpoint` option must not be empty when set".into());
        }
        options.insert("endpoint".into(), endpoint.to_string());

        if is_local_s3_endpoint(endpoint) {
            options
                .entry("disable_config_load".into())
                .or_insert_with(|| "true".into());
            options
                .entry("disable_ec2_metadata".into())
                .or_insert_with(|| "true".into());
            options
                .entry("enable_virtual_host_style".into())
                .or_insert_with(|| "false".into());
        }
    }

    if let Some(root) = options.get("root").cloned() {
        let root = root.trim();
        if !root.is_empty() && !root.starts_with('/') {
            return Err("OpenDAL s3 storage `root` option must be an absolute prefix".into());
        }
        if !root.is_empty() {
            options.insert("root".into(), root.trim_end_matches('/').to_string());
        }
    }

    Ok(())
}

fn is_local_s3_endpoint(endpoint: &str) -> bool {
    let endpoint = endpoint.to_ascii_lowercase();
    endpoint.contains("127.0.0.1")
        || endpoint.contains("localhost")
        || endpoint.contains("://minio")
        || endpoint.starts_with("minio")
}

fn opendal_to_application_error(error: opendal::Error) -> ApplicationError {
    ApplicationError::External(format!("OpenDAL object storage error: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[tokio::test]
    async fn opendal_fs_storage_round_trips_objects() {
        let root = std::env::temp_dir().join(format!("pyregistry-opendal-{}", Uuid::new_v4()));
        let storage = OpenDalObjectStorage::from_config(&OpenDalStorageConfig {
            scheme: "fs".into(),
            options: BTreeMap::from([("root".into(), root.to_string_lossy().into_owned())]),
        })
        .expect("storage");

        storage
            .put("tenant/project/file.whl", b"wheel-bytes".to_vec())
            .await
            .expect("put");
        assert_eq!(
            storage.get("tenant/project/file.whl").await.expect("get"),
            Some(b"wheel-bytes".to_vec())
        );
        storage
            .delete("tenant/project/file.whl")
            .await
            .expect("delete");
        assert_eq!(
            storage
                .get("tenant/project/file.whl")
                .await
                .expect("missing"),
            None
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn opendal_s3_storage_builds_from_minio_options() {
        let storage = OpenDalObjectStorage::from_config(&OpenDalStorageConfig {
            scheme: "s3".into(),
            options: BTreeMap::from([
                ("bucket".into(), "pyregistry".into()),
                ("endpoint".into(), "http://127.0.0.1:9000/".into()),
                ("region".into(), "us-east-1".into()),
                ("access_key_id".into(), "pyregistry".into()),
                ("secret_access_key".into(), "pyregistry123".into()),
                ("root".into(), "/artifacts".into()),
            ]),
        });

        assert!(storage.is_ok());
    }

    #[test]
    fn normalize_s3_options_adds_safe_minio_defaults() {
        let mut options = BTreeMap::from([
            ("bucket".into(), " pyregistry ".into()),
            ("endpoint".into(), "http://localhost:9000/".into()),
            ("root".into(), "/artifacts/".into()),
        ]);

        normalize_s3_options(&mut options).expect("normalize");

        assert_eq!(options.get("bucket"), Some(&"pyregistry".to_string()));
        assert_eq!(
            options.get("endpoint"),
            Some(&"http://localhost:9000".to_string())
        );
        assert_eq!(options.get("root"), Some(&"/artifacts".to_string()));
        assert_eq!(
            options.get("disable_config_load"),
            Some(&"true".to_string())
        );
        assert_eq!(
            options.get("enable_virtual_host_style"),
            Some(&"false".to_string())
        );
    }
}

#[async_trait]
impl ObjectStorage for FileSystemObjectStorage {
    async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), ApplicationError> {
        let path = self.path_for(key);
        debug!(
            "writing {} byte(s) to local object storage key `{}` at {}",
            bytes.len(),
            key,
            path.display()
        );
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|error| ApplicationError::External(error.to_string()))?;
        }
        fs::write(path, bytes)
            .await
            .map_err(|error| ApplicationError::External(error.to_string()))
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, ApplicationError> {
        let path = self.path_for(key);
        match fs::read(path).await {
            Ok(bytes) => {
                debug!(
                    "read {} byte(s) from local object storage key `{}`",
                    bytes.len(),
                    key
                );
                Ok(Some(bytes))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                debug!("local object storage miss for key `{key}`");
                Ok(None)
            }
            Err(error) => Err(ApplicationError::External(error.to_string())),
        }
    }

    async fn delete(&self, key: &str) -> Result<(), ApplicationError> {
        let path = self.path_for(key);
        match fs::remove_file(path).await {
            Ok(()) => {
                debug!("deleted local object storage key `{key}`");
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                debug!("local object storage delete skipped because key `{key}` does not exist");
                Ok(())
            }
            Err(error) => Err(ApplicationError::External(error.to_string())),
        }
    }
}
