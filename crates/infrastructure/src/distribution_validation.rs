use flate2::read::GzDecoder;
use log::debug;
use pyregistry_application::{
    ApplicationError, DistributionFileInspector, DistributionInspection, DistributionKind,
    FileTypeInspection,
};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Cursor, Read, Seek};
use std::path::Path;
#[cfg(feature = "file-type-ml")]
use std::sync::{LazyLock, Mutex};
use tar::Archive;
use zip::ZipArchive;

pub struct FilesystemDistributionInspector;

#[cfg(feature = "file-type-ml")]
static MAGIKA_SESSION: LazyLock<Mutex<Option<magika::Session>>> =
    LazyLock::new(|| Mutex::new(None));

impl DistributionFileInspector for FilesystemDistributionInspector {
    fn inspect_distribution(
        &self,
        path: &Path,
    ) -> Result<DistributionInspection, ApplicationError> {
        let kind = distribution_kind_from_path(path)?;
        let size_bytes = file_size(path)?;
        let sha256 = sha256_file(path)?;
        let file_type = inspect_file_type_from_path(kind, path)?;
        let archive_entry_count = if file_type.extension_mismatch() {
            0
        } else {
            match kind {
                DistributionKind::Wheel => inspect_wheel_archive_path(path)?,
                DistributionKind::SourceTarGz => inspect_source_tar_gz_archive_path(path)?,
                DistributionKind::SourceZip => inspect_source_zip_archive_path(path)?,
            }
        };

        debug!(
            "validated {} archive `{}`: size_bytes={}, sha256={}, entries={}",
            kind.label(),
            path.display(),
            size_bytes,
            sha256,
            archive_entry_count
        );

        Ok(DistributionInspection {
            kind,
            size_bytes,
            sha256,
            archive_entry_count,
            file_type,
        })
    }

    fn inspect_distribution_bytes(
        &self,
        filename: &str,
        bytes: &[u8],
    ) -> Result<DistributionInspection, ApplicationError> {
        let kind = distribution_kind_from_filename(filename, filename)?;
        let size_bytes = bytes.len() as u64;
        let sha256 = sha256_bytes(bytes);
        let file_type = inspect_file_type_from_bytes(kind, filename, bytes)?;
        let archive_entry_count = if file_type.extension_mismatch() {
            0
        } else {
            match kind {
                DistributionKind::Wheel => {
                    let archive = ZipArchive::new(Cursor::new(bytes))
                        .map_err(|error| ApplicationError::External(error.to_string()))?;
                    inspect_zip_archive(archive, filename)?
                }
                DistributionKind::SourceTarGz => {
                    inspect_source_tar_gz_reader(Cursor::new(bytes), filename)?
                }
                DistributionKind::SourceZip => {
                    let archive = ZipArchive::new(Cursor::new(bytes))
                        .map_err(|error| ApplicationError::External(error.to_string()))?;
                    inspect_source_zip_archive(archive, filename)?
                }
            }
        };

        debug!(
            "validated {} archive `{}` from memory: size_bytes={}, sha256={}, entries={}",
            kind.label(),
            filename,
            size_bytes,
            sha256,
            archive_entry_count
        );

        Ok(DistributionInspection {
            kind,
            size_bytes,
            sha256,
            archive_entry_count,
            file_type,
        })
    }
}

fn distribution_kind_from_path(path: &Path) -> Result<DistributionKind, ApplicationError> {
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            ApplicationError::Conflict(format!(
                "distribution path `{}` does not contain a valid UTF-8 file name",
                path.display()
            ))
        })?
        .to_ascii_lowercase();

    distribution_kind_from_filename(&filename, &path.display().to_string())
}

fn distribution_kind_from_filename(
    filename: &str,
    subject: &str,
) -> Result<DistributionKind, ApplicationError> {
    let filename = filename.to_ascii_lowercase();
    if filename.ends_with(".whl") {
        return Ok(DistributionKind::Wheel);
    }

    if filename.ends_with(".tar.gz") || filename.ends_with(".tgz") {
        return Ok(DistributionKind::SourceTarGz);
    }

    if filename.ends_with(".zip") {
        return Ok(DistributionKind::SourceZip);
    }

    Err(ApplicationError::Conflict(format!(
        "unsupported distribution file `{subject}`; expected .whl, .tar.gz, .tgz, or .zip"
    )))
}

fn inspect_file_type_from_path(
    kind: DistributionKind,
    path: &Path,
) -> Result<FileTypeInspection, ApplicationError> {
    #[cfg(feature = "file-type-ml")]
    {
        let file_type = with_magika_session(|session| session.identify_file_sync(path))?;
        return Ok(file_type_inspection(
            kind,
            path.extension_label(),
            file_type,
        ));
    }

    #[cfg(not(feature = "file-type-ml"))]
    {
        let mut file =
            File::open(path).map_err(|error| ApplicationError::External(error.to_string()))?;
        let mut header = [0_u8; 8];
        let bytes_read = file
            .read(&mut header)
            .map_err(|error| ApplicationError::External(error.to_string()))?;
        Ok(file_type_inspection_from_magic(
            kind,
            path.extension_label(),
            &header[..bytes_read],
        ))
    }
}

#[cfg(feature = "file-type-ml")]
fn inspect_file_type_from_bytes(
    kind: DistributionKind,
    filename: &str,
    bytes: &[u8],
) -> Result<FileTypeInspection, ApplicationError> {
    let file_type = with_magika_session(|session| session.identify_content_sync(bytes))?;
    Ok(file_type_inspection(
        kind,
        extension_label_from_filename(filename),
        file_type,
    ))
}

#[cfg(not(feature = "file-type-ml"))]
fn inspect_file_type_from_bytes(
    kind: DistributionKind,
    filename: &str,
    bytes: &[u8],
) -> Result<FileTypeInspection, ApplicationError> {
    Ok(file_type_inspection_from_magic(
        kind,
        extension_label_from_filename(filename),
        &bytes[..bytes.len().min(8)],
    ))
}

#[cfg(feature = "file-type-ml")]
fn with_magika_session<T>(
    inspect: impl FnOnce(&mut magika::Session) -> magika::Result<T>,
) -> Result<T, ApplicationError> {
    let mut session = MAGIKA_SESSION
        .lock()
        .map_err(|_| ApplicationError::External("Magika session lock was poisoned".into()))?;
    if session.is_none() {
        *session = Some(magika::Session::new().map_err(|error| {
            ApplicationError::External(format!("could not initialize Magika: {error}"))
        })?);
    }
    let session = session
        .as_mut()
        .expect("Magika session was initialized above");
    inspect(session).map_err(|error| ApplicationError::External(error.to_string()))
}

#[cfg(feature = "file-type-ml")]
fn file_type_inspection(
    kind: DistributionKind,
    actual_extension: Option<String>,
    file_type: magika::FileType,
) -> FileTypeInspection {
    let info = file_type.info();
    FileTypeInspection {
        detector: "magika".into(),
        label: info.label.into(),
        mime_type: info.mime_type.into(),
        group: info.group.into(),
        description: info.description.into(),
        score: file_type.score(),
        actual_extension,
        expected_extensions: expected_distribution_extensions(kind)
            .iter()
            .map(|extension| (*extension).to_string())
            .collect(),
        matches_extension: expected_magika_labels(kind).contains(&info.label),
    }
}

#[cfg(not(feature = "file-type-ml"))]
fn file_type_inspection_from_magic(
    kind: DistributionKind,
    actual_extension: Option<String>,
    bytes: &[u8],
) -> FileTypeInspection {
    let (label, mime_type, group, description, score) = if bytes.starts_with(b"PK\x03\x04")
        || bytes.starts_with(b"PK\x05\x06")
        || bytes.starts_with(b"PK\x07\x08")
    {
        ("zip", "application/zip", "archive", "ZIP archive", 1.0)
    } else if bytes.starts_with(&[0x1f, 0x8b]) {
        (
            "gzip",
            "application/gzip",
            "archive",
            "gzip compressed data",
            1.0,
        )
    } else {
        (
            "unknown",
            "application/octet-stream",
            "unknown",
            "unknown file type",
            0.0,
        )
    };

    FileTypeInspection {
        detector: "magic-bytes".into(),
        label: label.into(),
        mime_type: mime_type.into(),
        group: group.into(),
        description: description.into(),
        score,
        actual_extension,
        expected_extensions: expected_distribution_extensions(kind)
            .iter()
            .map(|extension| (*extension).to_string())
            .collect(),
        matches_extension: expected_magika_labels(kind).contains(&label),
    }
}

fn expected_distribution_extensions(kind: DistributionKind) -> &'static [&'static str] {
    match kind {
        DistributionKind::Wheel => &["whl"],
        DistributionKind::SourceTarGz => &["tar.gz", "tgz"],
        DistributionKind::SourceZip => &["zip"],
    }
}

fn expected_magika_labels(kind: DistributionKind) -> &'static [&'static str] {
    match kind {
        DistributionKind::Wheel | DistributionKind::SourceZip => &["zip", "npz"],
        DistributionKind::SourceTarGz => &["gzip"],
    }
}

trait DistributionPathExt {
    fn extension_label(&self) -> Option<String>;
}

impl DistributionPathExt for Path {
    fn extension_label(&self) -> Option<String> {
        let filename = self.file_name()?.to_str()?;
        extension_label_from_filename(filename)
    }
}

fn extension_label_from_filename(filename: &str) -> Option<String> {
    let filename = filename.to_ascii_lowercase();
    if filename.ends_with(".tar.gz") {
        return Some("tar.gz".into());
    }
    filename
        .rsplit_once('.')
        .map(|(_, extension)| extension.to_string())
        .filter(|extension| !extension.is_empty())
}

fn file_size(path: &Path) -> Result<u64, ApplicationError> {
    let metadata = path
        .metadata()
        .map_err(|error| ApplicationError::External(error.to_string()))?;
    if !metadata.is_file() {
        return Err(ApplicationError::Conflict(format!(
            "`{}` is not a regular file",
            path.display()
        )));
    }
    Ok(metadata.len())
}

fn sha256_file(path: &Path) -> Result<String, ApplicationError> {
    let mut file =
        File::open(path).map_err(|error| ApplicationError::External(error.to_string()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let bytes_read = file
            .read(&mut buffer)
            .map_err(|error| ApplicationError::External(error.to_string()))?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn inspect_wheel_archive_path(path: &Path) -> Result<usize, ApplicationError> {
    let file = File::open(path).map_err(|error| ApplicationError::External(error.to_string()))?;
    let archive =
        ZipArchive::new(file).map_err(|error| ApplicationError::External(error.to_string()))?;
    inspect_zip_archive(archive, &path.display().to_string())
}

fn inspect_source_zip_archive_path(path: &Path) -> Result<usize, ApplicationError> {
    let file = File::open(path).map_err(|error| ApplicationError::External(error.to_string()))?;
    let archive =
        ZipArchive::new(file).map_err(|error| ApplicationError::External(error.to_string()))?;
    inspect_source_zip_archive(archive, &path.display().to_string())
}

fn inspect_zip_archive<R: Read + Seek>(
    mut archive: ZipArchive<R>,
    label: &str,
) -> Result<usize, ApplicationError> {
    if archive.is_empty() {
        return Err(ApplicationError::Conflict(format!(
            "wheel archive `{label}` is empty"
        )));
    }

    let mut entry_count = 0;
    let mut has_wheel_metadata = false;
    let mut has_package_metadata = false;
    for index in 0..archive.len() {
        let mut file = archive
            .by_index(index)
            .map_err(|error| ApplicationError::External(error.to_string()))?;
        if file.is_dir() {
            continue;
        }

        let name = file.name().to_string();
        has_wheel_metadata |= name.ends_with(".dist-info/WHEEL");
        has_package_metadata |= name.ends_with(".dist-info/METADATA");
        io::copy(&mut file, &mut io::sink())
            .map_err(|error| ApplicationError::External(error.to_string()))?;
        entry_count += 1;
    }

    if entry_count == 0 {
        return Err(ApplicationError::Conflict(format!(
            "wheel archive `{label}` does not contain files"
        )));
    }
    if !has_wheel_metadata {
        return Err(ApplicationError::Conflict(format!(
            "wheel archive `{label}` is missing .dist-info/WHEEL"
        )));
    }
    if !has_package_metadata {
        return Err(ApplicationError::Conflict(format!(
            "wheel archive `{label}` is missing .dist-info/METADATA"
        )));
    }

    Ok(entry_count)
}

fn inspect_source_tar_gz_archive_path(path: &Path) -> Result<usize, ApplicationError> {
    let file = File::open(path).map_err(|error| ApplicationError::External(error.to_string()))?;
    inspect_source_tar_gz_reader(file, &path.display().to_string())
}

fn inspect_source_tar_gz_reader<R: Read>(
    reader: R,
    label: &str,
) -> Result<usize, ApplicationError> {
    let decoder = GzDecoder::new(reader);
    let mut archive = Archive::new(decoder);
    let entries = archive
        .entries()
        .map_err(|error| ApplicationError::External(error.to_string()))?;

    let mut entry_count = 0;
    for entry in entries {
        let mut entry = entry.map_err(|error| ApplicationError::External(error.to_string()))?;
        if !entry.header().entry_type().is_file() {
            continue;
        }

        io::copy(&mut entry, &mut io::sink())
            .map_err(|error| ApplicationError::External(error.to_string()))?;
        entry_count += 1;
    }

    if entry_count == 0 {
        return Err(ApplicationError::Conflict(format!(
            "source archive `{label}` does not contain files"
        )));
    }

    Ok(entry_count)
}

fn inspect_source_zip_archive<R: Read + Seek>(
    mut archive: ZipArchive<R>,
    label: &str,
) -> Result<usize, ApplicationError> {
    if archive.is_empty() {
        return Err(ApplicationError::Conflict(format!(
            "source zip archive `{label}` is empty"
        )));
    }

    let mut entry_count = 0;
    for index in 0..archive.len() {
        let mut file = archive
            .by_index(index)
            .map_err(|error| ApplicationError::External(error.to_string()))?;
        if file.is_dir() {
            continue;
        }

        io::copy(&mut file, &mut io::sink())
            .map_err(|error| ApplicationError::External(error.to_string()))?;
        entry_count += 1;
    }

    if entry_count == 0 {
        return Err(ApplicationError::Conflict(format!(
            "source zip archive `{label}` does not contain files"
        )));
    }

    Ok(entry_count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};
    use std::fs;
    use std::io::{Cursor, Write};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tar::{Builder, Header};
    use uuid::Uuid;
    use zip::ZipWriter;
    use zip::write::SimpleFileOptions;

    #[test]
    fn validates_wheel_archive_and_computes_sha256() {
        let bytes = build_zip_bytes(&[
            ZipFixtureEntry::file("demo_pkg/__init__.py", b"VALUE = 1"),
            ZipFixtureEntry::file(
                "demo_pkg-0.1.0.dist-info/WHEEL",
                b"Wheel-Version: 1.0\nGenerator: pyregistry-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
            ),
            ZipFixtureEntry::file("demo_pkg-0.1.0.dist-info/METADATA", b"Name: demo-pkg\n"),
        ]);
        let path = write_temp_file("demo_pkg-0.1.0-py3-none-any.whl", &bytes);

        let inspection = FilesystemDistributionInspector
            .inspect_distribution(&path)
            .expect("valid wheel");

        fs::remove_file(&path).expect("remove temp wheel");
        assert_eq!(inspection.kind, DistributionKind::Wheel);
        assert_eq!(inspection.size_bytes, bytes.len() as u64);
        assert_eq!(inspection.archive_entry_count, 3);
        assert_eq!(inspection.sha256, expected_sha256(&bytes));
    }

    #[test]
    fn reports_extension_mismatch_before_archive_validation() {
        let path = write_temp_file("broken-0.1.0-py3-none-any.whl", b"not a zip archive");

        let inspection = FilesystemDistributionInspector
            .inspect_distribution(&path)
            .expect("mismatched content should be inspected");

        fs::remove_file(&path).expect("remove temp wheel");
        assert!(inspection.file_type.extension_mismatch());
        assert_ne!(inspection.file_type.label, "zip");
        assert_eq!(inspection.archive_entry_count, 0);
    }

    #[test]
    fn rejects_empty_or_metadata_incomplete_wheel_archives() {
        let empty = build_zip_bytes(&[]);
        let error = FilesystemDistributionInspector
            .inspect_distribution_bytes("empty-0.1.0-py3-none-any.whl", &empty)
            .expect_err("empty wheel should fail");
        assert!(error.to_string().contains("empty"));

        let directory_only = build_zip_bytes(&[ZipFixtureEntry::dir("demo_pkg/")]);
        let error = FilesystemDistributionInspector
            .inspect_distribution_bytes("dirs-0.1.0-py3-none-any.whl", &directory_only)
            .expect_err("directory-only wheel should fail");
        assert!(error.to_string().contains("does not contain files"));

        let missing_wheel = build_zip_bytes(&[ZipFixtureEntry::file(
            "demo_pkg-0.1.0.dist-info/METADATA",
            b"Name: demo-pkg\n",
        )]);
        let error = FilesystemDistributionInspector
            .inspect_distribution_bytes("missing-wheel-0.1.0-py3-none-any.whl", &missing_wheel)
            .expect_err("missing WHEEL should fail");
        assert!(error.to_string().contains("WHEEL"));

        let missing_metadata = build_zip_bytes(&[ZipFixtureEntry::file(
            "demo_pkg-0.1.0.dist-info/WHEEL",
            b"Wheel-Version: 1.0\n",
        )]);
        let error = FilesystemDistributionInspector
            .inspect_distribution_bytes(
                "missing-metadata-0.1.0-py3-none-any.whl",
                &missing_metadata,
            )
            .expect_err("missing METADATA should fail");
        assert!(error.to_string().contains("METADATA"));
    }

    #[test]
    fn validates_source_tar_gz_archive_and_computes_sha256() {
        let bytes = build_tar_gz_bytes(&[
            (
                "demo_pkg-0.1.0/pyproject.toml",
                b"[project]\nname = \"demo-pkg\"\n".as_slice(),
            ),
            (
                "demo_pkg-0.1.0/demo_pkg/__init__.py",
                b"VALUE = 1".as_slice(),
            ),
        ]);
        let path = write_temp_file("demo_pkg-0.1.0.tar.gz", &bytes);

        let inspection = FilesystemDistributionInspector
            .inspect_distribution(&path)
            .expect("valid source tar.gz");

        fs::remove_file(&path).expect("remove temp source archive");
        assert_eq!(inspection.kind, DistributionKind::SourceTarGz);
        assert_eq!(inspection.size_bytes, bytes.len() as u64);
        assert_eq!(inspection.archive_entry_count, 2);
        assert_eq!(inspection.sha256, expected_sha256(&bytes));
    }

    #[test]
    fn validates_distribution_bytes_without_temp_file() {
        let bytes = build_tar_gz_bytes(&[(
            "demo_pkg-0.1.0/pyproject.toml",
            b"[project]\nname = \"demo-pkg\"\n".as_slice(),
        )]);

        let inspection = FilesystemDistributionInspector
            .inspect_distribution_bytes("demo_pkg-0.1.0.tgz", &bytes)
            .expect("valid source archive bytes");

        assert_eq!(inspection.kind, DistributionKind::SourceTarGz);
        assert_eq!(inspection.size_bytes, bytes.len() as u64);
        assert_eq!(inspection.archive_entry_count, 1);
        assert_eq!(inspection.sha256, expected_sha256(&bytes));
    }

    #[test]
    fn validates_source_zip_archive_and_computes_sha256() {
        let bytes = build_zip_bytes(&[
            ZipFixtureEntry::file(
                "demo_pkg-0.1.0/pyproject.toml",
                b"[project]\nname = \"demo-pkg\"\n",
            ),
            ZipFixtureEntry::file("demo_pkg-0.1.0/demo_pkg/__init__.py", b"VALUE = 1"),
        ]);
        let path = write_temp_file("demo_pkg-0.1.0.zip", &bytes);

        let inspection = FilesystemDistributionInspector
            .inspect_distribution(&path)
            .expect("valid source zip");

        fs::remove_file(&path).expect("remove temp source archive");
        assert_eq!(inspection.kind, DistributionKind::SourceZip);
        assert_eq!(inspection.size_bytes, bytes.len() as u64);
        assert_eq!(inspection.archive_entry_count, 2);
        assert_eq!(inspection.sha256, expected_sha256(&bytes));
    }

    #[test]
    fn validates_source_zip_distribution_bytes_without_temp_file() {
        let bytes = build_zip_bytes(&[ZipFixtureEntry::file(
            "demo_pkg-0.1.0/pyproject.toml",
            b"[project]\nname = \"demo-pkg\"\n",
        )]);

        let inspection = FilesystemDistributionInspector
            .inspect_distribution_bytes("demo_pkg-0.1.0.zip", &bytes)
            .expect("valid source zip bytes");

        assert_eq!(inspection.kind, DistributionKind::SourceZip);
        assert_eq!(inspection.size_bytes, bytes.len() as u64);
        assert_eq!(inspection.archive_entry_count, 1);
        assert_eq!(inspection.sha256, expected_sha256(&bytes));
    }

    #[test]
    fn rejects_empty_source_archives() {
        let empty_zip = build_zip_bytes(&[]);
        let error = FilesystemDistributionInspector
            .inspect_distribution_bytes("demo_pkg-0.1.0.zip", &empty_zip)
            .expect_err("empty source zip should fail");
        assert!(error.to_string().contains("empty"));

        let directory_only_zip = build_zip_bytes(&[ZipFixtureEntry::dir("demo_pkg-0.1.0/")]);
        let error = FilesystemDistributionInspector
            .inspect_distribution_bytes("demo_pkg-0.1.0.zip", &directory_only_zip)
            .expect_err("directory-only source zip should fail");
        assert!(error.to_string().contains("does not contain files"));

        let empty_tar = build_tar_gz_bytes(&[]);
        let error = FilesystemDistributionInspector
            .inspect_distribution_bytes("demo_pkg-0.1.0.tar.gz", &empty_tar)
            .expect_err("empty source tar should fail");
        assert!(error.to_string().contains("does not contain files"));
    }

    #[test]
    fn rejects_unsupported_distribution_extension() {
        let path = write_temp_file("demo_pkg-0.1.0.exe", b"not supported here");

        let error = FilesystemDistributionInspector
            .inspect_distribution(&path)
            .expect_err("unsupported extension should fail");

        fs::remove_file(&path).expect("remove temp file");
        assert!(matches!(error, ApplicationError::Conflict(_)));
    }

    #[test]
    fn rejects_paths_without_regular_distribution_files() {
        let unnamed_error = FilesystemDistributionInspector
            .inspect_distribution(Path::new(""))
            .expect_err("empty path should fail");
        assert!(unnamed_error.to_string().contains("valid UTF-8 file name"));

        let dir_path =
            std::env::temp_dir().join(format!("pyregistry-dist-dir-{}.whl", Uuid::new_v4()));
        fs::create_dir(&dir_path).expect("create directory");
        let dir_error = FilesystemDistributionInspector
            .inspect_distribution(&dir_path)
            .expect_err("directory should not validate as a wheel");
        assert!(dir_error.to_string().contains("not a regular file"));
        fs::remove_dir(&dir_path).expect("remove temp directory");
    }

    #[test]
    fn rejects_source_tar_archives_that_only_contain_directories() {
        let bytes = build_tar_gz_directory_bytes("demo_pkg-0.1.0/");

        let error = FilesystemDistributionInspector
            .inspect_distribution_bytes("demo_pkg-0.1.0.tar.gz", &bytes)
            .expect_err("directory-only source tar should fail");

        assert!(error.to_string().contains("does not contain files"));
    }

    enum ZipFixtureEntry<'a> {
        File(&'a str, &'a [u8]),
        Dir(&'a str),
    }

    impl<'a> ZipFixtureEntry<'a> {
        fn file(path: &'a str, contents: &'a [u8]) -> Self {
            Self::File(path, contents)
        }

        fn dir(path: &'a str) -> Self {
            Self::Dir(path)
        }
    }

    fn build_zip_bytes(entries: &[ZipFixtureEntry<'_>]) -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = ZipWriter::new(&mut cursor);
            for entry in entries {
                match entry {
                    ZipFixtureEntry::File(path, contents) => {
                        writer
                            .start_file(*path, SimpleFileOptions::default())
                            .expect("start zip file");
                        writer.write_all(contents).expect("write zip contents");
                    }
                    ZipFixtureEntry::Dir(path) => {
                        writer
                            .add_directory(*path, SimpleFileOptions::default())
                            .expect("add zip directory");
                    }
                }
            }
            writer.finish().expect("finish zip");
        }
        cursor.into_inner()
    }

    fn build_tar_gz_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut builder = Builder::new(encoder);
        for (path, contents) in entries {
            let mut header = Header::new_gnu();
            header.set_path(path).expect("set tar path");
            header.set_size(contents.len() as u64);
            header.set_cksum();
            builder
                .append(&header, *contents)
                .expect("append tar entry");
        }

        let encoder = builder.into_inner().expect("finish tar builder");
        encoder.finish().expect("finish gzip stream")
    }

    fn build_tar_gz_directory_bytes(path: &str) -> Vec<u8> {
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut builder = Builder::new(encoder);
        let mut header = Header::new_gnu();
        header.set_path(path).expect("set tar path");
        header.set_entry_type(tar::EntryType::Directory);
        header.set_size(0);
        header.set_cksum();
        builder
            .append(&header, std::io::empty())
            .expect("append tar directory");

        let encoder = builder.into_inner().expect("finish tar builder");
        encoder.finish().expect("finish gzip stream")
    }

    fn expected_sha256(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hex::encode(hasher.finalize())
    }

    fn write_temp_file(filename: &str, bytes: &[u8]) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "pyregistry-dist-validation-{}-{nonce}-{filename}",
            std::process::id()
        ));
        fs::write(&path, bytes).expect("write temp distribution");
        path
    }
}
