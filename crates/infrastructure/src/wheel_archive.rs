use pyregistry_application::{
    ApplicationError, WheelArchiveEntry, WheelArchiveReader, WheelArchiveSnapshot,
};
use std::fs::File;
use std::io::Cursor;
use std::io::Read;
use std::path::Path;
use zip::ZipArchive;

pub struct ZipWheelArchiveReader;

impl WheelArchiveReader for ZipWheelArchiveReader {
    fn read_wheel(&self, path: &Path) -> Result<WheelArchiveSnapshot, ApplicationError> {
        let file =
            File::open(path).map_err(|error| ApplicationError::External(error.to_string()))?;
        let wheel_filename = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("unknown.whl")
            .to_string();

        read_zip_archive(
            ZipArchive::new(file).map_err(|error| ApplicationError::External(error.to_string()))?,
            wheel_filename,
        )
    }

    fn read_wheel_bytes(
        &self,
        wheel_filename: &str,
        bytes: &[u8],
    ) -> Result<WheelArchiveSnapshot, ApplicationError> {
        let reader = Cursor::new(bytes);
        read_zip_archive(
            ZipArchive::new(reader)
                .map_err(|error| ApplicationError::External(error.to_string()))?,
            wheel_filename.to_string(),
        )
    }
}

fn read_zip_archive<R: Read + std::io::Seek>(
    mut archive: ZipArchive<R>,
    wheel_filename: String,
) -> Result<WheelArchiveSnapshot, ApplicationError> {
    let mut entries = Vec::new();
    for index in 0..archive.len() {
        let mut file = archive
            .by_index(index)
            .map_err(|error| ApplicationError::External(error.to_string()))?;
        if file.is_dir() {
            continue;
        }

        let mut contents = Vec::new();
        file.read_to_end(&mut contents)
            .map_err(|error| ApplicationError::External(error.to_string()))?;
        entries.push(WheelArchiveEntry {
            path: file.name().to_string(),
            contents,
        });
    }

    Ok(WheelArchiveSnapshot {
        wheel_filename,
        entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use zip::ZipWriter;
    use zip::write::SimpleFileOptions;

    #[test]
    fn reads_wheel_bytes_and_skips_directory_entries() {
        let bytes = build_zip_bytes(&[
            ZipFixtureEntry::directory("demo_pkg/"),
            ZipFixtureEntry::file("demo_pkg/__init__.py", b"VALUE = 1"),
            ZipFixtureEntry::file("demo_pkg-0.1.0.dist-info/METADATA", b"Name: demo-pkg"),
        ]);

        let archive = ZipWheelArchiveReader
            .read_wheel_bytes("demo_pkg-0.1.0-py3-none-any.whl", &bytes)
            .expect("wheel archive");

        assert_eq!(archive.wheel_filename, "demo_pkg-0.1.0-py3-none-any.whl");
        assert_eq!(archive.entries.len(), 2);
        assert_eq!(archive.entries[0].path, "demo_pkg/__init__.py");
        assert_eq!(archive.entries[0].contents, b"VALUE = 1");
        assert_eq!(archive.entries[1].path, "demo_pkg-0.1.0.dist-info/METADATA");
    }

    #[test]
    fn reads_wheel_from_filesystem_path() {
        let bytes = build_zip_bytes(&[ZipFixtureEntry::file("demo_pkg/module.py", b"print('ok')")]);
        let path = std::env::temp_dir().join(format!(
            "pyregistry-test-{}-demo_pkg-0.1.0-py3-none-any.whl",
            std::process::id()
        ));
        fs::write(&path, bytes).expect("write temp wheel");

        let archive = ZipWheelArchiveReader
            .read_wheel(&path)
            .expect("wheel archive from path");

        fs::remove_file(&path).expect("remove temp wheel");
        assert_eq!(
            archive.wheel_filename,
            path.file_name()
                .and_then(|name| name.to_str())
                .expect("temp wheel filename")
        );
        assert_eq!(archive.entries.len(), 1);
        assert_eq!(archive.entries[0].path, "demo_pkg/module.py");
    }

    #[test]
    fn rejects_invalid_wheel_bytes() {
        let error = ZipWheelArchiveReader
            .read_wheel_bytes("broken.whl", b"not a zip archive")
            .expect_err("invalid zip should fail");

        assert!(matches!(error, ApplicationError::External(_)));
    }

    enum ZipFixtureEntry<'a> {
        Directory(&'a str),
        File(&'a str, &'a [u8]),
    }

    impl<'a> ZipFixtureEntry<'a> {
        fn directory(path: &'a str) -> Self {
            Self::Directory(path)
        }

        fn file(path: &'a str, contents: &'a [u8]) -> Self {
            Self::File(path, contents)
        }
    }

    fn build_zip_bytes(entries: &[ZipFixtureEntry<'_>]) -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = ZipWriter::new(&mut cursor);
            for entry in entries {
                match entry {
                    ZipFixtureEntry::Directory(path) => writer
                        .add_directory(*path, SimpleFileOptions::default())
                        .expect("add zip directory"),
                    ZipFixtureEntry::File(path, contents) => {
                        writer
                            .start_file(*path, SimpleFileOptions::default())
                            .expect("start zip file");
                        writer.write_all(contents).expect("write zip contents");
                    }
                }
            }
            writer.finish().expect("finish zip");
        }
        cursor.into_inner()
    }
}
