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
