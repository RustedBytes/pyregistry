use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DistributionKind {
    Wheel,
    SourceTarGz,
    SourceZip,
}

impl DistributionKind {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Wheel => "wheel",
            Self::SourceTarGz => "source tar.gz",
            Self::SourceZip => "source zip",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributionInspection {
    pub kind: DistributionKind,
    pub size_bytes: u64,
    pub sha256: String,
    pub archive_entry_count: usize,
    pub file_type: FileTypeInspection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTypeInspection {
    pub detector: String,
    pub label: String,
    pub mime_type: String,
    pub group: String,
    pub description: String,
    pub score: f32,
    pub actual_extension: Option<String>,
    pub expected_extensions: Vec<String>,
    pub matches_extension: bool,
}

impl FileTypeInspection {
    #[must_use]
    pub fn unknown_for_extension(
        actual_extension: Option<String>,
        expected_extensions: Vec<String>,
    ) -> Self {
        Self {
            detector: "unknown".into(),
            label: "unknown".into(),
            mime_type: "application/octet-stream".into(),
            group: "unknown".into(),
            description: "file type was not inspected".into(),
            score: 0.0,
            actual_extension,
            expected_extensions,
            matches_extension: true,
        }
    }

    #[must_use]
    pub fn extension_mismatch(&self) -> bool {
        !self.matches_extension
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DistributionChecksumStatus {
    NotProvided,
    Matched { expected: String },
    Mismatched { expected: String, actual: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributionValidationReport {
    pub file_path: PathBuf,
    pub inspection: DistributionInspection,
    pub checksum: DistributionChecksumStatus,
}

impl DistributionValidationReport {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !matches!(self.checksum, DistributionChecksumStatus::Mismatched { .. })
            && !self.inspection.file_type.extension_mismatch()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegistryDistributionValidationStatus {
    Valid,
    MissingBlob,
    ChecksumMismatch,
    ExtensionMismatch,
    InvalidArchive,
    UnsupportedDistribution,
    StorageError,
}

impl RegistryDistributionValidationStatus {
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::MissingBlob => "missing blob",
            Self::ChecksumMismatch => "checksum mismatch",
            Self::ExtensionMismatch => "extension mismatch",
            Self::InvalidArchive => "invalid archive",
            Self::UnsupportedDistribution => "unsupported distribution",
            Self::StorageError => "storage error",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryDistributionValidationItem {
    pub tenant_slug: String,
    pub project_name: String,
    pub version: String,
    pub filename: String,
    pub object_key: String,
    pub expected_sha256: String,
    pub actual_sha256: Option<String>,
    pub recorded_size_bytes: u64,
    pub actual_size_bytes: Option<u64>,
    pub kind: Option<DistributionKind>,
    pub detected_file_type: Option<String>,
    pub detected_mime_type: Option<String>,
    pub extension_matches: Option<bool>,
    pub archive_entry_count: Option<usize>,
    pub status: RegistryDistributionValidationStatus,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegistryDistributionValidationReport {
    pub tenant_count: usize,
    pub project_count: usize,
    pub release_count: usize,
    pub artifact_count: usize,
    pub valid_count: usize,
    pub invalid_count: usize,
    pub missing_blob_count: usize,
    pub checksum_mismatch_count: usize,
    pub extension_mismatch_count: usize,
    pub invalid_archive_count: usize,
    pub unsupported_distribution_count: usize,
    pub storage_error_count: usize,
    pub items: Vec<RegistryDistributionValidationItem>,
}

impl RegistryDistributionValidationReport {
    pub fn push_item(&mut self, item: RegistryDistributionValidationItem) {
        self.artifact_count += 1;
        match &item.status {
            RegistryDistributionValidationStatus::Valid => {
                self.valid_count += 1;
            }
            RegistryDistributionValidationStatus::MissingBlob => {
                self.invalid_count += 1;
                self.missing_blob_count += 1;
            }
            RegistryDistributionValidationStatus::ChecksumMismatch => {
                self.invalid_count += 1;
                self.checksum_mismatch_count += 1;
            }
            RegistryDistributionValidationStatus::ExtensionMismatch => {
                self.invalid_count += 1;
                self.extension_mismatch_count += 1;
            }
            RegistryDistributionValidationStatus::InvalidArchive => {
                self.invalid_count += 1;
                self.invalid_archive_count += 1;
            }
            RegistryDistributionValidationStatus::UnsupportedDistribution => {
                self.invalid_count += 1;
                self.unsupported_distribution_count += 1;
            }
            RegistryDistributionValidationStatus::StorageError => {
                self.invalid_count += 1;
                self.storage_error_count += 1;
            }
        }
        self.items.push(item);
    }

    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.invalid_count == 0
    }
}
