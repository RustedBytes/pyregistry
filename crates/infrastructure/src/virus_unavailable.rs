use log::warn;
use pyregistry_application::{
    ApplicationError, WheelArchiveSnapshot, WheelVirusScanResult, WheelVirusScanner,
};
use std::path::PathBuf;

pub struct YaraWheelVirusScanner;

impl YaraWheelVirusScanner {
    #[must_use]
    pub fn from_rules_dir(_rules_path: impl Into<PathBuf>) -> Self {
        Self
    }

    #[must_use]
    pub fn from_rules_dir_with_ignored_rules(
        _rules_path: impl Into<PathBuf>,
        _ignored_rule_ids: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Self {
        Self
    }
}

impl WheelVirusScanner for YaraWheelVirusScanner {
    fn scan_archive(
        &self,
        archive: &WheelArchiveSnapshot,
    ) -> Result<WheelVirusScanResult, ApplicationError> {
        warn!("YARA virus scanning is unavailable because the `virus-yara` feature is disabled");
        Ok(WheelVirusScanResult {
            scanned_file_count: archive.entries.len(),
            signature_rule_count: 0,
            skipped_rule_count: 0,
            findings: Vec::new(),
        })
    }
}
