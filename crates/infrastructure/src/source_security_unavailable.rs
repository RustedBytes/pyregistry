use log::warn;
use pyregistry_application::{
    ApplicationError, WheelArchiveSnapshot, WheelSourceSecurityScanResult,
    WheelSourceSecurityScanner,
};

pub struct FoxGuardWheelSourceSecurityScanner;

impl Default for FoxGuardWheelSourceSecurityScanner {
    fn default() -> Self {
        Self::with_ignored_rules(Vec::<String>::new())
    }
}

impl FoxGuardWheelSourceSecurityScanner {
    #[must_use]
    pub fn with_ignored_rules(
        _ignored_rule_ids: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Self {
        Self
    }
}

impl WheelSourceSecurityScanner for FoxGuardWheelSourceSecurityScanner {
    fn scan_archive(
        &self,
        archive: &WheelArchiveSnapshot,
    ) -> Result<WheelSourceSecurityScanResult, ApplicationError> {
        warn!(
            "FoxGuard source security scanning is unavailable because the `source-security` feature is disabled"
        );
        Ok(WheelSourceSecurityScanResult {
            scanned_file_count: archive.entries.len(),
            findings: Vec::new(),
        })
    }
}
