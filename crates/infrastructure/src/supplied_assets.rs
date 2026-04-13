use include_dir::{Dir, DirEntry, include_dir};
use std::path::Path;

static SIGNATURE_BASE: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../../supplied/signature-base");

#[derive(Debug, Clone, Copy)]
pub(crate) struct BundledFile<'a> {
    pub(crate) relative_path: &'a Path,
    #[cfg_attr(test, allow(dead_code))]
    pub(crate) contents: &'a [u8],
}

pub(crate) fn bundled_yara_rule_files() -> Vec<BundledFile<'static>> {
    let mut files = Vec::new();
    collect_yara_rule_files(&SIGNATURE_BASE, &mut files);
    files
}

#[cfg(test)]
fn bundled_file_exists(relative_path: &str) -> bool {
    SIGNATURE_BASE.get_file(relative_path).is_some()
}

fn collect_yara_rule_files<'a>(dir: &'a Dir<'a>, files: &mut Vec<BundledFile<'a>>) {
    for entry in dir.entries() {
        match entry {
            DirEntry::Dir(child) => collect_yara_rule_files(child, files),
            DirEntry::File(file) if is_yara_rule_file(file.path()) => {
                files.push(BundledFile {
                    relative_path: file.path(),
                    contents: file.contents(),
                });
            }
            DirEntry::File(_) => {}
        }
    }
}

fn is_yara_rule_file(path: &Path) -> bool {
    matches!(
        path.extension()
            .and_then(|extension| extension.to_str())
            .map(|extension| extension.to_ascii_lowercase())
            .as_deref(),
        Some("yar" | "yara")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundles_signature_base_license_and_yara_rules() {
        let rule_files = bundled_yara_rule_files();

        assert!(bundled_file_exists("LICENSE"));
        assert!(bundled_file_exists("README.md"));
        assert!(rule_files.len() > 700);
        assert!(
            rule_files
                .iter()
                .any(|file| file.relative_path.ends_with("apt_stuxnet.yar"))
        );
    }
}
