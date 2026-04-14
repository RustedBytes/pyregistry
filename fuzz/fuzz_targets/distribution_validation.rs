#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use pyregistry_application::DistributionFileInspector;
use pyregistry_infrastructure::FilesystemDistributionInspector;

#[derive(Debug, Arbitrary)]
struct DistributionInput {
    filename_stem: String,
    suffix_choice: u8,
    bytes: Vec<u8>,
}

fuzz_target!(|data: &[u8]| {
    let inspector = FilesystemDistributionInspector;

    let mut unstructured = Unstructured::new(data);
    let Ok(input) = DistributionInput::arbitrary(&mut unstructured) else {
        return;
    };

    for filename in fixed_filenames(&input.filename_stem, input.suffix_choice) {
        let _ = inspector.inspect_distribution_bytes(&filename, data);
        let _ = inspector.inspect_distribution_bytes(&filename, &input.bytes);
    }
});

fn fixed_filenames(stem: &str, suffix_choice: u8) -> Vec<String> {
    vec![
        "fuzz-0.1.0-py3-none-any.whl".into(),
        "fuzz-0.1.0.tar.gz".into(),
        "fuzz-0.1.0.zip".into(),
        dynamic_filename(stem, suffix_choice),
    ]
}

fn dynamic_filename(stem: &str, suffix_choice: u8) -> String {
    let stem = stem
        .chars()
        .filter(|character| !character.is_control() && *character != '/' && *character != '\\')
        .take(96)
        .collect::<String>();
    let stem = if stem.trim().is_empty() {
        "fuzz".into()
    } else {
        stem
    };
    let suffix = match suffix_choice % 6 {
        0 => ".whl",
        1 => ".tar.gz",
        2 => ".tgz",
        3 => ".zip",
        4 => ".tar.bz2",
        _ => ".txt",
    };
    format!("{stem}{suffix}")
}
