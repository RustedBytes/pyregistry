#![no_main]

use libfuzzer_sys::fuzz_target;
use pyregistry_application::DistributionFileInspector;
use pyregistry_infrastructure::FilesystemDistributionInspector;

fuzz_target!(|data: &[u8]| {
    let inspector = FilesystemDistributionInspector;
    for filename in [
        "fuzz-0.1.0-py3-none-any.whl",
        "fuzz-0.1.0.tar.gz",
        "fuzz-0.1.0.zip",
    ] {
        let _ = inspector.inspect_distribution_bytes(filename, data);
    }
});
