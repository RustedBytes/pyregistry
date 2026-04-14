#![no_main]

use libfuzzer_sys::fuzz_target;
use pyregistry_domain::{ProjectName, ReleaseVersion, TenantSlug};

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = std::str::from_utf8(data) {
        let _ = TenantSlug::new(input);
        let _ = ProjectName::new(input);
        let _ = ReleaseVersion::new(input);
    }
});
