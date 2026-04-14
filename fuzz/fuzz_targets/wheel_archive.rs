#![no_main]

use libfuzzer_sys::fuzz_target;
use pyregistry_application::WheelArchiveReader;
use pyregistry_infrastructure::ZipWheelArchiveReader;

fuzz_target!(|data: &[u8]| {
    let _ = ZipWheelArchiveReader.read_wheel_bytes("fuzz.whl", data);
});
