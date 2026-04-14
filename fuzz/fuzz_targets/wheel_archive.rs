#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use pyregistry_application::WheelArchiveReader;
use pyregistry_infrastructure::ZipWheelArchiveReader;

#[derive(Debug, Arbitrary)]
struct WheelArchiveInput {
    wheel_filename: String,
    bytes: Vec<u8>,
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    if let Ok(input) = WheelArchiveInput::arbitrary(&mut unstructured) {
        let wheel_filename = if input.wheel_filename.trim().is_empty() {
            "fuzz.whl"
        } else {
            input.wheel_filename.as_str()
        };
        let _ = ZipWheelArchiveReader.read_wheel_bytes(wheel_filename, &input.bytes);
    }

    let _ = ZipWheelArchiveReader.read_wheel_bytes("fuzz.whl", data);
});
