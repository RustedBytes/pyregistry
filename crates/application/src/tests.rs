#![cfg(test)]

use rand::distr::{Alphanumeric, SampleString};

#[test]
fn issued_token_has_prefix() {
    let secret = format!("pyr_{}", Alphanumeric.sample_string(&mut rand::rng(), 8));
    assert!(secret.starts_with("pyr_"));
}
