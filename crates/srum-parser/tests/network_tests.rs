//! Integration tests for srum-network-parsing story.

use srum_parser::parse_network_usage;

#[test]
fn parse_network_invalid_header_returns_err() {
    use std::io::Write as _;
    let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
    let mut page = vec![0u8; 4096];
    page[4..8].copy_from_slice(&0xDEAD_BEEF_u32.to_le_bytes()); // wrong magic
    tmp.write_all(&page).expect("write");
    let result = parse_network_usage(tmp.path());
    assert!(result.is_err(), "invalid ESE header must return Err");
}
