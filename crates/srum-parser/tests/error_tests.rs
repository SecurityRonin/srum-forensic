//! Tests for `SrumError`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use srum_parser::SrumError;

#[test]
fn srum_error_decode_carries_page_and_tag() {
    let e = SrumError::DecodeError {
        page: 3,
        tag: 1,
        detail: "record too short".into(),
    };
    let msg = e.to_string();
    assert!(msg.contains("page 3"), "{msg}");
    assert!(msg.contains("tag 1"), "{msg}");
}
