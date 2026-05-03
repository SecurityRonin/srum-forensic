//! SRUDB.dat parser — reads SRUM records from ESE database files.
//!
//! SRUDB.dat is an ESE (JET Blue) database stored at
//! `C:\Windows\System32\sru\SRUDB.dat`. On a live system it is locked;
//! forensic analysis always operates on a copy.
//!
//! # TODO
//!
//! Implement full ESE B-tree record extraction to populate the returned
//! `Vec` with actual records from SRUDB.dat pages.

/// Parse network usage records from a SRUDB.dat file.
///
/// Returns all records from the
/// `{973F5D5C-1D90-4944-BE8E-24B22A728CF2}` table.
///
/// # Errors
///
/// Returns an error if the file cannot be read or is not a valid ESE database.
pub fn parse_network_usage(
    path: &std::path::Path,
) -> anyhow::Result<Vec<srum_core::NetworkUsageRecord>> {
    todo!()
}

/// Parse application usage records from a SRUDB.dat file.
///
/// Returns all records from the
/// `{5C8CF1C7-7257-4F13-B223-970EF5939312}` table.
///
/// # Errors
///
/// Returns an error if the file cannot be read or is not a valid ESE database.
pub fn parse_app_usage(
    path: &std::path::Path,
) -> anyhow::Result<Vec<srum_core::AppUsageRecord>> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use tempfile::NamedTempFile;

    #[test]
    fn nonexistent_file_network_returns_err() {
        let result = parse_network_usage(std::path::Path::new("/nonexistent/SRUDB.dat"));
        assert!(result.is_err());
    }

    #[test]
    fn nonexistent_file_app_returns_err() {
        let result = parse_app_usage(std::path::Path::new("/nonexistent/SRUDB.dat"));
        assert!(result.is_err());
    }

    #[test]
    fn empty_file_network_returns_err() {
        let tmp = NamedTempFile::new().expect("tempfile");
        let result = parse_network_usage(tmp.path());
        assert!(result.is_err(), "empty file must return Err");
    }

    #[test]
    fn empty_file_app_returns_err() {
        let tmp = NamedTempFile::new().expect("tempfile");
        let result = parse_app_usage(tmp.path());
        assert!(result.is_err(), "empty file must return Err");
    }

    /// Verify the return type compiles correctly — Vec<NetworkUsageRecord>.
    #[test]
    fn network_usage_result_type() {
        // This test verifies the type signature compiles; runtime is Err since
        // no real SRUDB.dat is present.
        let _: anyhow::Result<Vec<srum_core::NetworkUsageRecord>> =
            parse_network_usage(std::path::Path::new("/nonexistent/SRUDB.dat"));
    }

    /// Verify the return type compiles correctly — Vec<AppUsageRecord>.
    #[test]
    fn app_usage_result_type() {
        let _: anyhow::Result<Vec<srum_core::AppUsageRecord>> =
            parse_app_usage(std::path::Path::new("/nonexistent/SRUDB.dat"));
    }
}
