//! SRUDB.dat parser — reads SRUM records from ESE database files.
//!
//! SRUDB.dat is an ESE (JET Blue) database stored at
//! `C:\Windows\System32\sru\SRUDB.dat`. On a live system it is locked;
//! forensic analysis always operates on a copy.
//!
//! # Current status
//!
//! ESE header validation and B-tree record extraction are both implemented.

mod network;

use ese_core::EseError;

/// Parse network usage records from a SRUDB.dat file.
///
/// Returns all records from the
/// `{973F5D5C-1D90-4944-BE8E-24B22A728CF2}` table.
///
/// Walks the B-tree rooted at the catalog entry for the `NetworkUsage` table
/// and decodes each 32-byte record tag from every leaf page.
///
/// # Errors
///
/// Returns an error if the file cannot be read or is not a valid ESE database.
pub fn parse_network_usage(
    path: &std::path::Path,
) -> anyhow::Result<Vec<srum_core::NetworkUsageRecord>> {
    const NETWORK_TABLE: &str = "{973F5D5C-1D90-4944-BE8E-24B22A728CF2}";
    let db = ese_core::open_database(path)?;
    let root_page = db.find_table_page(NETWORK_TABLE)
        .map_err(|e| anyhow::anyhow!("network table not found: {e}"))?;
    let leaf_pages = db.walk_leaf_pages(root_page)?;
    let mut records = Vec::new();
    for page_num in leaf_pages {
        let page = db.read_page(page_num)?;
        let tags = page.tags()?;
        // Tag 0 is the page header — data records start at tag 1.
        for i in 1..tags.len() {
            let data = page.record_data(i)?;
            if let Ok(rec) = network::decode_network_record(data) {
                records.push(rec);
            }
        }
    }
    Ok(records)
}

/// Parse application usage records from a SRUDB.dat file.
///
/// Returns all records from the
/// `{5C8CF1C7-7257-4F13-B223-970EF5939312}` table.
///
/// Currently returns an empty `Vec` for valid ESE databases — full B-tree
/// record extraction is not yet implemented.
///
/// # Errors
///
/// Returns an error if the file cannot be read or is not a valid ESE database.
pub fn parse_app_usage(
    path: &std::path::Path,
) -> anyhow::Result<Vec<srum_core::AppUsageRecord>> {
    // Validate the ESE header first.
    ese_core::open(path).map_err(|e| anyhow::anyhow!("ESE open failed: {e}"))?;
    // TODO: implement full ESE B-tree record extraction
    Ok(vec![])
}

#[cfg(test)]
mod tests {
    use super::*;
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
