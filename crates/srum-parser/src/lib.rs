//! SRUDB.dat parser — reads SRUM records from ESE database files.
//!
//! SRUDB.dat is an ESE (JET Blue) database stored at
//! `C:\Windows\System32\sru\SRUDB.dat`. On a live system it is locked;
//! forensic analysis always operates on a copy.

mod app_usage;
mod id_map;
mod network;

use ese_core::EseError;

/// Errors produced by the SRUM parser.
#[derive(Debug, thiserror::Error)]
pub enum SrumError {
    #[error("ese: {0}")]
    Ese(#[from] EseError),
    #[error("page {page} tag {tag}: {detail}")]
    DecodeError { page: u32, tag: usize, detail: String },
}

/// Iterate a named ESE table and decode each record, silently skipping
/// records that fail either the ESE read or the domain decode step.
fn collect_table<T>(
    db: &ese_core::EseDatabase,
    table: &str,
    decode: impl Fn(&[u8], u32, usize) -> Result<T, SrumError>,
) -> anyhow::Result<Vec<T>> {
    let records = db.table_records(table)?
        .filter_map(|r| match r {
            Ok((page, tag, data)) => decode(&data, page, tag).ok(),
            Err(_) => None,
        })
        .collect();
    Ok(records)
}

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
    let db = ese_core::EseDatabase::open(path)?;
    collect_table(&db, "{973F5D5C-1D90-4944-BE8E-24B22A728CF2}", |data, page, tag| {
        network::decode_network_record(data, page, tag)
    })
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
    let db = ese_core::EseDatabase::open(path)?;
    collect_table(&db, "{5C8CF1C7-7257-4F13-B223-970EF5939312}", |data, page, tag| {
        app_usage::decode_app_record(data, page, tag)
    })
}

/// Parse ID map entries from a SRUDB.dat file.
///
/// Returns all entries from the `SruDbIdMapTable` table.
///
/// # Errors
///
/// Returns an error if the file cannot be read or is not a valid ESE database.
pub fn parse_id_map(
    path: &std::path::Path,
) -> anyhow::Result<Vec<srum_core::IdMapEntry>> {
    let db = ese_core::EseDatabase::open(path)?;
    collect_table(&db, "SruDbIdMapTable", |data, page, tag| {
        id_map::decode_id_map_entry(data, page, tag)
    })
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

    #[test]
    fn network_usage_result_type() {
        let _: anyhow::Result<Vec<srum_core::NetworkUsageRecord>> =
            parse_network_usage(std::path::Path::new("/nonexistent/SRUDB.dat"));
    }

    #[test]
    fn app_usage_result_type() {
        let _: anyhow::Result<Vec<srum_core::AppUsageRecord>> =
            parse_app_usage(std::path::Path::new("/nonexistent/SRUDB.dat"));
    }
}
