//! SRUDB.dat parser — reads SRUM records from ESE database files.
//!
//! SRUDB.dat is an ESE (JET Blue) database stored at
//! `C:\Windows\System32\sru\SRUDB.dat`. On a live system it is locked;
//! forensic analysis always operates on a copy.

mod app_timeline;
mod app_usage;
mod connectivity;
mod energy;
mod id_map;
mod network;
mod push_notification;

use ese_core::EseError;
use forensicnomicon::srum::{
    TABLE_APP_RESOURCE_USAGE, TABLE_APP_TIMELINE, TABLE_ENERGY_USAGE, TABLE_ID_MAP,
    TABLE_NETWORK_CONNECTIVITY, TABLE_NETWORK_USAGE, TABLE_PUSH_NOTIFICATIONS,
};

/// Errors produced by the SRUM parser.
#[derive(Debug, thiserror::Error)]
pub enum SrumError {
    #[error("ese: {0}")]
    Ese(#[from] EseError),
    #[error("page {page} tag {tag}: {detail}")]
    DecodeError {
        page: u32,
        tag: usize,
        detail: String,
    },
}

/// Iterate a named ESE table and decode each record, silently skipping
/// records that fail either the ESE read or the domain decode step.
fn collect_table<T>(
    db: &ese_core::EseDatabase,
    table: &str,
    decode: impl Fn(&[u8], u32, usize) -> Result<T, SrumError>,
) -> anyhow::Result<Vec<T>> {
    let records = db
        .table_records(table)?
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
    collect_table(&db, TABLE_NETWORK_USAGE, network::decode_network_record)
}

/// Parse application usage records from a SRUDB.dat file.
///
/// Returns all records from the
/// `{5C8CF1C7-7257-4F13-B223-970EF5939312}` table.
///
/// # Errors
///
/// Returns an error if the file cannot be read or is not a valid ESE database.
pub fn parse_app_usage(path: &std::path::Path) -> anyhow::Result<Vec<srum_core::AppUsageRecord>> {
    let db = ese_core::EseDatabase::open(path)?;
    collect_table(&db, TABLE_APP_RESOURCE_USAGE, app_usage::decode_app_record)
}

/// Parse network connectivity records from a SRUDB.dat file.
///
/// Returns all records from the
/// `{DD6636C4-8929-4683-974E-22C046A43763}` table.
///
/// # Errors
///
/// Returns an error if the file cannot be read or is not a valid ESE database.
pub fn parse_network_connectivity(
    path: &std::path::Path,
) -> anyhow::Result<Vec<srum_core::NetworkConnectivityRecord>> {
    let db = ese_core::EseDatabase::open(path)?;
    collect_table(
        &db,
        TABLE_NETWORK_CONNECTIVITY,
        connectivity::decode_connectivity_record,
    )
}

/// Parse energy usage records from a SRUDB.dat file.
///
/// Returns all records from the
/// `{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}` table.
///
/// # Errors
///
/// Returns an error if the file cannot be read or is not a valid ESE database.
pub fn parse_energy_usage(
    path: &std::path::Path,
) -> anyhow::Result<Vec<srum_core::EnergyUsageRecord>> {
    let db = ese_core::EseDatabase::open(path)?;
    collect_table(&db, TABLE_ENERGY_USAGE, energy::decode_energy_record)
}

/// Parse push notification records from a SRUDB.dat file.
///
/// Returns all records from the
/// `{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}` table.
///
/// # Errors
///
/// Returns an error if the file cannot be read or is not a valid ESE database.
pub fn parse_push_notifications(
    path: &std::path::Path,
) -> anyhow::Result<Vec<srum_core::PushNotificationRecord>> {
    let db = ese_core::EseDatabase::open(path)?;
    collect_table(
        &db,
        TABLE_PUSH_NOTIFICATIONS,
        push_notification::decode_push_notification_record,
    )
}

/// Parse application timeline records from a SRUDB.dat file.
///
/// Returns all records from the
/// `{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}` table.
///
/// Available since Windows 10 Anniversary Update (1607).
///
/// # Errors
///
/// Returns an error if the file cannot be read or is not a valid ESE database.
pub fn parse_app_timeline(
    path: &std::path::Path,
) -> anyhow::Result<Vec<srum_core::AppTimelineRecord>> {
    let db = ese_core::EseDatabase::open(path)?;
    collect_table(&db, TABLE_APP_TIMELINE, app_timeline::decode_app_timeline_record)
}

/// Parse ID map entries from a SRUDB.dat file.
///
/// Returns all entries from the `SruDbIdMapTable` table.
///
/// # Errors
///
/// Returns an error if the file cannot be read or is not a valid ESE database.
pub fn parse_id_map(path: &std::path::Path) -> anyhow::Result<Vec<srum_core::IdMapEntry>> {
    let db = ese_core::EseDatabase::open(path)?;
    collect_table(&db, TABLE_ID_MAP, |data, page, tag| {
        id_map::decode_id_map_entry(data, page, tag)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn nonexistent_file_app_timeline_returns_err() {
        let result = parse_app_timeline(std::path::Path::new("/nonexistent/SRUDB.dat"));
        assert!(result.is_err());
    }

    #[test]
    fn empty_file_app_timeline_returns_err() {
        let tmp = NamedTempFile::new().expect("tempfile");
        let result = parse_app_timeline(tmp.path());
        assert!(result.is_err(), "empty file must return Err");
    }

    #[test]
    fn app_timeline_result_type() {
        let _: anyhow::Result<Vec<srum_core::AppTimelineRecord>> =
            parse_app_timeline(std::path::Path::new("/nonexistent/SRUDB.dat"));
    }

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
