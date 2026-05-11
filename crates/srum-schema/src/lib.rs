//! SRUM table and column schema lookup.
//!
//! Thin static-data layer exposing SRUM GUID-to-name mappings and per-table
//! column definitions. All data is baked in at compile time — zero allocations
//! at lookup time.

mod columns;
mod tables;

pub use columns::SrumColumnDef;
pub use tables::SrumTableInfo;

/// Return the human-readable table name for a SRUM GUID (or "SruDbIdMapTable").
///
/// Returns `None` for unrecognised GUIDs.
pub fn srum_table_name(guid: &str) -> Option<&'static str> {
    tables::ALL_SRUM_TABLES
        .iter()
        .find(|t| t.guid == guid)
        .map(|t| t.name)
}

/// Return the column schema for a SRUM GUID.
///
/// Returns `None` for unrecognised GUIDs. The slice includes all columns
/// starting from the shared header columns (AutoIncId at 1, TimeStamp at 2,
/// AppId at 3, UserId at 4) through to table-specific columns.
pub fn srum_column_defs(guid: &str) -> Option<&'static [SrumColumnDef]> {
    columns::column_defs_for(guid)
}

/// Return all known SRUM tables.
pub fn all_srum_tables() -> &'static [SrumTableInfo] {
    tables::ALL_SRUM_TABLES
}
