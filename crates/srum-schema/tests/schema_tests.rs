//! Tests for srum-schema — Phase 2 stories 1–10.
//!
//! GUIDs match forensicnomicon constants and the existing sr-cli/srum-parser codebase.

use srum_schema::{all_srum_tables, srum_column_defs, srum_table_name, SrumColumnDef, SrumTableInfo};

// ── story 1/2: srum_table_name ────────────────────────────────────────────────

#[test]
fn srum_table_name_network_usage() {
    let name = srum_table_name("{973F5D5C-1D90-4944-BE8E-24B22A728CF2}");
    assert_eq!(name, Some("Network Data Usage"));
}

#[test]
fn srum_table_name_app_resource_usage() {
    let name = srum_table_name("{5C8CF1C7-7257-4F13-B223-970EF5939312}");
    assert_eq!(name, Some("App Resource Usage"));
}

#[test]
fn srum_table_name_push_notifications() {
    let name = srum_table_name("{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}");
    assert_eq!(name, Some("Push Notifications"));
}

#[test]
fn srum_table_name_id_map() {
    let name = srum_table_name("SruDbIdMapTable");
    assert_eq!(name, Some("ID Map"));
}

// ── story 7/8: unknown GUID returns None ──────────────────────────────────────

#[test]
fn srum_table_name_unknown_guid_returns_none() {
    let name = srum_table_name("{00000000-0000-0000-0000-000000000000}");
    assert_eq!(name, None);
}

// ── story 3/4: srum_column_defs — BytesSent at column 8 ─────────────────────

#[test]
fn srum_column_defs_network_usage_has_bytes_sent_at_col_8() {
    let defs = srum_column_defs("{973F5D5C-1D90-4944-BE8E-24B22A728CF2}")
        .expect("network usage schema must exist");
    let bytes_sent = defs.iter().find(|c| c.name == "BytesSent");
    assert!(bytes_sent.is_some(), "BytesSent column must be present");
    assert_eq!(bytes_sent.unwrap().column_id, 8, "BytesSent must be at column 8");
}

#[test]
fn srum_column_defs_network_usage_count() {
    let defs = srum_column_defs("{973F5D5C-1D90-4944-BE8E-24B22A728CF2}")
        .expect("network usage schema must exist");
    assert_eq!(defs.len(), 9, "network usage has 9 columns (1-9)");
}

// ── story 7/8: srum_column_defs for unknown GUID returns None ────────────────

#[test]
fn srum_column_defs_unknown_guid_returns_none() {
    let defs = srum_column_defs("{00000000-0000-0000-0000-000000000000}");
    assert!(defs.is_none());
}

// ── story 5/6: all_srum_tables returns 8 entries ─────────────────────────────

#[test]
fn all_srum_tables_count() {
    let tables = all_srum_tables();
    assert_eq!(tables.len(), 8, "8 tables: 7 GUID-based + SruDbIdMapTable");
}

#[test]
fn all_srum_tables_contains_network_usage() {
    let tables = all_srum_tables();
    let found = tables
        .iter()
        .any(|t| t.guid == "{973F5D5C-1D90-4944-BE8E-24B22A728CF2}");
    assert!(found, "all_srum_tables must include Network Data Usage");
}

#[test]
fn all_srum_tables_contains_id_map() {
    let tables = all_srum_tables();
    let found = tables.iter().any(|t| t.guid == "SruDbIdMapTable");
    assert!(found, "all_srum_tables must include SruDbIdMapTable");
}

// ── story 9/10: AppUsage schema has 19 columns ───────────────────────────────

#[test]
fn srum_column_defs_app_usage_has_19_columns() {
    let defs = srum_column_defs("{5C8CF1C7-7257-4F13-B223-970EF5939312}")
        .expect("app resource usage schema must exist");
    assert_eq!(defs.len(), 19, "App Resource Usage must have 19 columns (1-19)");
}

#[test]
fn srum_column_defs_app_usage_foreground_cycle_time_at_col_5() {
    let defs = srum_column_defs("{5C8CF1C7-7257-4F13-B223-970EF5939312}")
        .expect("app resource usage schema");
    let col = defs.iter().find(|c| c.column_id == 5).expect("column 5");
    assert_eq!(col.name, "ForegroundCycleTime");
}

// ── type assertions ───────────────────────────────────────────────────────────

#[test]
fn srum_column_def_type_fields_accessible() {
    let defs = srum_column_defs("{973F5D5C-1D90-4944-BE8E-24B22A728CF2}")
        .expect("network usage schema");
    let col = &defs[0];
    let _: u32 = col.column_id;
    let _: &str = col.name;
    let _: u8 = col.coltyp;
}

#[test]
fn srum_table_info_fields_accessible() {
    let tables = all_srum_tables();
    let t = &tables[0];
    let _: &str = t.guid;
    let _: &str = t.name;
}
