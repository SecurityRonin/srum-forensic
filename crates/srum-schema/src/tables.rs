//! Static SRUM table registry.

/// Metadata for one SRUM extension table.
pub struct SrumTableInfo {
    /// ESE table name (GUID string or "SruDbIdMapTable").
    pub guid: &'static str,
    /// Human-readable name.
    pub name: &'static str,
}

pub static ALL_SRUM_TABLES: &[SrumTableInfo] = &[];
