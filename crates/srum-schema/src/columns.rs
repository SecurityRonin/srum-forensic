//! Per-table column schema definitions.

/// A single SRUM column definition (compile-time static data).
pub struct SrumColumnDef {
    /// 1-based column identifier.
    pub column_id: u32,
    /// Column name as it appears in MSysObjects.
    pub name: &'static str,
    /// JET column type code (see ese-core coltyp constants).
    pub coltyp: u8,
}

pub fn column_defs_for(_guid: &str) -> Option<&'static [SrumColumnDef]> {
    None
}
