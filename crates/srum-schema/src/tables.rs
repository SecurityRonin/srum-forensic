//! Static SRUM table registry.
//!
//! GUIDs sourced from forensicnomicon constants and verified against
//! the sr-cli/srum-parser codebase.

/// Metadata for one SRUM extension table.
pub struct SrumTableInfo {
    /// ESE table name: a GUID string like `{973F5D5C-…}` or `"SruDbIdMapTable"`.
    pub guid: &'static str,
    /// Human-readable table name.
    pub name: &'static str,
}

pub static ALL_SRUM_TABLES: &[SrumTableInfo] = &[
    SrumTableInfo {
        guid: "{973F5D5C-1D90-4944-BE8E-24B94231A174}",
        name: "Network Data Usage",
    },
    SrumTableInfo {
        guid: "{5C8CF1C7-7257-4F13-B223-970EF5939312}",
        name: "App Resource Usage",
    },
    SrumTableInfo {
        guid: "{DD6636C4-8929-4683-974E-22C046A43763}",
        name: "Network Connectivity",
    },
    SrumTableInfo {
        guid: "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}",
        name: "Energy Usage",
    },
    SrumTableInfo {
        guid: "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}LT",
        name: "Energy Usage Long-Term",
    },
    SrumTableInfo {
        guid: "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}",
        name: "Push Notifications",
    },
    SrumTableInfo {
        guid: "{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}",
        name: "Application Timeline",
    },
    SrumTableInfo {
        guid: "SruDbIdMapTable",
        name: "ID Map",
    },
];
