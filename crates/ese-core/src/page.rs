//! ESE database page types.

/// A single ESE database page.
#[derive(Debug, Clone)]
pub struct EsePage {
    /// Page number (1-based).
    pub page_number: u32,
    /// Page flags.
    pub flags: u32,
    /// Raw page data.
    pub data: Vec<u8>,
}
