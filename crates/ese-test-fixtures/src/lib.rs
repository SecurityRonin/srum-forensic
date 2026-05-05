//! Shared ESE test fixture builders.
//!
//! Used as a `[dev-dependency]` by ese-core, ese-integrity, ese-carver,
//! and srum-parser. Never compiled into release binaries.

pub use ese_core::PAGE_SIZE;

pub struct PageBuilder {
    data: Vec<u8>,
    page_size: usize,
    record_offset: usize,
    tag_count: usize,
}

impl PageBuilder {
    pub fn new(page_size: usize) -> Self { todo!() }
    pub fn leaf(self) -> Self { todo!() }
    pub fn parent(self) -> Self { todo!() }
    pub fn with_db_time(self, _t: u32) -> Self { todo!() }
    pub fn with_db_state(self, _s: u32) -> Self { todo!() }
    pub fn add_record(self, _data: &[u8]) -> Self { todo!() }
    pub fn add_child_page(self, _page_num: u32) -> Self { todo!() }
    pub fn with_slack(self, _bytes: &[u8]) -> Self { todo!() }
    pub fn build(self) -> Vec<u8> { todo!() }
}

pub struct EseFileBuilder {
    db_time: u64,
    db_state: u32,
    extra_pages: Vec<Vec<u8>>,
}

impl EseFileBuilder {
    pub fn new() -> Self { todo!() }
    pub fn with_db_time(self, _t: u64) -> Self { todo!() }
    pub fn with_db_state(self, _s: u32) -> Self { todo!() }
    pub fn add_page(self, _page: Vec<u8>) -> Self { todo!() }
    pub fn write(self) -> tempfile::NamedTempFile { todo!() }
}

impl Default for EseFileBuilder {
    fn default() -> Self { Self::new() }
}
