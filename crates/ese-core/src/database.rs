//! ESE database handle for page-level access.

use std::path::{Path, PathBuf};

use memmap2::Mmap;

use crate::{catalog::CatalogEntry, record::ColumnDef, EseError, EseHeader, EsePage};

/// Iterator over raw record bytes across all leaf pages of a B-tree.
///
/// Each item is `(page_number, tag_index, record_bytes)`.
///
/// Error recovery: if a page cannot be read or its tag array is corrupt,
/// the error is yielded and the iterator advances to the next page. If an
/// individual tag's record data is corrupt, the error is yielded and the
/// iterator advances to the next tag on the same page.
#[derive(Debug)]
pub struct TableCursor<'db> {
    db: &'db EseDatabase,
    leaf_pages: Vec<u32>,
    page_idx: usize,
    tag_idx: usize, // starts at 1 (tag 0 is the page header tag)
}

impl Iterator for TableCursor<'_> {
    type Item = Result<(u32, usize, Vec<u8>), EseError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let &page_num = self.leaf_pages.get(self.page_idx)?;
            let page = match self.db.read_page(page_num) {
                Ok(p) => p,
                Err(e) => {
                    self.page_idx += 1;
                    self.tag_idx = 1;
                    return Some(Err(e));
                }
            };
            let tags = match page.tags() {
                Ok(t) => t,
                Err(e) => {
                    self.page_idx += 1;
                    self.tag_idx = 1;
                    return Some(Err(e));
                }
            };
            if self.tag_idx >= tags.len() {
                self.page_idx += 1;
                self.tag_idx = 1;
                continue;
            }
            let tag = self.tag_idx;
            self.tag_idx += 1;
            return match page.record_data(tag) {
                Ok(bytes) => Some(Ok((page_num, tag, bytes.to_vec()))),
                Err(e) => Some(Err(e)),
            };
        }
    }
}

/// An open ESE database file, memory-mapped for zero-copy page access.
///
/// The file is mapped once at [`open`][EseDatabase::open] time. All subsequent
/// [`read_page`][EseDatabase::read_page] and [`raw_page_slice`][EseDatabase::raw_page_slice]
/// calls slice directly into the mapping — no additional syscalls or heap
/// allocations per page.
///
/// # Safety invariant
///
/// The mapping is read-only. Callers must not modify the file on disk while an
/// `EseDatabase` is live; doing so is undefined behaviour (per `memmap2` docs).
/// In practice SRUDB.dat is treated as forensic evidence and never written.
pub struct EseDatabase {
    path: PathBuf,
    /// Parsed file header.
    pub header: EseHeader,
    mmap: Mmap,
}

impl std::fmt::Debug for EseDatabase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EseDatabase")
            .field("path", &self.path)
            .field("header", &self.header)
            .field("mmap_len", &self.mmap.len())
            .finish()
    }
}

impl EseDatabase {
    /// Open an ESE database at `path` and memory-map the entire file.
    ///
    /// # Errors
    ///
    /// Returns [`EseError`] if the file cannot be opened, mapped, or is not a
    /// valid ESE database.
    pub fn open(path: &Path) -> Result<Self, EseError> {
        let file = std::fs::File::open(path)?;
        // SAFETY: SRUDB.dat is read-only forensic evidence; we never write to
        // it while this mapping is live, so the UB precondition cannot trigger.
        let mmap = unsafe { Mmap::map(&file) }?;
        let header = EseHeader::from_bytes(&mmap)?;
        Ok(Self {
            path: path.to_owned(),
            header,
            mmap,
        })
    }

    /// Return a zero-copy slice of the raw bytes for page `page_number`.
    ///
    /// The slice borrows directly from the memory mapping — no heap allocation.
    /// Returns [`EseError::Corrupt`] if `page_number` is beyond the end of the
    /// file.
    ///
    /// # Errors
    ///
    /// Returns [`EseError`] if the requested page is out of range.
    pub fn raw_page_slice(&self, page_number: u32) -> Result<&[u8], EseError> {
        let page_size = self.header.page_size as usize;
        let start = usize::try_from(page_number)
            .unwrap_or(usize::MAX)
            .saturating_mul(page_size);
        let end = start.saturating_add(page_size);
        if end > self.mmap.len() {
            return Err(EseError::Corrupt {
                page: page_number,
                detail: format!(
                    "page beyond file end: need offset {end}, file is {} bytes",
                    self.mmap.len()
                ),
            });
        }
        Ok(&self.mmap[start..end])
    }

    /// Read a single page by its 0-based page number.
    ///
    /// Page 0 is the header page. Data pages start at page 1.
    /// Returns [`EseError::Corrupt`] if `page_number` is beyond the file.
    ///
    /// # Errors
    ///
    /// Returns [`EseError`] on I/O error or if the page is out of range.
    pub fn read_page(&self, page_number: u32) -> Result<EsePage, EseError> {
        Ok(EsePage {
            page_number,
            data: self.raw_page_slice(page_number)?.to_vec(),
        })
    }

    /// Return the total number of pages in the file (including the header page).
    pub fn page_count(&self) -> u64 {
        u64::try_from(self.mmap.len()).unwrap_or(0) / u64::from(self.header.page_size)
    }

    /// Read and parse all entries from the ESE catalog (page 4).
    ///
    /// The catalog maps table names to their root B-tree page numbers.
    /// Each tag on the catalog leaf page (tags 1+, skipping tag 0) is decoded
    /// as a [`CatalogEntry`].
    ///
    /// # Errors
    ///
    /// Returns [`EseError`] if the catalog page cannot be read or contains
    /// malformed records.
    pub fn catalog_entries(&self) -> Result<Vec<CatalogEntry>, EseError> {
        const CATALOG_ROOT: u32 = 4;
        let leaf_pages = self.walk_leaf_pages(CATALOG_ROOT)?;
        let mut entries = Vec::new();
        for page_num in leaf_pages {
            let page = self.read_page(page_num)?;
            let tags = page.tags()?;
            // Tag 0 is the page header tag — data records start at tag 1.
            for i in 1..tags.len() {
                let data = page.record_data(i)?;
                if let Ok(entry) = CatalogEntry::from_bytes(data) {
                    entries.push(entry);
                }
            }
        }
        Ok(entries)
    }

    /// Walk the B-tree rooted at `root_page` and return the page numbers of
    /// all leaf pages.
    ///
    /// - If the page has [`PAGE_FLAG_LEAF`][crate::PAGE_FLAG_LEAF] set, it is
    ///   returned directly.
    /// - If the page has [`PAGE_FLAG_PARENT`][crate::PAGE_FLAG_PARENT] set,
    ///   each tag (skipping tag 0) is decoded as an 8-byte child reference
    ///   whose first 4 bytes are the child page number (u32 LE); the walk
    ///   recurses into each child.
    ///
    /// # Errors
    ///
    /// Returns [`EseError`] if any page cannot be read or parsed.
    pub fn walk_leaf_pages(&self, root_page: u32) -> Result<Vec<u32>, EseError> {
        let page = self.read_page(root_page)?;
        let hdr = page.parse_header()?;
        if hdr.page_flags & crate::PAGE_FLAG_LEAF != 0 {
            return Ok(vec![root_page]);
        }
        // Parent page: collect child page numbers from tags 1+.
        let tag_count = hdr.available_page_tag_count as usize;
        let mut leaves = Vec::new();
        for i in 1..tag_count {
            let data = page.record_data(i)?;
            if data.len() < 4 {
                continue;
            }
            let child_page = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            let mut child_leaves = self.walk_leaf_pages(child_page)?;
            leaves.append(&mut child_leaves);
        }
        Ok(leaves)
    }

    /// Find the root B-tree page number for the named table.
    ///
    /// Reads the catalog and returns the `table_page` of the first entry
    /// whose `object_name` matches `name`.
    ///
    /// # Errors
    ///
    /// Returns [`EseError::TableNotFound`] if no matching table is in the catalog,
    /// or any I/O / parse error from [`catalog_entries`][Self::catalog_entries].
    pub fn find_table_page(&self, name: &str) -> Result<u32, EseError> {
        let entries = self.catalog_entries()?;
        entries
            .iter()
            .find(|e| e.object_name == name)
            .map(|e| e.table_page)
            .ok_or_else(|| EseError::TableNotFound {
                name: name.to_owned(),
            })
    }

    /// Open a cursor over all leaf records starting at `root_page`.
    ///
    /// # Errors
    ///
    /// Returns [`EseError`] if the leaf pages cannot be walked from `root_page`.
    pub fn table_records_from_root(&self, root_page: u32) -> Result<TableCursor<'_>, EseError> {
        let leaf_pages = self.walk_leaf_pages(root_page)?;
        Ok(TableCursor {
            db: self,
            leaf_pages,
            page_idx: 0,
            tag_idx: 1,
        })
    }

    /// Return the column definitions for a named table from the catalog.
    ///
    /// Reads the catalog, finds the table entry (object_type 1) whose name
    /// matches `table_name`, then collects all column entries (object_type 2)
    /// whose `parent_object_id` equals the table's `object_id`. In the
    /// synthetic catalog format, column entries store the JET coltyp in the
    /// `table_page` field. Results are sorted ascending by `column_id`.
    ///
    /// # Errors
    ///
    /// Returns [`EseError::TableNotFound`] if `table_name` is not in the
    /// catalog, or any I/O / parse error from [`catalog_entries`][Self::catalog_entries].
    pub fn table_columns(&self, table_name: &str) -> Result<Vec<ColumnDef>, EseError> {
        let entries = self.catalog_entries()?;
        let table = entries
            .iter()
            .find(|e| e.object_type == 1 && e.object_name == table_name)
            .ok_or_else(|| EseError::TableNotFound { name: table_name.to_owned() })?;
        let table_obj_id = table.object_id;
        let mut cols: Vec<ColumnDef> = entries
            .iter()
            .filter(|e| e.object_type == 2 && e.parent_object_id == table_obj_id)
            .map(|e| ColumnDef {
                column_id: e.object_id,
                name: e.object_name.clone(),
                coltyp: e.table_page as u8,
            })
            .collect();
        cols.sort_by_key(|c| c.column_id);
        Ok(cols)
    }

    /// Open a cursor over all records in a named SRUM table.
    ///
    /// Returns `Err(EseError::TableNotFound)` immediately if the table is absent.
    ///
    /// # Errors
    ///
    /// Returns [`EseError::TableNotFound`] if `table_name` is not in the catalog,
    /// or any I/O / parse error from reading the catalog or walking leaf pages.
    pub fn table_records(&self, table_name: &str) -> Result<TableCursor<'_>, EseError> {
        let root_page = self.find_table_page(table_name)?;
        self.table_records_from_root(root_page)
    }
}
