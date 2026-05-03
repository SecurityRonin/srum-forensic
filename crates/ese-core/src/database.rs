//! ESE database handle for page-level access.

use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::{Path, PathBuf};

use crate::{catalog::CatalogEntry, EseError, EseHeader, EsePage};

/// An open ESE database file, ready for page-level access.
///
/// Retains the parsed [`EseHeader`] (which carries `page_size`) so that
/// every [`read_page`][EseDatabase::read_page] call can locate the correct
/// byte offset without re-reading the header.
pub struct EseDatabase {
    path: PathBuf,
    /// Parsed file header.
    pub header: EseHeader,
}

impl EseDatabase {
    /// Open an ESE database at `path` and parse its header.
    ///
    /// # Errors
    ///
    /// Returns [`EseError`] if the file cannot be read or is not a valid ESE database.
    pub fn open(path: &Path) -> Result<Self, EseError> {
        let header = crate::open(path)?;
        Ok(Self {
            path: path.to_owned(),
            header,
        })
    }

    /// Read a single page by its 0-based page number.
    ///
    /// Page 0 is the header page. Data pages start at page 1.
    /// Returns [`EseError::TooShort`] if `page_number` is beyond the file.
    ///
    /// # Errors
    ///
    /// Returns [`EseError`] on I/O error or if the page is out of range.
    pub fn read_page(&self, page_number: u32) -> Result<EsePage, EseError> {
        let page_size = self.header.page_size as usize;
        let offset = page_number as u64 * page_size as u64;

        let mut f = std::fs::File::open(&self.path)?;
        let file_len = f.metadata()?.len();

        if offset + page_size as u64 > file_len {
            return Err(EseError::TooShort {
                need: (offset + page_size as u64) as usize,
                got: file_len as usize,
            });
        }

        f.seek(SeekFrom::Start(offset))?;
        let mut data = vec![0u8; page_size];
        f.read_exact(&mut data)?;

        Ok(EsePage {
            page_number,
            flags: 0,
            data,
        })
    }

    /// Return the total number of pages in the file (including the header page).
    pub fn page_count(&self) -> u64 {
        let file_len = std::fs::metadata(&self.path)
            .map(|m| m.len())
            .unwrap_or(0);
        file_len / self.header.page_size as u64
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
        const CATALOG_PAGE: u32 = 4;
        let page = self.read_page(CATALOG_PAGE)?;
        let tags = page.tags()?;
        let mut entries = Vec::new();
        // Tag 0 is the page header tag — skip it; data records start at tag 1.
        for i in 1..tags.len() {
            let data = page.record_data(i)?;
            match CatalogEntry::from_bytes(data) {
                Ok(entry) => entries.push(entry),
                Err(_) => continue, // skip malformed/padding records
            }
        }
        Ok(entries)
    }

    /// Find the root B-tree page number for the named table.
    ///
    /// Reads the catalog and returns the `table_page` of the first entry
    /// whose `object_name` matches `name`.
    ///
    /// # Errors
    ///
    /// Returns [`EseError::NotFound`] if no matching table is in the catalog,
    /// or any I/O / parse error from [`catalog_entries`][Self::catalog_entries].
    pub fn find_table_page(&self, name: &str) -> Result<u32, EseError> {
        let entries = self.catalog_entries()?;
        entries
            .iter()
            .find(|e| e.object_name == name)
            .map(|e| e.table_page)
            .ok_or_else(|| EseError::NotFound(format!("table '{name}' not in catalog")))
    }
}
