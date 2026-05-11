//! Tests for catalog_entries() following multi-page B-tree — Phase 1 stories 17–18.
//!
//! The catalog lives at page 4. When it spans multiple leaf pages (parent +
//! leaves), catalog_entries() must walk all leaf pages via walk_leaf_pages(4).

mod fixtures;
use ese_core::{CatalogEntry, EseDatabase};
use ese_test_fixtures::{EseFileBuilder, PageBuilder, PAGE_SIZE};

/// Build an ESE file with a two-level catalog B-tree.
///
/// Layout:
/// - page 4 = parent page pointing to pages 5 and 6
/// - page 5 = leaf with a single entry ("TableA")
/// - page 6 = leaf with a single entry ("TableB")
fn make_two_page_catalog() -> (EseDatabase, tempfile::NamedTempFile) {
    let entry_a = CatalogEntry {
        object_type: 1,
        object_id: 2,
        parent_object_id: 1,
        table_page: 10,
        object_name: "TableA".to_owned(),
    };
    let entry_b = CatalogEntry {
        object_type: 1,
        object_id: 3,
        parent_object_id: 1,
        table_page: 11,
        object_name: "TableB".to_owned(),
    };
    let leaf_a = PageBuilder::new(PAGE_SIZE)
        .leaf()
        .add_record(&entry_a.to_bytes())
        .build();
    let leaf_b = PageBuilder::new(PAGE_SIZE)
        .leaf()
        .add_record(&entry_b.to_bytes())
        .build();
    let parent = fixtures::make_parent_page_with_children(&[5, 6]);
    let blank = vec![0u8; PAGE_SIZE];
    let tmp = EseFileBuilder::new()
        .add_page(blank.clone()) // page 1
        .add_page(blank.clone()) // page 2
        .add_page(blank.clone()) // page 3
        .add_page(parent)         // page 4 = catalog root (parent)
        .add_page(leaf_a)         // page 5 = catalog leaf A
        .add_page(leaf_b)         // page 6 = catalog leaf B
        .write();
    let db = EseDatabase::open(tmp.path()).expect("open db");
    (db, tmp)
}

#[test]
fn catalog_entries_follows_btree_to_second_leaf() {
    let (db, _tmp) = make_two_page_catalog();
    let entries = db.catalog_entries().expect("catalog_entries");
    let has_b = entries.iter().any(|e| e.object_name == "TableB");
    assert!(
        has_b,
        "catalog_entries must follow B-tree and include TableB from the second leaf page"
    );
}

#[test]
fn catalog_entries_btree_returns_all_entries() {
    let (db, _tmp) = make_two_page_catalog();
    let entries = db.catalog_entries().expect("catalog_entries");
    assert_eq!(
        entries.len(),
        2,
        "both TableA and TableB must be present when catalog spans two leaf pages"
    );
}
