//! Integration tests for ese-btree-walk story.
//!
//! Tests [`EseDatabase::walk_leaf_pages`].

mod fixtures;
use ese_core::EseDatabase;

#[test]
fn walk_leaf_root_returns_root_page() {
    // A root page that is itself a leaf: walk_leaf_pages returns just that page number.
    let leaf = fixtures::make_leaf_page_with_records(0, &[]);
    let header = fixtures::make_ese_header_page();
    // page 0 = header, page 1 = leaf-root
    let tmp = fixtures::write_ese_file(&[header, leaf]);
    let db = EseDatabase::open(tmp.path()).expect("open");
    let leaves = db.walk_leaf_pages(1).expect("walk");
    assert_eq!(leaves, vec![1u32]);
}

#[test]
fn walk_two_level_btree_returns_leaf_pages_not_root() {
    // page 0 = header
    // page 1 = parent (root), ESE child refs [1, 2] → physical pages 2 and 3
    // page 2 = leaf A  (ESE page 1, physical 2)
    // page 3 = leaf B  (ESE page 2, physical 3)
    let header = fixtures::make_ese_header_page();
    let parent = fixtures::make_parent_page_with_children(&[1, 2]); // ESE page numbers
    let leaf_a = fixtures::make_leaf_page_with_records(0, &[]);
    let leaf_b = fixtures::make_leaf_page_with_records(0, &[]);
    let tmp = fixtures::write_ese_file(&[header, parent, leaf_a, leaf_b]);
    let db = EseDatabase::open(tmp.path()).expect("open");
    let mut leaves = db.walk_leaf_pages(1).expect("walk");
    leaves.sort_unstable();
    assert_eq!(leaves, vec![2u32, 3u32], "both leaf pages returned");
    assert!(!leaves.contains(&1), "root page must not be in result");
}

#[test]
fn walk_nonexistent_page_returns_err() {
    // Only page 0 (header) exists; asking for page 5 must fail.
    let header = fixtures::make_ese_header_page();
    let tmp = fixtures::write_ese_file(&[header]);
    let db = EseDatabase::open(tmp.path()).expect("open");
    assert!(db.walk_leaf_pages(5).is_err());
}
