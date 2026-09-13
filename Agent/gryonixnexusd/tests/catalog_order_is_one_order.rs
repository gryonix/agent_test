//! Catalog order is ONE order, and the crate keeps three copies of it.
//!
//! **Found by reordering one shelf.** Moving Forgejo ahead of GitLab in the
//! Swift catalog broke, in sequence: the report fixtures, the sudoers and
//! uninstall fixtures, the backup wrapper's own emission order, and finally
//! `RESTORABLE_ORDER` — four separate failures for one decision, each surfacing
//! only after the previous was fixed, and every one of them invisible until a
//! MULTI-service fixture happened to contain both forges.
//!
//! Nothing in the crate stated that these lists must agree, so this does. It
//! compares them against each other rather than against a fourth list written
//! here: a copy in the test is just one more thing to drift.
use std::fs;

/// Ids in the order a `const` array in the source lists them.
fn ordered_ids(source: &str, marker: &str) -> Vec<String> {
    let body = source
        .split_once(marker)
        .unwrap_or_else(|| panic!("{marker} must exist"))
        .1;
    let end = body.find("];").expect("the array must be closed");
    body[..end]
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.starts_with("//") {
                return None;
            }
            let start = line.find('"')?;
            let rest = &line[start + 1..];
            let stop = rest.find('"')?;
            Some(rest[..stop].to_string())
        })
        .collect()
}

fn read(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_else(|err| panic!("{path}: {err}"))
}

/// The two declared order lists must be the same sequence, for the ids they
/// share. `RESTORABLE_ORDER` is a subset — not everything can be restored —
/// so it is compared as a subsequence rather than for equality.
#[test]
fn restorable_order_follows_catalog_order() {
    let catalog = ordered_ids(&read("src/install/host/mod.rs"), "pub const CATALOG_ORDER");
    let restorable = ordered_ids(&read("src/install/host/restore.rs"), "const RESTORABLE_ORDER");
    assert!(!catalog.is_empty() && !restorable.is_empty());

    let filtered: Vec<&String> = catalog.iter().filter(|id| restorable.contains(id)).collect();
    let expected: Vec<&String> = restorable.iter().collect();
    assert_eq!(
        filtered, expected,
        "RESTORABLE_ORDER disagrees with CATALOG_ORDER — one shelf was reordered and only one list moved"
    );
}

/// The backup wrapper emits its service arms by hand, in source order, so its
/// sequence is a third copy. Compared by where each `if has("<id>")` appears.
#[test]
fn the_backup_wrappers_arms_follow_catalog_order() {
    let catalog = ordered_ids(&read("src/install/host/mod.rs"), "pub const CATALOG_ORDER");
    let source = read("src/install/host/backup_ctl.rs");

    let mut seen: Vec<(usize, String)> = Vec::new();
    for id in &catalog {
        if let Some(at) = source.find(&format!("if has(\"{id}\")")) {
            seen.push((at, id.clone()));
        }
    }
    let mut sorted = seen.clone();
    sorted.sort_by_key(|(at, _)| *at);
    assert_eq!(
        seen.iter().map(|(_, id)| id).collect::<Vec<_>>(),
        sorted.iter().map(|(_, id)| id).collect::<Vec<_>>(),
        "the backup wrapper emits services in a different order than the catalog — \
         its multi-service fixtures are the only other place this shows up"
    );
}
