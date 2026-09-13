//! The schema and the router have to agree — in BOTH directions.
//!
//! **This is not bookkeeping; it caught a real defect once and would catch it
//! again.** When `Install/InstallService` was added, the module doc already
//! said the verb was wired into `api.rs` while `route()` carried only a dead
//! `use` — the route itself was written afterwards, and nothing but a human
//! reading the file stood between "declared" and "reachable". A verb in the
//! schema that the router does not answer is a 404 the app reads as a dead
//! route, which is indistinguishable from an agent too old to know it.
//!
//! The reverse direction matters for a smaller reason: a path the router
//! answers but the schema never declares is a verb no generated client can
//! call, so it is either dead code or an undocumented back door.
//!
//! Read from the SOURCE FILES rather than from generated types on purpose. The
//! generated code is derived from the proto, so comparing it against the proto
//! would compare the schema with itself; `api.rs` is hand-written, and it is
//! the half that can drift.

use std::path::Path;

fn read(relative: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
}

/// The schema, wherever this crate is standing. It is a shared top-level
/// `Proto/` in the repository (three languages generate from it) and a staged
/// `../proto` inside the source archive a host builds from — the same two trees
/// `build.rs` resolves between, and for the same reason: the archive's layout
/// is a contract with servers that are already in the field.
fn read_proto() -> String {
    for candidate in ["../proto/gryonixnexusd/v1/gryonixnexusd.proto",
                      "../../Proto/gryonixnexusd/v1/gryonixnexusd.proto"] {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(candidate);
        if path.is_file() {
            return read(candidate);
        }
    }
    panic!("gryonixnexusd.proto found in neither ../proto nor ../../Proto");
}

/// Every `rpc Name(` in the schema.
fn declared_rpcs(proto: &str) -> Vec<String> {
    proto
        .lines()
        .map(str::trim)
        .filter_map(|line| line.strip_prefix("rpc "))
        .filter_map(|rest| rest.split('(').next())
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty())
        .collect()
}

/// Every `"/gryonixnexusd.v1.<Service>/<Method>"` the router matches on.
fn routed_rpcs(api: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in api.lines() {
        let mut rest = line;
        while let Some(start) = rest.find("\"/gryonixnexusd.v1.") {
            let after = &rest[start + 1..];
            let Some(end) = after.find('"') else { break };
            let path = &after[..end];
            if let Some(method) = path.rsplit('/').next() {
                if !method.is_empty() {
                    out.push(method.to_string());
                }
            }
            rest = &after[end..];
        }
    }
    out
}

#[test]
fn every_rpc_the_schema_declares_is_answered_by_the_router() {
    let declared = declared_rpcs(&read_proto());
    let routed = routed_rpcs(&read("src/api.rs"));
    assert!(!declared.is_empty(), "the proto parser found nothing — it stopped matching the file");
    assert!(!routed.is_empty(), "the router parser found nothing — it stopped matching the file");

    let missing: Vec<&String> = declared.iter().filter(|name| !routed.contains(name)).collect();
    assert!(
        missing.is_empty(),
        "declared in the schema but not routed, so the agent answers 404 — which the app reads as \
         a dead route rather than as a missing arm: {missing:?}"
    );
}

#[test]
fn every_route_the_agent_answers_is_declared_in_the_schema() {
    let declared = declared_rpcs(&read_proto());
    let routed = routed_rpcs(&read("src/api.rs"));

    let undeclared: Vec<&String> = routed.iter().filter(|name| !declared.contains(name)).collect();
    assert!(
        undeclared.is_empty(),
        "answered by the router but absent from the schema, so no generated client can reach it: \
         {undeclared:?}"
    );
}

/// **A streaming verb must read its request out of the ENVELOPE, and nothing
/// but this notices when one does not.**
///
/// Connect wraps the request of a streaming RPC in a five-byte frame. A route
/// that calls `decode` instead of `decode_enveloped` therefore hands serde the
/// frame header and gets "expected value at line 1 column 1" — a 500 with no
/// stream, for every call, always.
///
/// Measured on a live host 2026-08-22: three of the containers section's new
/// verbs shipped this way. Every unit test passed, because they exercise the
/// modules and the modules never see the wire; the app's own client could not
/// have caught it either, since it sits above the framing. The failure is
/// invisible until something speaks real Connect to a real agent.
///
/// So the check is structural and reads both files: whatever the SCHEMA calls
/// `returns (stream …)` must decode its request enveloped in `api.rs`.
#[test]
fn every_streaming_rpc_decodes_its_request_from_the_envelope() {
    let proto = read_proto();
    let api = read("src/api.rs");

    // `rpc Name(Req) returns (stream Resp);`
    let streaming: Vec<String> = proto
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("rpc ") && line.contains("returns (stream "))
        .filter_map(|line| line.strip_prefix("rpc "))
        .filter_map(|rest| rest.split('(').next())
        .map(|name| name.trim().to_string())
        .collect();
    assert!(
        streaming.len() >= 8,
        "the schema should still declare the streaming verbs; found {streaming:?}"
    );

    let mut plain = Vec::new();
    for method in &streaming {
        // The arm is the quoted path, and the decode is the first one after it.
        let Some(at) = api.find(&format!("/{}\"", method)).or_else(|| api.find(&format!("/{method}\""))) else {
            continue; // reachability is the other test's job
        };
        let tail = &api[at..];
        let Some(decode_at) = tail.find("codec.decode") else { continue };
        // Only the arm's own body, never the next one's.
        let arm_end = tail.find("\n        \"/gryonixnexusd").unwrap_or(tail.len());
        if decode_at > arm_end {
            continue; // this arm decodes nothing (no request fields worth reading)
        }
        if !tail[decode_at..].starts_with("codec.decode_enveloped") {
            plain.push(method.clone());
        }
    }
    assert!(
        plain.is_empty(),
        "these streaming verbs decode their request WITHOUT the Connect envelope, so every call \
         to them fails with a 500 and no stream:\n  {}",
        plain.join("\n  ")
    );
}
