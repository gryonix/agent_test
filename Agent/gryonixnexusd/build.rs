// Generate Rust types from the shared schema at build time. Same proto the
// clients generate from — one contract, no drift. Messages get serde derives so
// the Connect JSON codec (the debuggable wire path) can encode/decode them.
//
// The crate is compiled in TWO different trees and they do not agree on where
// the schema is:
//
//   * this repository, where the schema is a top-level `Proto/` shared by the
//     agent, the Swift client and the Kotlin one;
//   * the unpacked source archive ON A TARGET HOST, where `pack-agent-sources.sh`
//     stages the schema next to the crate as `../proto` because the layout
//     inside that archive is a runtime contract with every already-installed
//     server (the generated wrappers run `/root/Agent/bootstrap/install-agent.sh`).
//
// So the path is resolved, not assumed. Getting this wrong does not fail here —
// it fails on the customer's server, at the one moment nobody is watching.
fn main() {
    let candidates = ["../proto", "../../Proto"];
    let root = candidates
        .iter()
        .find(|dir| std::path::Path::new(dir).join("gryonixnexusd/v1/gryonixnexusd.proto").is_file())
        .unwrap_or_else(|| {
            panic!("gryonixnexusd.proto found in none of {candidates:?} (cwd {:?})",
                   std::env::current_dir())
        });
    let proto = format!("{root}/gryonixnexusd/v1/gryonixnexusd.proto");
    println!("cargo:rerun-if-changed={proto}");

    let mut config = prost_build::Config::new();
    config.message_attribute(
        ".",
        "#[derive(serde::Serialize, serde::Deserialize)] #[serde(rename_all = \"camelCase\", default)]",
    );
    config
        .compile_protos(&[proto.as_str()], &[root])
        .expect("compile gryonixnexusd.proto");
}
